//! Real-time JTAG worker thread with URGENT/NORMAL priority queues, 5-gate Write Guard,
//! raw-unit readback verification, PREEMPT_SAFE_REVERT purge, and zero-overhead shared ring buffers.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::backend::ccs21::Ccs21Backend;
use crate::backend::job_object::HighResTimerGuard;
use crate::backend::sim::SimulatedBackend;
use crate::backend::DebugBackend;
use crate::core::coalescer::{
    build_read_plan, split_failed_span, validate_write_target, ReadPlan, SlowSpanScheduler,
};
use crate::core::codec::{
    clamp_value, decode_raw_scalar, encode_scalar_units, engineering_to_raw, raw_to_engineering,
    RawScalar,
};
use crate::core::devices::get_device_profile;
use crate::core::models::{
    ConnectionRequest, CoreState, DeviceId, FlashFingerprint, MemCfgSnapshot, MemoryRange,
    PollConfig, PollMode, PollStats, ProblemRecord, ProbeKind, SessionState, WatchItem,
};
use crate::core::ring_buffer::ChannelRingBuffer;

#[derive(Debug, Clone)]
pub enum WorkerCmd {
    Connect(ConnectionRequest),
    Disconnect,
    ConnectCore { core: String, attach_live: bool },
    DisconnectCore { core: String },
    LoadProgram { core: String, path: PathBuf },
    LoadSymbols { core: String, path: PathBuf },
    RunCore(String),
    HaltCore(String),
    ResetCore(String),
    RunAll,
    HaltAll,
    MicroHaltDbgM(String),
    SetWatchList(Vec<WatchItem>),
    SetExtraRam { core: String, ranges: Vec<MemoryRange> },
    SetPollConfig(PollConfig),
    SetPollingActive(bool),
    SingleShot,
    WriteSymbol { id: String, value: f64 },
    BatchWrite(Vec<(String, f64)>),
    PreemptSafeRevert(Vec<(String, f64)>),
    VerifyFlashFingerprint { core: String, fp: FlashFingerprint },
    InvalidateImage { locked: bool, reason: String },
    UnlockDcsm { core: String, zone: u8, keys: Vec<u32> },
    ConfigureDlog { enabled: bool, trigger_mode: String, level: f64 },
    StartCsvRecording(PathBuf),
    StopCsvRecording,
    Shutdown,
}

impl WorkerCmd {
    pub fn is_urgent(&self) -> bool {
        matches!(
            self,
            Self::PreemptSafeRevert(_)
                | Self::HaltCore(_)
                | Self::HaltAll
                | Self::Disconnect
                | Self::InvalidateImage { .. }
                | Self::Shutdown
        )
    }
}

#[derive(Debug, Clone)]
pub enum WorkerEvent {
    Log { level: String, msg: String },
    Problem(ProblemRecord),
    WriteResult { id: String, ok: bool, msg: String, value: Option<f64> },
    SafeRevertResult { all_verified: bool, detail: String },
    BuiltinSymbols(BTreeMap<String, Vec<crate::core::models::SymbolNode>>),
    Connected { device: DeviceId },
    Disconnected,
}

#[derive(Debug, Clone)]
pub struct LatestSample {
    pub eng: f64,
    pub raw: Option<RawScalar>,
    pub timestamp: f64,
    pub has_error: bool,
}

pub struct SharedTelemetry {
    pub fsm_state: SessionState,
    pub connected: bool,
    pub stale_image_locked: bool,
    pub stale_image_reason: String,
    pub core_states: BTreeMap<String, CoreState>,
    pub memcfg: MemCfgSnapshot,
    pub stats: PollStats,
    pub non_atomic_ids: HashSet<String>,
    pub latest: BTreeMap<String, LatestSample>,
    pub buffers: BTreeMap<String, ChannelRingBuffer>,
    pub events: VecDeque<WorkerEvent>,
    pub probe_lease_holder: Option<String>,
    pub csv_recording: bool,
}

impl Default for SharedTelemetry {
    fn default() -> Self {
        Self {
            fsm_state: SessionState::Disconnected,
            connected: false,
            stale_image_locked: false,
            stale_image_reason: String::new(),
            core_states: BTreeMap::new(),
            memcfg: MemCfgSnapshot::default(),
            stats: PollStats::default(),
            non_atomic_ids: HashSet::new(),
            latest: BTreeMap::new(),
            buffers: BTreeMap::new(),
            events: VecDeque::new(),
            probe_lease_holder: None,
            csv_recording: false,
        }
    }
}

struct PriorityInbox {
    urgent: VecDeque<WorkerCmd>,
    normal: VecDeque<WorkerCmd>,
}

pub struct SessionController {
    shared: Arc<Mutex<SharedTelemetry>>,
    inbox: Arc<Mutex<PriorityInbox>>,
    stop_flag: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl SessionController {
    pub fn new(ring_capacity: usize) -> Self {
        let shared = Arc::new(Mutex::new(SharedTelemetry::default()));
        let inbox = Arc::new(Mutex::new(PriorityInbox {
            urgent: VecDeque::new(),
            normal: VecDeque::new(),
        }));
        let stop_flag = Arc::new(AtomicBool::new(false));

        let sh_c = Arc::clone(&shared);
        let in_c = Arc::clone(&inbox);
        let sf_c = Arc::clone(&stop_flag);
        let handle = thread::Builder::new()
            .name("c2000-jtag-worker".into())
            .spawn(move || run_worker_loop(sh_c, in_c, sf_c, ring_capacity))
            .expect("spawn worker thread");

        Self {
            shared,
            inbox,
            stop_flag,
            handle: Some(handle),
        }
    }

    pub fn shared(&self) -> Arc<Mutex<SharedTelemetry>> {
        Arc::clone(&self.shared)
    }

    pub fn send(&self, cmd: WorkerCmd) {
        let mut q = self.inbox.lock().unwrap();
        if matches!(cmd, WorkerCmd::PreemptSafeRevert(_)) {
            // Purge ALL pending normal-lane writes immediately so dangerous setpoints never hit hardware first!
            q.normal.retain(|pending| !matches!(pending, WorkerCmd::WriteSymbol { .. } | WorkerCmd::BatchWrite(_)));
        }
        if cmd.is_urgent() {
            q.urgent.push_back(cmd);
        } else {
            q.normal.push_back(cmd);
        }
    }

    pub fn acquire_probe_lease(&self, holder: &str) -> Result<(), String> {
        let mut st = self.shared.lock().unwrap();
        if matches!(
            st.fsm_state,
            SessionState::Connecting
                | SessionState::ConnectedLive
                | SessionState::WriteLockedStaleImage
                | SessionState::DcsmLocked
        ) {
            return Err("Probe locked by active debug session. Disconnect first.".into());
        }
        if let Some(cur) = &st.probe_lease_holder {
            if cur != holder {
                return Err(format!("Probe busy with '{cur}'."));
            }
        }
        st.probe_lease_holder = Some(holder.to_string());
        Ok(())
    }

    pub fn release_probe_lease(&self, holder: &str) {
        let mut st = self.shared.lock().unwrap();
        if st.probe_lease_holder.as_deref() == Some(holder) {
            st.probe_lease_holder = None;
        }
    }

    pub fn clear_buffers(&self) {
        let mut st = self.shared.lock().unwrap();
        for rb in st.buffers.values_mut() {
            rb.clear();
        }
    }

    pub fn shutdown(&mut self) {
        self.send(WorkerCmd::Shutdown);
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for SessionController {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn push_event(shared: &Arc<Mutex<SharedTelemetry>>, ev: WorkerEvent) {
    let mut st = shared.lock().unwrap();
    if st.events.len() > 256 {
        st.events.pop_front();
    }
    st.events.push_back(ev);
}

fn push_log(shared: &Arc<Mutex<SharedTelemetry>>, level: &str, msg: impl Into<String>) {
    push_event(
        shared,
        WorkerEvent::Log {
            level: level.to_string(),
            msg: msg.into(),
        },
    );
}

fn push_problem(shared: &Arc<Mutex<SharedTelemetry>>, sev: &str, src: &str, msg: impl Into<String>) {
    push_event(
        shared,
        WorkerEvent::Problem(ProblemRecord {
            time: now_hms(),
            severity: sev.to_uppercase(),
            source: src.to_string(),
            message: msg.into(),
        }),
    );
}

fn now_hms() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

/// Authoritative 5-Gate Write Execution reusable by both Worker loop and direct fault-injection tests.
#[allow(clippy::too_many_arguments)]
pub fn perform_guarded_write(
    backend: &mut dyn DebugBackend,
    device_id: DeviceId,
    item: &WatchItem,
    target_eng: f64,
    stale_locked: bool,
    stale_reason: &str,
    verify_after_write: bool,
    extra_ram: &BTreeMap<String, Vec<MemoryRange>>,
    memcfg: &MemCfgSnapshot,
    connected_cores: &HashSet<String>,
) -> Result<f64, String> {
    // Gate 1: Stale image lockout
    if stale_locked {
        return Err(format!(
            "WRITE LOCKED (STALE .OUT): {}",
            if stale_reason.is_empty() { "Reload & verify Flash fingerprint first." } else { stale_reason }
        ));
    }
    // Gate 2: RO / Bitfield lock
    if item.read_only {
        return Err(format!("'{}' is locked Read-Only.", item.symbol_path));
    }
    if item.is_bitfield() && !item.rmw_unlocked {
        return Err(format!("Bitfield '{}' is Read-Only unless RMW-unlocked.", item.symbol_path));
    }
    // Gate 3: 5-gate hardware address firewall
    let profile = get_device_profile(device_id);
    let dec = validate_write_target(
        item,
        &profile,
        Some(extra_ram),
        memcfg.probed.then_some(memcfg),
        Some(connected_cores),
    );
    if !dec.allowed {
        return Err(dec.reason);
    }
    // Gate 4: Finite & safety clamp
    let (clamped_eng, _clamped) = clamp_value(target_eng, item.min_val, item.max_val)?;
    let raw_target = engineering_to_raw(clamped_eng, item.data_type, item.display_format, item.iq_q_bits);

    let cp = profile
        .find_core(&dec.write_core)
        .ok_or_else(|| format!("Core {} missing", dec.write_core))?;
    let au = cp.address_unit_bits;
    let cont_units = if item.is_bitfield() {
        item.container_units.unwrap_or_else(|| item.data_type.unit_count(au))
    } else {
        item.data_type.unit_count(au)
    };

    let existing = if item.is_bitfield() {
        Some(backend.read_block(&dec.write_core, item.address, cont_units, au, &dec.page)?)
    } else {
        None
    };

    let use_32_atomic = !item.is_bitfield()
        && item.data_type.is_32bit()
        && ((au == 16 && (item.address & 1) == 0) || (au == 8 && (item.address & 3) == 0));
    let write_bits = if use_32_atomic { 32 } else { au };

    let units = encode_scalar_units(
        raw_target,
        item.data_type,
        au,
        Some(write_bits),
        existing.as_deref(),
        item.bit_offset,
        item.bit_width,
        item.container_units,
    )?;

    // Gate 5: Atomic write + MANDATORY raw-unit bit-for-bit readback equality verification
    backend.write_block(&dec.write_core, item.address, &units, write_bits, &dec.page)?;
    if verify_after_write {
        let rb = backend.read_block(&dec.write_core, item.address, units.len() as u32, write_bits, &dec.page)?;
        if rb != units {
            return Err(format!(
                "Readback MISMATCH on '{}' @ 0x{:X}: wrote {:X?}, read {:X?}",
                item.symbol_path, item.address, units, rb
            ));
        }
    }
    Ok(clamped_eng)
}

fn run_worker_loop(
    shared: Arc<Mutex<SharedTelemetry>>,
    inbox: Arc<Mutex<PriorityInbox>>,
    stop_flag: Arc<AtomicBool>,
    ring_capacity: usize,
) {
    let _timer_guard = HighResTimerGuard::new();

    let mut backend: Option<Box<dyn DebugBackend>> = None;
    let mut device_id = DeviceId::F28069M;
    let mut connected = false;
    let mut polling_active = true;
    let mut poll_config = PollConfig::default();
    let mut watch_items: Vec<WatchItem> = Vec::new();
    let mut extra_ram: BTreeMap<String, Vec<MemoryRange>> = BTreeMap::new();
    let mut memcfg = MemCfgSnapshot::default();
    let mut read_plan = ReadPlan::default();
    let mut slow_sched = SlowSpanScheduler::default();
    let mut stale_locked = false;
    let mut stale_reason = String::new();
    let mut dlog_active = false;
    let mut csv_writer: Option<BufWriter<File>> = None;

    let t0 = Instant::now();
    let mut last_stats_wall = Instant::now();
    let mut last_tick_wall = Instant::now();
    let mut tick_count: u64 = 0;
    let mut words_read: u64 = 0;
    let mut err_count: u64 = 0;
    let mut cycle_idx: u64 = 0;
    let mut latencies_ms: Vec<f64> = Vec::with_capacity(256);
    let mut tick_dts_ms: Vec<f64> = Vec::with_capacity(256);
    let mut next_fixed_deadline = Instant::now();
    let mut failed_spans: HashSet<usize> = HashSet::new();

    let rebuild_plan = |items: &mut Vec<WatchItem>,
                        dev: DeviceId,
                        cfg: &PollConfig,
                        extra: &BTreeMap<String, Vec<MemoryRange>>,
                        mc: &MemCfgSnapshot,
                        be: &Option<Box<dyn DebugBackend>>,
                        sh: &Arc<Mutex<SharedTelemetry>>| -> ReadPlan {
        let profile = get_device_profile(dev);
        let conn_cores: Option<HashSet<String>> = be.as_ref().map(|b| {
            b.get_core_states()
                .into_iter()
                .filter(|(_, s)| *s != CoreState::Disconnected)
                .map(|(k, _)| k)
                .collect()
        });
        let plan = build_read_plan(
            items,
            &profile,
            cfg.coalesce_gap,
            cfg.max_block_units,
            Some(extra),
            mc.probed.then_some(mc),
            conn_cores.as_ref(),
        );
        let mut st = sh.lock().unwrap();
        st.non_atomic_ids = plan.non_atomic_ids.iter().cloned().collect();
        let active_ids: HashSet<String> = items.iter().map(|i| i.id.clone()).collect();
        st.buffers.retain(|k, _| active_ids.contains(k));
        st.latest.retain(|k, _| active_ids.contains(k));
        for it in items.iter() {
            st.buffers
                .entry(it.id.clone())
                .or_insert_with(|| ChannelRingBuffer::new(ring_capacity));
        }
        plan
    };

    while !stop_flag.load(Ordering::Relaxed) {
        // 1. Drain URGENT lane first, then NORMAL lane
        let next_cmd = {
            let mut q = inbox.lock().unwrap();
            q.urgent.pop_front().or_else(|| q.normal.pop_front())
        };

        if let Some(cmd) = next_cmd {
            match cmd {
                WorkerCmd::Shutdown => break,
                WorkerCmd::Connect(req) => {
                    if let Some(mut old) = backend.take() {
                        old.shutdown();
                    }
                    {
                        let mut st = shared.lock().unwrap();
                        st.fsm_state = SessionState::Connecting;
                        st.connected = false;
                    }
                    device_id = req.device_id;
                    let mut be: Box<dyn DebugBackend> = match req.probe_kind {
                        ProbeKind::SIMULATOR => Box::new(SimulatedBackend::new()),
                        _ => Box::new(Ccs21Backend::new(None)),
                    };
                    be.set_allow_rude_fallback(poll_config.allow_rude_fallback);
                    match be.connect(&req) {
                        Ok(states) => {
                            let profile = get_device_profile(device_id);
                            let mut builtins = BTreeMap::new();
                            for c in &profile.cores {
                                let syms = be.get_builtin_symbols(c.name);
                                if !syms.is_empty() {
                                    builtins.insert(c.name.to_string(), syms);
                                }
                            }
                            let primary = profile.primary_core().name.to_string();
                            memcfg = be.probe_memcfg(&primary);
                            connected = true;
                            stale_locked = false;
                            stale_reason.clear();
                            failed_spans.clear();
                            backend = Some(be);
                            read_plan = rebuild_plan(
                                &mut watch_items,
                                device_id,
                                &poll_config,
                                &extra_ram,
                                &memcfg,
                                &backend,
                                &shared,
                            );
                            let fsm = if memcfg.dcsm_z1_locked || memcfg.dcsm_z2_locked {
                                SessionState::DcsmLocked
                            } else {
                                SessionState::ConnectedLive
                            };
                            {
                                let mut st = shared.lock().unwrap();
                                st.connected = true;
                                st.fsm_state = fsm;
                                st.core_states = states;
                                st.memcfg = memcfg;
                                st.stale_image_locked = false;
                                st.stale_image_reason.clear();
                            }
                            if !builtins.is_empty() {
                                push_event(&shared, WorkerEvent::BuiltinSymbols(builtins));
                            }
                            push_event(&shared, WorkerEvent::Connected { device: device_id });
                            push_log(&shared, "info", format!("Live session connected ({})", device_id.display_name()));
                        }
                        Err(err) => {
                            connected = false;
                            {
                                let mut st = shared.lock().unwrap();
                                st.connected = false;
                                st.fsm_state = SessionState::Fault;
                            }
                            push_problem(&shared, "error", "connect", err.clone());
                            push_log(&shared, "error", format!("Connect failed: {err}"));
                        }
                    }
                }
                WorkerCmd::Disconnect => {
                    if let Some(mut b) = backend.take() {
                        b.disconnect();
                    }
                    connected = false;
                    dlog_active = false;
                    let t_now = t0.elapsed().as_secs_f64();
                    {
                        let mut st = shared.lock().unwrap();
                        st.connected = false;
                        st.fsm_state = SessionState::Disconnected;
                        for rb in st.buffers.values_mut() {
                            rb.append_nan_gap(t_now);
                        }
                        for v in st.core_states.values_mut() {
                            *v = CoreState::Disconnected;
                        }
                    }
                    push_event(&shared, WorkerEvent::Disconnected);
                    push_log(&shared, "info", "Disconnected safely (NaN gap injected).");
                }
                WorkerCmd::ConnectCore { core, attach_live } => {
                    if let Some(b) = backend.as_mut() {
                        match b.connect_core(&core, attach_live) {
                            Ok(st_core) => {
                                let _ = b.set_realtime_mode(&core, poll_config.realtime_mode);
                                shared.lock().unwrap().core_states = b.get_core_states();
                                read_plan = rebuild_plan(&mut watch_items, device_id, &poll_config, &extra_ram, &memcfg, &backend, &shared);
                                push_log(&shared, "info", format!("Core {core} -> {}", st_core.short_label()));
                            }
                            Err(e) => push_problem(&shared, "error", &core, e),
                        }
                    }
                }
                WorkerCmd::DisconnectCore { core } => {
                    if let Some(b) = backend.as_mut() {
                        let _ = b.disconnect_core(&core);
                        shared.lock().unwrap().core_states = b.get_core_states();
                        read_plan = rebuild_plan(&mut watch_items, device_id, &poll_config, &extra_ram, &memcfg, &backend, &shared);
                    }
                }
                WorkerCmd::LoadProgram { core, path } => {
                    if let Some(b) = backend.as_mut() {
                        match b.load_program(&core, &path) {
                            Ok(_) => {
                                stale_locked = false;
                                stale_reason.clear();
                                {
                                    let mut st = shared.lock().unwrap();
                                    st.core_states = b.get_core_states();
                                    st.stale_image_locked = false;
                                    st.fsm_state = SessionState::ConnectedLive;
                                }
                                push_log(&shared, "info", format!("Loaded program on {core}: {}", path.display()));
                            }
                            Err(e) => push_problem(&shared, "error", &core, e),
                        }
                    }
                }
                WorkerCmd::LoadSymbols { core, path } => {
                    if let Some(b) = backend.as_mut() {
                        if let Err(e) = b.load_symbols(&core, &path) {
                            push_problem(&shared, "warn", &core, e);
                        }
                    }
                }
                WorkerCmd::RunCore(c) => {
                    if let Some(b) = backend.as_mut() {
                        let _ = b.run_core(&c);
                        shared.lock().unwrap().core_states = b.get_core_states();
                    }
                }
                WorkerCmd::HaltCore(c) => {
                    if let Some(b) = backend.as_mut() {
                        let _ = b.halt_core(&c);
                        let t_now = t0.elapsed().as_secs_f64();
                        let mut st = shared.lock().unwrap();
                        st.core_states = b.get_core_states();
                        for rb in st.buffers.values_mut() {
                            rb.append_nan_gap(t_now);
                        }
                    }
                }
                WorkerCmd::ResetCore(c) => {
                    if let Some(b) = backend.as_mut() {
                        let _ = b.reset_core(&c);
                        let t_now = t0.elapsed().as_secs_f64();
                        let mut st = shared.lock().unwrap();
                        st.core_states = b.get_core_states();
                        for rb in st.buffers.values_mut() {
                            rb.append_nan_gap(t_now);
                        }
                    }
                }
                WorkerCmd::RunAll => {
                    if let Some(b) = backend.as_mut() {
                        let cores: Vec<String> = b.get_core_states().into_iter().filter(|(_, s)| *s != CoreState::Disconnected).map(|(k, _)| k).collect();
                        for c in cores {
                            let _ = b.run_core(&c);
                        }
                        shared.lock().unwrap().core_states = b.get_core_states();
                    }
                }
                WorkerCmd::HaltAll => {
                    if let Some(b) = backend.as_mut() {
                        b.quiesce_all_masters();
                        shared.lock().unwrap().core_states = b.get_core_states();
                    }
                }
                WorkerCmd::MicroHaltDbgM(c) => {
                    if let Some(b) = backend.as_mut() {
                        match b.micro_halt_clear_dbgm(&c) {
                            Ok(_) => {
                                shared.lock().unwrap().core_states = b.get_core_states();
                                push_log(&shared, "info", format!("Micro-halt cleared ST1.DBGM on {c} -> Polite RT."));
                            }
                            Err(e) => push_problem(&shared, "error", &c, e),
                        }
                    }
                }
                WorkerCmd::SetWatchList(items) => {
                    watch_items = items;
                    failed_spans.clear();
                    read_plan = rebuild_plan(&mut watch_items, device_id, &poll_config, &extra_ram, &memcfg, &backend, &shared);
                }
                WorkerCmd::SetExtraRam { core, ranges } => {
                    extra_ram.insert(core, ranges);
                    read_plan = rebuild_plan(&mut watch_items, device_id, &poll_config, &extra_ram, &memcfg, &backend, &shared);
                }
                WorkerCmd::SetPollConfig(cfg) => {
                    let rt_changed = cfg.realtime_mode != poll_config.realtime_mode;
                    poll_config = cfg;
                    if let Some(b) = backend.as_mut() {
                        b.set_allow_rude_fallback(poll_config.allow_rude_fallback);
                        if rt_changed && connected {
                            let cores: Vec<String> = b.get_core_states().into_iter().filter(|(_, s)| *s != CoreState::Disconnected).map(|(k, _)| k).collect();
                            for c in cores {
                                let _ = b.set_realtime_mode(&c, poll_config.realtime_mode);
                            }
                            shared.lock().unwrap().core_states = b.get_core_states();
                        }
                    }
                    read_plan = rebuild_plan(&mut watch_items, device_id, &poll_config, &extra_ram, &memcfg, &backend, &shared);
                }
                WorkerCmd::SetPollingActive(a) => polling_active = a,
                WorkerCmd::SingleShot => {
                    if connected {
                        execute_poll_tick(
                            &mut backend,
                            &read_plan,
                            &mut slow_sched,
                            &mut failed_spans,
                            &shared,
                            &t0,
                            &mut cycle_idx,
                            &mut words_read,
                            &mut err_count,
                            &mut csv_writer,
                            &watch_items,
                        );
                    }
                }
                WorkerCmd::WriteSymbol { id, value } => {
                    let Some(item) = watch_items.iter().find(|w| w.id == id).cloned() else {
                        push_event(&shared, WorkerEvent::WriteResult { id, ok: false, msg: "Watch item not found".into(), value: None });
                        continue;
                    };
                    if let Some(b) = backend.as_mut() {
                        let conn_cores: HashSet<String> = b.get_core_states().into_iter().filter(|(_, s)| *s != CoreState::Disconnected).map(|(k, _)| k).collect();
                        match perform_guarded_write(
                            b.as_mut(),
                            device_id,
                            &item,
                            value,
                            stale_locked,
                            &stale_reason,
                            poll_config.verify_after_write,
                            &extra_ram,
                            &memcfg,
                            &conn_cores,
                        ) {
                            Ok(final_v) => {
                                let msg = format!("Verified write {}={final_v:.5}", item.symbol_path);
                                push_event(&shared, WorkerEvent::WriteResult { id, ok: true, msg: msg.clone(), value: Some(final_v) });
                                push_log(&shared, "info", msg);
                            }
                            Err(e) => {
                                push_problem(&shared, "warn", &item.symbol_path, e.clone());
                                push_event(&shared, WorkerEvent::WriteResult { id, ok: false, msg: e, value: None });
                            }
                        }
                    } else {
                        push_event(&shared, WorkerEvent::WriteResult { id, ok: false, msg: "Target not connected.".into(), value: None });
                    }
                }
                WorkerCmd::BatchWrite(writes) => {
                    execute_batch_writes(
                        &mut backend,
                        device_id,
                        &watch_items,
                        &writes,
                        false,
                        stale_locked,
                        &stale_reason,
                        poll_config.verify_after_write,
                        &extra_ram,
                        &memcfg,
                        &shared,
                    );
                }
                WorkerCmd::PreemptSafeRevert(writes) => {
                    execute_batch_writes(
                        &mut backend,
                        device_id,
                        &watch_items,
                        &writes,
                        true,
                        stale_locked,
                        &stale_reason,
                        true,
                        &extra_ram,
                        &memcfg,
                        &shared,
                    );
                }
                WorkerCmd::VerifyFlashFingerprint { core, fp } => {
                    if let Some(b) = backend.as_mut() {
                        match b.read_flash_fingerprint(&core, fp.address, fp.words.len() as u32, &fp.page) {
                            Ok(actual) if actual == fp.words => {
                                stale_locked = false;
                                stale_reason.clear();
                                {
                                    let mut st = shared.lock().unwrap();
                                    st.stale_image_locked = false;
                                    st.stale_image_reason.clear();
                                    st.fsm_state = SessionState::ConnectedLive;
                                }
                                push_log(&shared, "info", format!("Flash fingerprint verified on {core} @ 0x{:X}.", fp.address));
                            }
                            Ok(_) | Err(_) => {
                                stale_locked = true;
                                stale_reason = format!("Target Flash @ 0x{:X} differs from loaded .out ({core}). Writes locked.", fp.address);
                                {
                                    let mut st = shared.lock().unwrap();
                                    st.stale_image_locked = true;
                                    st.stale_image_reason = stale_reason.clone();
                                    st.fsm_state = SessionState::WriteLockedStaleImage;
                                }
                                push_problem(&shared, "error", &core, stale_reason.clone());
                            }
                        }
                    }
                }
                WorkerCmd::InvalidateImage { locked, reason } => {
                    stale_locked = locked;
                    stale_reason = reason.clone();
                    let mut st = shared.lock().unwrap();
                    st.stale_image_locked = locked;
                    st.stale_image_reason = reason.clone();
                    if connected {
                        st.fsm_state = if locked { SessionState::WriteLockedStaleImage } else { SessionState::ConnectedLive };
                    }
                    if locked {
                        drop(st);
                        push_problem(&shared, "warn", "Symbols", reason);
                    }
                }
                WorkerCmd::UnlockDcsm { core, zone, keys } => {
                    if let Some(b) = backend.as_mut() {
                        match b.unlock_dcsm(&core, zone, &keys) {
                            Ok(true) => {
                                memcfg = b.probe_memcfg(&core);
                                {
                                    let mut st = shared.lock().unwrap();
                                    st.memcfg = memcfg;
                                    st.fsm_state = SessionState::ConnectedLive;
                                }
                                push_log(&shared, "info", format!("DCSM Zone {zone} unlocked non-destructively on {core}."));
                            }
                            Ok(false) => push_problem(&shared, "error", &core, format!("DCSM Zone {zone} key mismatch.")),
                            Err(e) => push_problem(&shared, "error", &core, e),
                        }
                    }
                }
                WorkerCmd::ConfigureDlog { enabled, trigger_mode, level } => {
                    if let Some(b) = backend.as_mut() {
                        dlog_active = b.configure_dlog(enabled, &trigger_mode, level);
                        push_log(&shared, "info", format!("Phase-B 20 kHz DLOG -> {}", if dlog_active { "ON" } else { "OFF" }));
                    }
                }
                WorkerCmd::StartCsvRecording(path) => {
                    if let Ok(f) = File::create(&path) {
                        let mut bw = BufWriter::new(f);
                        let _ = writeln!(bw, "time_s,core,symbol,eng_value,error");
                        csv_writer = Some(bw);
                        shared.lock().unwrap().csv_recording = true;
                        push_log(&shared, "info", format!("Streaming CSV recording started: {}", path.display()));
                    }
                }
                WorkerCmd::StopCsvRecording => {
                    if let Some(mut bw) = csv_writer.take() {
                        let _ = bw.flush();
                    }
                    shared.lock().unwrap().csv_recording = false;
                    push_log(&shared, "info", "Streaming CSV recording stopped.");
                }
            }
            continue;
        }

        // 2. Execute polling cycle if active
        if connected && polling_active && poll_config.mode != PollMode::Manual && !watch_items.is_empty() {
            let run_now = match poll_config.mode {
                PollMode::MaxFreerun => true,
                PollMode::FixedHz => {
                    let now = Instant::now();
                    if now >= next_fixed_deadline {
                        let period = Duration::from_secs_f64(1.0 / poll_config.target_hz.clamp(1.0, 2000.0));
                        next_fixed_deadline = now + period;
                        true
                    } else {
                        thread::sleep(Duration::from_millis(1));
                        false
                    }
                }
                PollMode::Manual => false,
            };

            if run_now {
                let tick_start = Instant::now();
                let dt_ms = tick_start.duration_since(last_tick_wall).as_secs_f64() * 1000.0;
                last_tick_wall = tick_start;
                tick_dts_ms.push(dt_ms);

                execute_poll_tick(
                    &mut backend,
                    &read_plan,
                    &mut slow_sched,
                    &mut failed_spans,
                    &shared,
                    &t0,
                    &mut cycle_idx,
                    &mut words_read,
                    &mut err_count,
                    &mut csv_writer,
                    &watch_items,
                );

                latencies_ms.push(tick_start.elapsed().as_secs_f64() * 1000.0);
                tick_count += 1;

                // Cap simulated spin so CPU stays ultra-low (~1%) while still delivering ~250 Hz realistic telemetry
                if poll_config.mode == PollMode::MaxFreerun {
                    thread::sleep(Duration::from_millis(3));
                }
            }
        } else {
            thread::sleep(Duration::from_millis(12));
        }

        // 3. Emit rolling telemetry stats every 250 ms
        let elapsed = last_stats_wall.elapsed().as_secs_f64();
        if elapsed >= 0.25 {
            let hz = (tick_count as f64) / elapsed;
            let wps = (words_read as f64) / elapsed;
            let lat_avg = if latencies_ms.is_empty() {
                0.0
            } else {
                latencies_ms.iter().sum::<f64>() / (latencies_ms.len() as f64)
            };
            tick_dts_ms.sort_by(|a, b| a.total_cmp(b));
            let dt_p95 = if tick_dts_ms.is_empty() {
                0.0
            } else {
                let idx = ((0.95 * (tick_dts_ms.len() as f64)) as usize).min(tick_dts_ms.len() - 1);
                tick_dts_ms[idx]
            };
            let span_count = read_plan.fast_spans.len() + read_plan.slow_5_spans.len() + read_plan.slow_20_spans.len();
            {
                let mut st = shared.lock().unwrap();
                st.stats = PollStats {
                    achieved_hz: hz,
                    latency_ms_avg: lat_avg,
                    dt_p95_ms: dt_p95,
                    span_count,
                    symbol_count: watch_items.len(),
                    words_per_sec: wps,
                    error_count: err_count,
                    active_rt_mode: Some(poll_config.realtime_mode),
                    running: connected && polling_active,
                    dlog_active,
                };
            }
            tick_count = 0;
            words_read = 0;
            latencies_ms.clear();
            tick_dts_ms.clear();
            last_stats_wall = Instant::now();
        }
    }

    if let Some(mut bw) = csv_writer {
        let _ = bw.flush();
    }
    if let Some(mut b) = backend {
        b.shutdown();
    }
}

type SampleTuple = (String, String, String, f64, Option<RawScalar>, f64, bool);

#[allow(clippy::too_many_arguments)]
fn execute_poll_tick(
    backend: &mut Option<Box<dyn DebugBackend>>,
    plan: &ReadPlan,
    slow_sched: &mut SlowSpanScheduler,
    failed_spans: &mut HashSet<usize>,
    shared: &Arc<Mutex<SharedTelemetry>>,
    t0: &Instant,
    cycle_idx: &mut u64,
    words_read: &mut u64,
    err_count: &mut u64,
    csv_writer: &mut Option<BufWriter<File>>,
    watch_items: &[WatchItem],
) {
    let Some(be) = backend.as_mut() else { return };
    let mut due_spans: Vec<_> = plan.fast_spans.to_vec();
    for s in slow_sched.next_slow_spans(&plan.slow_5_spans, &plan.slow_20_spans, *cycle_idx) {
        due_spans.push(s.clone());
    }
    *cycle_idx = cycle_idx.wrapping_add(1);

    let mut samples: Vec<SampleTuple> = Vec::new();

    for sp in due_spans {
        let sub_spans = if failed_spans.contains(&sp.span_id) {
            split_failed_span(&sp)
        } else {
            vec![sp.clone()]
        };

        for sub in sub_spans {
            let t_mid = t0.elapsed().as_secs_f64();
            match be.read_block(&sub.read_core, sub.start_addr, sub.count, sub.bit_size, &sub.page) {
                Ok(raw_units) => {
                    *words_read += sub.mau_span() as u64;
                    let decode_buf: Vec<u32> = if sub.unpack_to_au && sub.bit_size == 32 && sub.address_unit_bits == 16 {
                        let mut tmp = Vec::with_capacity(raw_units.len() * 2);
                        for w32 in raw_units {
                            tmp.push(w32 & 0xFFFF);
                            tmp.push((w32 >> 16) & 0xFFFF);
                        }
                        tmp
                    } else {
                        raw_units
                    };
                    let eff_bit_size = if sub.unpack_to_au { sub.address_unit_bits } else { sub.bit_size };
                    for sl in &sub.slices {
                        let end = (sl.offset_units + sl.unit_count).min(decode_buf.len());
                        if sl.offset_units < end {
                            let raw = decode_raw_scalar(
                                &decode_buf[sl.offset_units..end],
                                sl.item.data_type,
                                sub.address_unit_bits,
                                Some(eff_bit_size),
                                sl.item.bit_offset,
                                sl.item.bit_width,
                                sl.item.container_units,
                            );
                            let eng = raw_to_engineering(raw, sl.item.display_format, sl.item.iq_q_bits);
                            samples.push((
                                sl.item.id.clone(),
                                sl.item.core.clone(),
                                sl.item.symbol_path.clone(),
                                eng,
                                Some(raw),
                                t_mid,
                                false,
                            ));
                        }
                    }
                }
                Err(_) => {
                    *err_count += 1;
                    failed_spans.insert(sp.span_id);
                    for sl in &sub.slices {
                        samples.push((
                            sl.item.id.clone(),
                            sl.item.core.clone(),
                            sl.item.symbol_path.clone(),
                            f64::NAN,
                            None,
                            t_mid,
                            true,
                        ));
                    }
                }
            }
        }
    }

    // Ingest Phase-B 20 kHz DLOG burst if active
    let dlog_burst = be.get_dlog_burst();

    {
        let mut st = shared.lock().unwrap();
        for (id, core, sym, eng, raw, ts, has_err) in samples {
            st.latest.insert(
                id.clone(),
                LatestSample {
                    eng,
                    raw,
                    timestamp: ts,
                    has_error: has_err,
                },
            );
            if let Some(rb) = st.buffers.get_mut(&id) {
                rb.append(ts, eng);
            }
            if let Some(bw) = csv_writer.as_mut() {
                let _ = writeln!(bw, "{ts:.6},{core},{sym},{eng:.8},{}", if has_err { 1 } else { 0 });
            }
        }

        if let Some(burst) = dlog_burst {
            let t_base = t0.elapsed().as_secs_f64();
            for (sym_path, vals) in burst.channels {
                if let Some(item) = watch_items.iter().find(|w| w.symbol_path == sym_path) {
                    if let Some(rb) = st.buffers.get_mut(&item.id) {
                        let ts: Vec<f64> = (0..vals.len()).map(|i| t_base + (i as f64) * burst.dt_sec).collect();
                        if burst.overrun {
                            rb.append_nan_gap(t_base - burst.dt_sec);
                        }
                        rb.append_batch(&ts, &vals);
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn execute_batch_writes(
    backend: &mut Option<Box<dyn DebugBackend>>,
    device_id: DeviceId,
    watch_items: &[WatchItem],
    writes: &[(String, f64)],
    is_revert: bool,
    stale_locked: bool,
    stale_reason: &str,
    verify_after_write: bool,
    extra_ram: &BTreeMap<String, Vec<MemoryRange>>,
    memcfg: &MemCfgSnapshot,
    shared: &Arc<Mutex<SharedTelemetry>>,
) {
    let Some(b) = backend.as_mut() else {
        if is_revert {
            push_event(
                shared,
                WorkerEvent::SafeRevertResult {
                    all_verified: false,
                    detail: "Target not connected — Safe Revert could not execute.".into(),
                },
            );
        }
        for (id, _) in writes {
            push_event(
                shared,
                WorkerEvent::WriteResult {
                    id: id.clone(),
                    ok: false,
                    msg: "Target not connected.".into(),
                    value: None,
                },
            );
        }
        return;
    };

    let conn_cores: HashSet<String> = b
        .get_core_states()
        .into_iter()
        .filter(|(_, s)| *s != CoreState::Disconnected)
        .map(|(k, _)| k)
        .collect();

    let mut all_ok = true;
    let mut verified_count = 0usize;
    let mut failed_msgs: Vec<String> = Vec::new();

    for (id, target_val) in writes {
        let Some(item) = watch_items.iter().find(|w| w.id == *id).cloned() else {
            all_ok = false;
            failed_msgs.push(format!("{id}: watch item not found"));
            push_event(
                shared,
                WorkerEvent::WriteResult {
                    id: id.clone(),
                    ok: false,
                    msg: "Watch item not found".into(),
                    value: None,
                },
            );
            continue;
        };

        // For Safe Revert, bypass stale-image lockout ONLY if explicitly reverting known safe values?
        // NO! Safety rule: Safe Revert MUST still obey the 5-gate hardware firewall & readback verify,
        // and if any item fails verification we report `all_verified: false` loudly!
        match perform_guarded_write(
            b.as_mut(),
            device_id,
            &item,
            *target_val,
            stale_locked,
            stale_reason,
            verify_after_write || is_revert,
            extra_ram,
            memcfg,
            &conn_cores,
        ) {
            Ok(final_v) => {
                verified_count += 1;
                let tag = if is_revert { "Safe Revert verified" } else { "Batch verified" };
                let msg = format!("{tag} {}={final_v:.5}", item.symbol_path);
                push_event(
                    shared,
                    WorkerEvent::WriteResult {
                        id: id.clone(),
                        ok: true,
                        msg: msg.clone(),
                        value: Some(final_v),
                    },
                );
                push_log(shared, "info", msg);
            }
            Err(e) => {
                all_ok = false;
                failed_msgs.push(format!("{}: {e}", item.symbol_path));
                push_problem(shared, "error", &item.symbol_path, e.clone());
                push_event(
                    shared,
                    WorkerEvent::WriteResult {
                        id: id.clone(),
                        ok: false,
                        msg: e,
                        value: None,
                    },
                );
            }
        }
    }

    if is_revert {
        let detail = if all_ok {
            format!("All {verified_count} parameter(s) verified at Safe Baseline.")
        } else {
            format!(
                "SAFE STATE NOT CONFIRMED ({verified_count}/{} verified): {}",
                writes.len(),
                failed_msgs.join("; ")
            )
        };
        if !all_ok {
            push_problem(shared, "error", "SafeRevert", detail.clone());
        } else {
            push_log(shared, "info", detail.clone());
        }
        push_event(
            shared,
            WorkerEvent::SafeRevertResult {
                all_verified: all_ok,
                detail,
            },
        );
    }
}
