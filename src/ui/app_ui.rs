//! Classic White Eclipse Workbench UI for C2000 JTAG Studio (Native Rust Edition).

use std::collections::{BTreeMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Instant, SystemTime};

use egui::{Color32, RichText, Stroke, Ui};

use crate::backend::ccs_env::{discover_ccs_environment, CcsEnvironment};
use crate::backend::ccxml::generate_uscif_dat;
use crate::backend::probe::{
    probe_max_tclk_staircase, reset_xds110_probe_only, run_jtag_integrity_test,
    scan_connected_probes,
};
use crate::backend::worker::{SessionController, WorkerCmd, WorkerEvent};
use crate::core::codec::{format_value, parse_numeric_input};
use crate::core::devices::{
    default_tclk, get_device_profile, probe_capabilities, probe_tclk_options,
};
use crate::core::models::{
    ConnectionRequest, CoreState, DataType, DetectedProbe, DeviceId, DisplayFormat, JtagMode,
    PhysicalMemoryDomain, PollConfig, PollMode, ProblemRecord, ProbeKind, RealtimeAccessMode,
    SessionState, SymbolNode, ThemeMode, WatchItem, WriteState,
};
use crate::core::workspace::{profile_key_for, WorkspaceProfile, WorkspaceStore};
use crate::symbols::cache::ParsedSymbolTable;
use crate::symbols::parser::{load_symbols_for_file, resolve_watch_items_from_table};
use crate::ui::file_dialog::{open_file_dialog, save_file_dialog};
use crate::ui::scope::{export_scope_csv, render_scope_png, ScopeState};
use crate::ui::theme::{apply_theme, palette_for, trace_color_for};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Perspective {
    Tune,
    Scope,
    Debug,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BottomTab {
    Console,
    Problems,
    Jobs,
}

#[derive(Debug, Clone)]
enum ConfirmAction {
    StopModeHalt,
    LoadAndRun { core: String, path: PathBuf },
    MicroHaltDbgM { core: String },
    UnlockBitfieldRmw { item_id: String, symbol: String },
    ExpertStaleOverride,
    BatchApply(Vec<(String, String, f64, f64)>),
    ResetXds110UsbOnly,
}

#[derive(Debug, Clone)]
struct BackgroundJobResult {
    label: String,
    payload: BgPayload,
}

#[derive(Debug, Clone)]
enum BgPayload {
    Probes(Vec<DetectedProbe>),
    Symbols {
        core: String,
        path: PathBuf,
        result: Box<Result<ParsedSymbolTable, String>>,
    },
    JtagTest {
        passed: bool,
        output: String,
    },
    MaxTclk {
        best: Option<String>,
        summary: String,
    },
    XdsReset {
        ok: bool,
        output: String,
    },
}

type SimWatchDef<'a> = (&'a str, u8, bool, Option<f64>, Option<f64>, f64, f64);

pub struct C2000StudioApp {
    controller: SessionController,
    store: WorkspaceStore,
    ccs_env: CcsEnvironment,

    // Target & connection config
    device_id: DeviceId,
    probe_kind: ProbeKind,
    detected_probes: Vec<DetectedProbe>,
    selected_serial: String,
    tclk_hz: String,
    jtag_mode: JtagMode,
    custom_ccxml_path: String,
    program_paths: BTreeMap<String, String>,
    program_mtimes: BTreeMap<String, SystemTime>,
    poll_config: PollConfig,
    polling_active: bool,
    dlog_enabled: bool,

    // Symbols & Watch & Tuner state
    symbol_trees: BTreeMap<String, Vec<SymbolNode>>,
    selected_sym_core: String,
    sym_search: String,
    watch_items: Vec<WatchItem>,
    inline_edits: BTreeMap<String, String>,
    staged_tuner: BTreeMap<String, f64>,
    safe_baseline: BTreeMap<String, f64>,
    tuning_presets: BTreeMap<String, BTreeMap<String, f64>>,
    next_color_idx: usize,
    next_item_seq: u64,

    // UI layout & theme
    theme_mode: ThemeMode,
    ui_scale_pct: u32,
    theme_dirty: bool,
    perspective: Perspective,
    show_jtag_drawer: bool,
    show_symbol_panel: bool,
    show_watch_panel: bool,
    show_scope_panel: bool,
    show_console_panel: bool,
    bottom_tab: BottomTab,
    scope: ScopeState,

    // Safety banners & modals
    safe_revert_failed_msg: Option<String>,
    pending_confirm: Option<ConfirmAction>,
    show_ccs_diag_modal: bool,
    show_dcsm_modal: bool,
    dcsm_zone: u8,
    dcsm_keys_hex: [String; 4],
    show_manual_addr_modal: bool,
    manual_addr_hex: String,
    manual_name: String,
    manual_dtype: DataType,
    manual_core: String,

    // Logs, problems & background jobs
    console_lines: VecDeque<(String, String)>,
    problems: VecDeque<ProblemRecord>,
    active_jobs: Vec<String>,
    bg_results: Arc<Mutex<VecDeque<BackgroundJobResult>>>,
    last_mtime_check: Instant,
    auto_connect_done: bool,
}

impl C2000StudioApp {
    pub fn new(cc: &eframe::CreationContext<'_>, auto_demo_sim: bool) -> Self {
        let controller = SessionController::new(20_000);
        let store = WorkspaceStore::new(None);
        let ccs_env = discover_ccs_environment(None);

        let mut app = Self {
            controller,
            store,
            ccs_env,
            device_id: DeviceId::F28069M,
            probe_kind: ProbeKind::SIMULATOR,
            detected_probes: Vec::new(),
            selected_serial: String::new(),
            tclk_hz: default_tclk(ProbeKind::SIMULATOR).into(),
            jtag_mode: JtagMode::Jtag4Pin,
            custom_ccxml_path: String::new(),
            program_paths: BTreeMap::new(),
            program_mtimes: BTreeMap::new(),
            poll_config: PollConfig::default(),
            polling_active: true,
            dlog_enabled: false,
            symbol_trees: BTreeMap::new(),
            selected_sym_core: "C28xx_0".into(),
            sym_search: String::new(),
            watch_items: Vec::new(),
            inline_edits: BTreeMap::new(),
            staged_tuner: BTreeMap::new(),
            safe_baseline: BTreeMap::new(),
            tuning_presets: BTreeMap::new(),
            next_color_idx: 0,
            next_item_seq: 1,
            theme_mode: ThemeMode::ClassicEclipseLight,
            ui_scale_pct: 100,
            theme_dirty: true,
            perspective: Perspective::Tune,
            show_jtag_drawer: false,
            show_symbol_panel: true,
            show_watch_panel: true,
            show_scope_panel: true,
            show_console_panel: true,
            bottom_tab: BottomTab::Console,
            scope: ScopeState::default(),
            safe_revert_failed_msg: None,
            pending_confirm: None,
            show_ccs_diag_modal: false,
            show_dcsm_modal: false,
            dcsm_zone: 1,
            dcsm_keys_hex: [
                "FFFFFFFF".into(),
                "FFFFFFFF".into(),
                "FFFFFFFF".into(),
                "FFFFFFFF".into(),
            ],
            show_manual_addr_modal: false,
            manual_addr_hex: "0x008000".into(),
            manual_name: "mem_0x008000".into(),
            manual_dtype: DataType::Float32,
            manual_core: "C28xx_0".into(),
            console_lines: VecDeque::new(),
            problems: VecDeque::new(),
            active_jobs: Vec::new(),
            bg_results: Arc::new(Mutex::new(VecDeque::new())),
            last_mtime_check: Instant::now(),
            auto_connect_done: !auto_demo_sim,
        };

        apply_theme(&cc.egui_ctx, app.theme_mode, app.ui_scale_pct);
        app.log("info", "C2000 JTAG Studio v2 (Native Rust Edition) ready — Classic White Eclipse Workbench.");
        if app.ccs_env.cloudagent_available() {
            app.log(
                "info",
                format!(
                    "Detected TI CCS 21 CloudAgent at {}",
                    app.ccs_env
                        .cloudagent_dir
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_default()
                ),
            );
        }
        app
    }

    fn log(&mut self, level: &str, msg: impl Into<String>) {
        if self.console_lines.len() >= 400 {
            self.console_lines.pop_front();
        }
        self.console_lines.push_back((level.to_uppercase(), msg.into()));
    }

    fn push_problem(&mut self, sev: &str, src: &str, msg: impl Into<String>) {
        if self.problems.len() >= 200 {
            self.problems.pop_front();
        }
        self.problems.push_front(ProblemRecord {
            time: now_hms(),
            severity: sev.to_uppercase(),
            source: src.to_string(),
            message: msg.into(),
        });
    }

    fn sync_watch_list_to_worker(&self) {
        self.controller.send(WorkerCmd::SetWatchList(self.watch_items.clone()));
    }

    fn sync_poll_config_to_worker(&self) {
        self.controller.send(WorkerCmd::SetPollConfig(self.poll_config.clone()));
    }

    fn on_device_changed(&mut self, new_dev: DeviceId) {
        self.device_id = new_dev;
        let prof = get_device_profile(new_dev);
        self.selected_sym_core = prof.primary_core().name.to_string();
        self.manual_core = self.selected_sym_core.clone();
        self.symbol_trees.clear();
        self.watch_items.clear();
        self.staged_tuner.clear();
        self.safe_baseline.clear();
        self.inline_edits.clear();
        self.sync_watch_list_to_worker();
    }

    fn trigger_connect(&mut self, attach_live: bool) {
        let req = ConnectionRequest {
            device_id: self.device_id,
            probe_kind: self.probe_kind,
            serial: self.selected_serial.clone(),
            tclk_hz: self.tclk_hz.clone(),
            jtag_mode: self.jtag_mode,
            attach_live,
            realtime_mode: self.poll_config.realtime_mode,
            custom_ccxml_path: self.custom_ccxml_path.clone(),
            program_paths: self.program_paths.clone(),
        };
        self.sync_poll_config_to_worker();
        self.controller.send(WorkerCmd::SetPollingActive(self.polling_active));
        self.controller.send(WorkerCmd::Connect(req));
    }

    fn add_symbol_to_watch(&mut self, node: &SymbolNode, plot_pane: u8, pin: bool) {
        if let Some(existing) = self.watch_items.iter_mut().find(|w| w.core == node.core && w.symbol_path == node.full_path) {
            if plot_pane > 0 {
                existing.plot_pane = plot_pane;
            }
            if pin {
                existing.pinned_tuner = true;
            }
            self.sync_watch_list_to_worker();
            return;
        }
        let id = format!("w_{}", self.next_item_seq);
        self.next_item_seq += 1;
        let color_index = self.next_color_idx;
        self.next_color_idx += 1;
        let default_fmt = if node.data_type.is_float() {
            DisplayFormat::Float
        } else {
            DisplayFormat::Dec
        };
        let is_ro = node.is_bitfield() || node.is_scratchpad || node.domain == PhysicalMemoryDomain::Flash;
        let item = WatchItem {
            id,
            core: node.core.clone(),
            symbol_path: node.full_path.clone(),
            address: node.address,
            page: node.page.clone(),
            data_type: node.data_type,
            display_format: default_fmt,
            iq_q_bits: 24,
            bit_offset: node.bit_offset,
            bit_width: node.bit_width,
            container_units: node.container_units,
            rate_divider: 1,
            plot_pane,
            color_index,
            line_style: "solid".into(),
            pinned_tuner: pin,
            min_val: None,
            max_val: None,
            step: if node.data_type.is_float() { 0.1 } else { 1.0 },
            read_only: is_ro,
            rmw_unlocked: false,
            live_drag_write: false,
            section_name: node.section_name.clone(),
            domain: node.domain,
            tu_scope: node.tu_scope.clone(),
            is_atomic: true,
            user_setpoint: None,
            write_state: WriteState::Idle,
            last_write_error: String::new(),
        };
        self.watch_items.push(item);
        self.sync_watch_list_to_worker();
    }

    fn populate_default_sim_watch(&mut self, trees: &BTreeMap<String, Vec<SymbolNode>>) {
        if !self.watch_items.is_empty() {
            return;
        }
        let mut flat = BTreeMap::new();
        for nodes in trees.values() {
            flatten_syms(nodes, &mut flat);
        }
        match self.device_id {
            DeviceId::F28069M => {
                let defs: &[SimWatchDef<'_>] = &[
                    ("gBuck.v_ref", 1, true, Some(0.0), Some(36.0), 0.5, 12.0),
                    ("gBuck.v_out", 1, false, None, None, 0.1, 12.0),
                    ("gBuck.i_L", 2, false, None, None, 0.1, 2.4),
                    ("gBuck.kp", 0, true, Some(0.005), Some(2.0), 0.01, 0.08),
                    ("gBuck.ki", 0, true, Some(0.0), Some(40.0), 0.5, 12.0),
                    ("gBuck.duty", 2, false, None, None, 0.01, 0.25),
                ];
                for &(path, pane, pin, lo, hi, step, safe) in defs {
                    if let Some(n) = flat.get(path) {
                        self.add_symbol_to_watch(n, pane, pin);
                        if let Some(w) = self.watch_items.last_mut() {
                            w.min_val = lo;
                            w.max_val = hi;
                            w.step = step;
                            if pin {
                                self.safe_baseline.insert(w.id.clone(), safe);
                            }
                        }
                    }
                }
            }
            DeviceId::F28388D => {
                let defs: &[SimWatchDef<'_>] = &[
                    ("gInv.foc.iq_ref", 1, true, Some(0.0), Some(25.0), 0.5, 8.0),
                    ("gInv.i_a", 1, false, None, None, 0.1, 0.0),
                    ("gInv.i_b", 1, false, None, None, 0.1, 0.0),
                    ("gInv.v_dc", 2, false, None, None, 1.0, 400.0),
                    ("gCmStats.cpu_temp_c", 2, false, None, None, 0.5, 42.5),
                ];
                for &(path, pane, pin, lo, hi, step, safe) in defs {
                    if let Some(n) = flat.get(path) {
                        self.add_symbol_to_watch(n, pane, pin);
                        if let Some(w) = self.watch_items.last_mut() {
                            w.min_val = lo;
                            w.max_val = hi;
                            w.step = step;
                            if pin {
                                self.safe_baseline.insert(w.id.clone(), safe);
                            }
                        }
                    }
                }
            }
        }
        self.sync_watch_list_to_worker();
    }

    fn trigger_safe_revert(&mut self) {
        let writes: Vec<(String, f64)> = self
            .watch_items
            .iter()
            .filter_map(|w| self.safe_baseline.get(&w.id).map(|&v| (w.id.clone(), v)))
            .collect();
        if writes.is_empty() {
            self.log("warn", "Safe Revert requested, but no Safe Baseline parameters are recorded (click 'Set Safe' first).");
            return;
        }
        self.log("warn", format!("PREEMPT_SAFE_REVERT fired for {} parameter(s) — purging normal write queue!", writes.len()));
        self.controller.send(WorkerCmd::PreemptSafeRevert(writes));
    }

    fn spawn_probe_scan(&mut self) {
        if let Err(e) = self.controller.acquire_probe_lease("probe_scan") {
            self.push_problem("warn", "ProbeScan", e);
            return;
        }
        let env = self.ccs_env.clone();
        let bg = Arc::clone(&self.bg_results);
        let shared = self.controller.shared();
        self.active_jobs.push("Scanning XDS110/XDS100v2 USB probes...".into());
        thread::spawn(move || {
            let probes = scan_connected_probes(Some(&env));
            {
                let mut st = shared.lock().unwrap();
                if st.probe_lease_holder.as_deref() == Some("probe_scan") {
                    st.probe_lease_holder = None;
                }
            }
            bg.lock().unwrap().push_back(BackgroundJobResult {
                label: "Scanning XDS110/XDS100v2 USB probes...".into(),
                payload: BgPayload::Probes(probes),
            });
        });
    }

    fn spawn_symbol_parse(&mut self, core: String, path: PathBuf) {
        let prof = get_device_profile(self.device_id);
        let Some(cp) = prof.find_core(&core).cloned() else {
            self.push_problem("error", "Symbols", format!("Unknown core '{core}'"));
            return;
        };
        let env = self.ccs_env.clone();
        let bg = Arc::clone(&self.bg_results);
        let label = format!("Parsing DWARF symbols ({})...", path.file_name().and_then(|s| s.to_str()).unwrap_or("file"));
        self.active_jobs.push(label.clone());
        let p_c = path.clone();
        thread::spawn(move || {
            let res = load_symbols_for_file(&p_c, &cp, Some(&env), true);
            bg.lock().unwrap().push_back(BackgroundJobResult {
                label,
                payload: BgPayload::Symbols { core, path: p_c, result: Box::new(res) },
            });
        });
    }

    fn spawn_jtag_test(&mut self) {
        if let Err(e) = self.controller.acquire_probe_lease("dbgjtag") {
            self.push_problem("warn", "JTAGTest", e);
            return;
        }
        let dev = self.device_id;
        let pk = self.probe_kind;
        let tclk = self.tclk_hz.clone();
        let jm = self.jtag_mode;
        let ser = self.selected_serial.clone();
        let env = self.ccs_env.clone();
        let bg = Arc::clone(&self.bg_results);
        let shared = self.controller.shared();
        let label = format!("dbgjtag integrity test ({tclk})...");
        self.active_jobs.push(label.clone());
        thread::spawn(move || {
            let tmp = std::env::temp_dir().join("c2000_rs_jtag_check.dat");
            let payload = match generate_uscif_dat(&tmp, dev, pk, &tclk, jm, &ser) {
                Ok(_) => {
                    let r = run_jtag_integrity_test(&tmp, &tclk, Some(&env));
                    let _ = std::fs::remove_file(&tmp);
                    BgPayload::JtagTest { passed: r.passed, output: r.output }
                }
                Err(e) => BgPayload::JtagTest { passed: false, output: e },
            };
            {
                let mut st = shared.lock().unwrap();
                if st.probe_lease_holder.as_deref() == Some("dbgjtag") {
                    st.probe_lease_holder = None;
                }
            }
            bg.lock().unwrap().push_back(BackgroundJobResult { label, payload });
        });
    }

    fn spawn_max_tclk_probe(&mut self) {
        if let Err(e) = self.controller.acquire_probe_lease("tclk_probe") {
            self.push_problem("warn", "MaxTCLK", e);
            return;
        }
        let dev = self.device_id;
        let pk = self.probe_kind;
        let ser = self.selected_serial.clone();
        let jm = self.jtag_mode;
        let bg = Arc::clone(&self.bg_results);
        let shared = self.controller.shared();
        let label = "Probing Max TCLK staircase (1-step backoff)...".to_string();
        self.active_jobs.push(label.clone());
        thread::spawn(move || {
            let (best, res) = probe_max_tclk_staircase(dev, pk, &ser, jm, 1);
            let summary = res
                .iter()
                .map(|r| format!("{}:{}", r.tclk_label, if r.passed { "PASS" } else { "FAIL" }))
                .collect::<Vec<_>>()
                .join(", ");
            {
                let mut st = shared.lock().unwrap();
                if st.probe_lease_holder.as_deref() == Some("tclk_probe") {
                    st.probe_lease_holder = None;
                }
            }
            bg.lock().unwrap().push_back(BackgroundJobResult {
                label,
                payload: BgPayload::MaxTclk { best, summary },
            });
        });
    }

    fn drain_events_and_jobs(&mut self) {
        // 1. Drain worker events
        let events: Vec<WorkerEvent> = {
            let sh = self.controller.shared();
            let mut st = sh.lock().unwrap();
            st.events.drain(..).collect()
        };
        for ev in events {
            match ev {
                WorkerEvent::Log { level, msg } => self.log(&level, msg),
                WorkerEvent::Problem(p) => {
                    if self.problems.len() >= 200 {
                        self.problems.pop_front();
                    }
                    self.problems.push_front(p);
                }
                WorkerEvent::WriteResult { id, ok, msg, value } => {
                    let mut sym_name = String::new();
                    if let Some(w) = self.watch_items.iter_mut().find(|x| x.id == id) {
                        sym_name = w.symbol_path.clone();
                        w.write_state = if ok { WriteState::Verified } else { WriteState::Failed };
                        w.last_write_error = if ok { String::new() } else { msg };
                        if let Some(v) = value {
                            w.user_setpoint = Some(v);
                            self.staged_tuner.remove(&id);
                        }
                    }
                    if ok && !sym_name.is_empty() {
                        let sh = self.controller.shared();
                        let t_now = sh.lock().unwrap().latest.get(&id).map(|s| s.timestamp).unwrap_or(0.0);
                        self.scope.notify_write_trigger(&sym_name, t_now);
                    }
                }
                WorkerEvent::SafeRevertResult { all_verified, detail } => {
                    if all_verified {
                        self.safe_revert_failed_msg = None;
                    } else {
                        self.safe_revert_failed_msg = Some(detail);
                    }
                }
                WorkerEvent::BuiltinSymbols(trees) => {
                    self.symbol_trees = trees.clone();
                    self.populate_default_sim_watch(&trees);
                }
                WorkerEvent::Connected { .. } => {}
                WorkerEvent::Disconnected => {
                    self.dlog_enabled = false;
                }
            }
        }

        // 2. Drain background jobs
        let done: Vec<BackgroundJobResult> = self.bg_results.lock().unwrap().drain(..).collect();
        for job in done {
            if let Some(pos) = self.active_jobs.iter().position(|j| j == &job.label) {
                self.active_jobs.remove(pos);
            }
            match job.payload {
                BgPayload::Probes(probes) => {
                    self.log("info", format!("Probe scan complete: {} USB probe(s) found.", probes.len()));
                    self.detected_probes = probes;
                }
                BgPayload::Symbols { core, path, result } => match *result {
                    Ok(table) => {
                        self.program_paths.insert(core.clone(), path.display().to_string());
                        if let Ok(md) = std::fs::metadata(&path) {
                            if let Ok(mt) = md.modified() {
                                self.program_mtimes.insert(core.clone(), mt);
                            }
                        }
                        if !table.ram_ranges.is_empty() {
                            self.controller.send(WorkerCmd::SetExtraRam {
                                core: core.clone(),
                                ranges: table.ram_ranges.clone(),
                            });
                        }
                        let (updated, moved, quar) = resolve_watch_items_from_table(&self.watch_items, &table);
                        self.watch_items = updated;
                        self.sync_watch_list_to_worker();
                        for m in moved {
                            self.log("info", format!("Re-resolved symbol: {m}"));
                        }
                        for q in quar {
                            self.push_problem("warn", &core, q);
                        }
                        let count = table.symbols.len();
                        self.symbol_trees.insert(core.clone(), table.symbols);
                        if let Some(fp) = table.flash_fingerprint {
                            self.controller.send(WorkerCmd::VerifyFlashFingerprint { core: core.clone(), fp });
                        } else {
                            self.controller.send(WorkerCmd::InvalidateImage { locked: false, reason: String::new() });
                        }
                        self.log("info", format!("Loaded {count} top-level symbol(s) for {core} from {}", path.display()));
                    }
                    Err(e) => {
                        self.push_problem("error", "Symbols", e.clone());
                        self.log("error", e);
                    }
                },
                BgPayload::JtagTest { passed, output } => {
                    let lvl = if passed { "info" } else { "error" };
                    self.log(lvl, format!("dbgjtag {}: {output}", if passed { "PASSED" } else { "FAILED" }));
                    if !passed {
                        self.push_problem("error", "dbgjtag", output);
                    }
                }
                BgPayload::MaxTclk { best, summary } => {
                    if let Some(b) = best {
                        self.tclk_hz = b.clone();
                        self.log("info", format!("Max safe TCLK (with 1-step backoff): {b} [{summary}]"));
                    } else {
                        self.push_problem("error", "MaxTCLK", format!("All TCLK steps failed: {summary}"));
                    }
                }
                BgPayload::XdsReset { ok, output } => {
                    self.log(if ok { "info" } else { "error" }, format!("XDS110 USB reset: {output}"));
                }
            }
        }

        // 3. Watch loaded .out mtimes every 1.2s -> automatically lock writes on rebuild!
        if self.last_mtime_check.elapsed().as_secs_f64() >= 1.2 {
            self.last_mtime_check = Instant::now();
            let mut stale_hits = Vec::new();
            for (core, path_str) in &self.program_paths {
                let p = Path::new(path_str);
                if let Ok(md) = std::fs::metadata(p) {
                    if let Ok(mt) = md.modified() {
                        if let Some(prev) = self.program_mtimes.get(core) {
                            if mt != *prev {
                                stale_hits.push((core.clone(), path_str.clone(), mt));
                            }
                        }
                    }
                }
            }
            for (core, path_str, mt) in stale_hits {
                self.program_mtimes.insert(core.clone(), mt);
                let reason = format!(
                    "Firmware image '{}' changed on disk ({core}). Reload & verify Flash fingerprint before writing!",
                    Path::new(&path_str).file_name().and_then(|s| s.to_str()).unwrap_or(&path_str)
                );
                self.controller.send(WorkerCmd::InvalidateImage { locked: true, reason });
            }
        }
    }

    fn save_workspace_dialog(&mut self) {
        let key = profile_key_for(self.probe_kind, &self.selected_serial, self.device_id);
        let prof = WorkspaceProfile {
            schema_version: 2,
            profile_key: key,
            device_id: self.device_id,
            probe_kind: self.probe_kind,
            probe_serial: self.selected_serial.clone(),
            tclk_hz: self.tclk_hz.clone(),
            jtag_mode: self.jtag_mode,
            custom_ccxml_path: self.custom_ccxml_path.clone(),
            program_paths: self.program_paths.clone(),
            poll_config: self.poll_config.clone(),
            watch_items: self.watch_items.clone(),
            tuning_presets: self.tuning_presets.clone(),
            safe_baseline: self.safe_baseline.clone(),
            plot_panes: self.scope.pane_count,
            plot_window_sec: self.scope.window_sec,
            theme_mode: self.theme_mode,
            ui_scale_pct: self.ui_scale_pct,
            perspective_name: match self.perspective {
                Perspective::Tune => "tune".into(),
                Perspective::Scope => "scope".into(),
                Perspective::Debug => "debug".into(),
            },
        };
        if let Some(path) = save_file_dialog("Save Workspace Profile", "workspace.json", "json", &[("Workspace JSON", "*.json")]) {
            match self.store.save(&prof, Some(&path)) {
                Ok(saved) => self.log("info", format!("Saved workspace: {}", saved.display())),
                Err(e) => self.push_problem("error", "Workspace", e),
            }
        }
    }

    fn load_workspace_dialog(&mut self) {
        if let Some(path) = open_file_dialog("Load Workspace Profile", &[("Workspace JSON", "*.json")]) {
            if let Some(prof) = self.store.load(&path) {
                self.device_id = prof.device_id;
                self.probe_kind = prof.probe_kind;
                self.selected_serial = prof.probe_serial;
                self.tclk_hz = prof.tclk_hz;
                self.jtag_mode = prof.jtag_mode;
                self.custom_ccxml_path = prof.custom_ccxml_path;
                self.program_paths = prof.program_paths;
                self.poll_config = prof.poll_config;
                self.watch_items = prof.watch_items;
                self.tuning_presets = prof.tuning_presets;
                self.safe_baseline = prof.safe_baseline;
                self.scope.pane_count = prof.plot_panes.clamp(1, 3);
                self.scope.window_sec = prof.plot_window_sec;
                self.theme_mode = prof.theme_mode;
                self.ui_scale_pct = prof.ui_scale_pct;
                self.theme_dirty = true;
                self.sync_poll_config_to_worker();
                self.sync_watch_list_to_worker();
                self.log("info", format!("Loaded workspace from {}", path.display()));
            } else {
                self.push_problem("error", "Workspace", "Failed to load workspace (corrupt file quarantined as .corrupt.bak).");
            }
        }
    }

    fn apply_perspective(&mut self, p: Perspective) {
        self.perspective = p;
        match p {
            Perspective::Tune => {
                self.show_symbol_panel = true;
                self.show_watch_panel = true;
                self.show_scope_panel = true;
                self.show_console_panel = true;
            }
            Perspective::Scope => {
                self.show_symbol_panel = false;
                self.show_watch_panel = true;
                self.show_scope_panel = true;
                self.show_console_panel = false;
            }
            Perspective::Debug => {
                self.show_symbol_panel = true;
                self.show_watch_panel = true;
                self.show_scope_panel = false;
                self.show_console_panel = true;
            }
        }
    }

    fn render_symbol_tree_node(
        &mut self,
        ui: &mut Ui,
        node: &SymbolNode,
        filter_lc: &str,
        pending_add: &mut Vec<(SymbolNode, u8, bool)>,
    ) {
        if !symbol_matches_filter(node, filter_lc) {
            return;
        }
        let p = palette_for(self.theme_mode);
        if node.children.is_empty() {
            ui.horizontal(|ui| {
                let tag = if node.is_bitfield() {
                    format!(
                        "{} [{}:{}]  0x{:06X}",
                        node.name,
                        node.bit_offset.unwrap_or(0),
                        node.bit_width.unwrap_or(1),
                        node.address
                    )
                } else {
                    format!("{} ({})  0x{:06X}", node.name, node.data_type.label(), node.address)
                };
                ui.label(RichText::new(tag).monospace().size(11.0));
                if ui.small_button("+W").on_hover_text("Add to Watch Table").clicked() {
                    pending_add.push((node.clone(), 0, false));
                }
                if ui.small_button("+P").on_hover_text("Add & Plot on Pane 1").clicked() {
                    pending_add.push((node.clone(), 1, false));
                }
            });
        } else {
            let hdr = format!("{} ({}) @ 0x{:06X}", node.name, node.type_name, node.address);
            let default_open = !filter_lc.is_empty() || node.children.len() <= 8;
            egui::CollapsingHeader::new(RichText::new(hdr).strong().color(p.ink).size(11.5))
                .id_source(format!("sym_{}_{}", node.core, node.full_path))
                .default_open(default_open)
                .show(ui, |ui| {
                    for ch in &node.children {
                        self.render_symbol_tree_node(ui, ch, filter_lc, pending_add);
                    }
                });
        }
    }
}

impl eframe::App for C2000StudioApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.theme_dirty {
            apply_theme(ctx, self.theme_mode, self.ui_scale_pct);
            self.theme_dirty = false;
        }

        if !self.auto_connect_done {
            self.auto_connect_done = true;
            self.trigger_connect(true);
        }

        // Global Emergency Shortcut: Ctrl+Shift+R -> PREEMPT_SAFE_REVERT
        let revert_hotkey = ctx.input(|i| i.modifiers.ctrl && i.modifiers.shift && i.key_pressed(egui::Key::R));
        if revert_hotkey {
            self.trigger_safe_revert();
        }

        self.drain_events_and_jobs();

        // Snapshot shared telemetry quickly (never hold mutex across UI layout!)
        let (fsm_state, connected, stale_locked, stale_reason, core_states, memcfg, stats, non_atomic_ids, latest, csv_recording) = {
            let sh = self.controller.shared();
            let st = sh.lock().unwrap();
            (
                st.fsm_state,
                st.connected,
                st.stale_image_locked,
                st.stale_image_reason.clone(),
                st.core_states.clone(),
                st.memcfg,
                st.stats.clone(),
                st.non_atomic_ids.clone(),
                st.latest.clone(),
                st.csv_recording,
            )
        };

        let p = palette_for(self.theme_mode);

        // 1. Classic White Eclipse Menu Bar + Top Coolbar + Core/Poll Strip + Safety Banners
        egui::TopBottomPanel::top("top_chrome")
            .frame(egui::Frame::none().fill(p.frame_bg).inner_margin(egui::Margin::symmetric(6.0, 4.0)))
            .show(ctx, |ui| {
                // Menu Bar
                egui::menu::bar(ui, |ui| {
                    ui.menu_button("File", |ui| {
                        if ui.button("Save Workspace...").clicked() {
                            self.save_workspace_dialog();
                            ui.close_menu();
                        }
                        if ui.button("Load Workspace...").clicked() {
                            self.load_workspace_dialog();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Export Oscilloscope CSV...").clicked() {
                            self.scope.request_export_csv = true;
                            ui.close_menu();
                        }
                        if ui.button("Export Oscilloscope PNG...").clicked() {
                            self.scope.request_export_png = true;
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Exit").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                    ui.menu_button("View", |ui| {
                        ui.label(RichText::new("Perspectives").strong());
                        if ui.selectable_label(self.perspective == Perspective::Tune, "Tune (Full Workbench)").clicked() {
                            self.apply_perspective(Perspective::Tune);
                            ui.close_menu();
                        }
                        if ui.selectable_label(self.perspective == Perspective::Scope, "Scope (Oscilloscope Focus)").clicked() {
                            self.apply_perspective(Perspective::Scope);
                            ui.close_menu();
                        }
                        if ui.selectable_label(self.perspective == Perspective::Debug, "Debug (Symbols + Watch + Console)").clicked() {
                            self.apply_perspective(Perspective::Debug);
                            ui.close_menu();
                        }
                        ui.separator();
                        ui.label(RichText::new("Theme").strong());
                        if ui.selectable_label(self.theme_mode == ThemeMode::ClassicEclipseLight, "Classic Eclipse Light (Default)").clicked() {
                            self.theme_mode = ThemeMode::ClassicEclipseLight;
                            self.theme_dirty = true;
                            ui.close_menu();
                        }
                        if ui.selectable_label(self.theme_mode == ThemeMode::DarkOled, "Dark OLED").clicked() {
                            self.theme_mode = ThemeMode::DarkOled;
                            self.theme_dirty = true;
                            ui.close_menu();
                        }
                        ui.separator();
                        ui.label(RichText::new("UI Scale").strong());
                        for &sc in &[90u32, 100, 115, 130] {
                            if ui.selectable_label(self.ui_scale_pct == sc, format!("{sc}%")).clicked() {
                                self.ui_scale_pct = sc;
                                self.theme_dirty = true;
                                ui.close_menu();
                            }
                        }
                        ui.separator();
                        ui.checkbox(&mut self.show_symbol_panel, "Symbol Browser");
                        ui.checkbox(&mut self.show_watch_panel, "Watch & Tuning Deck");
                        ui.checkbox(&mut self.show_scope_panel, "Oscilloscope");
                        ui.checkbox(&mut self.show_console_panel, "Console / Problems / Jobs");
                    });
                    ui.menu_button("Diagnostics", |ui| {
                        if ui.button("CCS 21 Environment & Tool Paths...").clicked() {
                            self.show_ccs_diag_modal = true;
                            ui.close_menu();
                        }
                        if ui.button("Unlock DCSM (Volatile RAM Keys)...").clicked() {
                            self.show_dcsm_modal = true;
                            ui.close_menu();
                        }
                        if ui.button("Reset XDS110 Probe (USB Only)...").clicked() {
                            self.pending_confirm = Some(ConfirmAction::ResetXds110UsbOnly);
                            ui.close_menu();
                        }
                    });
                });

                ui.separator();

                // Classic White Eclipse Coolbar
                ui.horizontal_wrapped(|ui| {
                    // MCU selector
                    let mut dev = self.device_id;
                    egui::ComboBox::from_id_source("cb_mcu")
                        .width(126.0)
                        .selected_text(dev.display_name())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut dev, DeviceId::F28069M, DeviceId::F28069M.display_name());
                            ui.selectable_value(&mut dev, DeviceId::F28388D, DeviceId::F28388D.display_name());
                        });
                    if dev != self.device_id && !connected {
                        self.on_device_changed(dev);
                    }

                    // Probe selector
                    let cur_probe_lbl = if !self.selected_serial.is_empty() {
                        format!("{} ({})", self.probe_kind.label(), self.selected_serial)
                    } else {
                        self.probe_kind.label().to_string()
                    };
                    egui::ComboBox::from_id_source("cb_probe")
                        .width(134.0)
                        .selected_text(cur_probe_lbl)
                        .show_ui(ui, |ui| {
                            for pk in [ProbeKind::SIMULATOR, ProbeKind::XDS110, ProbeKind::XDS100V2, ProbeKind::CUSTOM_CCXML] {
                                if ui.selectable_label(self.probe_kind == pk && self.selected_serial.is_empty(), pk.label()).clicked() {
                                    self.probe_kind = pk;
                                    self.selected_serial.clear();
                                    self.tclk_hz = default_tclk(pk).into();
                                }
                            }
                            if !self.detected_probes.is_empty() {
                                ui.separator();
                                for dp in &self.detected_probes {
                                    let sel = self.probe_kind == dp.probe_kind && self.selected_serial == dp.serial;
                                    if ui.selectable_label(sel, dp.display_label()).clicked() {
                                        self.probe_kind = dp.probe_kind;
                                        self.selected_serial = dp.serial.clone();
                                        self.tclk_hz = default_tclk(dp.probe_kind).into();
                                    }
                                }
                            }
                        });

                    if ui.add_enabled(!connected, egui::Button::new("Scan")).clicked() {
                        self.spawn_probe_scan();
                    }

                    // Primary Eclipse Blue Attach Live / Neutral Outlined Disconnect
                    if !connected {
                        let btn = egui::Button::new(RichText::new("Attach Live").color(Color32::WHITE).strong())
                            .fill(p.accent);
                        if ui.add(btn).clicked() {
                            self.trigger_connect(true);
                        }
                    } else {
                        // Neutral outlined Disconnect so crimson is reserved exclusively for Safe Revert!
                        let btn = egui::Button::new(RichText::new("Disconnect").strong())
                            .fill(p.panel_bg)
                            .stroke(Stroke::new(1.2_f32, p.border_strong));
                        if ui.add(btn).clicked() {
                            self.controller.send(WorkerCmd::Disconnect);
                        }
                    }

                    // Program dropdown
                    ui.menu_button("Program", |ui| {
                        if ui.button("Load Symbols (.out / .elf / .map)...").clicked() {
                            if let Some(path) = open_file_dialog(
                                "Open TI Firmware Symbols",
                                &[("TI Firmware/Symbols", "*.out;*.elf;*.map"), ("All Files", "*.*")],
                            ) {
                                let c = self.selected_sym_core.clone();
                                self.spawn_symbol_parse(c, path);
                            }
                            ui.close_menu();
                        }
                        if ui.add_enabled(connected, egui::Button::new("Flash Load & Run (.out)...")).clicked() {
                            if let Some(path) = open_file_dialog("Select .out to Flash & Run", &[("TI Executable", "*.out;*.elf")]) {
                                let c = self.selected_sym_core.clone();
                                self.pending_confirm = Some(ConfirmAction::LoadAndRun { core: c, path });
                            }
                            ui.close_menu();
                        }
                        if ui.button("Select Custom .ccxml...").clicked() {
                            if let Some(path) = open_file_dialog("Select CCS Target Configuration", &[("Target Config", "*.ccxml")]) {
                                self.custom_ccxml_path = path.display().to_string();
                                self.probe_kind = ProbeKind::CUSTOM_CCXML;
                                self.log("info", format!("Custom .ccxml selected (GEL stripped fail-closed): {}", self.custom_ccxml_path));
                            }
                            ui.close_menu();
                        }
                    });

                    let primary_core = get_device_profile(self.device_id).primary_core().name.to_string();
                    if ui.add_enabled(connected, egui::Button::new("Run")).clicked() {
                        self.controller.send(WorkerCmd::RunCore(primary_core.clone()));
                    }
                    if ui.add_enabled(connected, egui::Button::new("Halt")).clicked() {
                        self.controller.send(WorkerCmd::HaltCore(primary_core.clone()));
                    }
                    if ui.add_enabled(connected, egui::Button::new("Reset")).clicked() {
                        self.controller.send(WorkerCmd::ResetCore(primary_core));
                    }

                    ui.toggle_value(&mut self.show_jtag_drawer, "JTAG");

                    ui.separator();

                    // Permanent High-Contrast Target State Lamp
                    let (lamp_txt, lamp_fg, lamp_bg) = match fsm_state {
                        SessionState::Disconnected => ("DISCONNECTED", p.muted, p.header_bg),
                        SessionState::Connecting => ("CONNECTING...", p.warn_fg, p.warn_bg),
                        SessionState::ConnectedLive => {
                            let lbl = match self.poll_config.realtime_mode {
                                RealtimeAccessMode::SiliconRtPolite => "RT POLITE (LIVE)",
                                RealtimeAccessMode::SiliconRtRude => "RT RUDE (LIVE)",
                                RealtimeAccessMode::StopModeHalt => "STOP-MODE!",
                            };
                            (lbl, p.ok_fg, p.ok_bg)
                        }
                        SessionState::WriteLockedStaleImage => ("STALE .OUT — WRITE LOCKED", p.warn_fg, p.warn_bg),
                        SessionState::DcsmLocked => ("DCSM LOCKED", p.err_fg, p.err_bg),
                        SessionState::Fault => ("FAULT", p.err_fg, p.err_bg),
                        SessionState::Recovering => ("RECOVERING", p.warn_fg, p.warn_bg),
                    };
                    egui::Frame::none()
                        .fill(lamp_bg)
                        .stroke(Stroke::new(1.0_f32, lamp_fg))
                        .rounding(2.0)
                        .inner_margin(egui::Margin::symmetric(8.0, 2.0))
                        .show(ui, |ui| {
                            ui.label(RichText::new(lamp_txt).color(lamp_fg).strong().size(11.5));
                        });

                    // Perspective compact buttons
                    ui.separator();
                    for (persp, lbl) in [(Perspective::Tune, "Tune"), (Perspective::Scope, "Scope"), (Perspective::Debug, "Debug")] {
                        if ui.selectable_label(self.perspective == persp, lbl).clicked() {
                            self.apply_perspective(persp);
                        }
                    }

                    // Single Solid Crimson CTA: Safe Revert (Ctrl+Shift+R)
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let revert_btn = egui::Button::new(
                            RichText::new("Safe Revert (Ctrl+Shift+R)").color(Color32::WHITE).strong(),
                        )
                        .fill(p.crimson_cta);
                        if ui.add(revert_btn).on_hover_text("Preempt normal queue and restore verified Safe Baseline").clicked() {
                            self.trigger_safe_revert();
                        }
                    });
                });

                // Collapsible JTAG Hardware Drawer
                if self.show_jtag_drawer {
                    ui.add_space(2.0);
                    egui::Frame::none()
                        .fill(p.surface_alt)
                        .stroke(Stroke::new(1.0_f32, p.border))
                        .inner_margin(egui::Margin::symmetric(6.0, 3.0))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new("TCLK:").strong());
                                let opts = probe_tclk_options(self.probe_kind);
                                egui::ComboBox::from_id_source("cb_tclk")
                                    .width(82.0)
                                    .selected_text(&self.tclk_hz)
                                    .show_ui(ui, |ui| {
                                        for &o in opts {
                                            ui.selectable_value(&mut self.tclk_hz, o.to_string(), o);
                                        }
                                    });
                                let caps = probe_capabilities(self.probe_kind);
                                ui.label("Mode:");
                                egui::ComboBox::from_id_source("cb_jtag_mode")
                                    .width(108.0)
                                    .selected_text(self.jtag_mode.label())
                                    .show_ui(ui, |ui| {
                                        ui.selectable_value(&mut self.jtag_mode, JtagMode::Jtag4Pin, JtagMode::Jtag4Pin.label());
                                        if caps.supports_cjtag {
                                            ui.selectable_value(&mut self.jtag_mode, JtagMode::Cjtag2PinOscan2, JtagMode::Cjtag2PinOscan2.label());
                                            ui.selectable_value(&mut self.jtag_mode, JtagMode::Cjtag2PinOscan1, JtagMode::Cjtag2PinOscan1.label());
                                        }
                                    });
                                if ui.add_enabled(!connected && self.probe_kind != ProbeKind::SIMULATOR, egui::Button::new("Test JTAG Chain")).clicked() {
                                    self.spawn_jtag_test();
                                }
                                if ui.add_enabled(!connected && self.probe_kind != ProbeKind::SIMULATOR, egui::Button::new("Probe Max TCLK")).clicked() {
                                    self.spawn_max_tclk_probe();
                                }
                                ui.label(
                                    RichText::new(format!(
                                        "Caps: max {:.0} MHz | cJTAG: {} | AuxUART: {}",
                                        caps.max_tclk_mhz,
                                        if caps.supports_cjtag { "Yes" } else { "No" },
                                        if caps.supports_aux_uart { "Yes" } else { "No" }
                                    ))
                                    .color(p.muted)
                                    .size(11.0),
                                );
                            });
                        });
                }

                ui.add_space(3.0);

                // Core Strip + Polling / Realtime Control Row
                ui.horizontal_wrapped(|ui| {
                    let prof = get_device_profile(self.device_id);
                    for c in &prof.cores {
                        let st = core_states.get(c.name).copied().unwrap_or(CoreState::Disconnected);
                        let (fg, bg) = match st {
                            CoreState::ConnectedRtPolite | CoreState::ConnectedRunning => (p.ok_fg, p.ok_bg),
                            CoreState::ConnectedRtRude | CoreState::ConnectedHalted | CoreState::DbgMBlocked => (p.warn_fg, p.warn_bg),
                            CoreState::DcsmLocked | CoreState::Error => (p.err_fg, p.err_bg),
                            _ => (p.muted, p.header_bg),
                        };
                        let btn = egui::Button::new(
                            RichText::new(format!("{}: {}", c.display_tag, st.short_label()))
                                .color(fg)
                                .monospace()
                                .size(11.0),
                        )
                        .fill(bg)
                        .stroke(Stroke::new(1.0_f32, fg));
                        if ui.add_enabled(connected, btn).on_hover_text("Click to toggle core attach/detach").clicked() {
                            if st == CoreState::Disconnected {
                                self.controller.send(WorkerCmd::ConnectCore { core: c.name.into(), attach_live: true });
                            } else {
                                self.controller.send(WorkerCmd::DisconnectCore { core: c.name.into() });
                            }
                        }
                    }

                    if prof.cores.len() > 2 {
                        if ui.add_enabled(connected, egui::Button::new("Run All")).clicked() {
                            self.controller.send(WorkerCmd::RunAll);
                        }
                        if ui.add_enabled(connected, egui::Button::new("Halt All")).clicked() {
                            self.controller.send(WorkerCmd::HaltAll);
                        }
                    }

                    if memcfg.probed && self.device_id == DeviceId::F28388D {
                        ui.label(
                            RichText::new(format!(
                                "MemCfg: LS=0x{:X} GS=0x{:X}",
                                memcfg.ls_msel, memcfg.gs_msel
                            ))
                            .monospace()
                            .color(p.muted)
                            .size(10.5),
                        );
                    }

                    ui.separator();

                    // Polling controls
                    let poll_lbl = if self.polling_active { "Poll: ON" } else { "Poll: PAUSED" };
                    if ui.selectable_label(self.polling_active, poll_lbl).clicked() {
                        self.polling_active = !self.polling_active;
                        self.controller.send(WorkerCmd::SetPollingActive(self.polling_active));
                    }
                    if ui.add_enabled(connected, egui::Button::new("1-Shot")).clicked() {
                        self.controller.send(WorkerCmd::SingleShot);
                    }

                    let mut cfg_changed = false;
                    egui::ComboBox::from_id_source("cb_poll_mode")
                        .width(74.0)
                        .selected_text(self.poll_config.mode.label())
                        .show_ui(ui, |ui| {
                            for m in [PollMode::MaxFreerun, PollMode::FixedHz, PollMode::Manual] {
                                if ui.selectable_label(self.poll_config.mode == m, m.label()).clicked() {
                                    self.poll_config.mode = m;
                                    cfg_changed = true;
                                }
                            }
                        });
                    if self.poll_config.mode == PollMode::FixedHz {
                        egui::ComboBox::from_id_source("cb_poll_hz")
                            .width(64.0)
                            .selected_text(format!("{:.0}Hz", self.poll_config.target_hz))
                            .show_ui(ui, |ui| {
                                for &hz in &[20.0, 50.0, 100.0, 250.0, 500.0] {
                                    if ui.selectable_label((self.poll_config.target_hz - hz).abs() < 0.1, format!("{hz:.0}Hz")).clicked() {
                                        self.poll_config.target_hz = hz;
                                        cfg_changed = true;
                                    }
                                }
                            });
                    }

                    // Realtime access mode selector (Stop-Mode requires confirmation!)
                    egui::ComboBox::from_id_source("cb_rt_mode")
                        .width(86.0)
                        .selected_text(self.poll_config.realtime_mode.label())
                        .show_ui(ui, |ui| {
                            if ui.selectable_label(self.poll_config.realtime_mode == RealtimeAccessMode::SiliconRtPolite, "RT Polite").clicked() {
                                self.poll_config.realtime_mode = RealtimeAccessMode::SiliconRtPolite;
                                cfg_changed = true;
                            }
                            if ui.selectable_label(self.poll_config.realtime_mode == RealtimeAccessMode::SiliconRtRude, "RT Rude").clicked() {
                                self.poll_config.realtime_mode = RealtimeAccessMode::SiliconRtRude;
                                cfg_changed = true;
                            }
                            if ui.selectable_label(self.poll_config.realtime_mode == RealtimeAccessMode::StopModeHalt, "Stop-Mode!").clicked() {
                                self.pending_confirm = Some(ConfirmAction::StopModeHalt);
                            }
                        });

                    if ui.add_enabled(connected, egui::Button::new("DBGM")).on_hover_text("Clear ST1.DBGM via brief micro-halt (confirms first)").clicked() {
                        let c = get_device_profile(self.device_id).primary_core().name.to_string();
                        self.pending_confirm = Some(ConfirmAction::MicroHaltDbgM { core: c });
                    }

                    if ui.add_enabled(connected, egui::SelectableLabel::new(self.dlog_enabled, "DLOG 20k")).clicked() {
                        self.dlog_enabled = !self.dlog_enabled;
                        self.controller.send(WorkerCmd::ConfigureDlog {
                            enabled: self.dlog_enabled,
                            trigger_mode: "free".into(),
                            level: 0.0,
                        });
                    }

                    ui.menu_button("Opts", |ui| {
                        if ui.checkbox(&mut self.poll_config.verify_after_write, "Verify After Write (Mandatory Readback)").changed() {
                            cfg_changed = true;
                        }
                        if ui.checkbox(&mut self.poll_config.allow_rude_fallback, "Allow Rude Fallback if DBGM=1").changed() {
                            cfg_changed = true;
                        }
                        if ui.checkbox(&mut self.poll_config.pause_on_write, "Pause Polling During Writes").changed() {
                            cfg_changed = true;
                        }
                        ui.separator();
                        if !csv_recording {
                            if ui.add_enabled(connected, egui::Button::new("Start Live CSV Recording...")).clicked() {
                                if let Some(path) = save_file_dialog("Stream Live Telemetry CSV", "c2000_stream.csv", "csv", &[("CSV", "*.csv")]) {
                                    self.controller.send(WorkerCmd::StartCsvRecording(path));
                                }
                                ui.close_menu();
                            }
                        } else if ui.button("Stop Live CSV Recording").clicked() {
                            self.controller.send(WorkerCmd::StopCsvRecording);
                            ui.close_menu();
                        }
                    });

                    if cfg_changed {
                        self.sync_poll_config_to_worker();
                    }

                    // Telemetry readout
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "{:.0} Hz | {:.1} ms (p95 {:.1} ms) | {} sp | {:.1} kW/s | err {}",
                                stats.achieved_hz,
                                stats.latency_ms_avg,
                                stats.dt_p95_ms,
                                stats.span_count,
                                stats.words_per_sec / 1000.0,
                                stats.error_count
                            ))
                            .monospace()
                            .color(p.muted)
                            .size(11.0),
                        );
                    });
                });

                // Non-modal Safety Banners
                if stale_locked {
                    ui.add_space(3.0);
                    egui::Frame::none()
                        .fill(p.warn_bg)
                        .stroke(Stroke::new(1.5_f32, p.warn_fg))
                        .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new(format!("⚠ STALE .OUT — WRITES LOCKED: {stale_reason}")).color(p.warn_fg).strong());
                                if ui.button("Reload & Verify").clicked() {
                                    let c = self.selected_sym_core.clone();
                                    if let Some(ps) = self.program_paths.get(&c).cloned() {
                                        self.spawn_symbol_parse(c, PathBuf::from(ps));
                                    }
                                }
                                if ui.button("Expert Override").clicked() {
                                    self.pending_confirm = Some(ConfirmAction::ExpertStaleOverride);
                                }
                            });
                        });
                }

                if let Some(fail_msg) = self.safe_revert_failed_msg.clone() {
                    ui.add_space(3.0);
                    egui::Frame::none()
                        .fill(p.err_bg)
                        .stroke(Stroke::new(1.5_f32, p.err_fg))
                        .inner_margin(egui::Margin::symmetric(8.0, 4.0))
                        .show(ui, |ui| {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(RichText::new(format!("✖ {fail_msg}")).color(p.err_fg).strong());
                                if ui.button("Retry Safe Revert").clicked() {
                                    self.trigger_safe_revert();
                                }
                                if ui.button("Dismiss").clicked() {
                                    self.safe_revert_failed_msg = None;
                                }
                            });
                        });
                }
            });

        // 2. Bottom Console | Problems & Safety | Jobs Panel
        if self.show_console_panel {
            egui::TopBottomPanel::bottom("bottom_dock")
                .resizable(true)
                .default_height(130.0)
                .min_height(84.0)
                .frame(egui::Frame::none().fill(p.panel_bg).stroke(Stroke::new(1.0_f32, p.border)).inner_margin(egui::Margin::same(5.0)))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.selectable_value(&mut self.bottom_tab, BottomTab::Console, "Console");
                        ui.selectable_value(
                            &mut self.bottom_tab,
                            BottomTab::Problems,
                            format!("Problems & Safety ({})", self.problems.len()),
                        );
                        ui.selectable_value(
                            &mut self.bottom_tab,
                            BottomTab::Jobs,
                            format!("Jobs ({})", self.active_jobs.len()),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Clear").clicked() {
                                match self.bottom_tab {
                                    BottomTab::Console => self.console_lines.clear(),
                                    BottomTab::Problems => self.problems.clear(),
                                    BottomTab::Jobs => {}
                                }
                            }
                        });
                    });
                    ui.separator();
                    egui::ScrollArea::vertical().id_source("bottom_dock_scroll").stick_to_bottom(self.bottom_tab == BottomTab::Console).show(ui, |ui| {
                        match self.bottom_tab {
                            BottomTab::Console => {
                                for (lvl, line) in &self.console_lines {
                                    let col = match lvl.as_str() {
                                        "ERROR" => p.err_fg,
                                        "WARN" => p.warn_fg,
                                        _ => p.ink,
                                    };
                                    ui.label(RichText::new(format!("[{lvl}] {line}")).color(col).monospace().size(11.0));
                                }
                            }
                            BottomTab::Problems => {
                                if self.problems.is_empty() {
                                    ui.label(RichText::new("No active safety or hardware problems.").color(p.ok_fg));
                                } else {
                                    for pr in &self.problems {
                                        let col = if pr.severity == "ERROR" { p.err_fg } else { p.warn_fg };
                                        ui.label(
                                            RichText::new(format!("{} [{}] ({}) {}", pr.time, pr.severity, pr.source, pr.message))
                                                .color(col)
                                                .monospace()
                                                .size(11.0),
                                        );
                                    }
                                }
                            }
                            BottomTab::Jobs => {
                                if self.active_jobs.is_empty() {
                                    ui.label(RichText::new("No background jobs running.").color(p.muted));
                                } else {
                                    for j in &self.active_jobs {
                                        ui.horizontal(|ui| {
                                            ui.spinner();
                                            ui.label(RichText::new(j).monospace().size(11.5));
                                        });
                                    }
                                }
                            }
                        }
                    });
                });
        }

        // 3. Left Panel: Symbol Browser
        if self.show_symbol_panel {
            egui::SidePanel::left("symbol_browser_dock")
                .resizable(true)
                .default_width(248.0)
                .min_width(190.0)
                .frame(egui::Frame::none().fill(p.panel_bg).stroke(Stroke::new(1.0_f32, p.border)).inner_margin(egui::Margin::same(6.0)))
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Symbol Browser").strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button("Addr").on_hover_text("Add manual RAM address").clicked() {
                                self.show_manual_addr_modal = true;
                            }
                            if ui.small_button("Open").on_hover_text("Open .out / .elf / .map").clicked() {
                                if let Some(path) = open_file_dialog(
                                    "Open TI Firmware Symbols",
                                    &[("TI Firmware/Symbols", "*.out;*.elf;*.map"), ("All Files", "*.*")],
                                ) {
                                    let c = self.selected_sym_core.clone();
                                    self.spawn_symbol_parse(c, path);
                                }
                            }
                        });
                    });

                    ui.horizontal(|ui| {
                        let prof = get_device_profile(self.device_id);
                        egui::ComboBox::from_id_source("sym_core_cb")
                            .width(110.0)
                            .selected_text(&self.selected_sym_core)
                            .show_ui(ui, |ui| {
                                for c in &prof.cores {
                                    ui.selectable_value(&mut self.selected_sym_core, c.name.to_string(), c.name);
                                }
                            });
                        ui.add(egui::TextEdit::singleline(&mut self.sym_search).hint_text("Filter...").desired_width(ui.available_width()));
                    });

                    ui.separator();
                    let filter_lc = self.sym_search.trim().to_ascii_lowercase();
                    let nodes = self.symbol_trees.get(&self.selected_sym_core).cloned().unwrap_or_default();
                    let mut pending_add: Vec<(SymbolNode, u8, bool)> = Vec::new();
                    egui::ScrollArea::vertical().id_source("sym_tree_scroll").show(ui, |ui| {
                        if nodes.is_empty() {
                            ui.label(RichText::new("Click 'Attach Live' (Simulator) or 'Open' a TI .out/.elf/.map file.").color(p.muted));
                        } else {
                            for n in &nodes {
                                self.render_symbol_tree_node(ui, n, &filter_lc, &mut pending_add);
                            }
                        }
                    });
                    for (node, pane, pin) in pending_add {
                        self.add_symbol_to_watch(&node, pane, pin);
                    }
                });
        }

        // 4. Right Panel: Bench-Grade Oscilloscope
        if self.show_scope_panel {
            egui::SidePanel::right("scope_dock")
                .resizable(true)
                .default_width(510.0)
                .min_width(340.0)
                .frame(egui::Frame::none().fill(p.panel_bg).stroke(Stroke::new(1.0_f32, p.border)).inner_margin(egui::Margin::same(6.0)))
                .show(ctx, |ui| {
                    let sh = self.controller.shared();
                    let st = sh.lock().unwrap();
                    self.scope.ui(ui, self.theme_mode, &self.watch_items, &st.buffers);
                });

            if self.scope.request_clear {
                self.scope.request_clear = false;
                self.controller.clear_buffers();
                self.log("info", "Cleared oscilloscope ring buffers.");
            }
            if self.scope.request_export_csv {
                self.scope.request_export_csv = false;
                if let Some(path) = save_file_dialog("Export Bounded-ZOH CSV", "c2000_scope.csv", "csv", &[("CSV", "*.csv")]) {
                    let sh = self.controller.shared();
                    let st = sh.lock().unwrap();
                    let plotted: Vec<&WatchItem> = self.watch_items.iter().filter(|w| w.plot_pane > 0).collect();
                    let mut raw_slices: Vec<(String, Vec<f64>, Vec<f64>)> = Vec::new();
                    for w in &plotted {
                        if let Some(rb) = st.buffers.get(&w.id) {
                            let (ts, vs) = rb.view_window(self.scope.window_sec);
                            raw_slices.push((w.symbol_path.clone(), ts.to_vec(), vs.to_vec()));
                        }
                    }
                    drop(st);
                    let refs: Vec<(&str, &[f64], &[f64])> = raw_slices
                        .iter()
                        .map(|(n, t, v)| (n.as_str(), t.as_slice(), v.as_slice()))
                        .collect();
                    match export_scope_csv(&path, &refs, 0.25) {
                        Ok(rows) => self.log("info", format!("Exported {rows} rows (Bounded-ZOH CSV) -> {}", path.display())),
                        Err(e) => self.push_problem("error", "CSVExport", e),
                    }
                }
            }
            if self.scope.request_export_png {
                self.scope.request_export_png = false;
                if let Some(path) = save_file_dialog("Export Oscilloscope PNG", "c2000_scope.png", "png", &[("PNG Image", "*.png")]) {
                    let sh = self.controller.shared();
                    let st = sh.lock().unwrap();
                    let mut owned: Vec<(String, Color32, Vec<f64>, Vec<f64>)> = Vec::new();
                    for w in self.watch_items.iter().filter(|w| w.plot_pane > 0) {
                        if let Some(rb) = st.buffers.get(&w.id) {
                            let (ts, vs) = rb.view_window(self.scope.window_sec);
                            owned.push((w.symbol_path.clone(), trace_color_for(w.color_index, self.theme_mode), ts.to_vec(), vs.to_vec()));
                        }
                    }
                    drop(st);
                    let refs: Vec<(&str, Color32, &[f64], &[f64])> = owned
                        .iter()
                        .map(|(n, c, t, v)| (n.as_str(), *c, t.as_slice(), v.as_slice()))
                        .collect();
                    match render_scope_png(&path, 1280, 640, self.theme_mode, &refs) {
                        Ok(_) => self.log("info", format!("Exported Scope PNG -> {}", path.display())),
                        Err(e) => self.push_problem("error", "PNGExport", e),
                    }
                }
            }
        }

        // 5. Center Panel: Live Watch Table + Live Tuning Deck
        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(p.frame_bg).inner_margin(egui::Margin::same(6.0)))
            .show(ctx, |ui| {
                if !self.show_watch_panel {
                    ui.centered_and_justified(|ui| {
                        ui.label(RichText::new("Watch & Tuning panel hidden (View -> Watch & Tuning Deck)").color(p.muted));
                    });
                    return;
                }

                let avail_h = ui.available_height();
                let watch_h = (avail_h * 0.52).max(160.0);

                // Top Half: Watch Table
                egui::Frame::none()
                    .fill(p.panel_bg)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .inner_margin(egui::Margin::same(6.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label(RichText::new(format!("Live Watch Table ({})", self.watch_items.len())).strong());
                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                ui.label(RichText::new("Press Enter in Write field to apply via 5-Gate Firewall").color(p.muted).size(10.5));
                            });
                        });
                        ui.separator();

                        let mut watch_dirty = false;
                        let mut remove_idx: Option<usize> = None;
                        let mut writes_to_send: Vec<(String, f64)> = Vec::new();
                        let mut rmw_req: Option<(String, String)> = None;

                        egui::ScrollArea::both().id_source("watch_table_scroll").max_height(watch_h - 36.0).show(ui, |ui| {
                            egui::Grid::new("watch_grid").striped(true).spacing([6.0, 3.0]).show(ui, |ui| {
                                for h in ["Symbol", "Addr", "Live Value", "Write", "Fmt", "Plot", "Pin", "RO", "Status", ""] {
                                    ui.label(RichText::new(h).strong().size(11.0));
                                }
                                ui.end_row();

                                for (idx, item) in self.watch_items.iter_mut().enumerate() {
                                    let col = trace_color_for(item.color_index, self.theme_mode);
                                    let dot = if item.plot_pane > 0 { "● " } else { "" };
                                    ui.label(RichText::new(format!("{dot}{}", item.symbol_path)).color(if item.plot_pane > 0 { col } else { p.ink }).monospace().size(11.0));
                                    ui.label(RichText::new(format!("0x{:06X}", item.address)).color(p.muted).monospace().size(10.5));

                                    let sample = latest.get(&item.id);
                                    let live_txt = if let Some(s) = sample {
                                        if s.has_error {
                                            "ERR".into()
                                        } else {
                                            format_value(s.raw, item.data_type, item.display_format, item.iq_q_bits)
                                        }
                                    } else {
                                        "--".into()
                                    };
                                    ui.label(RichText::new(live_txt).monospace().strong().size(11.5));

                                    // Edit-safe inline write input
                                    let ro_eff = item.effective_read_only() || stale_locked || !connected;
                                    let buf = self.inline_edits.entry(item.id.clone()).or_default();
                                    let te = ui.add_enabled(!ro_eff, egui::TextEdit::singleline(buf).desired_width(64.0).hint_text("set"));
                                    if te.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                        match parse_numeric_input(buf) {
                                            Ok(v) => {
                                                writes_to_send.push((item.id.clone(), v));
                                                buf.clear();
                                            }
                                            Err(e) => {
                                                item.write_state = WriteState::Failed;
                                                item.last_write_error = e;
                                            }
                                        }
                                    }

                                    // Format combo
                                    egui::ComboBox::from_id_source(format!("fmt_{}", item.id))
                                        .width(50.0)
                                        .selected_text(item.display_format.label())
                                        .show_ui(ui, |ui| {
                                            for f in DisplayFormat::ALL {
                                                if ui.selectable_label(item.display_format == f, f.label()).clicked() {
                                                    item.display_format = f;
                                                    watch_dirty = true;
                                                }
                                            }
                                        });

                                    // Plot Pane combo
                                    let plbl = if item.plot_pane == 0 { "Off".into() } else { format!("P{}", item.plot_pane) };
                                    egui::ComboBox::from_id_source(format!("pane_{}", item.id))
                                        .width(42.0)
                                        .selected_text(plbl)
                                        .show_ui(ui, |ui| {
                                            for (v, t) in [(0u8, "Off"), (1, "P1"), (2, "P2"), (3, "P3")] {
                                                if ui.selectable_label(item.plot_pane == v, t).clicked() {
                                                    item.plot_pane = v;
                                                }
                                            }
                                        });

                                    ui.checkbox(&mut item.pinned_tuner, "");

                                    let mut ro_chk = item.read_only;
                                    if ui.checkbox(&mut ro_chk, "").changed() {
                                        if !ro_chk && item.is_bitfield() && !item.rmw_unlocked {
                                            rmw_req = Some((item.id.clone(), item.symbol_path.clone()));
                                        } else {
                                            item.read_only = ro_chk;
                                            watch_dirty = true;
                                        }
                                    }

                                    // Status pill
                                    let (st_txt, st_col) = if item.write_state == WriteState::Quarantined {
                                        ("[STALE-RO]", p.err_fg)
                                    } else if item.write_state == WriteState::Failed {
                                        ("FAILED", p.err_fg)
                                    } else if item.write_state == WriteState::Verified {
                                        ("VERIFIED", p.ok_fg)
                                    } else if non_atomic_ids.contains(&item.id) {
                                        ("[non-atomic]", p.warn_fg)
                                    } else if item.is_bitfield() && !item.rmw_unlocked {
                                        ("[RMW-LOCK]", p.muted)
                                    } else {
                                        ("OK", p.muted)
                                    };
                                    ui.label(RichText::new(st_txt).color(st_col).monospace().size(10.5))
                                        .on_hover_text(&item.last_write_error);

                                    if ui.small_button("×").on_hover_text("Remove watch item").clicked() {
                                        remove_idx = Some(idx);
                                    }
                                    ui.end_row();
                                }
                            });
                        });

                        if let Some(i) = remove_idx {
                            let removed = self.watch_items.remove(i);
                            self.staged_tuner.remove(&removed.id);
                            self.safe_baseline.remove(&removed.id);
                            watch_dirty = true;
                        }
                        if let Some((id, sym)) = rmw_req {
                            self.pending_confirm = Some(ConfirmAction::UnlockBitfieldRmw { item_id: id, symbol: sym });
                        }
                        for (id, v) in writes_to_send {
                            self.controller.send(WorkerCmd::WriteSymbol { id, value: v });
                        }
                        if watch_dirty {
                            self.sync_watch_list_to_worker();
                        }
                    });

                ui.add_space(6.0);

                // Bottom Half: Live Tuning Deck
                egui::Frame::none()
                    .fill(p.panel_bg)
                    .stroke(Stroke::new(1.0_f32, p.border))
                    .inner_margin(egui::Margin::same(6.0))
                    .show(ui, |ui| {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(RichText::new("Live Tuning Deck").strong());
                            ui.separator();
                            let staged_n = self.staged_tuner.len();
                            if ui.add_enabled(connected && !stale_locked && staged_n > 0, egui::Button::new(format!("Batch Apply ({staged_n})"))).clicked() {
                                let diffs: Vec<(String, String, f64, f64)> = self
                                    .staged_tuner
                                    .iter()
                                    .filter_map(|(id, &new_v)| {
                                        let w = self.watch_items.iter().find(|x| &x.id == id)?;
                                        let cur = latest.get(id).map(|s| s.eng).unwrap_or(0.0);
                                        Some((id.clone(), w.symbol_path.clone(), cur, new_v))
                                    })
                                    .collect();
                                if diffs.len() > 1 {
                                    self.pending_confirm = Some(ConfirmAction::BatchApply(diffs));
                                } else if let Some((id, _, _, nv)) = diffs.first() {
                                    self.controller.send(WorkerCmd::WriteSymbol { id: id.clone(), value: *nv });
                                }
                            }
                            if ui.button("Set Safe").on_hover_text("Record current live values of pinned parameters as Safe Revert baseline").clicked() {
                                let mut cnt = 0usize;
                                for w in self.watch_items.iter().filter(|w| w.pinned_tuner) {
                                    if let Some(s) = latest.get(&w.id) {
                                        if s.eng.is_finite() {
                                            self.safe_baseline.insert(w.id.clone(), s.eng);
                                            cnt += 1;
                                        }
                                    }
                                }
                                self.log("info", format!("Recorded Safe Revert baseline for {cnt} pinned parameter(s)."));
                            }
                            if ui.button("Save Preset").clicked() {
                                let mut snap = BTreeMap::new();
                                for w in self.watch_items.iter().filter(|w| w.pinned_tuner) {
                                    if let Some(s) = latest.get(&w.id) {
                                        if s.eng.is_finite() {
                                            snap.insert(w.id.clone(), s.eng);
                                        }
                                    }
                                }
                                self.tuning_presets.insert("Bench_A".into(), snap);
                                self.log("info", "Saved Tuning Preset 'Bench_A'.");
                            }
                            if ui.add_enabled(self.tuning_presets.contains_key("Bench_A"), egui::Button::new("Load Preset")).clicked() {
                                if let Some(preset) = self.tuning_presets.get("Bench_A").cloned() {
                                    for (id, v) in preset {
                                        self.staged_tuner.insert(id, v);
                                    }
                                    self.log("info", "Staged Preset 'Bench_A' — click Batch Apply to commit.");
                                }
                            }
                        });
                        ui.separator();

                        let mut card_writes: Vec<(String, f64)> = Vec::new();
                        let mut cfg_dirty = false;
                        egui::ScrollArea::vertical().id_source("tuner_deck_scroll").show(ui, |ui| {
                            let pinned_indices: Vec<usize> = self
                                .watch_items
                                .iter()
                                .enumerate()
                                .filter(|(_, w)| w.pinned_tuner)
                                .map(|(i, _)| i)
                                .collect();
                            if pinned_indices.is_empty() {
                                ui.label(RichText::new("Check 'Pin' on any Watch Table variable to open a Live Tuner Card.").color(p.muted));
                            } else {
                                for idx in pinned_indices {
                                    let w = &mut self.watch_items[idx];
                                    let rb = latest.get(&w.id).map(|s| s.eng).unwrap_or(0.0);
                                    let staged = *self.staged_tuner.get(&w.id).unwrap_or(&rb);
                                    let lo = w.min_val.unwrap_or(0.0);
                                    let hi = w.max_val.unwrap_or((rb.abs() * 2.0).max(10.0));
                                    let ro_eff = w.effective_read_only() || stale_locked || !connected;

                                    egui::Frame::none()
                                        .fill(p.surface_alt)
                                        .stroke(Stroke::new(1.0_f32, p.border))
                                        .rounding(2.0)
                                        .inner_margin(egui::Margin::same(6.0))
                                        .show(ui, |ui| {
                                            ui.horizontal(|ui| {
                                                ui.label(RichText::new(&w.symbol_path).strong().monospace().size(11.5));
                                                ui.label(RichText::new(format!("RB: {rb:.4}")).monospace().color(p.accent));
                                                if let Some(sp) = w.user_setpoint {
                                                    let mismatch = (rb - sp).abs() > (w.step.abs() * 0.5).max(1e-3);
                                                    let (btxt, bcol) = if w.write_state == WriteState::Failed {
                                                        ("FAILED", p.err_fg)
                                                    } else if mismatch {
                                                        ("MISMATCH", p.warn_fg)
                                                    } else {
                                                        ("VERIFIED", p.ok_fg)
                                                    };
                                                    ui.label(RichText::new(btxt).color(bcol).strong().size(10.5));
                                                }
                                                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                    if ui.checkbox(&mut w.live_drag_write, "Live Drag").changed() {
                                                        cfg_dirty = true;
                                                    }
                                                });
                                            });

                                            ui.horizontal(|ui| {
                                                let mut val = staged;
                                                let sl = ui.add_enabled(
                                                    !ro_eff,
                                                    egui::Slider::new(&mut val, lo..=hi).step_by((w.step.abs()).max(1e-4)).max_decimals(4),
                                                );
                                                if sl.changed() {
                                                    self.staged_tuner.insert(w.id.clone(), val);
                                                    if w.live_drag_write {
                                                        card_writes.push((w.id.clone(), val));
                                                    }
                                                }
                                                if ui.add_enabled(!ro_eff, egui::Button::new("-Step")).clicked() {
                                                    let nv = (val - w.step).clamp(lo, hi);
                                                    self.staged_tuner.insert(w.id.clone(), nv);
                                                    card_writes.push((w.id.clone(), nv));
                                                }
                                                if ui.add_enabled(!ro_eff, egui::Button::new("+Step")).clicked() {
                                                    let nv = (val + w.step).clamp(lo, hi);
                                                    self.staged_tuner.insert(w.id.clone(), nv);
                                                    card_writes.push((w.id.clone(), nv));
                                                }
                                                let apply_btn = egui::Button::new(RichText::new("Apply").color(Color32::WHITE).strong()).fill(p.accent);
                                                if ui.add_enabled(!ro_eff, apply_btn).clicked() {
                                                    card_writes.push((w.id.clone(), val));
                                                }
                                            });
                                        });
                                    ui.add_space(4.0);
                                }
                            }
                        });

                        for (id, v) in card_writes {
                            self.controller.send(WorkerCmd::WriteSymbol { id, value: v });
                        }
                        if cfg_dirty {
                            self.sync_watch_list_to_worker();
                        }
                    });
            });

        // 6. Modals (Confirmations, DCSM Volatile Unlock, CCS 21 Diagnostics, Manual Address)
        self.render_modals(ctx);

        // Request smooth ~30 Hz UI redraw when connected/live or background jobs active
        if connected || !self.active_jobs.is_empty() {
            ctx.request_repaint_after(std::time::Duration::from_millis(33));
        }
    }
}

impl C2000StudioApp {
    fn render_modals(&mut self, ctx: &egui::Context) {
        let p = palette_for(self.theme_mode);

        // Confirmation dialog
        if let Some(action) = self.pending_confirm.clone() {
            let mut close = false;
            let mut proceed = false;
            let (title, body) = match &action {
                ConfirmAction::StopModeHalt => (
                    "Confirm Stop-Mode Halt",
                    "Stop-Mode halts the C28x CPU during memory access. On a live power stage / inverter this can stop PWM control and damage hardware! Continue?".to_string(),
                ),
                ConfirmAction::LoadAndRun { core, path } => (
                    "Confirm Flash Load & Run",
                    format!("Quiesce ALL masters (CPU1/CPU2/CLA/CM4), flash program '{}', and run {core}?", path.display()),
                ),
                ConfirmAction::MicroHaltDbgM { core } => (
                    "Confirm Micro-Halt ST1.DBGM Clear",
                    format!("Briefly halt {core} to clear ST1.DBGM and re-enter Polite Real-Time mode. Only safe if PWM trip / Free-Run is configured! Proceed?"),
                ),
                ConfirmAction::UnlockBitfieldRmw { symbol, .. } => (
                    "Confirm Bitfield Read-Modify-Write Unlock",
                    format!("Unlocking '{symbol}' performs host-side Read-Modify-Write over JTAG (NOT hardware-atomic against concurrent ISR writes to sibling bits). Proceed?"),
                ),
                ConfirmAction::ExpertStaleOverride => (
                    "Confirm Expert Stale-Image Override",
                    "The .out image on disk differs from Target Flash! Writing with mismatched addresses can corrupt live control RAM. Unlock writes anyway?".to_string(),
                ),
                ConfirmAction::BatchApply(diffs) => {
                    let list = diffs
                        .iter()
                        .map(|(_, sym, cur, nv)| format!("  • {sym}: {cur:.4}  ->  {nv:.4}"))
                        .collect::<Vec<_>>()
                        .join("\n");
                    ("Confirm Batch Apply", format!("Apply and readback-verify {} parameters:\n\n{list}", diffs.len()))
                }
                ConfirmAction::ResetXds110UsbOnly => (
                    "Confirm XDS110 USB Probe Reset",
                    "Run `xdsdfu -r` to reboot ONLY the XDS110 USB interface (does NOT assert target nRESET). Proceed?".to_string(),
                ),
            };

            egui::Window::new(title).collapsible(false).resizable(false).anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0]).show(ctx, |ui| {
                ui.label(body);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Cancel").clicked() {
                        close = true;
                    }
                    let ok_btn = egui::Button::new(RichText::new("Confirm").color(Color32::WHITE).strong()).fill(p.accent);
                    if ui.add(ok_btn).clicked() {
                        proceed = true;
                        close = true;
                    }
                });
            });

            if proceed {
                match action {
                    ConfirmAction::StopModeHalt => {
                        self.poll_config.realtime_mode = RealtimeAccessMode::StopModeHalt;
                        self.sync_poll_config_to_worker();
                    }
                    ConfirmAction::LoadAndRun { core, path } => {
                        self.controller.send(WorkerCmd::LoadProgram { core: core.clone(), path: path.clone() });
                        self.spawn_symbol_parse(core, path);
                    }
                    ConfirmAction::MicroHaltDbgM { core } => {
                        self.controller.send(WorkerCmd::MicroHaltDbgM(core));
                    }
                    ConfirmAction::UnlockBitfieldRmw { item_id, .. } => {
                        if let Some(w) = self.watch_items.iter_mut().find(|x| x.id == item_id) {
                            w.rmw_unlocked = true;
                            w.read_only = false;
                        }
                        self.sync_watch_list_to_worker();
                    }
                    ConfirmAction::ExpertStaleOverride => {
                        self.controller.send(WorkerCmd::InvalidateImage { locked: false, reason: String::new() });
                        self.log("warn", "Expert Override unlocked stale-image write lockout.");
                    }
                    ConfirmAction::BatchApply(diffs) => {
                        let pairs: Vec<(String, f64)> = diffs.into_iter().map(|(id, _, _, nv)| (id, nv)).collect();
                        self.controller.send(WorkerCmd::BatchWrite(pairs));
                    }
                    ConfirmAction::ResetXds110UsbOnly => {
                        let ser = self.selected_serial.clone();
                        let bg = Arc::clone(&self.bg_results);
                        let lbl = "Resetting XDS110 probe (USB only)...".to_string();
                        self.active_jobs.push(lbl.clone());
                        thread::spawn(move || {
                            let (ok, output) = reset_xds110_probe_only(&ser);
                            bg.lock().unwrap().push_back(BackgroundJobResult {
                                label: lbl,
                                payload: BgPayload::XdsReset { ok, output },
                            });
                        });
                    }
                }
            }
            if close {
                self.pending_confirm = None;
            }
        }

        // CCS 21 Diagnostics modal
        if self.show_ccs_diag_modal {
            let mut open = self.show_ccs_diag_modal;
            egui::Window::new("TI CCS 21 Environment & Native Rust CloudAgent Diagnostics")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    egui::Grid::new("ccs_diag_grid").striped(true).spacing([12.0, 4.0]).show(ui, |ui| {
                        for (k, v) in self.ccs_env.diagnostic_lines() {
                            ui.label(RichText::new(k).strong());
                            ui.label(RichText::new(v).monospace().size(11.0));
                            ui.end_row();
                        }
                    });
                });
            self.show_ccs_diag_modal = open;
        }

        // DCSM Volatile RAM Unlock modal
        if self.show_dcsm_modal {
            let mut open = self.show_dcsm_modal;
            let mut close_now = false;
            egui::Window::new("Unlock DCSM (Volatile RAM Keys Only — Never Writes OTP)")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Zone:");
                        ui.selectable_value(&mut self.dcsm_zone, 1, "Zone 1");
                        ui.selectable_value(&mut self.dcsm_zone, 2, "Zone 2");
                    });
                    for i in 0..4 {
                        ui.horizontal(|ui| {
                            ui.label(format!("KEY{i} (hex):"));
                            ui.text_edit_singleline(&mut self.dcsm_keys_hex[i]);
                        });
                    }
                    if ui.button("Unlock Volatile RAM").clicked() {
                        let parsed: Result<Vec<u32>, _> = self
                            .dcsm_keys_hex
                            .iter()
                            .map(|h| u32::from_str_radix(h.trim().trim_start_matches("0x"), 16))
                            .collect();
                        match parsed {
                            Ok(keys) => {
                                let core = get_device_profile(self.device_id).primary_core().name.to_string();
                                self.controller.send(WorkerCmd::UnlockDcsm { core, zone: self.dcsm_zone, keys });
                                close_now = true;
                            }
                            Err(_) => self.push_problem("error", "DCSM", "Invalid 32-bit hex key."),
                        }
                    }
                });
            self.show_dcsm_modal = open && !close_now;
        }

        // Manual Address Entry modal
        if self.show_manual_addr_modal {
            let mut open = self.show_manual_addr_modal;
            let mut close_now = false;
            egui::Window::new("Add Manual Safe-RAM Address")
                .open(&mut open)
                .collapsible(false)
                .show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.label("Name:");
                        ui.text_edit_singleline(&mut self.manual_name);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Address (hex):");
                        ui.text_edit_singleline(&mut self.manual_addr_hex);
                    });
                    ui.horizontal(|ui| {
                        ui.label("Type:");
                        egui::ComboBox::from_id_source("man_dt_cb").selected_text(self.manual_dtype.label()).show_ui(ui, |ui| {
                            for dt in DataType::ALL {
                                ui.selectable_value(&mut self.manual_dtype, dt, dt.label());
                            }
                        });
                    });
                    if ui.button("Add to Watch").clicked() {
                        if let Ok(addr) = u32::from_str_radix(self.manual_addr_hex.trim().trim_start_matches("0x"), 16) {
                            let prof = get_device_profile(self.device_id);
                            let cp = prof.find_core(&self.selected_sym_core).unwrap_or_else(|| prof.primary_core());
                            let node = SymbolNode {
                                name: self.manual_name.clone(),
                                full_path: self.manual_name.clone(),
                                core: cp.name.into(),
                                address: addr,
                                page: cp.default_page.into(),
                                data_type: self.manual_dtype,
                                word_size: self.manual_dtype.unit_count(cp.address_unit_bits),
                                type_name: self.manual_dtype.label().into(),
                                bit_offset: None,
                                bit_width: None,
                                container_units: None,
                                is_struct: false,
                                is_array: false,
                                array_len: 0,
                                is_pointer: false,
                                is_function: false,
                                section_name: ".manual".into(),
                                domain: PhysicalMemoryDomain::Unknown,
                                tu_scope: String::new(),
                                is_scratchpad: false,
                                children: Vec::new(),
                            };
                            self.add_symbol_to_watch(&node, 1, false);
                            close_now = true;
                        }
                    }
                });
            self.show_manual_addr_modal = open && !close_now;
        }
    }
}

fn symbol_matches_filter(node: &SymbolNode, filter_lc: &str) -> bool {
    if filter_lc.is_empty() {
        return true;
    }
    if node.full_path.to_ascii_lowercase().contains(filter_lc)
        || node.type_name.to_ascii_lowercase().contains(filter_lc)
    {
        return true;
    }
    node.children.iter().any(|c| symbol_matches_filter(c, filter_lc))
}

fn flatten_syms<'a>(nodes: &'a [SymbolNode], out: &mut BTreeMap<String, &'a SymbolNode>) {
    for n in nodes {
        out.insert(n.full_path.clone(), n);
        if !n.children.is_empty() {
            flatten_syms(&n.children, out);
        }
    }
}

fn now_hms() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}
