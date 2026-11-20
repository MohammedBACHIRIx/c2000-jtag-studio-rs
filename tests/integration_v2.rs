//! Comprehensive v2 verification suite for C2000 JTAG Studio (Native Rust Edition).
//! Exercises hardware safety firewalls, codecs, coalescer, MemCfg, worker fault injection,
//! real TI cl2000/ofd2000/dbgjtag, live TI CCS 21 CloudAgent WebSocket RPC, FFT, CSV, and PNG export.

use std::collections::{BTreeMap, HashSet};
use std::f64::consts::TAU;
use std::fs;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use c2000_jtag_studio::backend::aux_uart::{decode_aux_frame, encode_aux_frame, verify_aux_uart_allowed};
use c2000_jtag_studio::backend::ccs21::Ccs21Backend;
use c2000_jtag_studio::backend::ccs_env::discover_ccs_environment;
use c2000_jtag_studio::backend::ccxml::{generate_ccxml, generate_uscif_dat, sanitize_custom_ccxml_strip_gel};
use c2000_jtag_studio::backend::probe::{parse_xds100serial_output, parse_xdsdfu_output};
use c2000_jtag_studio::backend::sim::SimulatedBackend;
use c2000_jtag_studio::backend::worker::{perform_guarded_write, SessionController, WorkerCmd, WorkerEvent};
use c2000_jtag_studio::backend::DebugBackend;
use c2000_jtag_studio::core::coalescer::{build_read_plan, validate_write_target, SlowSpanScheduler};
use c2000_jtag_studio::core::codec::{
    clamp_value, decode_raw_scalar, encode_scalar_units, engineering_to_raw, parse_numeric_input,
    raw_to_engineering, RawScalar,
};
use c2000_jtag_studio::core::devices::{get_device_profile, validate_device_profile_disjointness};
use c2000_jtag_studio::core::models::{
    ConnectionRequest, CoreState, DataType, DeviceId, DisplayFormat, FlashFingerprint, JtagMode,
    MemCfgSnapshot, PhysicalMemoryDomain, PollConfig, ProbeKind, RealtimeAccessMode, SessionState,
    ThemeMode, WatchItem, WriteState,
};
use c2000_jtag_studio::core::ring_buffer::ChannelRingBuffer;
use c2000_jtag_studio::core::workspace::{WorkspaceProfile, WorkspaceStore};
use c2000_jtag_studio::symbols::cache::{load_cached_symbols, save_cached_symbols, ParsedSymbolTable, CACHE_SCHEMA_VERSION};
use c2000_jtag_studio::symbols::parser::{
    extract_flash_fingerprint, load_symbols_for_file, parse_ofd_xml_stream,
    resolve_watch_items_from_table,
};
use c2000_jtag_studio::ui::scope::{align_bounded_zoh, compute_nan_safe_spectrum, export_scope_csv, render_scope_png};
use c2000_jtag_studio::ui::theme::trace_color_for;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

fn mk_item(id: &str, core: &str, path: &str, addr: u32, dtype: DataType) -> WatchItem {
    WatchItem {
        id: id.into(),
        core: core.into(),
        symbol_path: path.into(),
        address: addr,
        page: if core == "Cortex_M4_0" { "".into() } else { "DATA".into() },
        data_type: dtype,
        display_format: if dtype.is_float() { DisplayFormat::Float } else { DisplayFormat::Dec },
        iq_q_bits: 24,
        bit_offset: None,
        bit_width: None,
        container_units: None,
        rate_divider: 1,
        plot_pane: 1,
        color_index: 0,
        line_style: "solid".into(),
        pinned_tuner: true,
        min_val: None,
        max_val: None,
        step: 0.1,
        read_only: false,
        rmw_unlocked: false,
        live_drag_write: false,
        section_name: ".bss".into(),
        domain: PhysicalMemoryDomain::Unknown,
        tu_scope: String::new(),
        is_atomic: true,
        user_setpoint: None,
        write_state: WriteState::Idle,
        last_write_error: String::new(),
    }
}

#[test]
fn test_device_disjointness_and_silicon_deny_matrix() {
    for dev in [DeviceId::F28069M, DeviceId::F28388D] {
        let prof = get_device_profile(dev);
        assert!(validate_device_profile_disjointness(&prof).is_ok());
    }

    let p388 = get_device_profile(DeviceId::F28388D);
    // 1. EtherCAT ESC MMIO on CPU1 (0x50000) & CM4 (0x400A0000) MUST BE DENIED
    let esc_cpu1 = mk_item("esc1", "C28xx_CPU1", "esc_reg", 0x050000, DataType::Uint16);
    assert!(!validate_write_target(&esc_cpu1, &p388, None, None, None).allowed);

    let esc_cm4 = mk_item("esc2", "Cortex_M4_0", "cm_esc", 0x400A0000, DataType::Uint32);
    assert!(!validate_write_target(&esc_cm4, &p388, None, None, None).allowed);

    // 2. DCSM OTP (0x078000) & Flash (0x080000) MUST BE DENIED
    let otp = mk_item("otp", "C28xx_CPU1", "dcsm_otp", 0x078000, DataType::Uint32);
    assert!(!validate_write_target(&otp, &p388, None, None, None).allowed);

    let fls = mk_item("fls", "C28xx_CPU1", "flash_const", 0x080000, DataType::Uint32);
    assert!(!validate_write_target(&fls, &p388, None, None, None).allowed);

    // 3. Directional MSGRAM: CPU1->CLA1 (0x001500) writable by CPU1, CLA1->CPU1 (0x001480) RO for CPU1
    let msg_c2cla = mk_item("m1", "C28xx_CPU1", "cpu_to_cla", 0x001500, DataType::Float32);
    assert!(validate_write_target(&msg_c2cla, &p388, None, None, None).allowed);

    let msg_cla2c = mk_item("m2", "C28xx_CPU1", "cla_to_cpu", 0x001480, DataType::Float32);
    assert!(!validate_write_target(&msg_cla2c, &p388, None, None, None).allowed);

    // 4. Live MemCfg LSxCLAPGM & GSxMSEL enforcement
    let mut mc = MemCfgSnapshot {
        probed: true,
        ls_msel: 0b01,    // LS0 CLA-owned
        ls_clapgm: 0b1,   // LS0 is CLA program memory -> DENY writes!
        gs_msel: 0b10,    // GS1 owned by CPU2!
        dcsm_z1_locked: false,
        dcsm_z2_locked: false,
    };
    let ls0_item = mk_item("ls0", "C28xx_CPU1", "ls0_var", 0x008000, DataType::Float32);
    assert!(!validate_write_target(&ls0_item, &p388, None, Some(&mc), None).allowed);

    // GS1 is 0x00E000..0x00EFFF (GS0 is 0x00D000). With gs_msel=0b10 (GS1 owned by CPU2):
    // - If only CPU1 is connected (CPU2 detached), writing GS1 MUST be denied!
    // - If both CPU1 and CPU2 are connected, write_core redirects transparently to C28xx_CPU2!
    let cpu1_only: HashSet<String> = ["C28xx_CPU1".to_string()].into_iter().collect();
    let both_cpus: HashSet<String> = ["C28xx_CPU1".to_string(), "C28xx_CPU2".to_string()].into_iter().collect();
    let gs1_cpu1 = mk_item("gs1", "C28xx_CPU1", "gs1_var", 0x00E000, DataType::Float32);
    assert!(!validate_write_target(&gs1_cpu1, &p388, None, Some(&mc), Some(&cpu1_only)).allowed);
    let redir = validate_write_target(&gs1_cpu1, &p388, None, Some(&mc), Some(&both_cpus));
    assert!(redir.allowed && redir.write_core == "C28xx_CPU2");
    let gs1_cpu2 = mk_item("gs1b", "C28xx_CPU2", "gs1_var", 0x00E000, DataType::Float32);
    assert!(validate_write_target(&gs1_cpu2, &p388, None, Some(&mc), Some(&both_cpus)).allowed);

    mc.ls_clapgm = 0;
    assert!(validate_write_target(&ls0_item, &p388, None, Some(&mc), None).allowed);

    // 5. .scratchpad section MUST be rejected
    let mut scratch = mk_item("sc", "C28xx_CPU1", "cla_tmp", 0x00C000, DataType::Float32);
    scratch.section_name = ".scratchpad".into();
    assert!(!validate_write_target(&scratch, &p388, None, None, None).allowed);
}

#[test]
fn test_codec_packed_bitfields_iq_and_clamp() {
    // C28x 16-bit MAU float32 roundtrip
    let units = encode_scalar_units(12.345, DataType::Float32, 16, Some(32), None, None, None, None).unwrap();
    assert_eq!(units.len(), 1);
    let dec = decode_raw_scalar(&units, DataType::Float32, 16, Some(32), None, None, None);
    assert!((dec.as_f64() - 12.345).abs() < 1e-4);

    // Packed ARM 32-bit container bitfield RMW (4 bytes, bit_offset=10, bit_width=5)
    let exist_bytes = vec![0xFF, 0x00, 0xAA, 0x55];
    let patched = encode_scalar_units(
        21.0,
        DataType::Uint32,
        8,
        Some(8),
        Some(&exist_bytes),
        Some(10),
        Some(5),
        Some(4),
    )
    .unwrap();
    assert_eq!(patched.len(), 4);
    let extracted = decode_raw_scalar(&patched, DataType::Uint32, 8, Some(8), Some(10), Some(5), Some(4));
    assert_eq!(extracted, RawScalar::Uint(21));
    // Unrelated bytes remain untouched
    assert_eq!(patched[0], 0xFF);
    assert_eq!(patched[2], 0xAA);
    assert_eq!(patched[3], 0x55);

    // IQ24 conversion
    let raw_iq = engineering_to_raw(1.5, DataType::Int32, DisplayFormat::Iq, 24);
    let eng = raw_to_engineering(RawScalar::Int(raw_iq as i64), DisplayFormat::Iq, 24);
    assert!((eng - 1.5).abs() < 1e-6);

    // Clamp & NaN rejection
    assert!(clamp_value(f64::NAN, Some(0.0), Some(10.0)).is_err());
    assert_eq!(clamp_value(15.0, Some(0.0), Some(10.0)).unwrap(), (10.0, true));
    assert_eq!(parse_numeric_input("0x1A").unwrap(), 26.0);
    assert_eq!(parse_numeric_input("0b1010").unwrap(), 10.0);
}

#[test]
fn test_coalescer_anti_tearing_cla_proxy_and_slow_scheduler() {
    let p388 = get_device_profile(DeviceId::F28388D);
    let mut items = vec![
        mk_item("c1", "C28xx_CPU1", "a_f32", 0x00C000, DataType::Float32), // aligned 32-bit
        mk_item("c2", "C28xx_CPU1", "b_u16", 0x00C002, DataType::Uint16),  // mixed 16+32 in same span
        mk_item("c3", "CPU1_CLA1", "cla_shared", 0x008000, DataType::Float32), // proxied via C28xx_CPU1
        mk_item("c4", "Cortex_M4_0", "cm_u32", 0x20000000, DataType::Uint32),  // aligned 32-bit AHB-AP
    ];
    let mut slow5 = mk_item("s5", "C28xx_CPU1", "slow5", 0x00C040, DataType::Uint16);
    slow5.rate_divider = 5;
    let mut slow20 = mk_item("s20", "C28xx_CPU1", "slow20", 0x00C080, DataType::Uint16);
    slow20.rate_divider = 20;
    items.push(slow5);
    items.push(slow20);

    let plan = build_read_plan(&mut items, &p388, 32, 256, None, None, None);
    assert!(plan.fast_spans.iter().any(|sp| sp.read_core == "C28xx_CPU1" && sp.bit_size == 32));
    assert!(plan.fast_spans.iter().any(|sp| sp.read_core == "Cortex_M4_0" && sp.bit_size == 32));
    assert!(plan.fast_spans.iter().any(|sp| sp.read_core == "C28xx_CPU1" && sp.start_addr == 0x008000));

    // Verify SlowSpanScheduler visits BOTH slow_5 and slow_20 without starving slow_20!
    let mut sched = SlowSpanScheduler::default();
    let mut hit5 = 0usize;
    let mut hit20 = 0usize;
    for cyc in 0..40u64 {
        for sp in sched.next_slow_spans(&plan.slow_5_spans, &plan.slow_20_spans, cyc) {
            if sp.start_addr == 0x00C040 {
                hit5 += 1;
            } else if sp.start_addr == 0x00C080 {
                hit20 += 1;
            }
        }
    }
    assert!(hit5 > 0 && hit20 > 0);
}

/// Fault-injecting wrapper around SimulatedBackend that corrupts readback values to verify Gate-5 catches silent write failure!
struct CorruptReadbackBackend {
    inner: SimulatedBackend,
    corrupt_addr: u32,
}

impl DebugBackend for CorruptReadbackBackend {
    fn connect(&mut self, req: &ConnectionRequest) -> Result<BTreeMap<String, CoreState>, String> {
        self.inner.connect(req)
    }
    fn disconnect(&mut self) {
        self.inner.disconnect();
    }
    fn connect_core(&mut self, core: &str, attach_live: bool) -> Result<CoreState, String> {
        self.inner.connect_core(core, attach_live)
    }
    fn disconnect_core(&mut self, core: &str) -> Result<CoreState, String> {
        self.inner.disconnect_core(core)
    }
    fn load_program(&mut self, core: &str, path: &Path) -> Result<CoreState, String> {
        self.inner.load_program(core, path)
    }
    fn load_symbols(&mut self, core: &str, path: &Path) -> Result<(), String> {
        self.inner.load_symbols(core, path)
    }
    fn run_core(&mut self, core: &str) -> Result<CoreState, String> {
        self.inner.run_core(core)
    }
    fn halt_core(&mut self, core: &str) -> Result<CoreState, String> {
        self.inner.halt_core(core)
    }
    fn reset_core(&mut self, core: &str) -> Result<CoreState, String> {
        self.inner.reset_core(core)
    }
    fn set_realtime_mode(&mut self, core: &str, mode: RealtimeAccessMode) -> Result<CoreState, String> {
        self.inner.set_realtime_mode(core, mode)
    }
    fn micro_halt_clear_dbgm(&mut self, core: &str) -> Result<CoreState, String> {
        self.inner.micro_halt_clear_dbgm(core)
    }
    fn read_block(&mut self, core: &str, address: u32, count: u32, bit_size: u32, page: &str) -> Result<Vec<u32>, String> {
        let mut v = self.inner.read_block(core, address, count, bit_size, page)?;
        if address == self.corrupt_addr && !v.is_empty() {
            v[0] ^= 0x00FF;
        }
        Ok(v)
    }
    fn write_block(&mut self, core: &str, address: u32, values: &[u32], bit_size: u32, page: &str) -> Result<(), String> {
        self.inner.write_block(core, address, values, bit_size, page)
    }
    fn get_core_states(&self) -> BTreeMap<String, CoreState> {
        self.inner.get_core_states()
    }
}

#[test]
fn test_fault_injected_readback_mismatch_and_worker_preempt_safe_revert() {
    // 1. Direct Gate-5 fault injection
    let mut fault_be = CorruptReadbackBackend {
        inner: SimulatedBackend::new(),
        corrupt_addr: 0x008002,
    };
    let req = ConnectionRequest {
        device_id: DeviceId::F28069M,
        probe_kind: ProbeKind::SIMULATOR,
        serial: String::new(),
        tclk_hz: "Virtual".into(),
        jtag_mode: JtagMode::Jtag4Pin,
        attach_live: true,
        realtime_mode: RealtimeAccessMode::SiliconRtPolite,
        custom_ccxml_path: String::new(),
        program_paths: BTreeMap::new(),
    };
    fault_be.connect(&req).unwrap();
    let vref = mk_item("vref", "C28xx_0", "gBuck.v_ref", 0x008002, DataType::Float32);
    let conn: HashSet<String> = ["C28xx_0".to_string()].into_iter().collect();
    let res = perform_guarded_write(
        &mut fault_be,
        DeviceId::F28069M,
        &vref,
        18.0,
        false,
        "",
        true,
        &BTreeMap::new(),
        &MemCfgSnapshot::default(),
        &conn,
    );
    assert!(res.is_err());
    assert!(res.unwrap_err().contains("Readback MISMATCH"));

    // 2. Worker session: live sim polling, Flash fingerprint lockout, and PREEMPT_SAFE_REVERT purge!
    let mut ctrl = SessionController::new(2048);
    ctrl.send(WorkerCmd::SetPollConfig(PollConfig::default()));
    ctrl.send(WorkerCmd::SetWatchList(vec![vref.clone()]));
    ctrl.send(WorkerCmd::Connect(req));
    thread::sleep(Duration::from_millis(120));

    // Verify stale Flash fingerprint locks out writes
    let bad_fp = FlashFingerprint {
        address: 0x3F0000,
        page: "PROGRAM".into(),
        words: vec![0xDEAD; 16],
        address_unit_bits: 16,
    };
    ctrl.send(WorkerCmd::VerifyFlashFingerprint { core: "C28xx_0".into(), fp: bad_fp });
    thread::sleep(Duration::from_millis(80));
    {
        let st = ctrl.shared();
        let g = st.lock().unwrap();
        assert!(g.stale_image_locked);
        assert_eq!(g.fsm_state, SessionState::WriteLockedStaleImage);
    }

    // Unlock via valid fingerprint (F28069M sim seeds 0xA500..0xA50F at 0x3F0000)
    let good_fp = FlashFingerprint {
        address: 0x3F0000,
        page: "PROGRAM".into(),
        words: (0..16u32).map(|i| 0xA500 + i).collect(),
        address_unit_bits: 16,
    };
    ctrl.send(WorkerCmd::VerifyFlashFingerprint { core: "C28xx_0".into(), fp: good_fp });
    thread::sleep(Duration::from_millis(80));

    // Queue a dangerous normal write followed immediately by PREEMPT_SAFE_REVERT -> dangerous write MUST be purged!
    ctrl.send(WorkerCmd::WriteSymbol { id: "vref".into(), value: 35.0 });
    ctrl.send(WorkerCmd::PreemptSafeRevert(vec![("vref".into(), 12.0)]));
    thread::sleep(Duration::from_millis(120));

    let events: Vec<WorkerEvent> = {
        let st = ctrl.shared();
        let mut g = st.lock().unwrap();
        g.events.drain(..).collect()
    };
    let saw_safe_ok = events.iter().any(|e| matches!(e, WorkerEvent::SafeRevertResult { all_verified: true, .. }));
    let saw_35 = events.iter().any(|e| matches!(e, WorkerEvent::WriteResult { value: Some(v), .. } if (*v - 35.0).abs() < 0.01));
    assert!(saw_safe_ok, "Expected verified SafeRevertResult");
    assert!(!saw_35, "Queued normal write 35.0 should have been purged by PREEMPT_SAFE_REVERT!");

    ctrl.shutdown();
}

#[test]
fn test_ccxml_gel_stripping_probe_parsers_and_aux_uart() {
    let tmp = std::env::temp_dir().join("c2000_rs_test_ccxml");
    let _ = fs::create_dir_all(&tmp);
    let raw = tmp.join("dirty.ccxml");
    let clean = tmp.join("clean.ccxml");
    fs::write(
        &raw,
        r#"<configurations><property Type="stringfield" Value="../../gel/f28388d.gel" id="GEL File"/></configurations>"#,
    )
    .unwrap();
    sanitize_custom_ccxml_strip_gel(&raw, &clean).unwrap();
    let txt = fs::read_to_string(&clean).unwrap();
    assert!(txt.contains(r#"Value="""#));
    assert!(!txt.contains("f28388d.gel"));

    let gen = tmp.join("gen.ccxml");
    generate_ccxml(&gen, DeviceId::F28069M, ProbeKind::XDS110, "5.5MHz", JtagMode::Cjtag2PinOscan2, "XDS110_01", true).unwrap();
    let gtxt = fs::read_to_string(&gen).unwrap();
    assert!(gtxt.contains("XDS110_01") && gtxt.contains("5.5MHz"));

    let dfu = "<<<< Device 0 >>>>\nSerial Num:   L1100A1B\nVersion:      3.0.0.28\n";
    let p1 = parse_xdsdfu_output(dfu);
    assert_eq!(p1.len(), 1);
    assert_eq!(p1[0].serial, "L1100A1B");

    let x100 = "XDS100v2   VID=0x0403 PID=0xA6D0   TI89ABCD\n";
    let p2 = parse_xds100serial_output(x100);
    assert_eq!(p2.len(), 1);
    assert_eq!(p2[0].serial, "TI89ABCD");

    // Aux UART codec + capability & JTAG mutual exclusion guard
    assert!(verify_aux_uart_allowed(ProbeKind::XDS110, false).is_ok());
    assert!(verify_aux_uart_allowed(ProbeKind::XDS110, true).is_err());
    assert!(verify_aux_uart_allowed(ProbeKind::XDS100V2, false).is_err());
    let frame = encode_aux_frame(77, 125_000, &[12.0, -3.5]);
    let decoded = decode_aux_frame(&frame).unwrap();
    assert_eq!(decoded.seq, 77);
    assert_eq!(decoded.values.len(), 2);
    assert!((decoded.values[0] - 12.0).abs() < 1e-5);
}

#[test]
fn test_dwarf_v2_cache_lru_and_workspace_corrupt_quarantine() {
    // Synthetic DWARF XML testing DW_TAG_TI_far_type, C++ inheritance/namespace, TU statics, and .scratchpad exclusion
    let xml = r#"<?xml version="1.0"?>
<ofd><object_file>
  <ti_coff><file_header><target_id>0x9d</target_id></file_header></ti_coff>
  <section><name>.ebss</name><physical_addr>0x8000</physical_addr><raw_data_size>0x100</raw_data_size><initialized>false</initialized><bss>true</bss></section>
  <section><name>.scratchpad</name><physical_addr>0x9000</physical_addr><raw_data_size>0x40</raw_data_size><initialized>false</initialized><bss>true</bss></section>
  <dwarf><section name=".debug_info">
    <compile_unit>
      <die id="0x1" tag="DW_TAG_compile_unit">
        <attribute><type>DW_AT_name</type><value><string>ctrl.cpp</string></value></attribute>
        <die id="0x10" tag="DW_TAG_base_type">
          <attribute><type>DW_AT_name</type><value><string>float</string></value></attribute>
          <attribute><type>DW_AT_byte_size</type><value><constant>2</constant></value></attribute>
          <attribute><type>DW_AT_encoding</type><value><constant>4</constant></value></attribute>
        </die>
        <die id="0x11" tag="DW_TAG_TI_far_type">
          <attribute><type>DW_AT_type</type><value><ref idref="0x10"/></value></attribute>
        </die>
        <die id="0x20" tag="DW_TAG_class_type">
          <attribute><type>DW_AT_name</type><value><string>BaseCtrl</string></value></attribute>
          <attribute><type>DW_AT_byte_size</type><value><constant>2</constant></value></attribute>
          <die id="0x21" tag="DW_TAG_member">
            <attribute><type>DW_AT_name</type><value><string>kp</string></value></attribute>
            <attribute><type>DW_AT_type</type><value><ref idref="0x11"/></value></attribute>
            <attribute><type>DW_AT_data_member_location</type><value><block>DW_OP_plus_uconst 0</block></value></attribute>
          </die>
        </die>
        <die id="0x30" tag="DW_TAG_class_type">
          <attribute><type>DW_AT_name</type><value><string>DerivedCtrl</string></value></attribute>
          <attribute><type>DW_AT_byte_size</type><value><constant>4</constant></value></attribute>
          <die id="0x31" tag="DW_TAG_inheritance">
            <attribute><type>DW_AT_type</type><value><ref idref="0x20"/></value></attribute>
            <attribute><type>DW_AT_data_member_location</type><value><block>DW_OP_plus_uconst 0</block></value></attribute>
          </die>
          <die id="0x32" tag="DW_TAG_member">
            <attribute><type>DW_AT_name</type><value><string>ki</string></value></attribute>
            <attribute><type>DW_AT_type</type><value><ref idref="0x10"/></value></attribute>
            <attribute><type>DW_AT_data_member_location</type><value><block>DW_OP_plus_uconst 2</block></value></attribute>
          </die>
        </die>
        <die id="0x40" tag="DW_TAG_namespace">
          <attribute><type>DW_AT_name</type><value><string>Power</string></value></attribute>
          <die id="0x41" tag="DW_TAG_variable">
            <attribute><type>DW_AT_name</type><value><string>gLoop</string></value></attribute>
            <attribute><type>DW_AT_type</type><value><ref idref="0x30"/></value></attribute>
            <attribute><type>DW_AT_location</type><value><block>DW_OP_addr 0x8010</block></value></attribute>
          </die>
        </die>
        <die id="0x50" tag="DW_TAG_variable">
          <attribute><type>DW_AT_name</type><value><string>gScratchVar</string></value></attribute>
          <attribute><type>DW_AT_type</type><value><ref idref="0x10"/></value></attribute>
          <attribute><type>DW_AT_location</type><value><block>DW_OP_addr 0x9004</block></value></attribute>
        </die>
      </die>
    </compile_unit>
  </section></dwarf>
</object_file></ofd>"#;

    let tbl = parse_ofd_xml_stream(xml.as_bytes(), "C28xx_0", "DATA", 16, "test.out").unwrap();
    // .scratchpad variable excluded!
    assert!(!tbl.symbols.iter().any(|s| s.name == "gScratchVar"));
    let gloop = tbl.symbols.iter().find(|s| s.full_path == "Power::gLoop").expect("Power::gLoop parsed");
    assert_eq!(gloop.address, 0x8010);
    assert!(gloop.children.iter().any(|c| c.name == "kp" && c.address == 0x8010 && c.data_type == DataType::Float32));
    assert!(gloop.children.iter().any(|c| c.name == "ki" && c.address == 0x8012 && c.data_type == DataType::Float32));

    // Re-resolution moves existing WatchItem & quarantines missing ones RO
    let watch = vec![
        mk_item("w1", "C28xx_0", "Power::gLoop.ki", 0x8002, DataType::Float32),
        mk_item("w2", "C28xx_0", "gDeleted", 0x8020, DataType::Float32),
    ];
    let (resolved, moved, quar) = resolve_watch_items_from_table(&watch, &tbl);
    assert_eq!(resolved[0].address, 0x8012);
    assert_eq!(moved.len(), 1);
    assert!(resolved[1].read_only && resolved[1].write_state == WriteState::Quarantined);
    assert_eq!(quar.len(), 1);

    // Zlib cache roundtrip + LRU cap
    let tmp = std::env::temp_dir().join("c2000_rs_test_cache");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();
    let dummy_out = tmp.join("fw.out");
    fs::write(&dummy_out, b"ELF_DUMMY_PAYLOAD_12345").unwrap();
    let cache_tbl = ParsedSymbolTable {
        schema_version: CACHE_SCHEMA_VERSION.into(),
        ..tbl
    };
    save_cached_symbols(&cache_tbl, &dummy_out, "C28xx_0", Some(&tmp), 1024 * 1024, 4);
    let loaded = load_cached_symbols(&dummy_out, "C28xx_0", Some(&tmp)).expect("cache hit");
    assert_eq!(loaded.symbols.len(), cache_tbl.symbols.len());

    // Workspace v1->v2 migration + corrupt quarantine
    let ws_dir = tmp.join("ws");
    let store = WorkspaceStore::new(Some(ws_dir.clone()));
    let prof = WorkspaceProfile {
        schema_version: 1,
        profile_key: "TEST_KEY".into(),
        device_id: DeviceId::F28069M,
        probe_kind: ProbeKind::SIMULATOR,
        probe_serial: String::new(),
        tclk_hz: "Virtual".into(),
        jtag_mode: JtagMode::Jtag4Pin,
        custom_ccxml_path: String::new(),
        program_paths: BTreeMap::new(),
        poll_config: PollConfig::default(),
        watch_items: Vec::new(),
        tuning_presets: BTreeMap::new(),
        safe_baseline: BTreeMap::new(),
        plot_panes: 2,
        plot_window_sec: Some(10.0),
        theme_mode: ThemeMode::ClassicEclipseLight,
        ui_scale_pct: 100,
        perspective_name: "tune".into(),
    };
    let saved = store.save(&prof, None).unwrap();
    let loaded_ws = store.load(&saved).unwrap();
    assert_eq!(loaded_ws.schema_version, 2);

    let corrupt_path = ws_dir.join("broken.json");
    fs::write(&corrupt_path, "{ invalid json !!!").unwrap();
    assert!(store.load(&corrupt_path).is_none());
    assert!(PathBuf::from(format!("{}.corrupt.bak", corrupt_path.display())).is_file());
}

#[test]
fn test_ring_buffer_nan_safe_fft_bounded_zoh_csv_and_png_export() {
    let mut rb = ChannelRingBuffer::new(2048);
    let fs_hz = 200.0;
    for i in 0..512 {
        let t = (i as f64) / fs_hz;
        let v = if i == 100 {
            f64::NAN // Inject NaN disconnect gap!
        } else {
            10.0 + 2.0 * (TAU * 25.0 * t).sin() + 0.1 * (TAU * 75.0 * t).sin()
        };
        rb.append(t, v);
    }
    let (dt, dv, st) = rb.decimated_window(None, 128);
    assert!(dt.len() <= 160 && dv.iter().any(|x| x.is_nan()));
    let s = st.unwrap();
    assert!(s.pkpk > 3.5);

    // NaN-safe FFT should pick longest contiguous finite segment (samples 101..512 -> 256-pt FFT) and detect 25 Hz peak!
    let (ts, vs) = rb.view_all();
    let fft = compute_nan_safe_spectrum(ts, vs).expect("valid FFT");
    assert!((fft.peak_hz - 25.0).abs() < 1.5, "got peak_hz={}", fft.peak_hz);
    assert!(fft.thd_pct > 2.0 && fft.thd_pct < 12.0, "got thd={}", fft.thd_pct);

    // Bounded ZOH CSV emits NaN when staleness exceeds max_stale_s
    let t_fast = vec![0.0, 0.1, 0.2, 1.0];
    let v_fast = vec![1.0, 2.0, 3.0, 4.0];
    let t_slow = vec![0.0];
    let v_slow = vec![42.0];
    let (mt, cols) = align_bounded_zoh(&[("fast", &t_fast, &v_fast), ("slow", &t_slow, &v_slow)], 0.25);
    assert_eq!(mt.len(), 4);
    assert!((cols[1].1[2] - 42.0).abs() < 1e-6); // age 0.2 <= 0.25 -> held
    assert!(cols[1].1[3].is_nan());             // age 1.0 > 0.25 -> NaN!

    let tmp = std::env::temp_dir().join("c2000_rs_test_export");
    let _ = fs::create_dir_all(&tmp);
    let csv_p = tmp.join("out.csv");
    let rows = export_scope_csv(&csv_p, &[("fast", &t_fast, &v_fast), ("slow", &t_slow, &v_slow)], 0.25).unwrap();
    assert_eq!(rows, 4);
    let png_p = tmp.join("scope_light.png");
    render_scope_png(
        &png_p,
        800,
        400,
        ThemeMode::ClassicEclipseLight,
        &[("gBuck.v_out", trace_color_for(0, ThemeMode::ClassicEclipseLight), ts, vs)],
    )
    .unwrap();
    assert!(fs::metadata(&png_p).unwrap().len() > 1024);
}

#[test]
fn test_real_ti_cl2000_ofd2000_agent_header_and_ccs21_cloudagent_ws_rpc() {
    let env = discover_ccs_environment(None);
    if !env.cloudagent_available() {
        eprintln!("Skipping live CCS 21 hardware toolchain test (CCS 21 not installed).");
        return;
    }

    // 1. Real TI CCS 21 Native Rust WebSocket JSON-RPC handshake (zero Python!)
    let mut ccs = Ccs21Backend::new(None);
    let port = ccs.launch_cloudagent_and_ds().expect("TI CloudAgent WS-RPC launch");
    assert!(port > 0);
    let ver = ccs.version_info().expect("DS scripting.versionInfo over pure-Rust WS-RPC");
    eprintln!("[LIVE CCS 21 WS-RPC] port={port} versionInfo={ver}");
    ccs.shutdown();

    // 2. Real TI cl2000 + ofd2000 roundtrip + c2000_studio_agent.h compilation (EABI & COFF) + Flash Fingerprint
    let (Some(cl2000), Some(_ofd2000)) = (&env.cl2000_exe, &env.ofd2000_exe) else {
        return;
    };
    let inc_dir = cl2000.parent().unwrap().parent().unwrap().join("include");
    let lib_dir = cl2000.parent().unwrap().parent().unwrap().join("lib");
    let fw_inc = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("firmware");
    let tmp = std::env::temp_dir().join("c2000_rs_ti_toolchain");
    let _ = fs::remove_dir_all(&tmp);
    fs::create_dir_all(&tmp).unwrap();

    let src = tmp.join("bench_fw.c");
    fs::write(
        &src,
        r#"
#include "c2000_studio_agent.h"
typedef struct { float v_ref; float v_out; uint16_t flags; } Buck_t;
volatile Buck_t gBenchBuck = { 12.0f, 11.9f, 3U };
C2000TuneMailbox_t gTuneBox;
C2000DlogBuffer_t gDlog;
int main(void) {
    uint32_t k;
    c2000_tune_init(&gTuneBox, 0x12345678UL, 4U, 1000UL);
    c2000_tune_config_param(&gTuneBox, 0U, 12.0f, 12.0f, 0.0f, 36.0f, 0.1f);
    c2000_tune_config_param(&gTuneBox, 1U, 0.08f, 0.08f, 0.0f, 2.0f, 0.01f);
    c2000_dlog_init(&gDlog, 20000.0f, 4U);
    for (k = 0U; k < 4U; ++k) {
        uint16_t c = c2000_tune_isr_step(&gTuneBox);
        float ki_s = c2000_tune_bumpless_ki(0.1f, 0.2f, 4.0f);
        c2000_dlog_push4(&gDlog, gBenchBuck.v_ref, gBenchBuck.v_out, ki_s, 0.0f, c);
    }
    return 0;
}
"#,
    )
    .unwrap();

    let cmd_file = tmp.join("f28069_min.cmd");
    fs::write(
        &cmd_file,
        r#"
MEMORY {
  PAGE 0: FLASH_A : origin = 0x3F0000, length = 0x008000
  PAGE 1: RAML4   : origin = 0x00A000, length = 0x004000
}
SECTIONS {
  .text       : > FLASH_A, PAGE = 0
  .cinit      : > FLASH_A, PAGE = 0
  .init_array : > FLASH_A, PAGE = 0
  .pinit      : > FLASH_A, PAGE = 0
  .const      : > FLASH_A, PAGE = 0
  .econst     : > FLASH_A, PAGE = 0
  .switch     : > FLASH_A, PAGE = 0
  .ebss       : > RAML4,   PAGE = 1
  .bss        : > RAML4,   PAGE = 1
  .data       : > RAML4,   PAGE = 1
  .sysmem     : > RAML4,   PAGE = 1
  .esysmem    : > RAML4,   PAGE = 1
  .stack      : > RAML4,   PAGE = 1
  .cio        : > RAML4,   PAGE = 1
}
"#,
    )
    .unwrap();

    let p069 = get_device_profile(DeviceId::F28069M);
    let cp = p069.primary_core();

    for abi in ["eabi", "coffabi"] {
        let out_file = tmp.join(format!("bench_{abi}.out"));
        let obj_dir = tmp.join(format!("obj_{abi}"));
        fs::create_dir_all(&obj_dir).unwrap();
        let lib_search = format!("-i{}", lib_dir.display());
        let inc_cgt = format!("--include_path={}", inc_dir.display());
        let inc_fw = format!("--include_path={}", fw_inc.display());
        let obj_arg = format!("--obj_directory={}", obj_dir.display());
        let abi_arg = format!("--abi={abi}");
        let src_s = src.to_string_lossy().to_string();
        let cmd_s = cmd_file.to_string_lossy().to_string();
        let out_s = out_file.to_string_lossy().to_string();
        let mut args = vec![
            "-v28",
            "-ml",
            "-mt",
            "--float_support=fpu32",
            &abi_arg,
            "--c99",
            "-g",
            &inc_cgt,
            &inc_fw,
            &obj_arg,
            &src_s,
            "-z",
            "--rom_model",
            &lib_search,
            "-llibc.a",
        ];
        if abi == "eabi" {
            args.push("--retain=gBenchBuck");
            args.push("--retain=gTuneBox");
        }
        args.push(&cmd_s);
        args.push("-o");
        args.push(&out_s);
        let out = Command::new(cl2000)
            .args(&args)
            .creation_flags(CREATE_NO_WINDOW)
            .output()
            .expect("invoke cl2000");
        assert!(
            out.status.success(),
            "cl2000 ({abi}) failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let parsed = load_symbols_for_file(&out_file, cp, Some(&env), false).expect("ofd2000 parse");
        assert!(
            parsed.symbols.iter().any(|s| s.name == "gBenchBuck"),
            "gBenchBuck missing in {abi} DWARF parse"
        );
        let fp = extract_flash_fingerprint(&out_file, cp, 16).expect("flash fingerprint extracted");
        assert_eq!(fp.words.len(), 16);
        assert!(fp.address >= 0x3F0000);
    }

    // 3. USCIF .dat generation verification
    let dat = tmp.join("test_xds110.dat");
    generate_uscif_dat(&dat, DeviceId::F28069M, ProbeKind::XDS110, "5.5MHz", JtagMode::Jtag4Pin, "").unwrap();
    let dat_txt = fs::read_to_string(&dat).unwrap();
    assert!(dat_txt.contains("icepick_c") && dat_txt.contains("jioxds110.dll") && dat_txt.contains("5500kHz"));
}
