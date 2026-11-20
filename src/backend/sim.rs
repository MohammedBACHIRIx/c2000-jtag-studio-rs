//! Closed-loop F28069M Buck/Motor & F28388D 5-Core Inverter/CLA/CM4 physics simulator + Phase-B 20 kHz DLOG.

use std::collections::BTreeMap;
use std::f64::consts::TAU;
use std::path::Path;
use std::time::Instant;

use crate::backend::{DebugBackend, DlogBurst};
use crate::core::devices::get_device_profile;
use crate::core::models::{
    ConnectionRequest, CoreState, DataType, DeviceId, MemCfgSnapshot, PhysicalMemoryDomain,
    RealtimeAccessMode, SymbolNode,
};

struct VirtualMem {
    au_bits: u32,
    cells: BTreeMap<u32, u32>,
}

impl VirtualMem {
    fn new(au_bits: u32) -> Self {
        Self {
            au_bits,
            cells: BTreeMap::new(),
        }
    }

    fn write_f32(&mut self, addr: u32, v: f32) {
        let bits = v.to_bits();
        if self.au_bits == 16 {
            self.cells.insert(addr, bits & 0xFFFF);
            self.cells.insert(addr + 1, (bits >> 16) & 0xFFFF);
        } else {
            let bs = bits.to_le_bytes();
            for (i, b) in bs.iter().enumerate() {
                self.cells.insert(addr + i as u32, *b as u32);
            }
        }
    }

    fn read_f32(&self, addr: u32) -> f32 {
        if self.au_bits == 16 {
            let lo = self.cells.get(&addr).copied().unwrap_or(0) & 0xFFFF;
            let hi = self.cells.get(&(addr + 1)).copied().unwrap_or(0) & 0xFFFF;
            f32::from_bits(lo | (hi << 16))
        } else {
            let b0 = self.cells.get(&addr).copied().unwrap_or(0) as u8;
            let b1 = self.cells.get(&(addr + 1)).copied().unwrap_or(0) as u8;
            let b2 = self.cells.get(&(addr + 2)).copied().unwrap_or(0) as u8;
            let b3 = self.cells.get(&(addr + 3)).copied().unwrap_or(0) as u8;
            f32::from_le_bytes([b0, b1, b2, b3])
        }
    }

    fn write_u32(&mut self, addr: u32, v: u32) {
        if self.au_bits == 16 {
            self.cells.insert(addr, v & 0xFFFF);
            self.cells.insert(addr + 1, (v >> 16) & 0xFFFF);
        } else {
            for (i, b) in v.to_le_bytes().iter().enumerate() {
                self.cells.insert(addr + i as u32, *b as u32);
            }
        }
    }

    fn write_u16(&mut self, addr: u32, v: u16) {
        if self.au_bits == 16 {
            self.cells.insert(addr, v as u32);
        } else {
            for (i, b) in v.to_le_bytes().iter().enumerate() {
                self.cells.insert(addr + i as u32, *b as u32);
            }
        }
    }

    fn read_block(&self, addr: u32, count: u32, bit_size: u32) -> Vec<u32> {
        let mut out = Vec::with_capacity(count as usize);
        if self.au_bits == 16 && bit_size == 32 {
            for i in 0..count {
                let a = addr + i * 2;
                let lo = self.cells.get(&a).copied().unwrap_or(0) & 0xFFFF;
                let hi = self.cells.get(&(a + 1)).copied().unwrap_or(0) & 0xFFFF;
                out.push(lo | (hi << 16));
            }
        } else if self.au_bits == 8 && bit_size == 32 {
            for i in 0..count {
                let a = addr + i * 4;
                let b0 = self.cells.get(&a).copied().unwrap_or(0) & 0xFF;
                let b1 = self.cells.get(&(a + 1)).copied().unwrap_or(0) & 0xFF;
                let b2 = self.cells.get(&(a + 2)).copied().unwrap_or(0) & 0xFF;
                let b3 = self.cells.get(&(a + 3)).copied().unwrap_or(0) & 0xFF;
                out.push(b0 | (b1 << 8) | (b2 << 16) | (b3 << 24));
            }
        } else {
            let mask = if self.au_bits == 16 { 0xFFFF } else { 0xFF };
            for i in 0..count {
                out.push(self.cells.get(&(addr + i)).copied().unwrap_or(0) & mask);
            }
        }
        out
    }

    fn write_block(&mut self, addr: u32, values: &[u32], bit_size: u32) {
        if self.au_bits == 16 && bit_size == 32 {
            for (i, &v) in values.iter().enumerate() {
                let a = addr + (i as u32) * 2;
                self.cells.insert(a, v & 0xFFFF);
                self.cells.insert(a + 1, (v >> 16) & 0xFFFF);
            }
        } else if self.au_bits == 8 && bit_size == 32 {
            for (i, &v) in values.iter().enumerate() {
                let a = addr + (i as u32) * 4;
                for (b_i, b) in v.to_le_bytes().iter().enumerate() {
                    self.cells.insert(a + b_i as u32, *b as u32);
                }
            }
        } else {
            let mask = if self.au_bits == 16 { 0xFFFF } else { 0xFF };
            for (i, &v) in values.iter().enumerate() {
                self.cells.insert(addr + i as u32, v & mask);
            }
        }
    }
}

pub struct SimulatedBackend {
    device_id: DeviceId,
    mems: BTreeMap<String, VirtualMem>,
    core_states: BTreeMap<String, CoreState>,
    rt_modes: BTreeMap<String, RealtimeAccessMode>,
    symbols: BTreeMap<String, Vec<SymbolNode>>,
    sim_time: f64,
    last_wall: Option<Instant>,
    // F28069M Buck state
    buck_v_out: f64,
    buck_i_l: f64,
    buck_int: f64,
    isr_cnt: u32,
    // F28388D Inverter state
    inv_theta: f64,
    cm_rx: u32,
    // Phase-B DLOG
    dlog_enabled: bool,
    last_dlog_wall: Option<Instant>,
}

impl SimulatedBackend {
    pub fn new() -> Self {
        Self {
            device_id: DeviceId::F28069M,
            mems: BTreeMap::new(),
            core_states: BTreeMap::new(),
            rt_modes: BTreeMap::new(),
            symbols: BTreeMap::new(),
            sim_time: 0.0,
            last_wall: None,
            buck_v_out: 12.0,
            buck_i_l: 2.4,
            buck_int: 0.5,
            isr_cnt: 0,
            inv_theta: 0.0,
            cm_rx: 100,
            dlog_enabled: false,
            last_dlog_wall: None,
        }
    }

    fn init_f28069m(&mut self) {
        self.mems.clear();
        self.mems.insert("C28xx_0".into(), VirtualMem::new(16));
        self.mems.insert("CLA_0".into(), VirtualMem::new(16));
        self.buck_v_out = 12.0;
        self.buck_i_l = 2.4;
        self.buck_int = 0.5;
        self.isr_cnt = 0;

        let m = self.mems.get_mut("C28xx_0").unwrap();
        m.write_f32(0x008000, 24.0); // v_in
        m.write_f32(0x008002, 12.0); // v_ref
        m.write_f32(0x008004, 12.0); // v_out
        m.write_f32(0x008006, 2.4);  // i_L
        m.write_f32(0x008008, 0.5);  // duty
        m.write_f32(0x00800A, 0.08); // pid.kp
        m.write_f32(0x00800C, 3.2);  // pid.ki
        m.write_u16(0x00800E, 0x0001); // fault_flags (ready=1)

        // Motor in L4 CPU RAM (0x00A000..0x00A024)
        m.write_f32(0x00A000, 1500.0); // rpm_ref
        m.write_f32(0x00A002, 1500.0); // rpm_meas
        m.write_f32(0x00A004, 1.8);    // id_curr
        m.write_f32(0x00A006, 4.2);    // iq_curr
        m.write_u16(0x00A020, 2048);   // gAdcRaw[0]
        m.write_u32(0x00A024, 0);      // gIsrCount

        // Known Flash words for fingerprint verification
        for i in 0..16u32 {
            m.write_u16(0x3F0000 + i, 0xA500 + i as u16);
        }

        let s = |name: &str, fp: &str, addr: u32, dt: DataType, ws: u32, tn: &str, sec: &str, dm: PhysicalMemoryDomain| SymbolNode {
            name: name.into(),
            full_path: fp.into(),
            core: "C28xx_0".into(),
            address: addr,
            page: "DATA".into(),
            data_type: dt,
            word_size: ws,
            type_name: tn.into(),
            bit_offset: None,
            bit_width: None,
            container_units: None,
            is_struct: false,
            is_array: false,
            array_len: 0,
            is_pointer: false,
            is_function: false,
            section_name: sec.into(),
            domain: dm,
            tu_scope: String::new(),
            is_scratchpad: false,
            children: Vec::new(),
        };

        let mut pid = s("pid", "gBuck.pid", 0x00800A, DataType::Uint16, 4, "Pid_t", ".bss", PhysicalMemoryDomain::ClaShared);
        pid.is_struct = true;
        pid.children = vec![
            s("kp", "gBuck.pid.kp", 0x00800A, DataType::Float32, 2, "float", ".bss", PhysicalMemoryDomain::ClaShared),
            s("ki", "gBuck.pid.ki", 0x00800C, DataType::Float32, 2, "float", ".bss", PhysicalMemoryDomain::ClaShared),
        ];

        let mut ready_bf = s("ready", "gBuck.fault_flags.ready", 0x00800E, DataType::Uint16, 1, "uint16_t", ".bss", PhysicalMemoryDomain::ClaShared);
        ready_bf.bit_offset = Some(0);
        ready_bf.bit_width = Some(1);
        let mut ocp_bf = s("ocp", "gBuck.fault_flags.ocp", 0x00800E, DataType::Uint16, 1, "uint16_t", ".bss", PhysicalMemoryDomain::ClaShared);
        ocp_bf.bit_offset = Some(1);
        ocp_bf.bit_width = Some(1);
        let mut flags = s("fault_flags", "gBuck.fault_flags", 0x00800E, DataType::Uint16, 1, "Flags_t", ".bss", PhysicalMemoryDomain::ClaShared);
        flags.is_struct = true;
        flags.children = vec![ready_bf, ocp_bf];

        let mut buck = s("gBuck", "gBuck", 0x008000, DataType::Uint16, 15, "Buck_t", ".bss", PhysicalMemoryDomain::ClaShared);
        buck.is_struct = true;
        buck.children = vec![
            s("v_in", "gBuck.v_in", 0x008000, DataType::Float32, 2, "float", ".bss", PhysicalMemoryDomain::ClaShared),
            s("v_ref", "gBuck.v_ref", 0x008002, DataType::Float32, 2, "float", ".bss", PhysicalMemoryDomain::ClaShared),
            s("v_out", "gBuck.v_out", 0x008004, DataType::Float32, 2, "float", ".bss", PhysicalMemoryDomain::ClaShared),
            s("i_L", "gBuck.i_L", 0x008006, DataType::Float32, 2, "float", ".bss", PhysicalMemoryDomain::ClaShared),
            s("duty", "gBuck.duty", 0x008008, DataType::Float32, 2, "float", ".bss", PhysicalMemoryDomain::ClaShared),
            pid,
            flags,
        ];

        let mut motor = s("gMotor", "gMotor", 0x00A000, DataType::Uint16, 8, "Motor_t", ".ebss", PhysicalMemoryDomain::Cpu1Private);
        motor.is_struct = true;
        motor.children = vec![
            s("rpm_ref", "gMotor.rpm_ref", 0x00A000, DataType::Float32, 2, "float", ".ebss", PhysicalMemoryDomain::Cpu1Private),
            s("rpm_meas", "gMotor.rpm_meas", 0x00A002, DataType::Float32, 2, "float", ".ebss", PhysicalMemoryDomain::Cpu1Private),
            s("id_curr", "gMotor.id_curr", 0x00A004, DataType::Float32, 2, "float", ".ebss", PhysicalMemoryDomain::Cpu1Private),
            s("iq_curr", "gMotor.iq_curr", 0x00A006, DataType::Float32, 2, "float", ".ebss", PhysicalMemoryDomain::Cpu1Private),
        ];

        let mut adc = s("gAdcRaw", "gAdcRaw", 0x00A020, DataType::Uint16, 4, "uint16[4]", ".ebss", PhysicalMemoryDomain::Cpu1Private);
        adc.is_array = true;
        adc.array_len = 4;
        for i in 0..4u32 {
            adc.children.push(s(&format!("[{i}]"), &format!("gAdcRaw[{i}]"), 0x00A020 + i, DataType::Uint16, 1, "uint16_t", ".ebss", PhysicalMemoryDomain::Cpu1Private));
        }

        let isr = s("gIsrCount", "gIsrCount", 0x00A024, DataType::Uint32, 2, "uint32_t", ".ebss", PhysicalMemoryDomain::Cpu1Private);

        self.symbols.clear();
        self.symbols.insert("C28xx_0".into(), vec![buck, motor, adc, isr]);
        self.symbols.insert("CLA_0".into(), Vec::new());
    }

    fn init_f28388d(&mut self) {
        self.mems.clear();
        for (c, au) in [
            ("C28xx_CPU1", 16),
            ("CPU1_CLA1", 16),
            ("C28xx_CPU2", 16),
            ("CPU2_CLA1", 16),
            ("Cortex_M4_0", 8),
        ] {
            self.mems.insert(c.into(), VirtualMem::new(au));
        }
        let m1 = self.mems.get_mut("C28xx_CPU1").unwrap();
        m1.write_f32(0x00C000, 400.0); // v_dc
        m1.write_f32(0x00C002, 0.0);   // i_a
        m1.write_f32(0x00C004, 0.0);   // i_b
        m1.write_f32(0x00C006, 0.0);   // i_c
        m1.write_f32(0x00C00E, 8.0);   // foc.iq_ref
        for i in 0..16u32 {
            m1.write_u16(0x080000 + i, 0x5A00 + i as u16);
        }

        let cm = self.mems.get_mut("Cortex_M4_0").unwrap();
        cm.write_u32(0x20000000, 100);
        cm.write_f32(0x2000000C, 42.5);

        let mk = |core: &str, page: &str, name: &str, fp: &str, addr: u32, dt: DataType, ws: u32, tn: &str, dm: PhysicalMemoryDomain| SymbolNode {
            name: name.into(),
            full_path: fp.into(),
            core: core.into(),
            address: addr,
            page: page.into(),
            data_type: dt,
            word_size: ws,
            type_name: tn.into(),
            bit_offset: None,
            bit_width: None,
            container_units: None,
            is_struct: false,
            is_array: false,
            array_len: 0,
            is_pointer: false,
            is_function: false,
            section_name: ".bss".into(),
            domain: dm,
            tu_scope: String::new(),
            is_scratchpad: false,
            children: Vec::new(),
        };

        let mut inv = mk("C28xx_CPU1", "DATA", "gInv", "gInv", 0x00C000, DataType::Uint16, 16, "Inv_t", PhysicalMemoryDomain::Cpu1Private);
        inv.is_struct = true;
        inv.children = vec![
            mk("C28xx_CPU1", "DATA", "v_dc", "gInv.v_dc", 0x00C000, DataType::Float32, 2, "float", PhysicalMemoryDomain::Cpu1Private),
            mk("C28xx_CPU1", "DATA", "i_a", "gInv.i_a", 0x00C002, DataType::Float32, 2, "float", PhysicalMemoryDomain::Cpu1Private),
            mk("C28xx_CPU1", "DATA", "i_b", "gInv.i_b", 0x00C004, DataType::Float32, 2, "float", PhysicalMemoryDomain::Cpu1Private),
            mk("C28xx_CPU1", "DATA", "iq_ref", "gInv.foc.iq_ref", 0x00C00E, DataType::Float32, 2, "float", PhysicalMemoryDomain::Cpu1Private),
        ];

        let mut cm_stats = mk("Cortex_M4_0", "", "gCmStats", "gCmStats", 0x20000000, DataType::Uint32, 16, "CmStats_t", PhysicalMemoryDomain::Cm4Sram);
        cm_stats.is_struct = true;
        cm_stats.children = vec![
            mk("Cortex_M4_0", "", "ethercat_rx", "gCmStats.ethercat_rx", 0x20000000, DataType::Uint32, 4, "uint32_t", PhysicalMemoryDomain::Cm4Sram),
            mk("Cortex_M4_0", "", "cpu_temp_c", "gCmStats.cpu_temp_c", 0x2000000C, DataType::Float32, 4, "float", PhysicalMemoryDomain::Cm4Sram),
        ];

        self.symbols.clear();
        self.symbols.insert("C28xx_CPU1".into(), vec![inv]);
        self.symbols.insert("Cortex_M4_0".into(), vec![cm_stats]);
    }

    pub fn step_simulation(&mut self, dt: f64) {
        if dt <= 0.0 {
            return;
        }
        self.sim_time += dt;
        match self.device_id {
            DeviceId::F28069M => {
                let Some(m) = self.mems.get_mut("C28xx_0") else { return };
                let v_in = (m.read_f32(0x008000) as f64).clamp(5.0, 60.0);
                let v_ref = (m.read_f32(0x008002) as f64).clamp(0.0, 48.0);
                let kp = (m.read_f32(0x00800A) as f64).clamp(0.001, 5.0);
                let ki = (m.read_f32(0x00800C) as f64).clamp(0.0, 50.0);

                // Sub-step closed-loop second-order Buck converter with realistic overshoot & switching ripple
                let sub = 10;
                let h = dt / (sub as f64);
                let r_load = 5.0;
                let l_ind = 0.0008;
                let c_out = 0.0005;
                for _ in 0..sub {
                    let err = v_ref - self.buck_v_out;
                    self.buck_int = (self.buck_int + err * ki * h).clamp(0.02, 0.95);
                    let duty = (self.buck_int + kp * err).clamp(0.02, 0.95);
                    let di = ((duty * v_in - self.buck_v_out) - 0.12 * self.buck_i_l) / l_ind;
                    let dv = (self.buck_i_l - self.buck_v_out / r_load) / c_out;
                    self.buck_i_l = (self.buck_i_l + di * h).clamp(0.0, 25.0);
                    self.buck_v_out = (self.buck_v_out + dv * h).clamp(0.0, v_in);
                }
                let ripple_v = 0.04 * (TAU * 18.0 * self.sim_time).sin();
                let ripple_i = 0.16 * (TAU * 18.0 * self.sim_time).sin();
                self.isr_cnt = self.isr_cnt.wrapping_add(1);
                m.write_f32(0x008004, (self.buck_v_out + ripple_v) as f32);
                m.write_f32(0x008006, (self.buck_i_l + ripple_i) as f32);
                m.write_f32(0x008008, self.buck_int as f32);
                m.write_u32(0x00A024, self.isr_cnt);
            }
            DeviceId::F28388D => {
                self.inv_theta = (self.inv_theta + TAU * 60.0 * dt) % TAU;
                if let Some(m1) = self.mems.get_mut("C28xx_CPU1") {
                    let iq = (m1.read_f32(0x00C00E) as f64).clamp(0.0, 30.0);
                    m1.write_f32(0x00C002, (iq * self.inv_theta.sin()) as f32);
                    m1.write_f32(0x00C004, (iq * (self.inv_theta - TAU / 3.0).sin()) as f32);
                    m1.write_f32(0x00C006, (iq * (self.inv_theta + TAU / 3.0).sin()) as f32);
                }
                self.cm_rx = self.cm_rx.wrapping_add(1);
                if let Some(cm) = self.mems.get_mut("Cortex_M4_0") {
                    cm.write_u32(0x20000000, self.cm_rx);
                    cm.write_f32(0x2000000C, (42.5 + 1.2 * (0.4 * self.sim_time).sin()) as f32);
                }
            }
        }
    }

    fn advance_if_needed(&mut self) {
        let now = Instant::now();
        if let Some(prev) = self.last_wall {
            let dt = now.duration_since(prev).as_secs_f64().min(0.05);
            self.step_simulation(dt);
        }
        self.last_wall = Some(now);
    }
}

impl Default for SimulatedBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl DebugBackend for SimulatedBackend {
    fn connect(&mut self, req: &ConnectionRequest) -> Result<BTreeMap<String, CoreState>, String> {
        self.device_id = req.device_id;
        match req.device_id {
            DeviceId::F28069M => self.init_f28069m(),
            DeviceId::F28388D => self.init_f28388d(),
        }
        self.sim_time = 0.0;
        self.last_wall = Some(Instant::now());
        self.dlog_enabled = false;
        let rt_st = if !req.attach_live {
            CoreState::ConnectedHalted
        } else {
            match req.realtime_mode {
                RealtimeAccessMode::SiliconRtRude => CoreState::ConnectedRtRude,
                RealtimeAccessMode::SiliconRtPolite => CoreState::ConnectedRtPolite,
                RealtimeAccessMode::StopModeHalt => CoreState::ConnectedRunning,
            }
        };
        let profile = get_device_profile(req.device_id);
        self.core_states.clear();
        self.rt_modes.clear();
        for c in &profile.cores {
            self.core_states.insert(c.name.to_string(), rt_st);
            self.rt_modes.insert(c.name.to_string(), req.realtime_mode);
        }
        Ok(self.core_states.clone())
    }

    fn disconnect(&mut self) {
        self.dlog_enabled = false;
        for st in self.core_states.values_mut() {
            *st = CoreState::Disconnected;
        }
    }

    fn connect_core(&mut self, core: &str, attach_live: bool) -> Result<CoreState, String> {
        let st = if attach_live { CoreState::ConnectedRtPolite } else { CoreState::ConnectedHalted };
        self.core_states.insert(core.to_string(), st);
        Ok(st)
    }

    fn disconnect_core(&mut self, core: &str) -> Result<CoreState, String> {
        self.core_states.insert(core.to_string(), CoreState::Disconnected);
        Ok(CoreState::Disconnected)
    }

    fn load_program(&mut self, core: &str, _path: &Path) -> Result<CoreState, String> {
        self.quiesce_all_masters();
        self.core_states.insert(core.to_string(), CoreState::ConnectedHalted);
        Ok(CoreState::ConnectedHalted)
    }

    fn load_symbols(&mut self, _core: &str, _path: &Path) -> Result<(), String> {
        Ok(())
    }

    fn run_core(&mut self, core: &str) -> Result<CoreState, String> {
        let st = match self.rt_modes.get(core).copied().unwrap_or(RealtimeAccessMode::SiliconRtPolite) {
            RealtimeAccessMode::SiliconRtRude => CoreState::ConnectedRtRude,
            RealtimeAccessMode::SiliconRtPolite => CoreState::ConnectedRtPolite,
            RealtimeAccessMode::StopModeHalt => CoreState::ConnectedRunning,
        };
        self.core_states.insert(core.to_string(), st);
        Ok(st)
    }

    fn halt_core(&mut self, core: &str) -> Result<CoreState, String> {
        self.core_states.insert(core.to_string(), CoreState::ConnectedHalted);
        Ok(CoreState::ConnectedHalted)
    }

    fn reset_core(&mut self, core: &str) -> Result<CoreState, String> {
        match self.device_id {
            DeviceId::F28069M => self.init_f28069m(),
            DeviceId::F28388D => self.init_f28388d(),
        }
        self.core_states.insert(core.to_string(), CoreState::ConnectedHalted);
        Ok(CoreState::ConnectedHalted)
    }

    fn set_realtime_mode(&mut self, core: &str, mode: RealtimeAccessMode) -> Result<CoreState, String> {
        self.rt_modes.insert(core.to_string(), mode);
        if self.core_states.get(core) == Some(&CoreState::ConnectedHalted) {
            return Ok(CoreState::ConnectedHalted);
        }
        self.run_core(core)
    }

    fn micro_halt_clear_dbgm(&mut self, core: &str) -> Result<CoreState, String> {
        self.rt_modes.insert(core.to_string(), RealtimeAccessMode::SiliconRtPolite);
        self.core_states.insert(core.to_string(), CoreState::ConnectedRtPolite);
        Ok(CoreState::ConnectedRtPolite)
    }

    fn read_block(&mut self, core: &str, address: u32, count: u32, bit_size: u32, _page: &str) -> Result<Vec<u32>, String> {
        if self.core_states.get(core) == Some(&CoreState::Disconnected) {
            return Err(format!("Simulated core '{core}' is disconnected"));
        }
        self.advance_if_needed();
        let mem = self.mems.get(core).ok_or_else(|| format!("Unknown simulated core {core}"))?;
        Ok(mem.read_block(address, count, bit_size))
    }

    fn write_block(&mut self, core: &str, address: u32, values: &[u32], bit_size: u32, _page: &str) -> Result<(), String> {
        if self.core_states.get(core) == Some(&CoreState::Disconnected) {
            return Err(format!("Simulated core '{core}' is disconnected"));
        }
        let mem = self.mems.get_mut(core).ok_or_else(|| format!("Unknown simulated core {core}"))?;
        mem.write_block(address, values, bit_size);
        Ok(())
    }

    fn probe_memcfg(&mut self, _core: &str) -> MemCfgSnapshot {
        MemCfgSnapshot {
            probed: true,
            ..Default::default()
        }
    }

    fn get_core_states(&self) -> BTreeMap<String, CoreState> {
        self.core_states.clone()
    }

    fn get_builtin_symbols(&self, core: &str) -> Vec<SymbolNode> {
        self.symbols.get(core).cloned().unwrap_or_default()
    }

    fn configure_dlog(&mut self, enabled: bool, _trigger_mode: &str, _level: f64) -> bool {
        self.dlog_enabled = enabled;
        self.last_dlog_wall = Some(Instant::now());
        enabled
    }

    fn get_dlog_burst(&mut self) -> Option<DlogBurst> {
        if !self.dlog_enabled {
            return None;
        }
        let now = Instant::now();
        if let Some(prev) = self.last_dlog_wall {
            if now.duration_since(prev).as_secs_f64() < 0.025 {
                return None;
            }
        }
        self.last_dlog_wall = Some(now);
        let n = 64usize;
        let dt = 1.0 / 20_000.0;
        let mut v_out_arr = Vec::with_capacity(n);
        let mut i_l_arr = Vec::with_capacity(n);
        for i in 0..n {
            let phase = TAU * 2000.0 * (self.sim_time + (i as f64) * dt);
            v_out_arr.push(self.buck_v_out + 0.04 * phase.sin());
            i_l_arr.push(self.buck_i_l + 0.16 * phase.sin());
        }
        Some(DlogBurst {
            dt_sec: dt,
            overrun: false,
            channels: vec![
                ("gBuck.v_out".into(), v_out_arr),
                ("gBuck.i_L".into(), i_l_arr),
            ],
        })
    }
}
