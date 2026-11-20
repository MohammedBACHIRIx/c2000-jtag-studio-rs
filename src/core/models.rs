//! Core domain models, enums, FSM states, and serializable DTOs for C2000 JTAG Studio (Rust v2).

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const PROTOCOL_VERSION: u32 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DeviceId {
    F28069M,
    F28388D,
}

impl DeviceId {
    pub fn display_name(self) -> &'static str {
        match self {
            Self::F28069M => "TMS320F28069M",
            Self::F28388D => "TMS320F28388D",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProbeKind {
    XDS100V2,
    XDS110,
    SIMULATOR,
    CUSTOM_CCXML,
}

impl ProbeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::XDS100V2 => "XDS100v2",
            Self::XDS110 => "XDS110",
            Self::SIMULATOR => "Offline Simulator",
            Self::CUSTOM_CCXML => "Custom .ccxml",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum JtagMode {
    Jtag4Pin,
    Cjtag2PinOscan1,
    Cjtag2PinOscan2,
}

impl JtagMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Jtag4Pin => "JTAG 4-pin",
            Self::Cjtag2PinOscan2 => "cJTAG OSCAN2",
            Self::Cjtag2PinOscan1 => "cJTAG OSCAN1",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SessionState {
    Disconnected,
    Connecting,
    ConnectedLive,
    WriteLockedStaleImage,
    DcsmLocked,
    Fault,
    Recovering,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CoreState {
    Disconnected,
    ConnectedHalted,
    ConnectedRunning,
    ConnectedRtPolite,
    ConnectedRtRude,
    DbgMBlocked,
    DcsmLocked,
    InReset,
    Error,
}

impl CoreState {
    pub fn short_label(self) -> &'static str {
        match self {
            Self::Disconnected => "Detached",
            Self::ConnectedHalted => "Halted",
            Self::ConnectedRunning => "Running",
            Self::ConnectedRtPolite => "RT Polite",
            Self::ConnectedRtRude => "RT Rude",
            Self::DbgMBlocked => "DBGM=1",
            Self::DcsmLocked => "DCSM Lock",
            Self::InReset => "In-Reset",
            Self::Error => "Error",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PhysicalMemoryDomain {
    Cpu1Private,
    Cpu2Private,
    GsShared,
    ClaShared,
    MsgCpuToCla,
    MsgClaToCpu,
    MsgCpu1ToCpu2,
    MsgCpu2ToCpu1,
    MsgCmToCpu,
    MsgCpuToCm,
    Cm4Sram,
    Flash,
    Mmio,
    Otp,
    Scratchpad,
    Unknown,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ThemeMode {
    #[default]
    ClassicEclipseLight,
    DarkOled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriggerMode {
    Free,
    Auto,
    Single,
    OnWrite,
}

impl TriggerMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Free => "Free",
            Self::Auto => "Auto",
            Self::Single => "Single",
            Self::OnWrite => "On-Write",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TriggerSlope {
    Rising,
    Falling,
    WindowOut,
    BitHigh,
}

impl TriggerSlope {
    pub fn label(self) -> &'static str {
        match self {
            Self::Rising => "Rising",
            Self::Falling => "Falling",
            Self::WindowOut => "Window Out",
            Self::BitHigh => "Bit High",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DataType {
    Int8,
    Uint8,
    Int16,
    Uint16,
    Int32,
    Uint32,
    Int64,
    Uint64,
    Float32,
    Float64,
}

impl DataType {
    pub const ALL: [DataType; 10] = [
        Self::Int8,
        Self::Uint8,
        Self::Int16,
        Self::Uint16,
        Self::Int32,
        Self::Uint32,
        Self::Int64,
        Self::Uint64,
        Self::Float32,
        Self::Float64,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Int8 => "int8",
            Self::Uint8 => "uint8",
            Self::Int16 => "int16",
            Self::Uint16 => "uint16",
            Self::Int32 => "int32",
            Self::Uint32 => "uint32",
            Self::Int64 => "int64",
            Self::Uint64 => "uint64",
            Self::Float32 => "float32",
            Self::Float64 => "float64",
        }
    }

    pub fn bit_size(self) -> u32 {
        match self {
            Self::Int8 | Self::Uint8 => 8,
            Self::Int16 | Self::Uint16 => 16,
            Self::Int32 | Self::Uint32 | Self::Float32 => 32,
            Self::Int64 | Self::Uint64 | Self::Float64 => 64,
        }
    }

    pub fn is_float(self) -> bool {
        matches!(self, Self::Float32 | Self::Float64)
    }

    pub fn is_signed(self) -> bool {
        matches!(
            self,
            Self::Int8 | Self::Int16 | Self::Int32 | Self::Int64 | Self::Float32 | Self::Float64
        )
    }

    pub fn is_32bit(self) -> bool {
        matches!(self, Self::Int32 | Self::Uint32 | Self::Float32)
    }

    pub fn unit_count(self, address_unit_bits: u32) -> u32 {
        assert!(address_unit_bits == 8 || address_unit_bits == 16);
        self.bit_size().div_ceil(address_unit_bits).max(1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DisplayFormat {
    Dec,
    Hex,
    Bin,
    Float,
    Iq,
}

impl DisplayFormat {
    pub const ALL: [DisplayFormat; 5] = [Self::Dec, Self::Hex, Self::Bin, Self::Float, Self::Iq];

    pub fn label(self) -> &'static str {
        match self {
            Self::Dec => "Dec",
            Self::Hex => "Hex",
            Self::Bin => "Bin",
            Self::Float => "Float",
            Self::Iq => "IQ",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PollMode {
    MaxFreerun,
    FixedHz,
    Manual,
}

impl PollMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::MaxFreerun => "MAX",
            Self::FixedHz => "Fixed Hz",
            Self::Manual => "Manual",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RealtimeAccessMode {
    SiliconRtPolite,
    SiliconRtRude,
    StopModeHalt,
}

impl RealtimeAccessMode {
    pub fn label(self) -> &'static str {
        match self {
            Self::SiliconRtPolite => "RT Polite",
            Self::SiliconRtRude => "RT Rude",
            Self::StopModeHalt => "Stop-Mode!",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlashFingerprint {
    pub address: u32,
    pub page: String,
    pub words: Vec<u32>,
    pub address_unit_bits: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemCfgSnapshot {
    pub ls_msel: u32,
    pub ls_clapgm: u32,
    pub gs_msel: u32,
    pub dcsm_z1_locked: bool,
    pub dcsm_z2_locked: bool,
    pub probed: bool,
}

impl MemCfgSnapshot {
    pub fn ls_is_cla_owned(&self, block_idx: usize) -> bool {
        if !self.probed || block_idx >= 8 {
            return false;
        }
        ((self.ls_msel >> (2 * block_idx)) & 0x3) == 1
    }

    pub fn ls_is_cla_program(&self, block_idx: usize) -> bool {
        if !self.probed || block_idx >= 8 {
            return false;
        }
        self.ls_is_cla_owned(block_idx) && (((self.ls_clapgm >> block_idx) & 0x1) != 0)
    }

    pub fn gs_owner_core(&self, block_idx: usize) -> &'static str {
        if !self.probed || block_idx >= 16 {
            return "C28xx_CPU1";
        }
        if ((self.gs_msel >> block_idx) & 0x1) != 0 {
            "C28xx_CPU2"
        } else {
            "C28xx_CPU1"
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryRange {
    pub start: u32,
    pub end: u32, // inclusive
    pub name: String,
    pub is_ram: bool,
    pub is_peripheral: bool,
    pub is_cla_shared: bool,
    pub domain: PhysicalMemoryDomain,
    pub writable_by: Vec<String>,
    pub readable_by: Vec<String>,
    pub bank_index: Option<usize>,
}

impl MemoryRange {
    pub fn contains(&self, addr: u32, length: u32) -> bool {
        if length == 0 {
            return addr >= self.start && addr <= self.end;
        }
        let end = addr.saturating_add(length - 1);
        addr >= self.start && end <= self.end
    }

    pub fn overlaps(&self, start: u32, end: u32) -> bool {
        !(end < self.start || start > self.end)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreProfile {
    pub name: &'static str,
    pub display_tag: &'static str,
    pub isa: &'static str,
    pub address_unit_bits: u32,
    pub default_page: &'static str,
    pub supports_realtime_gel: bool,
    pub ofd_tool: &'static str, // "ofd2000" or "tiarmofd"
    pub is_primary: bool,
    pub proxy_parent_core: Option<&'static str>,
    pub badge_hex: &'static str,
}

#[derive(Debug, Clone)]
pub struct DeviceProfile {
    pub device_id: DeviceId,
    pub display_name: &'static str,
    pub targetdb_device_xml: &'static str,
    pub default_probe: ProbeKind,
    pub cores: Vec<CoreProfile>,
    pub ram_ranges: BTreeMap<String, Vec<MemoryRange>>,
    pub flash_ranges: BTreeMap<String, Vec<MemoryRange>>,
    pub forbidden_mmio_ranges: BTreeMap<String, Vec<MemoryRange>>,
    pub cla_shared_ranges: Vec<MemoryRange>,
}

impl DeviceProfile {
    pub fn primary_core(&self) -> &CoreProfile {
        self.cores.iter().find(|c| c.is_primary).unwrap_or(&self.cores[0])
    }

    pub fn find_core(&self, core_name: &str) -> Option<&CoreProfile> {
        self.cores.iter().find(|c| c.name == core_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolNode {
    pub name: String,
    pub full_path: String,
    pub core: String,
    pub address: u32,
    pub page: String,
    pub data_type: DataType,
    pub word_size: u32,
    pub type_name: String,
    pub bit_offset: Option<u32>,
    pub bit_width: Option<u32>,
    pub container_units: Option<u32>,
    pub is_struct: bool,
    pub is_array: bool,
    pub array_len: usize,
    pub is_pointer: bool,
    pub is_function: bool,
    pub section_name: String,
    pub domain: PhysicalMemoryDomain,
    pub tu_scope: String,
    pub is_scratchpad: bool,
    pub children: Vec<SymbolNode>,
}

impl SymbolNode {
    pub fn is_bitfield(&self) -> bool {
        self.bit_offset.is_some() && self.bit_width.is_some()
    }

    pub fn is_leaf_scalar(&self) -> bool {
        !self.is_struct && !self.is_array && !self.is_function && self.children.is_empty()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum WriteState {
    #[default]
    Idle,
    Staged,
    Verified,
    Failed,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatchItem {
    pub id: String,
    pub core: String,
    pub symbol_path: String,
    pub address: u32,
    pub page: String,
    pub data_type: DataType,
    pub display_format: DisplayFormat,
    pub iq_q_bits: u32,
    pub bit_offset: Option<u32>,
    pub bit_width: Option<u32>,
    pub container_units: Option<u32>,
    pub rate_divider: u32,
    pub plot_pane: u8, // 0=Off, 1..=3
    pub color_index: usize,
    pub line_style: String, // "solid" | "dash" | "dot"
    pub pinned_tuner: bool,
    pub min_val: Option<f64>,
    pub max_val: Option<f64>,
    pub step: f64,
    pub read_only: bool,
    pub rmw_unlocked: bool,
    pub live_drag_write: bool,
    pub section_name: String,
    pub domain: PhysicalMemoryDomain,
    pub tu_scope: String,
    pub is_atomic: bool,
    pub user_setpoint: Option<f64>,
    #[serde(skip)]
    pub write_state: WriteState,
    #[serde(skip)]
    pub last_write_error: String,
}

impl WatchItem {
    pub fn is_bitfield(&self) -> bool {
        self.bit_offset.is_some() && self.bit_width.is_some()
    }

    pub fn effective_read_only(&self) -> bool {
        self.read_only || (self.is_bitfield() && !self.rmw_unlocked) || self.write_state == WriteState::Quarantined
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PollConfig {
    pub mode: PollMode,
    pub target_hz: f64,
    pub realtime_mode: RealtimeAccessMode,
    pub coalesce_gap: u32,
    pub max_block_units: u32,
    pub pause_on_write: bool,
    pub verify_after_write: bool,
    pub allow_rude_fallback: bool,
    pub pause_when_minimized: bool,
    pub verbose_ccs_logs: bool,
}

impl Default for PollConfig {
    fn default() -> Self {
        Self {
            mode: PollMode::MaxFreerun,
            target_hz: 200.0,
            realtime_mode: RealtimeAccessMode::SiliconRtPolite,
            coalesce_gap: 64,
            max_block_units: 512,
            pause_on_write: false,
            verify_after_write: true,
            allow_rude_fallback: false,
            pause_when_minimized: false,
            verbose_ccs_logs: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PollStats {
    pub achieved_hz: f64,
    pub latency_ms_avg: f64,
    pub dt_p95_ms: f64,
    pub span_count: usize,
    pub symbol_count: usize,
    pub words_per_sec: f64,
    pub error_count: u64,
    pub active_rt_mode: Option<RealtimeAccessMode>,
    pub running: bool,
    pub dlog_active: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectedProbe {
    pub probe_kind: ProbeKind,
    pub serial: String,
    pub description: String,
    pub firmware_version: String,
}

impl DetectedProbe {
    pub fn display_label(&self) -> String {
        let mut s = if self.serial.is_empty() {
            self.probe_kind.label().to_string()
        } else {
            format!("{} ({})", self.probe_kind.label(), self.serial)
        };
        if !self.firmware_version.is_empty() {
            s.push_str(&format!(" fw {}", self.firmware_version));
        }
        s
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionRequest {
    pub device_id: DeviceId,
    pub probe_kind: ProbeKind,
    pub serial: String,
    pub tclk_hz: String,
    pub jtag_mode: JtagMode,
    pub attach_live: bool,
    pub realtime_mode: RealtimeAccessMode,
    pub custom_ccxml_path: String,
    pub program_paths: BTreeMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ProblemRecord {
    pub time: String,
    pub severity: String,
    pub source: String,
    pub message: String,
}
