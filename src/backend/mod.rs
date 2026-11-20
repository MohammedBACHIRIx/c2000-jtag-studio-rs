pub mod aux_uart;
pub mod ccs21;
pub mod ccs_env;
pub mod ccxml;
pub mod job_object;
pub mod probe;
pub mod sim;
pub mod worker;
pub mod ws_rpc;

use std::collections::BTreeMap;
use std::path::Path;

use crate::core::models::{
    ConnectionRequest, CoreState, MemCfgSnapshot, RealtimeAccessMode, SymbolNode,
};

#[derive(Debug, Clone)]
pub struct DlogBurst {
    pub dt_sec: f64,
    pub overrun: bool,
    pub channels: Vec<(String, Vec<f64>)>,
}

/// Hardware-agnostic C2000 Debug Backend trait implemented by both Native CCS 21 CloudAgent and Offline Simulator.
pub trait DebugBackend: Send {
    fn connect(&mut self, req: &ConnectionRequest) -> Result<BTreeMap<String, CoreState>, String>;
    fn disconnect(&mut self);
    fn shutdown(&mut self) {
        self.disconnect();
    }
    fn connect_core(&mut self, core: &str, attach_live: bool) -> Result<CoreState, String>;
    fn disconnect_core(&mut self, core: &str) -> Result<CoreState, String>;
    fn load_program(&mut self, core: &str, path: &Path) -> Result<CoreState, String>;
    fn load_symbols(&mut self, core: &str, path: &Path) -> Result<(), String>;
    fn run_core(&mut self, core: &str) -> Result<CoreState, String>;
    fn halt_core(&mut self, core: &str) -> Result<CoreState, String>;
    fn reset_core(&mut self, core: &str) -> Result<CoreState, String>;
    fn set_realtime_mode(&mut self, core: &str, mode: RealtimeAccessMode) -> Result<CoreState, String>;
    fn set_allow_rude_fallback(&mut self, _allow: bool) {}
    fn micro_halt_clear_dbgm(&mut self, core: &str) -> Result<CoreState, String>;
    fn read_block(&mut self, core: &str, address: u32, count: u32, bit_size: u32, page: &str) -> Result<Vec<u32>, String>;
    fn write_block(&mut self, core: &str, address: u32, values: &[u32], bit_size: u32, page: &str) -> Result<(), String>;
    fn get_core_states(&self) -> BTreeMap<String, CoreState>;
    fn get_builtin_symbols(&self, _core: &str) -> Vec<SymbolNode> {
        Vec::new()
    }
    fn probe_memcfg(&mut self, _core: &str) -> MemCfgSnapshot {
        MemCfgSnapshot::default()
    }
    fn unlock_dcsm(&mut self, _core: &str, _zone: u8, _keys: &[u32]) -> Result<bool, String> {
        Ok(true)
    }
    fn quiesce_all_masters(&mut self) {}
    fn read_flash_fingerprint(&mut self, core: &str, address: u32, word_count: u32, page: &str) -> Result<Vec<u32>, String> {
        self.read_block(core, address, word_count, 16, page)
    }
    fn configure_dlog(&mut self, _enabled: bool, _trigger_mode: &str, _level: f64) -> bool {
        false
    }
    fn get_dlog_burst(&mut self) -> Option<DlogBurst> {
        None
    }
}
