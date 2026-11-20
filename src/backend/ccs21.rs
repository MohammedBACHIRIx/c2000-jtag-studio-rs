//! Native Rust TI CCS 21 CloudAgent DebugBackend over RFC 6455 localhost WebSocket JSON-RPC.
//! Zero Python runtime dependency; child CloudAgent process is contained inside a Windows Job Object.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use crate::backend::ccs_env::{discover_ccs_environment, CcsEnvironment};
use crate::backend::ccxml::{generate_ccxml, sanitize_custom_ccxml_strip_gel};
use crate::backend::job_object::WindowsJobObject;
use crate::backend::ws_rpc::WsRpcClient;
use crate::backend::DebugBackend;
use crate::core::devices::get_device_profile;
use crate::core::models::{
    ConnectionRequest, CoreState, DeviceId, MemCfgSnapshot, ProbeKind, RealtimeAccessMode,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const SETUP_TIMEOUT: Duration = Duration::from_secs(45);
const POLL_OP_TIMEOUT: Duration = Duration::from_millis(1500);

pub struct Ccs21Backend {
    env: CcsEnvironment,
    job: Option<WindowsJobObject>,
    child: Option<Child>,
    host_agent: Option<WsRpcClient>,
    ds: Option<WsRpcClient>,
    sessions: BTreeMap<String, WsRpcClient>,
    core_states: BTreeMap<String, CoreState>,
    rt_modes: BTreeMap<String, RealtimeAccessMode>,
    device_id: DeviceId,
    allow_rude_fallback: bool,
    temp_ccxml: Option<PathBuf>,
}

impl Ccs21Backend {
    pub fn new(ccs_root: Option<&Path>) -> Self {
        Self {
            env: discover_ccs_environment(ccs_root),
            job: None,
            child: None,
            host_agent: None,
            ds: None,
            sessions: BTreeMap::new(),
            core_states: BTreeMap::new(),
            rt_modes: BTreeMap::new(),
            device_id: DeviceId::F28069M,
            allow_rude_fallback: false,
            temp_ccxml: None,
        }
    }

    pub fn launch_cloudagent_and_ds(&mut self) -> Result<u16, String> {
        let ca_dir = self
            .env
            .cloudagent_dir
            .clone()
            .ok_or_else(|| "TI CCS 21 CloudAgent directory not found.".to_string())?;
        let node = ca_dir.join("node.exe");
        let main_js = ca_dir.join("src").join("main.js");
        if !node.is_file() || !main_js.is_file() {
            return Err(format!("CloudAgent node/main.js missing in {}", ca_dir.display()));
        }

        let job = WindowsJobObject::create();
        let mut child = Command::new(&node)
            .arg(&main_js)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| format!("Failed to spawn TI CloudAgent: {e}"))?;

        if let Some(j) = &job {
            j.assign_child(&child);
        }

        let stdout = child.stdout.take().ok_or("CloudAgent stdout unavailable")?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut port: Option<u16> = None;
        for _ in 0..16 {
            line.clear();
            let n = reader.read_line(&mut line).map_err(|e| e.to_string())?;
            if n == 0 {
                break;
            }
            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                if let Some(p) = v.get("port").and_then(Value::as_u64) {
                    port = Some(p as u16);
                    break;
                }
            }
        }
        let port = port.ok_or_else(|| "TI CloudAgent exited before announcing WebSocket port".to_string())?;

        // Drain stdout in background so pipe never stalls CloudAgent
        std::thread::spawn(move || {
            let mut sink = String::new();
            while reader.read_line(&mut sink).unwrap_or(0) > 0 {
                sink.clear();
            }
        });

        let mut host = WsRpcClient::connect(port, None, SETUP_TIMEOUT)?;
        let _ = host.call(
            "addConfigProperty",
            vec![
                json!("cloudAgentInstallerServerURL"),
                json!(format!("http://localhost:{port}/ticloudagent")),
            ],
            SETUP_TIMEOUT,
        );
        let ds = host.create_sub_module("DS", SETUP_TIMEOUT)?;

        self.job = job;
        self.child = Some(child);
        self.host_agent = Some(host);
        self.ds = Some(ds);
        Ok(port)
    }

    pub fn version_info(&mut self) -> Result<Value, String> {
        let ds = self.ds.as_mut().ok_or("DS module not initialized")?;
        ds.call("scripting.versionInfo", vec![], SETUP_TIMEOUT)
    }

    /// Fail-closed GEL unloader: unloads every attached GEL script and asserts zero remain before target.connect().
    pub fn unload_session_gels_fail_closed(sess: &mut WsRpcClient) -> Result<Vec<String>, String> {
        let loaded = sess.call("gel.getLoadedFiles", vec![], SETUP_TIMEOUT)?;
        let files = loaded
            .get("files")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut unloaded = Vec::new();
        for entry in files {
            let fname = entry
                .get("fileName")
                .and_then(Value::as_str)
                .or_else(|| entry.as_str())
                .unwrap_or("");
            if !fname.is_empty() {
                let _ = sess.call("gel.unloadFile", vec![json!(fname)], SETUP_TIMEOUT);
                unloaded.push(fname.to_string());
            }
        }
        let verify = sess.call("gel.getLoadedFiles", vec![], SETUP_TIMEOUT)?;
        let remaining = verify
            .get("files")
            .and_then(Value::as_array)
            .map(|a| a.len())
            .unwrap_or(0);
        if remaining > 0 {
            return Err(format!(
                "Attach Live aborted (fail-closed): {remaining} GEL script(s) still loaded before connect. \
                 Running OnTargetConnect() could zero RAM or reset a live power stage."
            ));
        }
        Ok(unloaded)
    }

    fn apply_rt_settings(sess: &mut WsRpcClient, mode: RealtimeAccessMode) -> Result<(), String> {
        match mode {
            RealtimeAccessMode::SiliconRtPolite => {
                let _ = sess.call("scripting.settings.setBoolean", vec![json!("EnableRealtimeMode"), json!(true)], SETUP_TIMEOUT);
                let _ = sess.call("scripting.settings.setBoolean", vec![json!("EnablePoliteRealtimeMode"), json!(true)], SETUP_TIMEOUT);
            }
            RealtimeAccessMode::SiliconRtRude => {
                let _ = sess.call("scripting.settings.setBoolean", vec![json!("EnableRealtimeMode"), json!(true)], SETUP_TIMEOUT);
                let _ = sess.call("scripting.settings.setBoolean", vec![json!("EnablePoliteRealtimeMode"), json!(false)], SETUP_TIMEOUT);
            }
            RealtimeAccessMode::StopModeHalt => {
                let _ = sess.call("scripting.settings.setBoolean", vec![json!("EnableRealtimeMode"), json!(false)], SETUP_TIMEOUT);
            }
        }
        Ok(())
    }
}

impl DebugBackend for Ccs21Backend {
    fn connect(&mut self, req: &ConnectionRequest) -> Result<BTreeMap<String, CoreState>, String> {
        self.disconnect();
        self.device_id = req.device_id;
        let profile = get_device_profile(req.device_id);
        for c in &profile.cores {
            self.core_states.insert(c.name.to_string(), CoreState::Disconnected);
            self.rt_modes.insert(c.name.to_string(), req.realtime_mode);
        }

        // Generate or sanitize .ccxml with fail-closed GEL stripping during Attach Live
        let tmp_ccxml = std::env::temp_dir().join(format!("c2000_rs_{}.ccxml", std::process::id()));
        let ccxml_path = if req.probe_kind == ProbeKind::CUSTOM_CCXML && !req.custom_ccxml_path.is_empty() {
            if req.attach_live {
                sanitize_custom_ccxml_strip_gel(Path::new(&req.custom_ccxml_path), &tmp_ccxml)?
            } else {
                PathBuf::from(&req.custom_ccxml_path)
            }
        } else {
            generate_ccxml(
                &tmp_ccxml,
                req.device_id,
                req.probe_kind,
                &req.tclk_hz,
                req.jtag_mode,
                &req.serial,
                req.attach_live,
            )?
        };
        self.temp_ccxml = Some(tmp_ccxml);

        self.launch_cloudagent_and_ds()?;
        let ds = self.ds.as_mut().ok_or("DS module missing")?;
        ds.call(
            "scripting.configure",
            vec![json!(ccxml_path.to_string_lossy().to_string())],
            SETUP_TIMEOUT,
        )?;

        let primary = profile.primary_core().name.to_string();
        self.connect_core(&primary, req.attach_live)?;
        self.set_realtime_mode(&primary, req.realtime_mode)?;
        Ok(self.core_states.clone())
    }

    fn disconnect(&mut self) {
        let keys: Vec<String> = self.sessions.keys().cloned().collect();
        for k in keys {
            if let Some(mut s) = self.sessions.remove(&k) {
                let _ = s.call("scripting.target.disconnect", vec![], Duration::from_secs(2));
                s.close();
            }
        }
        if let Some(mut ds) = self.ds.take() {
            let _ = ds.call("scripting.deconfigure", vec![], Duration::from_secs(2));
            ds.close();
        }
        if let Some(host) = self.host_agent.take() {
            host.close();
        }
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        if let Some(mut j) = self.job.take() {
            j.terminate();
        }
        if let Some(p) = self.temp_ccxml.take() {
            let _ = std::fs::remove_file(p);
        }
        for st in self.core_states.values_mut() {
            *st = CoreState::Disconnected;
        }
    }

    fn connect_core(&mut self, core: &str, attach_live: bool) -> Result<CoreState, String> {
        let ds = self.ds.as_mut().ok_or("CCS DS not connected")?;
        let core_list = ds.call("scripting.listCores", vec![], SETUP_TIMEOUT)?;
        let full_name = core_list
            .get("cores")
            .and_then(Value::as_array)
            .and_then(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .find(|name| name.contains(core))
                    .map(String::from)
            })
            .unwrap_or_else(|| core.to_string());

        let mut sess = ds.create_sub_module(&full_name, SETUP_TIMEOUT)?;
        if attach_live {
            Self::unload_session_gels_fail_closed(&mut sess)?;
            let mode = *self.rt_modes.get(core).unwrap_or(&RealtimeAccessMode::SiliconRtPolite);
            Self::apply_rt_settings(&mut sess, mode)?;
        }
        sess.call("scripting.target.connect", vec![], SETUP_TIMEOUT)?;
        let is_halted = sess
            .call("scripting.target.isHalted", vec![], POLL_OP_TIMEOUT)
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let st = if is_halted {
            CoreState::ConnectedHalted
        } else {
            match self.rt_modes.get(core).copied().unwrap_or(RealtimeAccessMode::SiliconRtPolite) {
                RealtimeAccessMode::SiliconRtRude => CoreState::ConnectedRtRude,
                RealtimeAccessMode::SiliconRtPolite => CoreState::ConnectedRtPolite,
                RealtimeAccessMode::StopModeHalt => CoreState::ConnectedRunning,
            }
        };
        self.sessions.insert(core.to_string(), sess);
        self.core_states.insert(core.to_string(), st);
        Ok(st)
    }

    fn disconnect_core(&mut self, core: &str) -> Result<CoreState, String> {
        if let Some(mut sess) = self.sessions.remove(core) {
            let _ = sess.call("scripting.target.disconnect", vec![], Duration::from_secs(2));
            sess.close();
        }
        self.core_states.insert(core.to_string(), CoreState::Disconnected);
        Ok(CoreState::Disconnected)
    }

    fn quiesce_all_masters(&mut self) {
        for (core, sess) in self.sessions.iter_mut() {
            let _ = sess.call("scripting.target.halt", vec![], Duration::from_secs(2));
            self.core_states.insert(core.clone(), CoreState::ConnectedHalted);
        }
    }

    fn load_program(&mut self, core: &str, path: &Path) -> Result<CoreState, String> {
        self.quiesce_all_masters();
        let sess = self.sessions.get_mut(core).ok_or_else(|| format!("Core {core} not attached"))?;
        sess.call(
            "scripting.memory.loadProgram",
            vec![json!(path.to_string_lossy().to_string())],
            Duration::from_secs(90),
        )?;
        self.core_states.insert(core.to_string(), CoreState::ConnectedHalted);
        Ok(CoreState::ConnectedHalted)
    }

    fn load_symbols(&mut self, core: &str, path: &Path) -> Result<(), String> {
        let sess = self.sessions.get_mut(core).ok_or_else(|| format!("Core {core} not attached"))?;
        sess.call(
            "scripting.symbols.load",
            vec![json!(path.to_string_lossy().to_string())],
            SETUP_TIMEOUT,
        )?;
        Ok(())
    }

    fn run_core(&mut self, core: &str) -> Result<CoreState, String> {
        let sess = self.sessions.get_mut(core).ok_or_else(|| format!("Core {core} not attached"))?;
        sess.call("scripting.target.runAsynch", vec![], POLL_OP_TIMEOUT)?;
        let st = match self.rt_modes.get(core).copied().unwrap_or(RealtimeAccessMode::SiliconRtPolite) {
            RealtimeAccessMode::SiliconRtRude => CoreState::ConnectedRtRude,
            RealtimeAccessMode::SiliconRtPolite => CoreState::ConnectedRtPolite,
            RealtimeAccessMode::StopModeHalt => CoreState::ConnectedRunning,
        };
        self.core_states.insert(core.to_string(), st);
        Ok(st)
    }

    fn halt_core(&mut self, core: &str) -> Result<CoreState, String> {
        let sess = self.sessions.get_mut(core).ok_or_else(|| format!("Core {core} not attached"))?;
        sess.call("scripting.target.halt", vec![], Duration::from_secs(3))?;
        self.core_states.insert(core.to_string(), CoreState::ConnectedHalted);
        Ok(CoreState::ConnectedHalted)
    }

    fn reset_core(&mut self, core: &str) -> Result<CoreState, String> {
        let sess = self.sessions.get_mut(core).ok_or_else(|| format!("Core {core} not attached"))?;
        sess.call("scripting.target.reset", vec![], Duration::from_secs(5))?;
        self.core_states.insert(core.to_string(), CoreState::ConnectedHalted);
        Ok(CoreState::ConnectedHalted)
    }

    fn set_realtime_mode(&mut self, core: &str, mode: RealtimeAccessMode) -> Result<CoreState, String> {
        self.rt_modes.insert(core.to_string(), mode);
        let Some(sess) = self.sessions.get_mut(core) else {
            return Ok(CoreState::Disconnected);
        };
        Self::apply_rt_settings(sess, mode)?;
        let st = if self.core_states.get(core) == Some(&CoreState::ConnectedHalted) {
            CoreState::ConnectedHalted
        } else {
            match mode {
                RealtimeAccessMode::SiliconRtRude => CoreState::ConnectedRtRude,
                RealtimeAccessMode::SiliconRtPolite => CoreState::ConnectedRtPolite,
                RealtimeAccessMode::StopModeHalt => CoreState::ConnectedRunning,
            }
        };
        self.core_states.insert(core.to_string(), st);
        Ok(st)
    }

    fn set_allow_rude_fallback(&mut self, allow: bool) {
        self.allow_rude_fallback = allow;
    }

    fn micro_halt_clear_dbgm(&mut self, core: &str) -> Result<CoreState, String> {
        let sess = self.sessions.get_mut(core).ok_or_else(|| format!("Core {core} not attached"))?;
        sess.call("scripting.target.halt", vec![], Duration::from_secs(2))?;
        let _ = sess.call("scripting.expressions.evaluate", vec![json!("ST1 &= ~0x0002")], POLL_OP_TIMEOUT);
        Self::apply_rt_settings(sess, RealtimeAccessMode::SiliconRtPolite)?;
        sess.call("scripting.target.runAsynch", vec![], POLL_OP_TIMEOUT)?;
        self.rt_modes.insert(core.to_string(), RealtimeAccessMode::SiliconRtPolite);
        self.core_states.insert(core.to_string(), CoreState::ConnectedRtPolite);
        Ok(CoreState::ConnectedRtPolite)
    }

    fn read_block(&mut self, core: &str, address: u32, count: u32, bit_size: u32, page: &str) -> Result<Vec<u32>, String> {
        let do_read = |sess: &mut WsRpcClient| -> Result<Vec<u32>, String> {
            let args = if page.is_empty() {
                vec![json!(address), json!(count), json!(bit_size)]
            } else {
                vec![json!(address), json!(count), json!(bit_size), json!(page)]
            };
            let res = sess.call("scripting.memory.read", args, POLL_OP_TIMEOUT)?;
            let arr = res
                .as_array()
                .or_else(|| res.get("values").and_then(Value::as_array))
                .ok_or_else(|| format!("Unexpected memory.read payload: {res}"))?;
            Ok(arr.iter().map(|v| v.as_u64().unwrap_or(0) as u32).collect())
        };

        let sess = self.sessions.get_mut(core).ok_or_else(|| format!("Core {core} not attached"))?;
        match do_read(sess) {
            Ok(vals) => Ok(vals),
            Err(first_err) => {
                // Fail-closed: NEVER silently escalate Polite -> Rude unless explicitly opted in
                let is_polite = self.rt_modes.get(core) == Some(&RealtimeAccessMode::SiliconRtPolite);
                if self.allow_rude_fallback && is_polite {
                    let _ = Self::apply_rt_settings(sess, RealtimeAccessMode::SiliconRtRude);
                    let retry = do_read(sess);
                    let _ = Self::apply_rt_settings(sess, RealtimeAccessMode::SiliconRtPolite);
                    return retry;
                }
                Err(first_err)
            }
        }
    }

    fn write_block(&mut self, core: &str, address: u32, values: &[u32], bit_size: u32, page: &str) -> Result<(), String> {
        let do_write = |sess: &mut WsRpcClient| -> Result<(), String> {
            let args = if page.is_empty() {
                vec![json!(address), json!(values), json!(bit_size)]
            } else {
                vec![json!(address), json!(values), json!(bit_size), json!(page)]
            };
            sess.call("scripting.memory.write", args, POLL_OP_TIMEOUT)?;
            Ok(())
        };

        let sess = self.sessions.get_mut(core).ok_or_else(|| format!("Core {core} not attached"))?;
        match do_write(sess) {
            Ok(()) => Ok(()),
            Err(first_err) => {
                let is_polite = self.rt_modes.get(core) == Some(&RealtimeAccessMode::SiliconRtPolite);
                if self.allow_rude_fallback && is_polite {
                    let _ = Self::apply_rt_settings(sess, RealtimeAccessMode::SiliconRtRude);
                    let retry = do_write(sess);
                    let _ = Self::apply_rt_settings(sess, RealtimeAccessMode::SiliconRtPolite);
                    return retry;
                }
                Err(first_err)
            }
        }
    }

    fn probe_memcfg(&mut self, core: &str) -> MemCfgSnapshot {
        if self.device_id == DeviceId::F28388D {
            let ls_msel = self.read_block(core, 0x05F420, 1, 32, "DATA").ok().and_then(|v| v.first().copied()).unwrap_or(0);
            let ls_clapgm = self.read_block(core, 0x05F422, 1, 32, "DATA").ok().and_then(|v| v.first().copied()).unwrap_or(0);
            let gs_msel = self.read_block(core, 0x05F444, 1, 32, "DATA").ok().and_then(|v| v.first().copied()).unwrap_or(0);
            let z1_cr = self.read_block(core, 0x05F014, 1, 32, "DATA").ok().and_then(|v| v.first().copied()).unwrap_or(0xFFFFFFFF);
            let z2_cr = self.read_block(core, 0x05F054, 1, 32, "DATA").ok().and_then(|v| v.first().copied()).unwrap_or(0xFFFFFFFF);
            MemCfgSnapshot {
                ls_msel,
                ls_clapgm,
                gs_msel,
                dcsm_z1_locked: (z1_cr & (1 << 5)) == 0,
                dcsm_z2_locked: (z2_cr & (1 << 5)) == 0,
                probed: true,
            }
        } else {
            let csms = self.read_block(core, 0x000AEF, 1, 16, "DATA").ok().and_then(|v| v.first().copied()).unwrap_or(0);
            MemCfgSnapshot {
                dcsm_z1_locked: (csms & 0x1) != 0,
                probed: true,
                ..Default::default()
            }
        }
    }

    fn unlock_dcsm(&mut self, core: &str, zone: u8, keys: &[u32]) -> Result<bool, String> {
        if self.device_id == DeviceId::F28388D {
            let base = if zone == 2 { 0x05F050 } else { 0x05F010 };
            for (i, &k) in keys.iter().take(4).enumerate() {
                self.write_block(core, base + (i as u32) * 2, &[k], 32, "DATA")?;
            }
            let snap = self.probe_memcfg(core);
            Ok(if zone == 2 { !snap.dcsm_z2_locked } else { !snap.dcsm_z1_locked })
        } else {
            // F28069M CSMKEY0..7 at 0x0AE0..0x0AE7 (16-bit words)
            for (i, &k) in keys.iter().take(4).enumerate() {
                let lo = k & 0xFFFF;
                let hi = (k >> 16) & 0xFFFF;
                self.write_block(core, 0x000AE0 + (i as u32) * 2, &[lo, hi], 16, "DATA")?;
            }
            let snap = self.probe_memcfg(core);
            Ok(!snap.dcsm_z1_locked)
        }
    }

    fn get_core_states(&self) -> BTreeMap<String, CoreState> {
        self.core_states.clone()
    }
}

impl Drop for Ccs21Backend {
    fn drop(&mut self) {
        self.disconnect();
    }
}
