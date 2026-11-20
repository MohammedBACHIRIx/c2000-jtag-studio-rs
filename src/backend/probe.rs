//! XDS110 / XDS100v2 USB probe discovery, dbgjtag scan-chain integrity test, TCLK staircase, and USB-only reset.

use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;

use crate::backend::ccs_env::{discover_ccs_environment, CcsEnvironment};
use crate::backend::ccxml::generate_uscif_dat;
use crate::core::devices::probe_tclk_options;
use crate::core::models::{DetectedProbe, DeviceId, JtagMode, ProbeKind};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone)]
pub struct JtagTestResult {
    pub tclk_label: String,
    pub passed: bool,
    pub output: String,
}

pub fn parse_xdsdfu_output(text: &str) -> Vec<DetectedProbe> {
    let mut out = Vec::new();
    let mut cur_serial = String::new();
    let mut cur_ver = String::new();
    for line in text.lines() {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("Serial Num:") {
            cur_serial = rest.trim().to_string();
        } else if let Some(rest) = t.strip_prefix("Version:") {
            cur_ver = rest.trim().to_string();
        } else if t.starts_with("<<<< Device") && !cur_serial.is_empty() {
            out.push(DetectedProbe {
                probe_kind: ProbeKind::XDS110,
                serial: std::mem::take(&mut cur_serial),
                description: "TI XDS110 USB Debug Probe".into(),
                firmware_version: std::mem::take(&mut cur_ver),
            });
        }
    }
    if !cur_serial.is_empty() {
        out.push(DetectedProbe {
            probe_kind: ProbeKind::XDS110,
            serial: cur_serial,
            description: "TI XDS110 USB Debug Probe".into(),
            firmware_version: cur_ver,
        });
    }
    out
}

pub fn parse_xds100serial_output(text: &str) -> Vec<DetectedProbe> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        if t.contains("XDS100v2") || t.contains("TI XDS100") {
            let parts: Vec<&str> = t.split_whitespace().collect();
            let serial = parts.last().copied().unwrap_or("").to_string();
            if !serial.is_empty() && serial != "none" {
                out.push(DetectedProbe {
                    probe_kind: ProbeKind::XDS100V2,
                    serial,
                    description: "TI XDS100v2 USB Debug Probe".into(),
                    firmware_version: String::new(),
                });
            }
        }
    }
    out
}

pub fn scan_connected_probes(env: Option<&CcsEnvironment>) -> Vec<DetectedProbe> {
    let owned;
    let env = match env {
        Some(e) => e,
        None => {
            owned = discover_ccs_environment(None);
            &owned
        }
    };
    let mut probes = Vec::new();
    if let Some(exe) = &env.xdsdfu_exe {
        if let Ok(out) = Command::new(exe)
            .arg("-e")
            .creation_flags(CREATE_NO_WINDOW)
            .output()
        {
            let text = String::from_utf8_lossy(&out.stdout);
            probes.extend(parse_xdsdfu_output(&text));
        }
    }
    if let Some(exe) = &env.xds100serial_exe {
        if let Ok(out) = Command::new(exe).creation_flags(CREATE_NO_WINDOW).output() {
            let text = String::from_utf8_lossy(&out.stdout);
            probes.extend(parse_xds100serial_output(&text));
        }
    }
    probes
}

pub fn run_jtag_integrity_test(
    dat_file: &Path,
    tclk_label: &str,
    env: Option<&CcsEnvironment>,
) -> JtagTestResult {
    let owned;
    let env = match env {
        Some(e) => e,
        None => {
            owned = discover_ccs_environment(None);
            &owned
        }
    };
    let Some(exe) = &env.dbgjtag_exe else {
        return JtagTestResult {
            tclk_label: tclk_label.to_string(),
            passed: false,
            output: "dbgjtag.exe not found in CCS installation.".into(),
        };
    };
    let res = Command::new(exe)
        .args(["-f", &dat_file.to_string_lossy(), "-rv", "-S", "integrity"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match res {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            let passed = out.status.success() && combined.to_ascii_lowercase().contains("succeeded");
            JtagTestResult {
                tclk_label: tclk_label.to_string(),
                passed,
                output: combined.trim().to_string(),
            }
        }
        Err(e) => JtagTestResult {
            tclk_label: tclk_label.to_string(),
            passed: false,
            output: format!("Failed to invoke dbgjtag.exe: {e}"),
        },
    }
}

pub fn probe_max_tclk_staircase(
    device_id: DeviceId,
    probe_kind: ProbeKind,
    serial: &str,
    jtag_mode: JtagMode,
    backoff_steps: usize,
) -> (Option<String>, Vec<JtagTestResult>) {
    let opts = probe_tclk_options(probe_kind);
    let env = discover_ccs_environment(None);
    let mut results = Vec::new();
    let mut passed_list = Vec::new();
    let tmp_dat = std::env::temp_dir().join("c2000_rs_tclk_probe.dat");

    for &tclk in opts {
        if let Err(e) = generate_uscif_dat(&tmp_dat, device_id, probe_kind, tclk, jtag_mode, serial) {
            results.push(JtagTestResult {
                tclk_label: tclk.into(),
                passed: false,
                output: e,
            });
            break;
        }
        let r = run_jtag_integrity_test(&tmp_dat, tclk, Some(&env));
        let ok = r.passed;
        results.push(r);
        if ok {
            passed_list.push(tclk.to_string());
        } else {
            break;
        }
    }
    let _ = std::fs::remove_file(&tmp_dat);
    if passed_list.is_empty() {
        return (None, results);
    }
    let idx = passed_list.len().saturating_sub(1 + backoff_steps);
    (Some(passed_list[idx].clone()), results)
}

/// Reboot ONLY the XDS110 probe USB interface via `xdsdfu -r` (never toggles target nRESET).
pub fn reset_xds110_probe_only(serial: &str) -> (bool, String) {
    let env = discover_ccs_environment(None);
    let Some(exe) = &env.xdsdfu_exe else {
        return (false, "xdsdfu.exe not found.".into());
    };
    let mut cmd = Command::new(exe);
    if !serial.is_empty() {
        cmd.args(["-s", serial]);
    }
    cmd.arg("-r").creation_flags(CREATE_NO_WINDOW);
    match cmd.output() {
        Ok(out) => {
            let txt = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            (out.status.success(), txt.trim().to_string())
        }
        Err(e) => (false, format!("xdsdfu launch error: {e}")),
    }
}
