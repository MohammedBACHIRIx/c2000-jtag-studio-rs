//! Atomic JSON Workspace Profile Store (schema v2) with v1 forward migration and .corrupt.bak quarantine.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::core::models::{DeviceId, JtagMode, PollConfig, ProbeKind, ThemeMode, WatchItem};

pub const WORKSPACE_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkspaceProfile {
    #[serde(default = "default_schema")]
    pub schema_version: u32,
    pub profile_key: String,
    pub device_id: DeviceId,
    pub probe_kind: ProbeKind,
    #[serde(default)]
    pub probe_serial: String,
    #[serde(default = "default_tclk")]
    pub tclk_hz: String,
    #[serde(default = "default_jtag")]
    pub jtag_mode: JtagMode,
    #[serde(default)]
    pub custom_ccxml_path: String,
    #[serde(default)]
    pub program_paths: BTreeMap<String, String>,
    #[serde(default)]
    pub poll_config: PollConfig,
    #[serde(default)]
    pub watch_items: Vec<WatchItem>,
    #[serde(default)]
    pub tuning_presets: BTreeMap<String, BTreeMap<String, f64>>,
    #[serde(default)]
    pub safe_baseline: BTreeMap<String, f64>,
    #[serde(default = "default_panes")]
    pub plot_panes: usize,
    #[serde(default = "default_win")]
    pub plot_window_sec: Option<f64>,
    #[serde(default)]
    pub theme_mode: ThemeMode,
    #[serde(default = "default_scale")]
    pub ui_scale_pct: u32,
    #[serde(default = "default_persp")]
    pub perspective_name: String,
}

fn default_schema() -> u32 {
    1
}
fn default_tclk() -> String {
    "5.5MHz".into()
}
fn default_jtag() -> JtagMode {
    JtagMode::Jtag4Pin
}
fn default_panes() -> usize {
    2
}
fn default_win() -> Option<f64> {
    Some(10.0)
}
fn default_scale() -> u32 {
    100
}
fn default_persp() -> String {
    "tune".into()
}

pub fn profile_key_for(kind: ProbeKind, serial: &str, device: DeviceId) -> String {
    let ser = if serial.is_empty() { "AUTO" } else { serial };
    format!("{:?}_{ser}_{:?}", kind, device)
}

pub struct WorkspaceStore {
    root: PathBuf,
}

impl WorkspaceStore {
    pub fn new(root: Option<PathBuf>) -> Self {
        let dir = root.unwrap_or_else(|| {
            let base = std::env::var_os("LOCALAPPDATA")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("."));
            base.join("C2000JtagStudioRs").join("profiles")
        });
        let _ = fs::create_dir_all(&dir);
        Self { root: dir }
    }

    fn path_for_key(&self, key: &str) -> PathBuf {
        let safe: String = key
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
            .collect();
        self.root.join(format!("{safe}.json"))
    }

    pub fn save(&self, profile: &WorkspaceProfile, explicit_path: Option<&Path>) -> Result<PathBuf, String> {
        let dest = explicit_path
            .map(PathBuf::from)
            .unwrap_or_else(|| self.path_for_key(&profile.profile_key));
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let mut p = profile.clone();
        p.schema_version = WORKSPACE_SCHEMA_VERSION;
        let json = serde_json::to_string_pretty(&p).map_err(|e| e.to_string())?;
        let tmp = dest.with_extension(format!("json.{}.tmp", std::process::id()));
        fs::write(&tmp, json).map_err(|e| e.to_string())?;
        fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
        Ok(dest)
    }

    pub fn load(&self, key_or_path: &Path) -> Option<WorkspaceProfile> {
        let path = if key_or_path.is_file() {
            key_or_path.to_path_buf()
        } else {
            self.path_for_key(&key_or_path.to_string_lossy())
        };
        if !path.is_file() {
            return None;
        }
        let text = fs::read_to_string(&path).ok()?;
        match serde_json::from_str::<WorkspaceProfile>(&text) {
            Ok(mut prof) => {
                if prof.schema_version < WORKSPACE_SCHEMA_VERSION {
                    prof.poll_config.verify_after_write = true;
                    prof.schema_version = WORKSPACE_SCHEMA_VERSION;
                }
                Some(prof)
            }
            Err(_) => {
                let bak = PathBuf::from(format!("{}.corrupt.bak", path.display()));
                let _ = fs::copy(&path, &bak);
                None
            }
        }
    }
}
