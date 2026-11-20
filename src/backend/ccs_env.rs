//! SemVer-sorted discovery of TI Code Composer Studio 21.x, CloudAgent, probe utilities, and object dumpers.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct CcsEnvironment {
    pub ccs_root: Option<PathBuf>,
    pub cloudagent_dir: Option<PathBuf>,
    pub targetdb_dir: Option<PathBuf>,
    pub xdsdfu_exe: Option<PathBuf>,
    pub xds100serial_exe: Option<PathBuf>,
    pub dbgjtag_exe: Option<PathBuf>,
    pub ofd2000_exe: Option<PathBuf>,
    pub tiarmofd_exe: Option<PathBuf>,
    pub cl2000_exe: Option<PathBuf>,
}

impl CcsEnvironment {
    pub fn cloudagent_available(&self) -> bool {
        self.cloudagent_dir
            .as_ref()
            .is_some_and(|d| d.join("node.exe").is_file() && d.join("src").join("main.js").is_file())
    }

    pub fn diagnostic_lines(&self) -> Vec<(String, String)> {
        let fmt = |p: &Option<PathBuf>| {
            p.as_ref()
                .map(|x| x.display().to_string())
                .unwrap_or_else(|| "Not Found".to_string())
        };
        vec![
            ("CCS Root".into(), fmt(&self.ccs_root)),
            ("CloudAgent".into(), fmt(&self.cloudagent_dir)),
            ("TargetDB".into(), fmt(&self.targetdb_dir)),
            ("xdsdfu.exe".into(), fmt(&self.xdsdfu_exe)),
            ("xds100serial.exe".into(), fmt(&self.xds100serial_exe)),
            ("dbgjtag.exe".into(), fmt(&self.dbgjtag_exe)),
            ("ofd2000.exe".into(), fmt(&self.ofd2000_exe)),
            ("tiarmofd.exe".into(), fmt(&self.tiarmofd_exe)),
            ("cl2000.exe".into(), fmt(&self.cl2000_exe)),
        ]
    }
}

fn version_sort_key(path: &Path) -> (Vec<u64>, String) {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    let mut nums = Vec::new();
    let mut cur = String::new();
    for ch in name.chars() {
        if ch.is_ascii_digit() {
            cur.push(ch);
        } else if !cur.is_empty() {
            if let Ok(v) = cur.parse::<u64>() {
                nums.push(v);
            }
            cur.clear();
        }
    }
    if !cur.is_empty() {
        if let Ok(v) = cur.parse::<u64>() {
            nums.push(v);
        }
    }
    (nums, name.to_ascii_lowercase())
}

fn find_ccs_root(explicit: Option<&Path>) -> Option<PathBuf> {
    let mut cands = Vec::new();
    if let Some(p) = explicit {
        cands.push(p.to_path_buf());
    }
    if let Ok(env_root) = std::env::var("CCS_ROOT") {
        if !env_root.is_empty() {
            cands.push(PathBuf::from(env_root));
        }
    }
    let ti_base = Path::new(r"C:\ti");
    if ti_base.is_dir() {
        if let Ok(rd) = fs::read_dir(ti_base) {
            let mut dirs: Vec<PathBuf> = rd
                .filter_map(|e| e.ok().map(|x| x.path()))
                .filter(|p| {
                    p.is_dir()
                        && p.file_name()
                            .and_then(|s| s.to_str())
                            .is_some_and(|n| n.to_ascii_lowercase().starts_with("ccs"))
                })
                .collect();
            dirs.sort_by_key(|a| std::cmp::Reverse(version_sort_key(a)));
            for d in dirs {
                let inner = d.join("ccs");
                if inner.join("ccs_base").is_dir() {
                    cands.push(inner);
                } else {
                    cands.push(d);
                }
            }
        }
    }
    for c in cands {
        if c.join("ccs_base").is_dir() {
            return Some(c);
        }
        if c.join("ccs").join("ccs_base").is_dir() {
            return Some(c.join("ccs"));
        }
    }
    None
}

fn pick_compiler_tool(root: &Path, prefix: &str, exe_name: &str) -> Option<PathBuf> {
    let comp_dir = root.join("tools").join("compiler");
    let rd = fs::read_dir(&comp_dir).ok()?;
    let mut dirs: Vec<PathBuf> = rd
        .filter_map(|e| e.ok().map(|x| x.path()))
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|s| s.to_str())
                    .is_some_and(|n| n.to_ascii_lowercase().starts_with(prefix))
        })
        .collect();
    dirs.sort_by_key(|a| std::cmp::Reverse(version_sort_key(a)));
    for d in dirs {
        let exe = d.join("bin").join(exe_name);
        if exe.is_file() {
            return Some(exe);
        }
    }
    None
}

pub fn discover_ccs_environment(explicit_root: Option<&Path>) -> CcsEnvironment {
    let Some(root) = find_ccs_root(explicit_root) else {
        return CcsEnvironment {
            ccs_root: None,
            cloudagent_dir: None,
            targetdb_dir: None,
            xdsdfu_exe: None,
            xds100serial_exe: None,
            dbgjtag_exe: None,
            ofd2000_exe: None,
            tiarmofd_exe: None,
            cl2000_exe: None,
        };
    };

    let cloudagent = root.join("ccs_base").join("cloudagent");
    let targetdb = root.join("ccs_base").join("common").join("targetdb");
    let uscif = root.join("ccs_base").join("common").join("uscif");
    let xdsdfu = uscif.join("xds110").join("xdsdfu.exe");
    let xds100 = uscif.join("xds100serial.exe");
    let dbgjtag = uscif.join("dbgjtag.exe");

    CcsEnvironment {
        ofd2000_exe: pick_compiler_tool(&root, "ti-cgt-c2000", "ofd2000.exe"),
        cl2000_exe: pick_compiler_tool(&root, "ti-cgt-c2000", "cl2000.exe"),
        tiarmofd_exe: pick_compiler_tool(&root, "ti-cgt-armllvm", "tiarmofd.exe"),
        cloudagent_dir: cloudagent.is_dir().then_some(cloudagent),
        targetdb_dir: targetdb.is_dir().then_some(targetdb),
        xdsdfu_exe: xdsdfu.is_file().then_some(xdsdfu),
        xds100serial_exe: xds100.is_file().then_some(xds100),
        dbgjtag_exe: dbgjtag.is_file().then_some(dbgjtag),
        ccs_root: Some(root),
    }
}
