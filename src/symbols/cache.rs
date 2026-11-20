//! Zlib-compressed, 100 MB / 24-entry LRU disk cache for parsed symbol trees keyed by full-file CRC/size/path.

use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::core::models::{FlashFingerprint, MemoryRange, SymbolNode};

pub const CACHE_SCHEMA_VERSION: &str = "v3-rs";
pub const DEFAULT_MAX_CACHE_BYTES: u64 = 100 * 1024 * 1024;
pub const DEFAULT_MAX_CACHE_ENTRIES: usize = 24;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedSymbolTable {
    pub schema_version: String,
    pub source_path: String,
    pub core: String,
    pub abi: String,
    pub address_unit_bits: u32,
    pub symbols: Vec<SymbolNode>,
    pub ram_ranges: Vec<MemoryRange>,
    pub flash_ranges: Vec<MemoryRange>,
    pub build_digest: String,
    pub flash_fingerprint: Option<FlashFingerprint>,
}

pub fn compute_file_digest(path: &Path) -> Result<String, String> {
    let mut f = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut h = crc32fast::Hasher::new();
    let mut buf = [0u8; 65536];
    let mut total = 0u64;
    loop {
        let n = f.read(&mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        total += n as u64;
    }
    Ok(format!("{total:016x}_{:08x}", h.finalize()))
}

fn default_cache_dir() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let d = base.join("C2000JtagStudioRs").join("symcache");
    let _ = fs::create_dir_all(&d);
    d
}

fn cache_key(path: &Path, core: &str, digest: &str) -> String {
    let mut h = crc32fast::Hasher::new();
    h.update(CACHE_SCHEMA_VERSION.as_bytes());
    h.update(path.to_string_lossy().as_bytes());
    h.update(core.as_bytes());
    h.update(digest.as_bytes());
    format!("{:08x}_{digest}", h.finalize())
}

pub fn evict_lru_cache(root: &Path, max_bytes: u64, max_entries: usize) -> usize {
    let Ok(rd) = fs::read_dir(root) else { return 0 };
    let mut entries: Vec<(SystemTime, u64, PathBuf)> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.to_string_lossy().ends_with(".json.zlib"))
        .filter_map(|p| {
            let meta = fs::metadata(&p).ok()?;
            let mt = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            Some((mt, meta.len(), p))
        })
        .collect();
    entries.sort_by_key(|a| std::cmp::Reverse(a.0));
    let mut kept_bytes = 0u64;
    let mut kept_cnt = 0usize;
    let mut removed = 0usize;
    for (_mt, sz, p) in entries {
        if kept_cnt < max_entries && (kept_bytes + sz <= max_bytes || kept_cnt == 0) {
            kept_cnt += 1;
            kept_bytes += sz;
        } else if fs::remove_file(&p).is_ok() {
            removed += 1;
        }
    }
    removed
}

pub fn load_cached_symbols(path: &Path, core: &str, cache_root: Option<&Path>) -> Option<ParsedSymbolTable> {
    let digest = compute_file_digest(path).ok()?;
    let root = cache_root.map(PathBuf::from).unwrap_or_else(default_cache_dir);
    let file = root.join(format!("{}.json.zlib", cache_key(path, core, &digest)));
    if !file.is_file() {
        return None;
    }
    let compressed = fs::read(&file).ok()?;
    let mut dec = ZlibDecoder::new(compressed.as_slice());
    let mut json_str = String::new();
    dec.read_to_string(&mut json_str).ok()?;
    let tbl: ParsedSymbolTable = serde_json::from_str(&json_str).ok()?;
    if tbl.schema_version != CACHE_SCHEMA_VERSION {
        return None;
    }
    Some(tbl)
}

pub fn save_cached_symbols(
    table: &ParsedSymbolTable,
    path: &Path,
    core: &str,
    cache_root: Option<&Path>,
    max_bytes: u64,
    max_entries: usize,
) {
    let Ok(digest) = compute_file_digest(path) else { return };
    let root = cache_root.map(PathBuf::from).unwrap_or_else(default_cache_dir);
    let _ = fs::create_dir_all(&root);
    let file = root.join(format!("{}.json.zlib", cache_key(path, core, &digest)));
    let Ok(json_bytes) = serde_json::to_vec(table) else { return };
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    if enc.write_all(&json_bytes).is_err() {
        return;
    }
    let Ok(comp) = enc.finish() else { return };
    let tmp = file.with_extension("zlib.tmp");
    if fs::write(&tmp, comp).is_ok() {
        let _ = fs::rename(&tmp, &file);
        evict_lru_cache(&root, max_bytes, max_entries);
    }
}
