//! TI COFF/EABI .out DWARF parser (ofd2000 / tiarmofd XML), native ELF32/COFF Flash fingerprint extractor,
//! TI .map fallback, and atomic WatchItem re-resolution on rebuild.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::{BufReader, Read};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use xml::reader::{EventReader, XmlEvent};

use crate::backend::ccs_env::{discover_ccs_environment, CcsEnvironment};
use crate::core::models::{
    CoreProfile, DataType, FlashFingerprint, MemoryRange, PhysicalMemoryDomain, SymbolNode,
    WatchItem, WriteState,
};
use crate::symbols::cache::{
    compute_file_digest, load_cached_symbols, save_cached_symbols, ParsedSymbolTable,
    CACHE_SCHEMA_VERSION, DEFAULT_MAX_CACHE_BYTES, DEFAULT_MAX_CACHE_ENTRIES,
};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const MAX_ARRAY_EXPAND: usize = 64;

const EXCLUDED_SECTIONS: &[&str] = &[
    ".scratchpad",
    "scratchpad",
    ".stack",
    ".sysmem",
    ".esysmem",
    ".cio",
    ".reset",
    "codestart",
];

#[derive(Debug, Default, Clone)]
struct DieEntry {
    id: String,
    tag: String,
    attrs: HashMap<String, String>,
    refs: HashMap<String, String>,
    children: Vec<DieEntry>,
}

fn parse_int(s: Option<&str>, default: i64) -> i64 {
    let Some(raw) = s else { return default };
    let t = raw.trim();
    if let Some(hex) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        i64::from_str_radix(hex, 16).unwrap_or(default)
    } else {
        t.parse::<i64>().unwrap_or(default)
    }
}

fn normalize_c_name(raw: &str, is_coff: bool) -> String {
    if is_coff && raw.starts_with('_') && !raw.starts_with("__") {
        raw[1..].to_string()
    } else {
        raw.to_string()
    }
}

fn is_excluded_section(name: &str) -> bool {
    let low = name.trim().to_ascii_lowercase();
    EXCLUDED_SECTIONS.iter().any(|p| low.starts_with(p))
}

fn is_compiler_temp(name: &str) -> bool {
    name.is_empty()
        || name.starts_with('$')
        || name.starts_with("__TI_")
        || name.starts_with("__cla")
        || name.starts_with(".L")
        || name.starts_with("__stack")
        || name.starts_with("__SYSMEM")
}

fn map_base_type(name: &str, byte_size: u32, encoding: i64, au: u32) -> DataType {
    let bits = (byte_size * au).max(1);
    let low = name.to_ascii_lowercase();
    if encoding == 4 || low.contains("float") || low.contains("double") {
        return if bits >= 64 { DataType::Float64 } else { DataType::Float32 };
    }
    let unsigned = matches!(encoding, 2 | 7 | 8) || low.contains("unsigned") || low.contains("bool");
    if bits <= 8 {
        if unsigned { DataType::Uint8 } else { DataType::Int8 }
    } else if bits <= 16 {
        if unsigned { DataType::Uint16 } else { DataType::Int16 }
    } else if bits <= 32 {
        if unsigned { DataType::Uint32 } else { DataType::Int32 }
    } else if unsigned {
        DataType::Uint64
    } else {
        DataType::Int64
    }
}

fn extract_op_num(expr: &str, op: &str) -> Option<u32> {
    let idx = expr.find(op)?;
    let rest = expr[idx + op.len()..].trim_start();
    let tok = rest.split_whitespace().next()?;
    let v = parse_int(Some(tok), -1);
    (v >= 0).then_some(v as u32)
}

/// Extract deterministic 16-word Flash fingerprint directly from an ELF32 or TI COFF2 .out binary.
pub fn extract_flash_fingerprint(path: &Path, cp: &CoreProfile, num_words: usize) -> Option<FlashFingerprint> {
    let data = fs::read(path).ok()?;
    if data.len() < 64 {
        return None;
    }
    let au = cp.address_unit_bits;
    let unit_bytes = if au == 16 { 2 } else { 1 };
    let want_bytes = num_words * unit_bytes;
    let page = if cp.default_page.is_empty() { String::new() } else { "PROGRAM".to_string() };

    let read_u16 = |off: usize| u16::from_le_bytes(data[off..off + 2].try_into().unwrap());
    let read_u32 = |off: usize| u32::from_le_bytes(data[off..off + 4].try_into().unwrap());

    // 1. ELF32 little-endian
    if data.starts_with(b"\x7fELF") && data[4] == 1 && data[5] == 1 {
        let e_shoff = read_u32(32) as usize;
        let e_shentsize = read_u16(46) as usize;
        let e_shnum = read_u16(48) as usize;
        let e_shstrndx = read_u16(50) as usize;
        if e_shoff == 0 || e_shnum == 0 || e_shentsize < 40 {
            return None;
        }
        let str_off = e_shoff + e_shstrndx * e_shentsize;
        if str_off + 40 > data.len() {
            return None;
        }
        let shstr_file_off = read_u32(str_off + 16) as usize;
        let shstr_size = read_u32(str_off + 20) as usize;
        let shstr = data.get(shstr_file_off..shstr_file_off + shstr_size)?;

        let mut cands: Vec<(u8, u32, &[u8])> = Vec::new();
        for i in 0..e_shnum {
            let off = e_shoff + i * e_shentsize;
            if off + 40 > data.len() {
                break;
            }
            let sh_name = read_u32(off) as usize;
            let sh_type = read_u32(off + 4);
            let sh_flags = read_u32(off + 8);
            let sh_addr = read_u32(off + 12);
            let sh_offset = read_u32(off + 16) as usize;
            let sh_size = read_u32(off + 20) as usize;
            if sh_type != 1 || (sh_flags & 0x2) == 0 || sh_size < want_bytes || sh_offset + want_bytes > data.len() {
                continue;
            }
            let is_exec = (sh_flags & 0x4) != 0;
            let is_write = (sh_flags & 0x1) != 0;
            if !is_exec && is_write {
                continue;
            }
            let name_bytes = shstr.get(sh_name..).unwrap_or(&[]);
            let end_nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len().min(32));
            let sec_name = std::str::from_utf8(&name_bytes[..end_nul]).unwrap_or("");
            let prio = if matches!(sec_name, ".text" | "codestart" | ".cinit") { 0 } else if is_exec { 1 } else { 2 };
            cands.push((prio, sh_addr, &data[sh_offset..sh_offset + want_bytes]));
        }
        cands.sort_by_key(|c| (c.0, c.1));
        let &(_prio, addr, raw) = cands.first()?;
        let words: Vec<u32> = if au == 16 {
            raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c) as u32).collect()
        } else {
            raw.iter().map(|&b| b as u32).collect()
        };
        return Some(FlashFingerprint {
            address: addr,
            page,
            words,
            address_unit_bits: au,
        });
    }

    // 2. TI COFF2 (magic 0x00C2)
    if read_u16(0) == 0x00C2 && data.len() >= 22 {
        let nscns = read_u16(2) as usize;
        let opthdr = read_u16(16) as usize;
        let scn_off = 22 + opthdr;
        let scn_sz = 48;
        let mut cands: Vec<(u8, u32, &[u8])> = Vec::new();
        for i in 0..nscns {
            let off = scn_off + i * scn_sz;
            if off + scn_sz > data.len() {
                break;
            }
            let raw_name = std::str::from_utf8(&data[off..off + 8]).unwrap_or("").trim_end_matches('\0');
            let paddr = read_u32(off + 8);
            let vaddr = read_u32(off + 12);
            let s_size = read_u32(off + 16) as usize;
            let s_scnptr = read_u32(off + 20) as usize;
            let s_flags = read_u32(off + 40);
            let is_text = (s_flags & 0x20) != 0;
            let is_bss = (s_flags & 0x80) != 0;
            let is_copy = (s_flags & 0x10) != 0;
            if is_bss || is_copy || s_scnptr == 0 || s_size * unit_bytes < want_bytes || s_scnptr + want_bytes > data.len() {
                continue;
            }
            let prio = if raw_name.starts_with(".text") { 0 } else if is_text { 1 } else { 2 };
            let addr = if vaddr != 0 { vaddr } else { paddr };
            cands.push((prio, addr, &data[s_scnptr..s_scnptr + want_bytes]));
        }
        cands.sort_by_key(|c| (c.0, c.1));
        let &(_prio, addr, raw) = cands.first()?;
        let words: Vec<u32> = if au == 16 {
            raw.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c) as u32).collect()
        } else {
            raw.iter().map(|&b| b as u32).collect()
        };
        return Some(FlashFingerprint {
            address: addr,
            page,
            words,
            address_unit_bits: au,
        });
    }
    None
}

/// Streaming parser for `ofd2000 --xml --dwarf` and `tiarmofd --xml --dwarf`.
pub fn parse_ofd_xml_stream<R: Read>(
    reader: R,
    core: &str,
    page: &str,
    au: u32,
    source_path: &str,
) -> Result<ParsedSymbolTable, String> {
    let parser = EventReader::new(BufReader::new(reader));

    let mut abi = "eabi".to_string();
    let mut raw_sections: Vec<(String, u32, u32, bool, bool, bool)> = Vec::new();
    let mut raw_symtab: HashMap<String, (u32, bool)> = HashMap::new();
    let mut root_units: Vec<(String, Vec<DieEntry>)> = Vec::new();
    let mut dies_by_id: HashMap<String, DieEntry> = HashMap::new();

    // Streaming XML stack state
    let mut path_stack: Vec<String> = Vec::new();
    let mut text_buf = String::new();

    // Section accumulators
    let mut in_elf_shdr = false;
    let mut sh_name = String::new();
    let mut sh_addr = 0u32;
    let mut sh_size = 0u32;
    let mut sh_flags: HashSet<String> = HashSet::new();

    let mut in_coff_sec = false;
    let mut c_name = String::new();
    let mut c_paddr: Option<u32> = None;
    let mut c_vaddr: Option<u32> = None;
    let mut c_raw_sz = 0u32;
    let mut c_copy = false;
    let mut c_bss = false;
    let mut c_data = false;
    let mut c_text = false;
    let mut c_page = String::new();

    // Symtab accumulators
    let mut in_elf_sym = false;
    let mut es_type = String::new();
    let mut es_bind = String::new();
    let mut es_shndx = String::new();
    let mut es_name = String::new();
    let mut es_val = 0u32;

    let mut in_coff_sym = false;
    let mut cs_kind = String::new();
    let mut cs_class = String::new();
    let mut cs_name = String::new();
    let mut cs_val = 0u32;

    // DWARF DIE stack
    let mut die_stack: Vec<DieEntry> = Vec::new();
    let mut cur_unit_dies: Vec<DieEntry> = Vec::new();
    let mut cur_unit_name = String::new();
    let mut cur_attr_type = String::new();
    let mut cur_attr_val: Option<String> = None;
    let mut cur_attr_ref: Option<String> = None;
    let mut in_attr = false;
    let mut in_attr_value = false;

    for ev in parser {
        let ev = ev.map_err(|e| format!("XML parse error: {e}"))?;
        match ev {
            XmlEvent::StartElement { name, attributes, .. } => {
                let tag = name.local_name;
                text_buf.clear();
                match tag.as_str() {
                    "ti_coff" => abi = "coff".into(),
                    "elf" => abi = "eabi".into(),
                    "elf32_shdr" => {
                        in_elf_shdr = true;
                        sh_name.clear();
                        sh_addr = 0;
                        sh_size = 0;
                        sh_flags.clear();
                    }
                    "section"
                        if !in_elf_shdr
                            && !path_stack.iter().any(|s| s == "elf" || s == "dwarf" || s == "symbol_table") =>
                    {
                        in_coff_sec = true;
                        c_name.clear();
                        c_paddr = None;
                        c_vaddr = None;
                        c_raw_sz = 0;
                        c_copy = false;
                        c_bss = false;
                        c_data = false;
                        c_text = false;
                        c_page.clear();
                    }
                    "elf32_sym" => {
                        in_elf_sym = true;
                        es_type.clear();
                        es_bind.clear();
                        es_shndx.clear();
                        es_name.clear();
                        es_val = 0;
                    }
                    "symbol" if path_stack.iter().any(|s| s == "symbol_table") => {
                        in_coff_sym = true;
                        cs_kind.clear();
                        cs_class.clear();
                        cs_name.clear();
                        cs_val = 0;
                    }
                    "compile_unit" | "type_unit" => {
                        cur_unit_dies.clear();
                        cur_unit_name.clear();
                    }
                    "die" => {
                        let id = attributes
                            .iter()
                            .find(|a| a.name.local_name == "id")
                            .map(|a| a.value.clone())
                            .unwrap_or_default();
                        let tag = attributes
                            .iter()
                            .find(|a| a.name.local_name == "tag")
                            .map(|a| a.value.clone())
                            .unwrap_or_default();
                        die_stack.push(DieEntry {
                            id,
                            tag,
                            ..Default::default()
                        });
                    }
                    "attribute" if !die_stack.is_empty() => {
                        in_attr = true;
                        cur_attr_type.clear();
                        cur_attr_val = None;
                        cur_attr_ref = None;
                    }
                    "value" if in_attr => {
                        in_attr_value = true;
                    }
                    "ref" if in_attr_value => {
                        if let Some(r) = attributes.iter().find(|a| a.name.local_name == "idref") {
                            cur_attr_ref = Some(r.value.clone());
                        }
                    }
                    _ => {}
                }
                path_stack.push(tag);
            }
            XmlEvent::Characters(s) => {
                text_buf.push_str(&s);
            }
            XmlEvent::EndElement { name } => {
                let tag = name.local_name;
                let txt = text_buf.trim().to_string();
                path_stack.pop();

                if in_elf_shdr {
                    match tag.as_str() {
                        "sh_name_string" => sh_name = txt,
                        "sh_addr" => sh_addr = parse_int(Some(&txt), 0).max(0) as u32,
                        "sh_size" => sh_size = parse_int(Some(&txt), 0).max(0) as u32,
                        "flag" => {
                            if !txt.is_empty() {
                                sh_flags.insert(txt);
                            }
                        }
                        "elf32_shdr" => {
                            in_elf_shdr = false;
                            if sh_flags.contains("SHF_ALLOC") && sh_size > 0 {
                                let units = if au == 16 { sh_size.div_ceil(2).max(1) } else { sh_size };
                                let is_sp = is_excluded_section(&sh_name);
                                let is_ram = sh_flags.contains("SHF_WRITE") && !is_sp;
                                let is_flash = sh_flags.contains("SHF_EXECINSTR") && !sh_flags.contains("SHF_WRITE");
                                raw_sections.push((sh_name.clone(), sh_addr, units, is_ram, is_flash, is_sp));
                            }
                        }
                        _ => {}
                    }
                } else if in_elf_sym {
                    match tag.as_str() {
                        "st_type" => es_type = txt,
                        "st_bind" => es_bind = txt,
                        "st_shndx" => es_shndx = txt,
                        "st_name_string" => es_name = txt,
                        "st_value" => es_val = parse_int(Some(&txt), 0).max(0) as u32,
                        "elf32_sym" => {
                            in_elf_sym = false;
                            if es_type == "STT_OBJECT" && es_shndx != "SHN_UNDEF" && !es_name.is_empty() {
                                let is_local = es_bind == "STB_LOCAL";
                                if !is_local || !is_compiler_temp(&es_name) {
                                    raw_symtab.insert(es_name.clone(), (es_val, is_local));
                                }
                            }
                        }
                        _ => {}
                    }
                } else if in_coff_sym {
                    match tag.as_str() {
                        "kind" => cs_kind = txt.to_ascii_lowercase(),
                        "storage_class" => cs_class = txt,
                        "name" => cs_name = txt,
                        "value" => cs_val = parse_int(Some(&txt), 0).max(0) as u32,
                        "symbol" => {
                            in_coff_sym = false;
                            if cs_kind == "defined"
                                && (cs_class == "C_EXT" || cs_class == "C_STAT")
                                && !cs_name.is_empty()
                                && !cs_name.starts_with('.')
                                && !cs_name.starts_with('$')
                            {
                                raw_symtab.insert(cs_name.clone(), (cs_val, cs_class == "C_STAT"));
                            }
                        }
                        _ => {}
                    }
                } else if in_coff_sec {
                    match tag.as_str() {
                        "name" => c_name = txt,
                        "physical_addr" => c_paddr = Some(parse_int(Some(&txt), 0).max(0) as u32),
                        "virtual_addr" => c_vaddr = Some(parse_int(Some(&txt), 0).max(0) as u32),
                        "raw_data_size" => c_raw_sz = parse_int(Some(&txt), 0).max(0) as u32,
                        "copy" => c_copy = txt.eq_ignore_ascii_case("true"),
                        "bss" => c_bss = txt.eq_ignore_ascii_case("true"),
                        "data" => c_data = txt.eq_ignore_ascii_case("true"),
                        "text" => c_text = txt.eq_ignore_ascii_case("true"),
                        "page" => c_page = txt.to_ascii_lowercase(),
                        "section" => {
                            in_coff_sec = false;
                            if c_paddr.is_some() && !c_copy && c_raw_sz > 0 {
                                let addr = c_vaddr.or(c_paddr).unwrap_or(0);
                                let units = if au == 16 { c_raw_sz.div_ceil(2).max(1) } else { c_raw_sz };
                                let is_sp = is_excluded_section(&c_name);
                                let low = c_name.to_ascii_lowercase();
                                let non_ram_name = matches!(
                                    low.as_str(),
                                    ".cinit" | ".econst" | ".const" | ".pinit" | ".switch" | ".text" | ".reset" | "codestart"
                                );
                                let is_prog = matches!(c_page.as_str(), "0" | "program");
                                let is_ram = (c_bss || c_data) && !non_ram_name && !is_prog && !is_sp;
                                let is_flash = c_text || (non_ram_name && !c_bss && !is_sp) || is_prog;
                                raw_sections.push((c_name.clone(), addr, units, is_ram, is_flash, is_sp));
                            }
                        }
                        _ => {}
                    }
                } else if !die_stack.is_empty() {
                    if in_attr {
                        match tag.as_str() {
                            "type" => cur_attr_type = txt,
                            "value" => {
                                if cur_attr_val.is_none() && !txt.is_empty() {
                                    cur_attr_val = Some(txt);
                                }
                                in_attr_value = false;
                            }
                            "attribute" => {
                                in_attr = false;
                                if let Some(top) = die_stack.last_mut() {
                                    if !cur_attr_type.is_empty() {
                                        if let Some(r) = cur_attr_ref.take() {
                                            top.refs.insert(cur_attr_type.clone(), r);
                                        } else if let Some(v) = cur_attr_val.take() {
                                            top.attrs.insert(cur_attr_type.clone(), v);
                                        }
                                    }
                                }
                            }
                            _ if in_attr_value && tag != "ref" && !txt.is_empty() => {
                                cur_attr_val = Some(txt);
                            }
                            _ => {}
                        }
                    } else if tag == "tag" {
                        if let Some(top) = die_stack.last_mut() {
                            top.tag = txt;
                        }
                    } else if tag == "die" {
                        let finished = die_stack.pop().unwrap();
                        if !finished.id.is_empty() {
                            dies_by_id.insert(finished.id.clone(), finished.clone());
                        }
                        if let Some(parent) = die_stack.last_mut() {
                            parent.children.push(finished);
                        } else {
                            if finished.tag == "DW_TAG_compile_unit" {
                                if let Some(cu_path) = finished.attrs.get("DW_AT_name") {
                                    cur_unit_name = Path::new(cu_path)
                                        .file_name()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or(cu_path)
                                        .to_string();
                                }
                            }
                            cur_unit_dies.push(finished);
                        }
                    }
                } else if tag == "compile_unit" || tag == "type_unit" {
                    root_units.push((std::mem::take(&mut cur_unit_name), std::mem::take(&mut cur_unit_dies)));
                }
                text_buf.clear();
            }
            _ => {}
        }
    }

    let is_coff = abi == "coff";
    let classify_sec = |addr: u32| -> (String, PhysicalMemoryDomain, bool, bool) {
        for (sn, sa, su, _ir, ifl, isp) in &raw_sections {
            if addr >= *sa && addr < sa.saturating_add(*su) {
                if *isp {
                    return (sn.clone(), PhysicalMemoryDomain::Scratchpad, true, false);
                }
                if *ifl {
                    return (sn.clone(), PhysicalMemoryDomain::Flash, false, true);
                }
                return (sn.clone(), PhysicalMemoryDomain::Unknown, false, false);
            }
        }
        (String::new(), PhysicalMemoryDomain::Unknown, false, false)
    };

    let mut raw_vars: Vec<(String, String, u32, Option<String>, bool)> = Vec::new();
    for (cu, roots) in &root_units {
        for r in roots {
            collect_vars(r, &dies_by_id, cu, "", is_coff, &mut raw_vars);
        }
    }

    let mut name_addrs: HashMap<String, HashSet<u32>> = HashMap::new();
    for (full, _cu, addr, _tr, _st) in &raw_vars {
        name_addrs.entry(full.clone()).or_default().insert(*addr);
    }

    let mut symbols: Vec<SymbolNode> = Vec::new();
    let mut seen_keys: HashSet<(String, u32)> = HashSet::new();
    let mut seen_names: HashSet<String> = HashSet::new();

    for (full, cu, addr, tref, is_static) in raw_vars {
        let (sec, dm, is_sp, _is_fl) = classify_sec(addr);
        if is_sp {
            continue;
        }
        let mut disp = full.clone();
        let mut tu_scope = if is_static { cu.clone() } else { String::new() };
        if name_addrs.get(&full).is_some_and(|s| s.len() > 1) && !cu.is_empty() {
            disp = format!("{cu}::{full}");
            tu_scope = cu.clone();
        }
        if !seen_keys.insert((disp.clone(), addr)) {
            continue;
        }
        seen_names.insert(full);
        seen_names.insert(disp.clone());
        symbols.push(build_symbol_node(
            &dies_by_id,
            core,
            page,
            au,
            &disp,
            &disp,
            addr,
            tref.as_deref(),
            None,
            None,
            None,
            &sec,
            dm,
            &tu_scope,
            0,
        ));
    }

    for (raw_sym, (sval, _loc)) in raw_symtab {
        let norm = normalize_c_name(&raw_sym, is_coff);
        if seen_names.contains(&norm) || is_compiler_temp(&norm) {
            continue;
        }
        let (sec, dm, is_sp, is_fl) = classify_sec(sval);
        if is_sp || (is_coff && is_fl) {
            continue;
        }
        seen_names.insert(norm.clone());
        symbols.push(SymbolNode {
            name: norm.clone(),
            full_path: norm,
            core: core.to_string(),
            address: sval,
            page: page.to_string(),
            data_type: if au == 16 { DataType::Uint16 } else { DataType::Uint32 },
            word_size: if au == 16 { 1 } else { 4 },
            type_name: "symbol".into(),
            bit_offset: None,
            bit_width: None,
            container_units: None,
            is_struct: false,
            is_array: false,
            array_len: 0,
            is_pointer: false,
            is_function: false,
            section_name: sec,
            domain: dm,
            tu_scope: String::new(),
            is_scratchpad: false,
            children: Vec::new(),
        });
    }

    symbols.sort_by_key(|a| a.full_path.to_ascii_lowercase());

    let ram_ranges = raw_sections
        .iter()
        .filter(|(_, _, sz, is_ram, _, is_sp)| *is_ram && !*is_sp && *sz > 0)
        .map(|(nm, addr, sz, _, _, _)| MemoryRange {
            start: *addr,
            end: addr.saturating_add(*sz - 1),
            name: nm.clone(),
            is_ram: true,
            is_peripheral: false,
            is_cla_shared: false,
            domain: PhysicalMemoryDomain::Unknown,
            writable_by: Vec::new(),
            readable_by: Vec::new(),
            bank_index: None,
        })
        .collect();

    let flash_ranges = raw_sections
        .iter()
        .filter(|(_, _, sz, _, is_fl, _)| *is_fl && *sz > 0)
        .map(|(nm, addr, sz, _, _, _)| MemoryRange {
            start: *addr,
            end: addr.saturating_add(*sz - 1),
            name: nm.clone(),
            is_ram: false,
            is_peripheral: false,
            is_cla_shared: false,
            domain: PhysicalMemoryDomain::Flash,
            writable_by: Vec::new(),
            readable_by: Vec::new(),
            bank_index: None,
        })
        .collect();

    Ok(ParsedSymbolTable {
        schema_version: CACHE_SCHEMA_VERSION.to_string(),
        source_path: source_path.to_string(),
        core: core.to_string(),
        abi,
        address_unit_bits: au,
        symbols,
        ram_ranges,
        flash_ranges,
        build_digest: String::new(),
        flash_fingerprint: None,
    })
}

fn resolve_spec_attr<'a>(die: &'a DieEntry, map: &'a HashMap<String, DieEntry>, attr: &str) -> Option<&'a str> {
    let mut visited = HashSet::new();
    let mut cur = Some(die);
    while let Some(d) = cur {
        if !d.id.is_empty() && !visited.insert(d.id.as_str()) {
            break;
        }
        if let Some(v) = d.attrs.get(attr) {
            return Some(v.as_str());
        }
        let next_id = d.refs.get("DW_AT_specification").or_else(|| d.refs.get("DW_AT_abstract_origin"));
        cur = next_id.and_then(|id| map.get(id));
    }
    None
}

fn resolve_spec_ref<'a>(die: &'a DieEntry, map: &'a HashMap<String, DieEntry>, attr: &str) -> Option<&'a str> {
    let mut visited = HashSet::new();
    let mut cur = Some(die);
    while let Some(d) = cur {
        if !d.id.is_empty() && !visited.insert(d.id.as_str()) {
            break;
        }
        if let Some(v) = d.refs.get(attr) {
            return Some(v.as_str());
        }
        let next_id = d.refs.get("DW_AT_specification").or_else(|| d.refs.get("DW_AT_abstract_origin"));
        cur = next_id.and_then(|id| map.get(id));
    }
    None
}

fn collect_vars(
    die: &DieEntry,
    map: &HashMap<String, DieEntry>,
    cu: &str,
    ns_prefix: &str,
    is_coff: bool,
    out: &mut Vec<(String, String, u32, Option<String>, bool)>,
) {
    if die.tag == "DW_TAG_namespace" {
        let next_ns = match die.attrs.get("DW_AT_name") {
            Some(ns) if !ns.is_empty() => format!("{ns_prefix}{ns}::"),
            _ => ns_prefix.to_string(),
        };
        for ch in &die.children {
            collect_vars(ch, map, cu, &next_ns, is_coff, out);
        }
        return;
    }
    if die.tag == "DW_TAG_variable" {
        if let Some(loc) = die.attrs.get("DW_AT_location") {
            if let Some(addr) = extract_op_num(loc, "DW_OP_addr") {
                if let Some(raw_name) = resolve_spec_attr(die, map, "DW_AT_name") {
                    if !is_compiler_temp(raw_name) {
                        let norm = normalize_c_name(raw_name, is_coff);
                        let full = if !ns_prefix.is_empty() && !norm.contains("::") {
                            format!("{ns_prefix}{norm}")
                        } else {
                            norm
                        };
                        let is_ext = matches!(resolve_spec_attr(die, map, "DW_AT_external"), Some("1" | "true" | "True"));
                        let tref = resolve_spec_ref(die, map, "DW_AT_type").map(String::from);
                        out.push((full, cu.to_string(), addr, tref, !is_ext));
                    }
                }
            }
        }
        return;
    }
    for ch in &die.children {
        if ch.tag != "DW_TAG_subprogram" {
            collect_vars(ch, map, cu, ns_prefix, is_coff, out);
        }
    }
}

fn unwrap_type<'a>(map: &'a HashMap<String, DieEntry>, type_id: Option<&str>) -> (Option<&'a DieEntry>, String) {
    let mut visited = HashSet::new();
    let mut alias = String::new();
    let mut cur = type_id;
    while let Some(id) = cur {
        if !visited.insert(id.to_string()) {
            break;
        }
        let Some(die) = map.get(id) else {
            return (None, alias);
        };
        if matches!(
            die.tag.as_str(),
            "DW_TAG_typedef"
                | "DW_TAG_volatile_type"
                | "DW_TAG_const_type"
                | "DW_TAG_restrict_type"
                | "DW_TAG_TI_far_type"
                | "DW_TAG_TI_near_type"
                | "DW_TAG_TI_ioport_type"
        ) {
            if die.tag == "DW_TAG_typedef" && alias.is_empty() {
                if let Some(nm) = die.attrs.get("DW_AT_name") {
                    alias = nm.clone();
                }
            }
            cur = die.refs.get("DW_AT_type").map(String::as_str);
            continue;
        }
        let label = if !alias.is_empty() {
            alias
        } else {
            die.attrs.get("DW_AT_name").cloned().unwrap_or_default()
        };
        return (Some(die), label);
    }
    (None, alias)
}

fn array_dims(die: &DieEntry) -> Vec<usize> {
    let mut dims = Vec::new();
    for ch in &die.children {
        if ch.tag == "DW_TAG_subrange_type" {
            if let Some(ub) = ch.attrs.get("DW_AT_upper_bound") {
                dims.push((parse_int(Some(ub), 0) + 1).max(1) as usize);
            } else if let Some(cnt) = ch.attrs.get("DW_AT_count") {
                dims.push(parse_int(Some(cnt), 1).max(1) as usize);
            }
        }
    }
    dims
}

fn type_word_size(map: &HashMap<String, DieEntry>, die: Option<&DieEntry>, au: u32) -> u32 {
    let Some(d) = die else { return 1 };
    if let Some(bs) = d.attrs.get("DW_AT_byte_size") {
        return parse_int(Some(bs), 1).max(1) as u32;
    }
    if d.tag == "DW_TAG_pointer_type" {
        return if au == 16 { 2 } else { 4 };
    }
    if d.tag == "DW_TAG_array_type" {
        let (ed, _) = unwrap_type(map, d.refs.get("DW_AT_type").map(String::as_str));
        let eu = type_word_size(map, ed, au);
        let prod: usize = array_dims(d).into_iter().product::<usize>().max(1);
        return eu.saturating_mul(prod as u32).max(1);
    }
    1
}

#[allow(clippy::too_many_arguments)]
fn append_struct_members(
    map: &HashMap<String, DieEntry>,
    struct_die: &DieEntry,
    core: &str,
    page: &str,
    au: u32,
    base_addr: u32,
    base_path: &str,
    sec: &str,
    dm: PhysicalMemoryDomain,
    tu: &str,
    depth: usize,
    out: &mut Vec<SymbolNode>,
) {
    let is_struct = matches!(struct_die.tag.as_str(), "DW_TAG_structure_type" | "DW_TAG_class_type");
    let struct_bsize = parse_int(struct_die.attrs.get("DW_AT_byte_size").map(String::as_str), 0).max(0) as u32;

    for m in &struct_die.children {
        if m.tag == "DW_TAG_inheritance" && depth < 6 {
            let loc = m.attrs.get("DW_AT_data_member_location").map(String::as_str).unwrap_or("0");
            let off = extract_op_num(loc, "DW_OP_plus_uconst").unwrap_or_else(|| parse_int(Some(loc), 0).max(0) as u32);
            let (bd, _) = unwrap_type(map, m.refs.get("DW_AT_type").map(String::as_str));
            if let Some(b) = bd {
                if matches!(b.tag.as_str(), "DW_TAG_structure_type" | "DW_TAG_class_type") {
                    append_struct_members(map, b, core, page, au, base_addr + off, base_path, sec, dm, tu, depth + 1, out);
                }
            }
            continue;
        }
        if m.tag != "DW_TAG_member" {
            continue;
        }
        let loc = m.attrs.get("DW_AT_data_member_location").map(String::as_str).unwrap_or("0");
        let mut m_off = if is_struct {
            extract_op_num(loc, "DW_OP_plus_uconst").unwrap_or_else(|| parse_int(Some(loc), 0).max(0) as u32)
        } else {
            0
        };
        let tref = m.refs.get("DW_AT_type").map(String::as_str);
        let m_name = m.attrs.get("DW_AT_name").map(String::as_str).unwrap_or("");
        if m_name.is_empty() {
            let (ad, _) = unwrap_type(map, tref);
            if let Some(a) = ad {
                if matches!(a.tag.as_str(), "DW_TAG_structure_type" | "DW_TAG_union_type" | "DW_TAG_class_type") && depth < 6 {
                    append_struct_members(map, a, core, page, au, base_addr + m_off, base_path, sec, dm, tu, depth + 1, out);
                }
            }
            continue;
        }

        let bit_sz = parse_int(m.attrs.get("DW_AT_bit_size").map(String::as_str), 0).max(0) as u32;
        let mut bit_off = None;
        let mut bit_width = None;
        let mut cont_units_opt = None;
        if bit_sz > 0 {
            bit_width = Some(bit_sz);
            let (mtd, _) = unwrap_type(map, tref);
            let mb = parse_int(m.attrs.get("DW_AT_byte_size").map(String::as_str), 0).max(0) as u32;
            let cont_units = if mb > 0 { mb } else { type_word_size(map, mtd, au) };
            let cont_bits = (cont_units * au).max(au);
            if let Some(dbo) = m.attrs.get("DW_AT_data_bit_offset") {
                let abs_bit = parse_int(Some(dbo), 0).max(0) as u32;
                if struct_bsize > 0 && ((abs_bit / cont_bits) * cont_units + cont_units) > struct_bsize {
                    m_off = abs_bit / au;
                    let bo = abs_bit % au;
                    bit_off = Some(bo);
                    let rem = struct_bsize.saturating_sub(m_off).max(1);
                    let need = (bo + bit_sz).div_ceil(au).max(1);
                    cont_units_opt = Some(rem.min(need));
                } else {
                    m_off = (abs_bit / cont_bits) * cont_units;
                    bit_off = Some(abs_bit % cont_bits);
                    cont_units_opt = Some(cont_units);
                }
            } else if let Some(bo_s) = m.attrs.get("DW_AT_bit_offset") {
                let msb = parse_int(Some(bo_s), 0).max(0) as u32;
                bit_off = Some(cont_bits.saturating_sub(msb + bit_sz));
                cont_units_opt = Some(if struct_bsize > 0 && m_off + cont_units > struct_bsize {
                    struct_bsize.saturating_sub(m_off).max(1)
                } else {
                    cont_units
                });
            }
        }

        out.push(build_symbol_node(
            map,
            core,
            page,
            au,
            m_name,
            &format!("{base_path}.{m_name}"),
            base_addr + m_off,
            tref,
            bit_off,
            bit_width,
            cont_units_opt,
            sec,
            dm,
            tu,
            depth + 1,
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn build_symbol_node(
    map: &HashMap<String, DieEntry>,
    core: &str,
    page: &str,
    au: u32,
    name: &str,
    full_path: &str,
    addr: u32,
    type_id: Option<&str>,
    bit_offset: Option<u32>,
    bit_width: Option<u32>,
    container_units: Option<u32>,
    sec: &str,
    dm: PhysicalMemoryDomain,
    tu: &str,
    depth: usize,
) -> SymbolNode {
    let (tdie, tlabel) = unwrap_type(map, type_id);
    let default_dt = if au == 16 { DataType::Uint16 } else { DataType::Uint32 };
    let Some(die) = tdie.filter(|_| depth <= 6) else {
        return SymbolNode {
            name: name.into(),
            full_path: full_path.into(),
            core: core.into(),
            address: addr,
            page: page.into(),
            data_type: default_dt,
            word_size: if au == 16 { 1 } else { 4 },
            type_name: if tlabel.is_empty() { "uint".into() } else { tlabel },
            bit_offset,
            bit_width,
            container_units,
            is_struct: false,
            is_array: false,
            array_len: 0,
            is_pointer: false,
            is_function: false,
            section_name: sec.into(),
            domain: dm,
            tu_scope: tu.into(),
            is_scratchpad: false,
            children: Vec::new(),
        };
    };

    match die.tag.as_str() {
        "DW_TAG_base_type" => {
            let bs = parse_int(die.attrs.get("DW_AT_byte_size").map(String::as_str), 1).max(1) as u32;
            let enc = parse_int(die.attrs.get("DW_AT_encoding").map(String::as_str), 7);
            let dt = map_base_type(die.attrs.get("DW_AT_name").map(String::as_str).unwrap_or(&tlabel), bs, enc, au);
            SymbolNode {
                name: name.into(),
                full_path: full_path.into(),
                core: core.into(),
                address: addr,
                page: page.into(),
                data_type: dt,
                word_size: bs,
                type_name: if tlabel.is_empty() { dt.label().into() } else { tlabel },
                bit_offset,
                bit_width,
                container_units,
                is_struct: false,
                is_array: false,
                array_len: 0,
                is_pointer: false,
                is_function: false,
                section_name: sec.into(),
                domain: dm,
                tu_scope: tu.into(),
                is_scratchpad: false,
                children: Vec::new(),
            }
        }
        "DW_TAG_enumeration_type" => {
            let bs = parse_int(die.attrs.get("DW_AT_byte_size").map(String::as_str), if au == 16 { 1 } else { 4 }).max(1) as u32;
            let enc = parse_int(die.attrs.get("DW_AT_encoding").map(String::as_str), 7);
            let dt = map_base_type(&tlabel, bs, enc, au);
            SymbolNode {
                name: name.into(),
                full_path: full_path.into(),
                core: core.into(),
                address: addr,
                page: page.into(),
                data_type: dt,
                word_size: bs,
                type_name: format!("enum {tlabel}").trim().to_string(),
                bit_offset,
                bit_width,
                container_units,
                is_struct: false,
                is_array: false,
                array_len: 0,
                is_pointer: false,
                is_function: false,
                section_name: sec.into(),
                domain: dm,
                tu_scope: tu.into(),
                is_scratchpad: false,
                children: Vec::new(),
            }
        }
        "DW_TAG_structure_type" | "DW_TAG_union_type" | "DW_TAG_class_type" => {
            let bs = parse_int(die.attrs.get("DW_AT_byte_size").map(String::as_str), 1).max(1) as u32;
            let mut children = Vec::new();
            append_struct_members(map, die, core, page, au, addr, full_path, sec, dm, tu, depth, &mut children);
            SymbolNode {
                name: name.into(),
                full_path: full_path.into(),
                core: core.into(),
                address: addr,
                page: page.into(),
                data_type: default_dt,
                word_size: bs,
                type_name: if tlabel.is_empty() { "struct".into() } else { tlabel },
                bit_offset: None,
                bit_width: None,
                container_units: None,
                is_struct: true,
                is_array: false,
                array_len: 0,
                is_pointer: false,
                is_function: false,
                section_name: sec.into(),
                domain: dm,
                tu_scope: tu.into(),
                is_scratchpad: false,
                children,
            }
        }
        "DW_TAG_array_type" => {
            let elem_ref = die.refs.get("DW_AT_type").map(String::as_str);
            let (ed, elabel) = unwrap_type(map, elem_ref);
            let eu = type_word_size(map, ed, au);
            let mut dims = array_dims(die);
            if dims.is_empty() {
                dims.push(1);
            }
            let dim0 = dims[0];
            let expand = dim0.min(MAX_ARRAY_EXPAND);
            let mut children = Vec::with_capacity(expand);
            for i in 0..expand {
                children.push(build_symbol_node(
                    map,
                    core,
                    page,
                    au,
                    &format!("[{i}]"),
                    &format!("{full_path}[{i}]"),
                    addr + (i as u32) * eu,
                    elem_ref,
                    None,
                    None,
                    None,
                    sec,
                    dm,
                    tu,
                    depth + 1,
                ));
            }
            let prod: usize = dims.iter().product::<usize>().max(1);
            SymbolNode {
                name: name.into(),
                full_path: full_path.into(),
                core: core.into(),
                address: addr,
                page: page.into(),
                data_type: default_dt,
                word_size: eu.saturating_mul(prod as u32).max(1),
                type_name: format!("{}[{}]", if elabel.is_empty() { "array" } else { &elabel }, dim0),
                bit_offset: None,
                bit_width: None,
                container_units: None,
                is_struct: false,
                is_array: true,
                array_len: dim0,
                is_pointer: false,
                is_function: false,
                section_name: sec.into(),
                domain: dm,
                tu_scope: tu.into(),
                is_scratchpad: false,
                children,
            }
        }
        _ => SymbolNode {
            name: name.into(),
            full_path: full_path.into(),
            core: core.into(),
            address: addr,
            page: page.into(),
            data_type: default_dt,
            word_size: type_word_size(map, Some(die), au),
            type_name: if tlabel.is_empty() { die.tag.clone() } else { tlabel },
            bit_offset,
            bit_width,
            container_units,
            is_struct: false,
            is_array: false,
            array_len: 0,
            is_pointer: die.tag == "DW_TAG_pointer_type",
            is_function: false,
            section_name: sec.into(),
            domain: dm,
            tu_scope: tu.into(),
            is_scratchpad: false,
            children: Vec::new(),
        },
    }
}

pub fn parse_ti_map_file(path: &Path, cp: &CoreProfile) -> Result<ParsedSymbolTable, String> {
    let text = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut symbols = Vec::new();
    let mut seen = HashSet::new();
    let mut in_globals = false;
    for line in text.lines() {
        let up = line.to_ascii_uppercase();
        if up.contains("GLOBAL SYMBOLS") {
            in_globals = true;
            continue;
        }
        if in_globals && line.trim_start().starts_with("LINKER GENERATED") {
            in_globals = false;
            continue;
        }
        if !in_globals {
            continue;
        }
        let toks: Vec<&str> = line.split_whitespace().collect();
        let (page_opt, addr_hex, raw_name) = match toks.as_slice() {
            [p, a, n] if (*p == "0" || *p == "1") => (Some(*p), *a, *n),
            [a, n] => (None, *a, *n),
            _ => continue,
        };
        let Ok(addr) = u32::from_str_radix(addr_hex, 16) else { continue };
        if addr == 0 || is_compiler_temp(raw_name) {
            continue;
        }
        let is_coff = raw_name.starts_with('_') && !raw_name.starts_with("__");
        let norm = normalize_c_name(raw_name, is_coff);
        if !seen.insert(norm.clone()) {
            continue;
        }
        let page = if page_opt == Some("0") && !cp.default_page.is_empty() {
            "PROGRAM".to_string()
        } else {
            cp.default_page.to_string()
        };
        symbols.push(SymbolNode {
            name: norm.clone(),
            full_path: norm,
            core: cp.name.to_string(),
            address: addr,
            page,
            data_type: if cp.address_unit_bits == 16 { DataType::Uint16 } else { DataType::Uint32 },
            word_size: if cp.address_unit_bits == 16 { 1 } else { 4 },
            type_name: "map_symbol".into(),
            bit_offset: None,
            bit_width: None,
            container_units: None,
            is_struct: false,
            is_array: false,
            array_len: 0,
            is_pointer: false,
            is_function: false,
            section_name: String::new(),
            domain: PhysicalMemoryDomain::Unknown,
            tu_scope: String::new(),
            is_scratchpad: false,
            children: Vec::new(),
        });
    }
    symbols.sort_by_key(|a| a.full_path.to_ascii_lowercase());
    Ok(ParsedSymbolTable {
        schema_version: CACHE_SCHEMA_VERSION.to_string(),
        source_path: path.display().to_string(),
        core: cp.name.to_string(),
        abi: "map".into(),
        address_unit_bits: cp.address_unit_bits,
        symbols,
        ram_ranges: Vec::new(),
        flash_ranges: Vec::new(),
        build_digest: compute_file_digest(path).unwrap_or_default(),
        flash_fingerprint: None,
    })
}

pub fn load_symbols_for_file(
    path: &Path,
    cp: &CoreProfile,
    env: Option<&CcsEnvironment>,
    use_cache: bool,
) -> Result<ParsedSymbolTable, String> {
    if !path.is_file() {
        return Err(format!("Symbol file not found: {}", path.display()));
    }
    if path.extension().and_then(|s| s.to_str()).is_some_and(|e| e.eq_ignore_ascii_case("map")) {
        return parse_ti_map_file(path, cp);
    }
    if use_cache {
        if let Some(cached) = load_cached_symbols(path, cp.name, None) {
            return Ok(cached);
        }
    }
    let owned;
    let env = match env {
        Some(e) => e,
        None => {
            owned = discover_ccs_environment(None);
            &owned
        }
    };
    let ofd = if cp.ofd_tool == "tiarmofd" {
        env.tiarmofd_exe.as_ref()
    } else {
        env.ofd2000_exe.as_ref()
    }
    .ok_or_else(|| format!("TI object dumper '{}.exe' not found.", cp.ofd_tool))?;

    let mut child = Command::new(ofd)
        .args([
            "--xml",
            "--dwarf",
            "--dwarf_display=none,dinfo",
            "--obj_display=none,sections,symbols",
            "--xml_indent=0",
            &path.to_string_lossy(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("Failed to spawn {}: {e}", ofd.display()))?;

    let stdout = child.stdout.take().ok_or("ofd stdout missing")?;
    let mut stderr = child.stderr.take();
    // Drain stderr concurrently so noisy compiler warnings can never deadlock pipe
    let err_handle = std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(ref mut se) = stderr {
            let _ = se.read_to_string(&mut s);
        }
        s
    });

    let mut table = parse_ofd_xml_stream(stdout, cp.name, cp.default_page, cp.address_unit_bits, &path.display().to_string())?;
    let status = child.wait().map_err(|e| e.to_string())?;
    let err_txt = err_handle.join().unwrap_or_default();
    if !status.success() {
        return Err(format!("{} failed ({status}): {}", ofd.display(), err_txt.trim()));
    }
    table.build_digest = compute_file_digest(path).unwrap_or_default();
    table.flash_fingerprint = extract_flash_fingerprint(path, cp, 16);

    if use_cache {
        save_cached_symbols(&table, path, cp.name, None, DEFAULT_MAX_CACHE_BYTES, DEFAULT_MAX_CACHE_ENTRIES);
    }
    Ok(table)
}

fn flatten_nodes<'a>(nodes: &'a [SymbolNode], out: &mut BTreeMap<String, &'a SymbolNode>) {
    for n in nodes {
        out.insert(n.full_path.clone(), n);
        if !n.children.is_empty() {
            flatten_nodes(&n.children, out);
        }
    }
}

/// Atomically re-resolve WatchItems after a .out rebuild; quarantines missing or type-mutated items RO.
pub fn resolve_watch_items_from_table(
    items: &[WatchItem],
    table: &ParsedSymbolTable,
) -> (Vec<WatchItem>, Vec<String>, Vec<String>) {
    let mut flat = BTreeMap::new();
    flatten_nodes(&table.symbols, &mut flat);
    let mut updated = Vec::with_capacity(items.len());
    let mut moved_msgs = Vec::new();
    let mut quarantined_msgs = Vec::new();

    for it in items {
        if it.core != table.core {
            updated.push(it.clone());
            continue;
        }
        let node = flat.get(&it.symbol_path).copied().or_else(|| {
            if !it.tu_scope.is_empty() {
                flat.get(&format!("{}::{}", it.tu_scope, it.symbol_path)).copied()
            } else {
                None
            }
        });
        let Some(n) = node else {
            if it.symbol_path.starts_with("mem_0x") {
                updated.push(it.clone());
                continue;
            }
            let mut q = it.clone();
            q.read_only = true;
            q.rmw_unlocked = false;
            q.write_state = WriteState::Quarantined;
            q.last_write_error = format!("Symbol '{}' missing after rebuild (locked RO)", it.symbol_path);
            quarantined_msgs.push(q.last_write_error.clone());
            updated.push(q);
            continue;
        };

        let type_changed = it.data_type != n.data_type || it.bit_offset != n.bit_offset || it.bit_width != n.bit_width;
        let mut next = it.clone();
        let old_addr = next.address;
        next.address = n.address;
        next.page = n.page.clone();
        next.data_type = n.data_type;
        next.bit_offset = n.bit_offset;
        next.bit_width = n.bit_width;
        next.container_units = n.container_units;
        next.section_name = n.section_name.clone();
        next.domain = n.domain;
        if !n.tu_scope.is_empty() {
            next.tu_scope = n.tu_scope.clone();
        }
        if type_changed {
            next.read_only = true;
            next.write_state = WriteState::Quarantined;
            next.last_write_error = format!("Type changed {:?} -> {:?} (locked RO)", it.data_type, n.data_type);
            quarantined_msgs.push(format!("{}:{} {}", it.core, it.symbol_path, next.last_write_error));
        } else if old_addr != n.address {
            next.write_state = WriteState::Idle;
            moved_msgs.push(format!("{}:{} moved 0x{:06X} -> 0x{:06X}", it.core, it.symbol_path, old_addr, n.address));
        }
        updated.push(next);
    }
    (updated, moved_msgs, quarantined_msgs)
}
