//! RAM-safe span coalescer, 5-gate MemCfg write firewall, CLA proxy routing, and 32-bit anti-tearing.

use std::collections::{BTreeMap, HashSet};

use crate::core::models::{
    CoreProfile, DeviceProfile, MemCfgSnapshot, MemoryRange, PhysicalMemoryDomain, WatchItem,
};

#[derive(Debug, Clone)]
pub struct SymbolSlice {
    pub item: WatchItem,
    pub offset_units: usize,
    pub unit_count: usize,
}

#[derive(Debug, Clone)]
pub struct CoalescedSpan {
    pub span_id: usize,
    pub read_core: String,
    pub page: String,
    pub start_addr: u32,
    pub count: u32,
    pub bit_size: u32,
    pub address_unit_bits: u32,
    pub slices: Vec<SymbolSlice>,
    pub unpack_to_au: bool,
}

impl CoalescedSpan {
    pub fn mau_span(&self) -> u32 {
        if self.bit_size == 32 && self.address_unit_bits == 16 {
            self.count * 2
        } else if self.bit_size == 32 && self.address_unit_bits == 8 {
            self.count * 4
        } else {
            self.count
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ReadPlan {
    pub fast_spans: Vec<CoalescedSpan>,
    pub slow_5_spans: Vec<CoalescedSpan>,
    pub slow_20_spans: Vec<CoalescedSpan>,
    pub non_atomic_ids: Vec<String>,
}

#[derive(Debug, Default)]
pub struct SlowSpanScheduler {
    cursor_5: usize,
    cursor_20: usize,
    turn_toggle: usize,
}

impl SlowSpanScheduler {
    pub fn next_slow_spans<'a>(
        &mut self,
        spans_5: &'a [CoalescedSpan],
        spans_20: &'a [CoalescedSpan],
        cycle_index: u64,
    ) -> Vec<&'a CoalescedSpan> {
        let due_5 = !spans_5.is_empty() && (cycle_index.is_multiple_of(5) || spans_5.len() >= 5);
        let due_20 = !spans_20.is_empty() && (cycle_index % 20 == 1 || spans_20.len() >= 20);
        if due_5 && due_20 {
            if cycle_index % 20 == 1 || (self.turn_toggle % 2 == 1) {
                self.turn_toggle += 1;
                let sp = &spans_20[self.cursor_20 % spans_20.len()];
                self.cursor_20 += 1;
                return vec![sp];
            }
            self.turn_toggle += 1;
            let sp = &spans_5[self.cursor_5 % spans_5.len()];
            self.cursor_5 += 1;
            return vec![sp];
        }
        if due_20 {
            let sp = &spans_20[self.cursor_20 % spans_20.len()];
            self.cursor_20 += 1;
            return vec![sp];
        }
        if due_5 {
            let sp = &spans_5[self.cursor_5 % spans_5.len()];
            self.cursor_5 += 1;
            return vec![sp];
        }
        Vec::new()
    }
}

pub fn resolve_read_core_and_page(item: &WatchItem, profile: &DeviceProfile) -> (String, String) {
    let Some(cp) = profile.find_core(&item.core) else {
        return (item.core.clone(), item.page.clone());
    };
    if let Some(parent) = cp.proxy_parent_core {
        let units = item.data_type.unit_count(cp.address_unit_bits);
        let ranges = profile
            .ram_ranges
            .get(cp.name)
            .map(Vec::as_slice)
            .unwrap_or(&profile.cla_shared_ranges);
        if ranges.iter().any(|r| r.is_cla_shared && r.contains(item.address, units)) {
            if let Some(p_prof) = profile.find_core(parent) {
                return (p_prof.name.to_string(), p_prof.default_page.to_string());
            }
        }
    }
    let pg = if item.page.is_empty() {
        cp.default_page.to_string()
    } else {
        item.page.clone()
    };
    (cp.name.to_string(), pg)
}

fn range_runtime_key(rng: &MemoryRange, core: &str, memcfg: Option<&MemCfgSnapshot>) -> (PhysicalMemoryDomain, String, bool) {
    if let (Some(mc), Some(bi)) = (memcfg.filter(|m| m.probed), rng.bank_index) {
        if rng.domain == PhysicalMemoryDomain::ClaShared {
            let is_pgm = mc.ls_is_cla_program(bi);
            return (rng.domain, if is_pgm { "CLA_PGM".into() } else { core.into() }, !is_pgm);
        }
        if rng.domain == PhysicalMemoryDomain::GsShared {
            return (rng.domain, mc.gs_owner_core(bi).to_string(), true);
        }
    }
    (rng.domain, core.to_string(), true)
}

fn merge_contiguous_safe_ram(candidates: &[MemoryRange], core: &str, memcfg: Option<&MemCfgSnapshot>) -> Vec<(u32, u32)> {
    let mut valid: Vec<&MemoryRange> = candidates
        .iter()
        .filter(|r| r.is_ram && !r.is_peripheral && range_runtime_key(r, core, memcfg).2)
        .collect();
    if valid.is_empty() {
        return Vec::new();
    }
    valid.sort_by_key(|r| (r.start, r.end));
    let mut merged: Vec<(u32, u32, (PhysicalMemoryDomain, String, bool))> = Vec::new();
    for r in valid {
        let key = range_runtime_key(r, core, memcfg);
        if let Some(last) = merged.last_mut() {
            let same_owner = last.2 .1 == key.1 && last.2 .2 == key.2;
            let compat = last.2 .0 == key.0
                || matches!(
                    (last.2 .0, key.0),
                    (PhysicalMemoryDomain::Cpu1Private, PhysicalMemoryDomain::GsShared)
                        | (PhysicalMemoryDomain::GsShared, PhysicalMemoryDomain::Cpu1Private)
                        | (PhysicalMemoryDomain::Cpu2Private, PhysicalMemoryDomain::GsShared)
                        | (PhysicalMemoryDomain::GsShared, PhysicalMemoryDomain::Cpu2Private)
                        | (PhysicalMemoryDomain::Unknown, _)
                        | (_, PhysicalMemoryDomain::Unknown)
                );
            if r.start <= last.1.saturating_add(1) && same_owner && compat {
                last.1 = last.1.max(r.end);
                continue;
            }
        }
        merged.push((r.start, r.end, key));
    }
    merged.into_iter().map(|(s, e, _)| (s, e)).collect()
}

pub fn is_address_safe_to_coalesce(
    core: &str,
    start_addr: u32,
    end_addr: u32,
    profile: &DeviceProfile,
    extra_ram: Option<&BTreeMap<String, Vec<MemoryRange>>>,
    memcfg: Option<&MemCfgSnapshot>,
) -> bool {
    if start_addr > end_addr {
        return false;
    }
    if let Some(denies) = profile.forbidden_mmio_ranges.get(core) {
        if denies.iter().any(|d| d.overlaps(start_addr, end_addr)) {
            return false;
        }
    }
    if let Some(flashes) = profile.flash_ranges.get(core) {
        if flashes.iter().any(|f| f.overlaps(start_addr, end_addr)) {
            return false;
        }
    }
    let mut all_ram: Vec<MemoryRange> = profile.ram_ranges.get(core).cloned().unwrap_or_default();
    if let Some(extra) = extra_ram.and_then(|m| m.get(core)) {
        all_ram.extend(extra.iter().cloned());
    }
    merge_contiguous_safe_ram(&all_ram, core, memcfg)
        .into_iter()
        .any(|(s, e)| start_addr >= s && end_addr <= e)
}

#[derive(Debug, Clone)]
pub struct WriteTargetDecision {
    pub allowed: bool,
    pub reason: String,
    pub write_core: String,
    pub page: String,
}

/// Authoritative hardware-safety write firewall (Gate 3):
/// Checks Silicon Base Deny-Matrix, Flash, `.scratchpad`/non-RAM sections, directional MSGRAMs,
/// runtime MemCfg LSxCLAPGM/GSxMSEL ownership, and concurrent CLA/GSx bitfield RMW lockouts.
pub fn validate_write_target(
    item: &WatchItem,
    profile: &DeviceProfile,
    extra_ram: Option<&BTreeMap<String, Vec<MemoryRange>>>,
    memcfg: Option<&MemCfgSnapshot>,
    connected_cores: Option<&HashSet<String>>,
) -> WriteTargetDecision {
    let Some(cp) = profile.find_core(&item.core) else {
        return WriteTargetDecision {
            allowed: false,
            reason: format!("Unknown target core '{}'.", item.core),
            write_core: item.core.clone(),
            page: item.page.clone(),
        };
    };
    let sec_low = item.section_name.to_ascii_lowercase();
    if item.domain == PhysicalMemoryDomain::Scratchpad
        || sec_low.contains(".scratchpad")
        || matches!(
            sec_low.as_str(),
            ".stack" | ".sysmem" | ".esysmem" | ".text" | ".cinit" | ".const" | ".econst"
        )
    {
        return WriteTargetDecision {
            allowed: false,
            reason: format!("Write denied: '{}' resides in protected section '{}'.", item.symbol_path, item.section_name),
            write_core: item.core.clone(),
            page: item.page.clone(),
        };
    }

    let au = cp.address_unit_bits;
    let units = if item.is_bitfield() {
        item.container_units.unwrap_or_else(|| item.data_type.unit_count(au))
    } else {
        item.data_type.unit_count(au)
    }
    .max(1);
    let start_addr = item.address;
    let end_addr = start_addr.saturating_add(units - 1);

    let mut check_cores = vec![cp.name];
    if let Some(p) = cp.proxy_parent_core {
        check_cores.push(p);
    }
    for c in check_cores {
        if let Some(denies) = profile.forbidden_mmio_ranges.get(c) {
            if let Some(bad) = denies.iter().find(|d| d.overlaps(start_addr, end_addr)) {
                return WriteTargetDecision {
                    allowed: false,
                    reason: format!("Write denied: 0x{start_addr:X} overlaps forbidden {} ({:?}).", bad.name, bad.domain),
                    write_core: item.core.clone(),
                    page: item.page.clone(),
                };
            }
        }
        if let Some(flashes) = profile.flash_ranges.get(c) {
            if let Some(fl) = flashes.iter().find(|f| f.overlaps(start_addr, end_addr)) {
                return WriteTargetDecision {
                    allowed: false,
                    reason: format!("Write denied: 0x{start_addr:X} overlaps non-volatile Flash {}.", fl.name),
                    write_core: item.core.clone(),
                    page: item.page.clone(),
                };
            }
        }
    }

    let mut write_core = item.core.clone();
    let mut page = if item.page.is_empty() {
        cp.default_page.to_string()
    } else {
        item.page.clone()
    };

    if let Some(matched) = profile
        .ram_ranges
        .get(&item.core)
        .and_then(|rs| rs.iter().find(|r| r.contains(start_addr, units)))
    {
        if !matched.writable_by.is_empty() {
            let core_ok = matched.writable_by.iter().any(|c| c == &item.core);
            if !core_ok {
                if let Some(parent) = cp.proxy_parent_core {
                    if matched.writable_by.iter().any(|c| c == parent) {
                        write_core = parent.to_string();
                        if let Some(pp) = profile.find_core(parent) {
                            page = pp.default_page.to_string();
                        }
                    } else {
                        return WriteTargetDecision {
                            allowed: false,
                            reason: format!(
                                "Write denied: {} (0x{start_addr:X}) is hardware Read-Only for {}.",
                                matched.name, item.core
                            ),
                            write_core: item.core.clone(),
                            page,
                        };
                    }
                } else {
                    return WriteTargetDecision {
                        allowed: false,
                        reason: format!(
                            "Write denied: {} (0x{start_addr:X}) is hardware Read-Only for {} (writable by {:?}).",
                            matched.name, item.core, matched.writable_by
                        ),
                        write_core: item.core.clone(),
                        page,
                    };
                }
            } else if let Some(parent) = cp.proxy_parent_core {
                if matched.writable_by.iter().any(|c| c == parent) {
                    write_core = parent.to_string();
                    if let Some(pp) = profile.find_core(parent) {
                        page = pp.default_page.to_string();
                    }
                }
            }
        } else if matches!(
            matched.domain,
            PhysicalMemoryDomain::MsgCmToCpu | PhysicalMemoryDomain::MsgCpuToCm
        ) {
            return WriteTargetDecision {
                allowed: false,
                reason: format!("Write denied: {} (0x{start_addr:X}) is hardware Read-Only for {}.", matched.name, item.core),
                write_core,
                page,
            };
        }

        if let (Some(mc), Some(bi)) = (memcfg.filter(|m| m.probed), matched.bank_index) {
            if matched.domain == PhysicalMemoryDomain::ClaShared && mc.ls_is_cla_program(bi) {
                return WriteTargetDecision {
                    allowed: false,
                    reason: format!("Write denied: {} has MemCfg LSxCLAPGM=1 (CLA Program RAM).", matched.name),
                    write_core,
                    page,
                };
            }
            if matched.domain == PhysicalMemoryDomain::GsShared {
                let owner = mc.gs_owner_core(bi);
                if owner != write_core {
                    if connected_cores.is_none_or(|cc| cc.contains(owner)) {
                        write_core = owner.to_string();
                        if let Some(op) = profile.find_core(owner) {
                            page = op.default_page.to_string();
                        }
                    } else {
                        return WriteTargetDecision {
                            allowed: false,
                            reason: format!("Write denied: {} is owned by {} (GSxMSEL), which is detached.", matched.name, owner),
                            write_core: owner.to_string(),
                            page,
                        };
                    }
                }
            }
        }

        if item.is_bitfield()
            && matches!(
                matched.domain,
                PhysicalMemoryDomain::ClaShared
                    | PhysicalMemoryDomain::MsgClaToCpu
                    | PhysicalMemoryDomain::MsgCpuToCla
                    | PhysicalMemoryDomain::GsShared
            )
        {
            if matched.is_cla_shared {
                if let (Some(mc), Some(bi)) = (memcfg.filter(|m| m.probed), matched.bank_index) {
                    if mc.ls_is_cla_owned(bi) {
                        return WriteTargetDecision {
                            allowed: false,
                            reason: format!("Bitfield RMW denied on CLA-owned {} (races 200 MHz CLA).", matched.name),
                            write_core,
                            page,
                        };
                    }
                }
            } else if matched.domain == PhysicalMemoryDomain::GsShared
                && connected_cores.is_some_and(|cc| cc.contains("C28xx_CPU2"))
            {
                return WriteTargetDecision {
                    allowed: false,
                    reason: format!("Bitfield RMW denied on dual-core shared {} while CPU2 is active.", matched.name),
                    write_core,
                    page,
                };
            }
        }

        return WriteTargetDecision {
            allowed: true,
            reason: String::new(),
            write_core,
            page,
        };
    }

    if is_address_safe_to_coalesce(&write_core, start_addr, end_addr, profile, extra_ram, memcfg) {
        return WriteTargetDecision {
            allowed: true,
            reason: String::new(),
            write_core,
            page,
        };
    }

    WriteTargetDecision {
        allowed: false,
        reason: format!("Write denied: 0x{start_addr:X}..0x{end_addr:X} on {} is outside validated RAM.", item.core),
        write_core,
        page,
    }
}

fn check_atomicity(item: &WatchItem, cp: &CoreProfile) -> bool {
    let bits = item.data_type.bit_size();
    if cp.address_unit_bits == 16 {
        if bits == 32 {
            return (item.address & 1) == 0;
        }
        return bits <= 16;
    }
    if bits == 32 {
        return (item.address & 3) == 0;
    }
    bits <= 16
}

#[allow(clippy::too_many_arguments)]
fn make_span(
    span_id: usize,
    read_core: &str,
    page: &str,
    au: u32,
    items: &[WatchItem],
    profile: &DeviceProfile,
    extra_ram: Option<&BTreeMap<String, Vec<MemoryRange>>>,
    memcfg: Option<&MemCfgSnapshot>,
) -> CoalescedSpan {
    let mut min_addr = u32::MAX;
    let mut max_end = 0u32;
    let mut any_32 = false;
    let mut all_32_aligned = true;

    for it in items {
        let u = it.data_type.unit_count(au);
        min_addr = min_addr.min(it.address);
        max_end = max_end.max(it.address.saturating_add(u - 1));
        if it.data_type.is_32bit() {
            any_32 = true;
        }
        let align_mask = if au == 16 { 1 } else { 3 };
        if !it.data_type.is_32bit() || (it.address & align_mask) != 0 {
            all_32_aligned = false;
        }
    }

    let mut start = min_addr;
    let mut end = max_end;
    let mut bit_size = au;
    let mut unpack_to_au = false;

    if au == 16 && any_32 {
        let aligned_start = start & !1;
        let aligned_end = end | 1;
        if is_address_safe_to_coalesce(read_core, aligned_start, aligned_end, profile, extra_ram, memcfg) {
            start = aligned_start;
            end = aligned_end;
            bit_size = 32;
            unpack_to_au = !all_32_aligned;
        }
    } else if au == 8 && any_32 && all_32_aligned && (start & 3) == 0 && (end - start + 1).is_multiple_of(4) {
        bit_size = 32;
        unpack_to_au = false;
    }

    let total_units = end - start + 1;
    let count = if bit_size == 32 && au == 16 {
        total_units / 2
    } else if bit_size == 32 && au == 8 {
        total_units / 4
    } else {
        total_units
    };

    let slices = items
        .iter()
        .map(|it| {
            let off_mau = (it.address - start) as usize;
            let u_cnt = it.data_type.unit_count(au) as usize;
            let (off, cnt) = if bit_size == 32 && !unpack_to_au {
                let div = if au == 16 { 2 } else { 4 };
                (off_mau / div, (u_cnt / div).max(1))
            } else {
                (off_mau, u_cnt)
            };
            SymbolSlice {
                item: it.clone(),
                offset_units: off,
                unit_count: cnt,
            }
        })
        .collect();

    CoalescedSpan {
        span_id,
        read_core: read_core.to_string(),
        page: page.to_string(),
        start_addr: start,
        count,
        bit_size,
        address_unit_bits: au,
        slices,
        unpack_to_au,
    }
}

pub fn build_read_plan(
    items: &mut [WatchItem],
    profile: &DeviceProfile,
    coalesce_gap: u32,
    max_block_units: u32,
    extra_ram: Option<&BTreeMap<String, Vec<MemoryRange>>>,
    memcfg: Option<&MemCfgSnapshot>,
    connected_cores: Option<&HashSet<String>>,
) -> ReadPlan {
    let mut plan = ReadPlan::default();
    let mut next_span_id = 1usize;

    // Partition into fast (rate <= 1) vs slow (5 / 20), resolving read_core & atomicity
    let mut grouped_fast: BTreeMap<(String, String), Vec<WatchItem>> = BTreeMap::new();
    let mut slow_pool: Vec<(String, String, WatchItem)> = Vec::new();

    for it in items.iter_mut() {
        let (rc, pg) = resolve_read_core_and_page(it, profile);
        if let Some(cc) = connected_cores {
            if !cc.contains(&rc) {
                continue;
            }
        }
        if let Some(cp) = profile.find_core(&rc) {
            it.is_atomic = check_atomicity(it, cp);
            if !it.is_atomic {
                plan.non_atomic_ids.push(it.id.clone());
            }
        }
        if it.rate_divider <= 1 {
            grouped_fast.entry((rc, pg)).or_default().push(it.clone());
        } else {
            slow_pool.push((rc, pg, it.clone()));
        }
    }

    // Free promotion: if a slow symbol lies within coalesce_gap of any fast symbol on same core/page inside safe RAM, promote it!
    let mut remaining_slow_5: BTreeMap<(String, String), Vec<WatchItem>> = BTreeMap::new();
    let mut remaining_slow_20: BTreeMap<(String, String), Vec<WatchItem>> = BTreeMap::new();

    for (rc, pg, sit) in slow_pool {
        let au = profile.find_core(&rc).map(|c| c.address_unit_bits).unwrap_or(16);
        let eff_gap = if au == 8 { coalesce_gap * 2 } else { coalesce_gap };
        let mut promoted = false;
        if let Some(fast_list) = grouped_fast.get_mut(&(rc.clone(), pg.clone())) {
            for fit in fast_list.iter() {
                let lo = fit.address.min(sit.address);
                let hi = (fit.address + fit.data_type.unit_count(au) - 1)
                    .max(sit.address + sit.data_type.unit_count(au) - 1);
                if hi.saturating_sub(lo) <= eff_gap
                    && is_address_safe_to_coalesce(&rc, lo, hi, profile, extra_ram, memcfg)
                {
                    fast_list.push(sit.clone());
                    promoted = true;
                    break;
                }
            }
        }
        if !promoted {
            if sit.rate_divider <= 5 {
                remaining_slow_5.entry((rc, pg)).or_default().push(sit);
            } else {
                remaining_slow_20.entry((rc, pg)).or_default().push(sit);
            }
        }
    }

    let mut coalesce_group = |groups: BTreeMap<(String, String), Vec<WatchItem>>, out: &mut Vec<CoalescedSpan>| {
        for ((rc, pg), mut list) in groups {
            let au = profile.find_core(&rc).map(|c| c.address_unit_bits).unwrap_or(16);
            let eff_gap = if au == 8 { coalesce_gap * 2 } else { coalesce_gap };
            let eff_max = if au == 8 { max_block_units * 2 } else { max_block_units };
            list.sort_by_key(|i| i.address);

            let mut cur: Vec<WatchItem> = Vec::new();
            let mut cur_start = 0u32;
            let mut cur_end = 0u32;

            for it in list {
                let it_end = it.address.saturating_add(it.data_type.unit_count(au) - 1);
                if cur.is_empty() {
                    cur_start = it.address;
                    cur_end = it_end;
                    cur.push(it);
                    continue;
                }
                let gap = it.address.saturating_sub(cur_end + 1);
                let new_end = cur_end.max(it_end);
                if gap <= eff_gap
                    && (new_end - cur_start + 1) <= eff_max
                    && is_address_safe_to_coalesce(&rc, cur_start, new_end, profile, extra_ram, memcfg)
                {
                    cur_end = new_end;
                    cur.push(it);
                } else {
                    out.push(make_span(next_span_id, &rc, &pg, au, &cur, profile, extra_ram, memcfg));
                    next_span_id += 1;
                    cur_start = it.address;
                    cur_end = it_end;
                    cur = vec![it];
                }
            }
            if !cur.is_empty() {
                out.push(make_span(next_span_id, &rc, &pg, au, &cur, profile, extra_ram, memcfg));
                next_span_id += 1;
            }
        }
    };

    coalesce_group(grouped_fast, &mut plan.fast_spans);
    coalesce_group(remaining_slow_5, &mut plan.slow_5_spans);
    coalesce_group(remaining_slow_20, &mut plan.slow_20_spans);
    plan
}

pub fn split_failed_span(span: &CoalescedSpan) -> Vec<CoalescedSpan> {
    if span.slices.len() <= 1 {
        return vec![span.clone()];
    }
    span.slices
        .iter()
        .enumerate()
        .map(|(i, sl)| {
            let units = sl.item.data_type.unit_count(span.address_unit_bits);
            CoalescedSpan {
                span_id: span.span_id * 1000 + i + 1,
                read_core: span.read_core.clone(),
                page: span.page.clone(),
                start_addr: sl.item.address,
                count: units,
                bit_size: span.address_unit_bits,
                address_unit_bits: span.address_unit_bits,
                slices: vec![SymbolSlice {
                    item: sl.item.clone(),
                    offset_units: 0,
                    unit_count: units as usize,
                }],
                unpack_to_au: false,
            }
        })
        .collect()
}
