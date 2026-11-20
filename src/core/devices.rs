//! TMS320F28069M and TMS320F28388D memory maps, Silicon Deny-Matrix, directional MSGRAM rights, and Probe Capabilities.

use std::collections::BTreeMap;

use crate::core::models::{
    CoreProfile, DeviceId, DeviceProfile, MemoryRange, PhysicalMemoryDomain, ProbeKind,
};

#[derive(Debug, Clone, Copy)]
pub struct ProbeCapabilities {
    pub supports_cjtag: bool,
    pub supports_aux_uart: bool,
    pub max_tclk_mhz: f64,
    pub max_burst_kbps: u32,
}

pub fn probe_capabilities(kind: ProbeKind) -> ProbeCapabilities {
    match kind {
        ProbeKind::XDS110 => ProbeCapabilities {
            supports_cjtag: true,
            supports_aux_uart: true,
            max_tclk_mhz: 14.0,
            max_burst_kbps: 2400,
        },
        ProbeKind::XDS100V2 => ProbeCapabilities {
            supports_cjtag: false,
            supports_aux_uart: false,
            max_tclk_mhz: 6.0,
            max_burst_kbps: 220,
        },
        ProbeKind::SIMULATOR => ProbeCapabilities {
            supports_cjtag: true,
            supports_aux_uart: false,
            max_tclk_mhz: 14.0,
            max_burst_kbps: 10000,
        },
        ProbeKind::CUSTOM_CCXML => ProbeCapabilities {
            supports_cjtag: true,
            supports_aux_uart: false,
            max_tclk_mhz: 14.0,
            max_burst_kbps: 2400,
        },
    }
}

pub fn probe_tclk_options(kind: ProbeKind) -> &'static [&'static str] {
    match kind {
        ProbeKind::XDS110 => &["1.0MHz", "2.5MHz", "5.5MHz", "8.5MHz", "10.0MHz", "14.0MHz"],
        ProbeKind::XDS100V2 => &["1.0MHz", "2.5MHz", "4.0MHz", "6.0MHz"],
        ProbeKind::SIMULATOR => &["Virtual"],
        ProbeKind::CUSTOM_CCXML => &["Custom"],
    }
}

pub fn default_tclk(kind: ProbeKind) -> &'static str {
    match kind {
        ProbeKind::XDS110 => "5.5MHz",
        ProbeKind::XDS100V2 => "2.5MHz",
        ProbeKind::SIMULATOR => "Virtual",
        ProbeKind::CUSTOM_CCXML => "Custom",
    }
}

#[allow(clippy::too_many_arguments)]
fn mr(
    start: u32,
    end: u32,
    name: &str,
    is_ram: bool,
    is_peripheral: bool,
    is_cla_shared: bool,
    domain: PhysicalMemoryDomain,
    readable_by: &[&str],
    writable_by: &[&str],
    bank_index: Option<usize>,
) -> MemoryRange {
    MemoryRange {
        start,
        end,
        name: name.to_string(),
        is_ram,
        is_peripheral,
        is_cla_shared,
        domain,
        readable_by: readable_by.iter().map(|s| s.to_string()).collect(),
        writable_by: writable_by.iter().map(|s| s.to_string()).collect(),
        bank_index,
    }
}

pub fn build_f28069m_profile() -> DeviceProfile {
    let cores = vec![
        CoreProfile {
            name: "C28xx_0",
            display_tag: "C28x",
            isa: "C28x",
            address_unit_bits: 16,
            default_page: "DATA",
            supports_realtime_gel: true,
            ofd_tool: "ofd2000",
            is_primary: true,
            proxy_parent_core: None,
            badge_hex: "#0055D4",
        },
        CoreProfile {
            name: "CLA_0",
            display_tag: "CLA",
            isa: "CLA",
            address_unit_bits: 16,
            default_page: "DATA",
            supports_realtime_gel: false,
            ofd_tool: "ofd2000",
            is_primary: false,
            proxy_parent_core: Some("C28xx_0"),
            badge_hex: "#0E7C3A",
        },
    ];

    let c28_ram = vec![
        mr(0x000000, 0x0007FF, "M0_M1_SARAM", true, false, false, PhysicalMemoryDomain::Cpu1Private, &["C28xx_0"], &["C28xx_0"], None),
        mr(0x001480, 0x0014FF, "CLA_TO_CPU_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgClaToCpu, &["C28xx_0", "CLA_0"], &["CLA_0"], None),
        mr(0x001500, 0x00157F, "CPU_TO_CLA_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgCpuToCla, &["C28xx_0", "CLA_0"], &["C28xx_0"], None),
        mr(0x008000, 0x008FFF, "L0_L2_DPSARAM", true, false, true, PhysicalMemoryDomain::ClaShared, &["C28xx_0", "CLA_0"], &["C28xx_0", "CLA_0"], None),
        mr(0x009000, 0x009FFF, "L3_CLA_PROG_RAM", true, false, true, PhysicalMemoryDomain::ClaShared, &["C28xx_0", "CLA_0"], &["C28xx_0", "CLA_0"], Some(3)),
        mr(0x00A000, 0x013FFF, "L4_L8_CPU_DMA_RAM", true, false, false, PhysicalMemoryDomain::Cpu1Private, &["C28xx_0"], &["C28xx_0"], None),
    ];
    let cla_ram = vec![
        mr(0x001480, 0x0014FF, "CLA_TO_CPU_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgClaToCpu, &["C28xx_0", "CLA_0"], &["CLA_0"], None),
        mr(0x001500, 0x00157F, "CPU_TO_CLA_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgCpuToCla, &["C28xx_0", "CLA_0"], &["C28xx_0"], None),
        mr(0x008000, 0x008FFF, "L0_L2_DPSARAM", true, false, true, PhysicalMemoryDomain::ClaShared, &["C28xx_0", "CLA_0"], &["C28xx_0", "CLA_0"], None),
        mr(0x009000, 0x009FFF, "L3_CLA_PROG_RAM", true, false, true, PhysicalMemoryDomain::ClaShared, &["C28xx_0", "CLA_0"], &["C28xx_0", "CLA_0"], Some(3)),
    ];
    let flash = vec![
        mr(0x3D8000, 0x3F7FF7, "FLASH_A_H", false, false, false, PhysicalMemoryDomain::Flash, &["C28xx_0"], &[], None),
    ];
    let deny = vec![
        mr(0x000800, 0x00147F, "PERIPH_FRAME_0_1", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x001580, 0x007FFF, "PERIPH_FRAME_2_3", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x3D7800, 0x3D7BFF, "F28069M_OTP", false, true, false, PhysicalMemoryDomain::Otp, &[], &[], None),
        mr(0x3F7FF8, 0x3F7FFF, "F28069M_CSM_PASSWORDS", false, true, false, PhysicalMemoryDomain::Otp, &[], &[], None),
    ];

    let mut ram_ranges = BTreeMap::new();
    ram_ranges.insert("C28xx_0".to_string(), c28_ram);
    ram_ranges.insert("CLA_0".to_string(), cla_ram.clone());
    let mut flash_ranges = BTreeMap::new();
    flash_ranges.insert("C28xx_0".to_string(), flash);
    let mut forbidden_mmio_ranges = BTreeMap::new();
    forbidden_mmio_ranges.insert("C28xx_0".to_string(), deny.clone());
    forbidden_mmio_ranges.insert("CLA_0".to_string(), deny);

    DeviceProfile {
        device_id: DeviceId::F28069M,
        display_name: "TMS320F28069M",
        targetdb_device_xml: "devices/f28069m.xml",
        default_probe: ProbeKind::XDS100V2,
        cores,
        ram_ranges,
        flash_ranges,
        forbidden_mmio_ranges,
        cla_shared_ranges: cla_ram,
    }
}

fn build_f28388d_ls(cpu: &str, cla: &str) -> Vec<MemoryRange> {
    (0..8)
        .map(|i| {
            let start = 0x008000 + (i as u32) * 0x800;
            mr(
                start,
                start + 0x7FF,
                &format!("LS{i}_RAM"),
                true,
                false,
                true,
                PhysicalMemoryDomain::ClaShared,
                &[cpu, cla],
                &[cpu, cla],
                Some(i),
            )
        })
        .collect()
}

fn build_f28388d_gs() -> Vec<MemoryRange> {
    (0..16)
        .map(|i| {
            let start = 0x00D000 + (i as u32) * 0x1000;
            mr(
                start,
                start + 0xFFF,
                &format!("GS{i}_RAM"),
                true,
                false,
                false,
                PhysicalMemoryDomain::GsShared,
                &["C28xx_CPU1", "C28xx_CPU2"],
                &["C28xx_CPU1", "C28xx_CPU2"],
                Some(i),
            )
        })
        .collect()
}

pub fn build_f28388d_profile() -> DeviceProfile {
    let cores = vec![
        CoreProfile {
            name: "C28xx_CPU1",
            display_tag: "CPU1",
            isa: "C28x",
            address_unit_bits: 16,
            default_page: "DATA",
            supports_realtime_gel: true,
            ofd_tool: "ofd2000",
            is_primary: true,
            proxy_parent_core: None,
            badge_hex: "#0055D4",
        },
        CoreProfile {
            name: "CPU1_CLA1",
            display_tag: "CLA1",
            isa: "CLA",
            address_unit_bits: 16,
            default_page: "DATA",
            supports_realtime_gel: false,
            ofd_tool: "ofd2000",
            is_primary: false,
            proxy_parent_core: Some("C28xx_CPU1"),
            badge_hex: "#0E7C3A",
        },
        CoreProfile {
            name: "C28xx_CPU2",
            display_tag: "CPU2",
            isa: "C28x",
            address_unit_bits: 16,
            default_page: "DATA",
            supports_realtime_gel: true,
            ofd_tool: "ofd2000",
            is_primary: false,
            proxy_parent_core: None,
            badge_hex: "#6D28D9",
        },
        CoreProfile {
            name: "CPU2_CLA1",
            display_tag: "CLA2",
            isa: "CLA",
            address_unit_bits: 16,
            default_page: "DATA",
            supports_realtime_gel: false,
            ofd_tool: "ofd2000",
            is_primary: false,
            proxy_parent_core: Some("C28xx_CPU2"),
            badge_hex: "#0F766E",
        },
        CoreProfile {
            name: "Cortex_M4_0",
            display_tag: "CM4",
            isa: "ARM",
            address_unit_bits: 8,
            default_page: "",
            supports_realtime_gel: false,
            ofd_tool: "tiarmofd",
            is_primary: false,
            proxy_parent_core: None,
            badge_hex: "#B45309",
        },
    ];

    let gs = build_f28388d_gs();
    let ls1 = build_f28388d_ls("C28xx_CPU1", "CPU1_CLA1");
    let ls2 = build_f28388d_ls("C28xx_CPU2", "CPU2_CLA1");

    let mut cpu1_ram = vec![
        mr(0x000000, 0x0007FF, "CPU1_M0_M1_SARAM", true, false, false, PhysicalMemoryDomain::Cpu1Private, &["C28xx_CPU1"], &["C28xx_CPU1"], None),
        mr(0x001480, 0x0014FF, "CLA1_TO_CPU1_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgClaToCpu, &["C28xx_CPU1", "CPU1_CLA1"], &["CPU1_CLA1"], None),
        mr(0x001500, 0x00157F, "CPU1_TO_CLA1_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgCpuToCla, &["C28xx_CPU1", "CPU1_CLA1"], &["C28xx_CPU1"], None),
    ];
    cpu1_ram.extend(ls1.clone());
    cpu1_ram.push(mr(0x00C000, 0x00CFFF, "CPU1_D0_D1_RAM", true, false, false, PhysicalMemoryDomain::Cpu1Private, &["C28xx_CPU1"], &["C28xx_CPU1"], None));
    cpu1_ram.extend(gs.clone());
    cpu1_ram.push(mr(0x038000, 0x0387FF, "CM_TO_CPU1_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCmToCpu, &["C28xx_CPU1"], &[], None));
    cpu1_ram.push(mr(0x039000, 0x0397FF, "CPU1_TO_CM_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCpuToCm, &["C28xx_CPU1"], &["C28xx_CPU1"], None));
    cpu1_ram.push(mr(0x03A000, 0x03A7FF, "CPU1_TO_CPU2_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCpu1ToCpu2, &["C28xx_CPU1", "C28xx_CPU2"], &["C28xx_CPU1"], None));
    cpu1_ram.push(mr(0x03B000, 0x03B7FF, "CPU2_TO_CPU1_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCpu2ToCpu1, &["C28xx_CPU1", "C28xx_CPU2"], &["C28xx_CPU2"], None));

    let mut cpu2_ram = vec![
        mr(0x000000, 0x0007FF, "CPU2_M0_M1_SARAM", true, false, false, PhysicalMemoryDomain::Cpu2Private, &["C28xx_CPU2"], &["C28xx_CPU2"], None),
        mr(0x001480, 0x0014FF, "CLA2_TO_CPU2_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgClaToCpu, &["C28xx_CPU2", "CPU2_CLA1"], &["CPU2_CLA1"], None),
        mr(0x001500, 0x00157F, "CPU2_TO_CLA2_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgCpuToCla, &["C28xx_CPU2", "CPU2_CLA1"], &["C28xx_CPU2"], None),
    ];
    cpu2_ram.extend(ls2.clone());
    cpu2_ram.push(mr(0x00C000, 0x00CFFF, "CPU2_D0_D1_RAM", true, false, false, PhysicalMemoryDomain::Cpu2Private, &["C28xx_CPU2"], &["C28xx_CPU2"], None));
    cpu2_ram.extend(gs);
    cpu2_ram.push(mr(0x038000, 0x0387FF, "CM_TO_CPU2_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCmToCpu, &["C28xx_CPU2"], &[], None));
    cpu2_ram.push(mr(0x039000, 0x0397FF, "CPU2_TO_CM_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCpuToCm, &["C28xx_CPU2"], &["C28xx_CPU2"], None));
    cpu2_ram.push(mr(0x03A000, 0x03A7FF, "CPU1_TO_CPU2_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCpu1ToCpu2, &["C28xx_CPU1", "C28xx_CPU2"], &["C28xx_CPU1"], None));
    cpu2_ram.push(mr(0x03B000, 0x03B7FF, "CPU2_TO_CPU1_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCpu2ToCpu1, &["C28xx_CPU1", "C28xx_CPU2"], &["C28xx_CPU2"], None));

    let mut cla1_ram = vec![
        mr(0x001480, 0x0014FF, "CLA1_TO_CPU1_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgClaToCpu, &["C28xx_CPU1", "CPU1_CLA1"], &["CPU1_CLA1"], None),
        mr(0x001500, 0x00157F, "CPU1_TO_CLA1_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgCpuToCla, &["C28xx_CPU1", "CPU1_CLA1"], &["C28xx_CPU1"], None),
    ];
    cla1_ram.extend(ls1);

    let mut cla2_ram = vec![
        mr(0x001480, 0x0014FF, "CLA2_TO_CPU2_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgClaToCpu, &["C28xx_CPU2", "CPU2_CLA1"], &["CPU2_CLA1"], None),
        mr(0x001500, 0x00157F, "CPU2_TO_CLA2_MSGRAM", true, false, true, PhysicalMemoryDomain::MsgCpuToCla, &["C28xx_CPU2", "CPU2_CLA1"], &["C28xx_CPU2"], None),
    ];
    cla2_ram.extend(ls2);

    let cm4_ram = vec![
        mr(0x1FFFC000, 0x1FFFFFFF, "CM_C1_C0_SRAM", true, false, false, PhysicalMemoryDomain::Cm4Sram, &["Cortex_M4_0"], &["Cortex_M4_0"], None),
        mr(0x20000000, 0x20013FFF, "CM_S0_S3_E0_SRAM", true, false, false, PhysicalMemoryDomain::Cm4Sram, &["Cortex_M4_0"], &["Cortex_M4_0"], None),
        mr(0x20080000, 0x20080FFF, "CM_CPU1TOCM_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCpuToCm, &["Cortex_M4_0"], &[], None),
        mr(0x20082000, 0x20082FFF, "CM_CMTOCPU1_MSGRAM", true, false, false, PhysicalMemoryDomain::MsgCmToCpu, &["Cortex_M4_0"], &["Cortex_M4_0"], None),
    ];

    let c28_deny = vec![
        mr(0x000800, 0x00147F, "C28_PERIPH_0", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x001580, 0x007FFF, "C28_PERIPH_CLB_EPWM_ADC", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x030000, 0x0327FF, "ETHERCAT_ESC_AND_PERIPH", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x038800, 0x038FFF, "IPC_GAP_0", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x039800, 0x039FFF, "IPC_GAP_1", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x03A800, 0x03AFFF, "IPC_GAP_2", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x040000, 0x05FFFF, "C28_SYS_MEMCFG_REGS", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x070000, 0x0783FF, "F28388D_DCSM_OTP", false, true, false, PhysicalMemoryDomain::Otp, &[], &[], None),
    ];

    let cm4_deny = vec![
        mr(0x00380000, 0x003807FF, "CM4_USER_OTP", false, true, false, PhysicalMemoryDomain::Otp, &[], &[], None),
        mr(0x20014000, 0x2007FFFF, "CM4_UNMAPPED_GAP", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0x40000000, 0x5FFFFFFF, "CM4_PERIPH_MMIO", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
        mr(0xE0000000, 0xE00FFFFF, "CM4_PPB_DEBUG", false, true, false, PhysicalMemoryDomain::Mmio, &[], &[], None),
    ];

    let c28_flash = vec![
        mr(0x080000, 0x0BFFFF, "C28_FLASH_BANK", false, false, false, PhysicalMemoryDomain::Flash, &["C28xx_CPU1", "C28xx_CPU2"], &[], None),
    ];
    let cm4_flash = vec![
        mr(0x00200000, 0x0027FFFF, "CM4_FLASH", false, false, false, PhysicalMemoryDomain::Flash, &["Cortex_M4_0"], &[], None),
    ];

    let mut ram_ranges = BTreeMap::new();
    ram_ranges.insert("C28xx_CPU1".to_string(), cpu1_ram);
    ram_ranges.insert("CPU1_CLA1".to_string(), cla1_ram.clone());
    ram_ranges.insert("C28xx_CPU2".to_string(), cpu2_ram);
    ram_ranges.insert("CPU2_CLA1".to_string(), cla2_ram);
    ram_ranges.insert("Cortex_M4_0".to_string(), cm4_ram);

    let mut flash_ranges = BTreeMap::new();
    flash_ranges.insert("C28xx_CPU1".to_string(), c28_flash.clone());
    flash_ranges.insert("C28xx_CPU2".to_string(), c28_flash);
    flash_ranges.insert("Cortex_M4_0".to_string(), cm4_flash);

    let mut forbidden_mmio_ranges = BTreeMap::new();
    for c in ["C28xx_CPU1", "CPU1_CLA1", "C28xx_CPU2", "CPU2_CLA1"] {
        forbidden_mmio_ranges.insert(c.to_string(), c28_deny.clone());
    }
    forbidden_mmio_ranges.insert("Cortex_M4_0".to_string(), cm4_deny);

    DeviceProfile {
        device_id: DeviceId::F28388D,
        display_name: "TMS320F28388D",
        targetdb_device_xml: "devices/f28388d.xml",
        default_probe: ProbeKind::XDS110,
        cores,
        ram_ranges,
        flash_ranges,
        forbidden_mmio_ranges,
        cla_shared_ranges: cla1_ram,
    }
}

pub fn get_device_profile(device_id: DeviceId) -> DeviceProfile {
    match device_id {
        DeviceId::F28069M => build_f28069m_profile(),
        DeviceId::F28388D => build_f28388d_profile(),
    }
}

/// Startup invariant: no RAM range may overlap any forbidden MMIO/OTP/Flash range.
pub fn validate_device_profile_disjointness(profile: &DeviceProfile) -> Result<(), String> {
    for (core, rams) in &profile.ram_ranges {
        let denies = profile.forbidden_mmio_ranges.get(core);
        let flashes = profile.flash_ranges.get(core);
        for r in rams {
            if let Some(ds) = denies {
                for d in ds {
                    if r.overlaps(d.start, d.end) {
                        return Err(format!(
                            "{} {}: RAM {} overlaps forbidden {}",
                            profile.display_name, core, r.name, d.name
                        ));
                    }
                }
            }
            if let Some(fs) = flashes {
                for f in fs {
                    if r.overlaps(f.start, f.end) {
                        return Err(format!(
                            "{} {}: RAM {} overlaps Flash {}",
                            profile.display_name, core, r.name, f.name
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
