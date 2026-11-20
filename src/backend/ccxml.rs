//! TI CCS 21 .ccxml & USCIF .dat generator plus fail-closed custom .ccxml GEL stripper.

use std::fs;
use std::path::{Path, PathBuf};

use crate::core::models::{DeviceId, JtagMode, ProbeKind};

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

pub fn generate_ccxml(
    out_path: &Path,
    device_id: DeviceId,
    probe_kind: ProbeKind,
    tclk_hz: &str,
    jtag_mode: JtagMode,
    serial: &str,
    strip_gel: bool,
) -> Result<PathBuf, String> {
    let (conn_id, conn_xml, conn_name) = match probe_kind {
        ProbeKind::XDS110 => (
            "Texas Instruments XDS110 USB Debug Probe",
            "connections/TIXDS110_Connection.xml",
            "TIXDS110_Connection",
        ),
        _ => (
            "Texas Instruments XDS100v2 USB Debug Probe",
            "connections/TIXDS100v2_Connection.xml",
            "TIXDS100v2_Connection",
        ),
    };

    let (dev_id_str, dev_xml, dev_name) = match device_id {
        DeviceId::F28069M => ("TMS320F28069M", "devices/f28069m.xml", "TMS320F28069M"),
        DeviceId::F28388D => ("TMS320F28388D", "devices/f28388d.xml", "TMS320F28388D"),
    };

    let mut props = String::new();
    if probe_kind == ProbeKind::XDS110 {
        let mode_val = match jtag_mode {
            JtagMode::Jtag4Pin => "JTAG (1149.1), SWD and cJTAG are disabled",
            JtagMode::Cjtag2PinOscan2 => "cJTAG (1149.7) 2-pin advanced modes",
            JtagMode::Cjtag2PinOscan1 => "cJTAG (1149.7) 2-pin standard mode",
        };
        props.push_str(&format!(
            "        <property Type=\"choicelist\" Value=\"0\" id=\"SWD Mode Settings\">\n          <choice Name=\"{}\" value=\"ignored\"/>\n        </property>\n",
            xml_escape(mode_val)
        ));
        props.push_str(&format!(
            "        <property Type=\"choicelist\" Value=\"1\" id=\"JTAG TCLK Frequency (MHz)\">\n          <choice Name=\"Fixed with user specified value\" value=\"SPECIFIC\">\n            <property Type=\"stringfield\" Value=\"{}\" id=\"-- Enter a value from 100.0kHz to 14.0MHz\"/>\n          </choice>\n        </property>\n",
            xml_escape(tclk_hz)
        ));
        if !serial.is_empty() {
            props.push_str(&format!(
                "        <property Type=\"choicelist\" Value=\"1\" id=\"Debug Probe Selection\">\n          <choice Name=\"Select by serial number\" value=\"1\">\n            <property Type=\"stringfield\" Value=\"{}\" id=\"-- Enter the serial number\"/>\n          </choice>\n        </property>\n",
                xml_escape(serial)
            ));
        }
    } else if !serial.is_empty() {
        props.push_str(&format!(
            "        <property Type=\"choicelist\" Value=\"1\" id=\"Debug Probe Selection\">\n          <choice Name=\"Select by serial number\" value=\"1\">\n            <property Type=\"stringfield\" Value=\"{}\" id=\"-- Enter the serial number\"/>\n          </choice>\n        </property>\n",
            xml_escape(serial)
        ));
    }

    let gel_prop = if strip_gel {
        "            <property Type=\"stringfield\" Value=\"\" id=\"GEL File\"/>\n"
    } else {
        ""
    };

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<configurations XML_version="1.2" id="configurations_0">
  <configuration XML_version="1.2" id="{conn_id}_0">
    <instance XML_version="1.2" desc="{conn_id}" href="{conn_xml}" id="{conn_id}" xml="{conn_name}.xml" xmlpath="connections"/>
    <connection XML_version="1.2" id="{conn_id}">
      <instance XML_version="1.2" href="drivers/tixds510c28x.xml" id="drivers" xml="tixds510c28x.xml" xmlpath="drivers"/>
{props}      <platform XML_version="1.2" id="platform_0">
        <instance XML_version="1.2" desc="{dev_id_str}" href="{dev_xml}" id="{dev_id_str}" xml="{dev_name}.xml" xmlpath="devices">
{gel_prop}        </instance>
      </platform>
    </connection>
  </configuration>
</configurations>
"#
    );

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(out_path, xml).map_err(|e| e.to_string())?;
    Ok(out_path.to_path_buf())
}

/// Clone a custom .ccxml and force every `id="GEL File"` property's `Value="..."` to `Value=""`
/// so Attach Live never triggers destructive OnTargetConnect() RAM-zeroing or GEL_Reset().
pub fn sanitize_custom_ccxml_strip_gel(custom_path: &Path, out_path: &Path) -> Result<PathBuf, String> {
    let text = fs::read_to_string(custom_path).map_err(|e| format!("Cannot read custom .ccxml: {e}"))?;
    let mut out_lines = Vec::new();
    for line in text.lines() {
        if line.contains("id=\"GEL File\"") || line.contains("id='GEL File'") {
            let mut sanitized = line.to_string();
            if let Some(pos) = sanitized.find("Value=\"") {
                let start = pos + 7;
                if let Some(end_rel) = sanitized[start..].find('"') {
                    sanitized.replace_range(start..start + end_rel, "");
                }
            }
            out_lines.push(sanitized);
        } else {
            out_lines.push(line.to_string());
        }
    }
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(out_path, out_lines.join("\n")).map_err(|e| e.to_string())?;
    Ok(out_path.to_path_buf())
}

pub fn generate_uscif_dat(
    out_path: &Path,
    device_id: DeviceId,
    probe_kind: ProbeKind,
    tclk_hz: &str,
    _jtag_mode: JtagMode,
    serial: &str,
) -> Result<PathBuf, String> {
    let (pod_drvr, pod_port, tclk_khz) = match probe_kind {
        ProbeKind::XDS110 => ("jioxds110.dll", "0", parse_tclk_khz(tclk_hz).unwrap_or(5500)),
        _ => ("jioxds100v2.dll", "0", parse_tclk_khz(tclk_hz).unwrap_or(2500)),
    };
    let dev_tag = match device_id {
        DeviceId::F28069M => "icepick_c_0",
        DeviceId::F28388D => "icepick_c_0",
    };
    let ser_line = if serial.is_empty() {
        String::new()
    } else {
        format!("  POD_SERIAL={serial}\n")
    };
    let dat = format!(
        "# config version=3.5\n$ uscif\n  tclk_program=SPECIFIC\n  tclk_frequency={tclk_khz}kHz\n{ser_line}$ /\n$ sepk\n  pod_drvr={pod_drvr}\n  pod_port={pod_port}\n$ /\n@ {dev_tag} family=icepick_c irbits=6 drbits=1 subpaths=1\n  & subpath_0 address=16 default=no custom=no force=yes pseudo=no\n    @ c28xx_0 family=tms320c28xx irbits=38 drbits=1\n  & /\n# /\n"
    );
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(out_path, dat).map_err(|e| e.to_string())?;
    Ok(out_path.to_path_buf())
}

fn parse_tclk_khz(s: &str) -> Option<u32> {
    let low = s.trim().to_ascii_lowercase();
    if let Some(m) = low.strip_suffix("mhz") {
        let v: f64 = m.trim().parse().ok()?;
        return Some((v * 1000.0).round() as u32);
    }
    if let Some(k) = low.strip_suffix("khz") {
        let v: f64 = k.trim().parse().ok()?;
        return Some(v.round() as u32);
    }
    None
}
