//! Phase-B XDS110 Auxiliary UART high-rate stream codec with capability & JTAG mutual-exclusion guards.

use crate::core::devices::probe_capabilities;
use crate::core::models::ProbeKind;

pub const AUX_FRAME_MAGIC: [u8; 2] = [0xAA, 0x55];

#[derive(Debug, Clone, PartialEq)]
pub struct AuxUartSample {
    pub seq: u32,
    pub timestamp_s: f64,
    pub values: Vec<f32>,
}

pub fn verify_aux_uart_allowed(probe_kind: ProbeKind, jtag_dlog_active: bool) -> Result<(), String> {
    if !probe_capabilities(probe_kind).supports_aux_uart {
        return Err(format!(
            "Probe '{}' does not provide an Auxiliary UART sideband channel (XDS110 required).",
            probe_kind.label()
        ));
    }
    if jtag_dlog_active {
        return Err(
            "XDS110 Aux UART stream cannot run concurrently with JTAG DLOG bursts (shared USB bus).".into(),
        );
    }
    Ok(())
}

pub fn encode_aux_frame(seq: u32, timestamp_us: u32, values: &[f32]) -> Vec<u8> {
    let n = values.len().min(16);
    let mut payload = Vec::with_capacity(10 + n * 4);
    payload.extend_from_slice(&seq.to_le_bytes());
    payload.extend_from_slice(&timestamp_us.to_le_bytes());
    payload.extend_from_slice(&(n as u16).to_le_bytes());
    for &v in &values[..n] {
        payload.extend_from_slice(&v.to_le_bytes());
    }
    let chk = payload.iter().fold(0u8, |acc, &b| acc ^ b);
    let mut out = Vec::with_capacity(payload.len() + 3);
    out.extend_from_slice(&AUX_FRAME_MAGIC);
    out.extend_from_slice(&payload);
    out.push(chk);
    out
}

pub fn decode_aux_frame(raw: &[u8]) -> Option<AuxUartSample> {
    if raw.len() < 13 || raw[0..2] != AUX_FRAME_MAGIC {
        return None;
    }
    let body = &raw[2..raw.len() - 1];
    let expected = raw[raw.len() - 1];
    let chk = body.iter().fold(0u8, |acc, &b| acc ^ b);
    if chk != expected {
        return None;
    }
    let seq = u32::from_le_bytes(body[0..4].try_into().ok()?);
    let ts_us = u32::from_le_bytes(body[4..8].try_into().ok()?);
    let n = u16::from_le_bytes(body[8..10].try_into().ok()?) as usize;
    if body.len() != 10 + 4 * n {
        return None;
    }
    let mut vals = Vec::with_capacity(n);
    for i in 0..n {
        let off = 10 + 4 * i;
        vals.push(f32::from_le_bytes(body[off..off + 4].try_into().ok()?));
    }
    Some(AuxUartSample {
        seq,
        timestamp_s: (ts_us as f64) * 1e-6,
        values: vals,
    })
}
