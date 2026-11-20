//! C28x 16-bit MAU and ARM 8-bit byte scalar codecs, packed bitfield RMW, IQ math, and safety clamping.

use crate::core::models::{DataType, DisplayFormat};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RawScalar {
    Int(i64),
    Uint(u64),
    Float(f64),
}

impl RawScalar {
    pub fn as_f64(self) -> f64 {
        match self {
            Self::Int(v) => v as f64,
            Self::Uint(v) => v as f64,
            Self::Float(v) => v,
        }
    }
}

pub fn unpack_units_to_le_bytes(units: &[u32], address_unit_bits: u32, span_bit_size: Option<u32>) -> Vec<u8> {
    let eff = span_bit_size.unwrap_or(address_unit_bits);
    let mut out = Vec::with_capacity(units.len() * (eff as usize / 8));
    match eff {
        8 => {
            for &u in units {
                out.push((u & 0xFF) as u8);
            }
        }
        16 => {
            for &u in units {
                out.extend_from_slice(&((u & 0xFFFF) as u16).to_le_bytes());
            }
        }
        32 => {
            for &u in units {
                out.extend_from_slice(&u.to_le_bytes());
            }
        }
        _ => panic!("Unsupported span_bit_size={eff}"),
    }
    out
}

pub fn pack_le_bytes_to_units(raw_bytes: &[u8], address_unit_bits: u32, target_bit_size: Option<u32>) -> Vec<u32> {
    let eff = target_bit_size.unwrap_or(address_unit_bits);
    match eff {
        8 => raw_bytes.iter().map(|&b| b as u32).collect(),
        16 => raw_bytes
            .chunks(2)
            .map(|c| {
                let lo = c[0] as u32;
                let hi = *c.get(1).unwrap_or(&0) as u32;
                lo | (hi << 8)
            })
            .collect(),
        32 => raw_bytes
            .chunks(4)
            .map(|c| {
                let b0 = c[0] as u32;
                let b1 = *c.get(1).unwrap_or(&0) as u32;
                let b2 = *c.get(2).unwrap_or(&0) as u32;
                let b3 = *c.get(3).unwrap_or(&0) as u32;
                b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
            })
            .collect(),
        _ => panic!("Unsupported target_bit_size={eff}"),
    }
}

pub fn decode_raw_scalar(
    units: &[u32],
    dtype: DataType,
    address_unit_bits: u32,
    span_bit_size: Option<u32>,
    bit_offset: Option<u32>,
    bit_width: Option<u32>,
    container_units: Option<u32>,
) -> RawScalar {
    let raw_bytes = unpack_units_to_le_bytes(units, address_unit_bits, span_bit_size);
    let mut padded = [0u8; 8];
    let n_copy = raw_bytes.len().min(8);
    padded[..n_copy].copy_from_slice(&raw_bytes[..n_copy]);

    if let (Some(bo), Some(bw)) = (bit_offset, bit_width) {
        let cont_bytes = container_units
            .map(|cu| ((cu * address_unit_bits) / 8).clamp(1, 8) as usize)
            .unwrap_or_else(|| (dtype.bit_size() / 8).clamp(1, 8) as usize);
        let mut cbuf = [0u8; 8];
        let copy_n = raw_bytes.len().min(cont_bytes);
        cbuf[..copy_n].copy_from_slice(&raw_bytes[..copy_n]);
        let container = u64::from_le_bytes(cbuf);
        let mask = if bw >= 64 { u64::MAX } else { (1u64 << bw) - 1 };
        let extracted = (container >> bo) & mask;
        if dtype.is_signed() && bw < 64 && ((extracted >> (bw - 1)) & 1) != 0 {
            let signed = (extracted as i64) - (1i64 << bw);
            return RawScalar::Int(signed);
        }
        return RawScalar::Uint(extracted);
    }

    match dtype {
        DataType::Int8 => RawScalar::Int(padded[0] as i8 as i64),
        DataType::Uint8 => RawScalar::Uint(padded[0] as u64),
        DataType::Int16 => RawScalar::Int(i16::from_le_bytes([padded[0], padded[1]]) as i64),
        DataType::Uint16 => RawScalar::Uint(u16::from_le_bytes([padded[0], padded[1]]) as u64),
        DataType::Int32 => RawScalar::Int(i32::from_le_bytes(padded[0..4].try_into().unwrap()) as i64),
        DataType::Uint32 => RawScalar::Uint(u32::from_le_bytes(padded[0..4].try_into().unwrap()) as u64),
        DataType::Int64 => RawScalar::Int(i64::from_le_bytes(padded)),
        DataType::Uint64 => RawScalar::Uint(u64::from_le_bytes(padded)),
        DataType::Float32 => RawScalar::Float(f32::from_le_bytes(padded[0..4].try_into().unwrap()) as f64),
        DataType::Float64 => RawScalar::Float(f64::from_le_bytes(padded)),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn encode_scalar_units(
    value: f64,
    dtype: DataType,
    address_unit_bits: u32,
    target_bit_size: Option<u32>,
    existing_units: Option<&[u32]>,
    bit_offset: Option<u32>,
    bit_width: Option<u32>,
    container_units: Option<u32>,
) -> Result<Vec<u32>, String> {
    if !value.is_finite() {
        return Err(format!("Refusing non-finite value {value}"));
    }
    if let (Some(bo), Some(bw)) = (bit_offset, bit_width) {
        let exist = existing_units.ok_or_else(|| "Bitfield write requires existing_units for RMW".to_string())?;
        let cont_bytes = container_units
            .map(|cu| ((cu * address_unit_bits) / 8).clamp(1, 8) as usize)
            .unwrap_or_else(|| (dtype.bit_size() / 8).clamp(1, 8) as usize);
        let cur_bytes = unpack_units_to_le_bytes(exist, address_unit_bits, None);
        let mut cbuf = [0u8; 8];
        let copy_n = cur_bytes.len().min(cont_bytes);
        cbuf[..copy_n].copy_from_slice(&cur_bytes[..copy_n]);
        let cur_val = u64::from_le_bytes(cbuf);

        let mask = if bw >= 64 { u64::MAX } else { (1u64 << bw) - 1 };
        let ival = value.round() as i128;
        let sat: u64 = if dtype.is_signed() {
            let lo = -(1i128 << (bw - 1));
            let hi = (1i128 << (bw - 1)) - 1;
            let clamped = ival.clamp(lo, hi);
            (clamped as u64) & mask
        } else {
            let hi = if bw >= 64 { u64::MAX as i128 } else { (1i128 << bw) - 1 };
            (ival.clamp(0, hi) as u64) & mask
        };
        let patched = (cur_val & !(mask << bo)) | ((sat & mask) << bo);
        let out_bytes = &patched.to_le_bytes()[..cont_bytes];
        return Ok(pack_le_bytes_to_units(out_bytes, address_unit_bits, target_bit_size));
    }

    let raw_bytes: Vec<u8> = match dtype {
        DataType::Int8 => vec![(value.round().clamp(i8::MIN as f64, i8::MAX as f64) as i8) as u8],
        DataType::Uint8 => vec![value.round().clamp(0.0, u8::MAX as f64) as u8],
        DataType::Int16 => (value.round().clamp(i16::MIN as f64, i16::MAX as f64) as i16).to_le_bytes().to_vec(),
        DataType::Uint16 => (value.round().clamp(0.0, u16::MAX as f64) as u16).to_le_bytes().to_vec(),
        DataType::Int32 => (value.round().clamp(i32::MIN as f64, i32::MAX as f64) as i32).to_le_bytes().to_vec(),
        DataType::Uint32 => (value.round().clamp(0.0, u32::MAX as f64) as u32).to_le_bytes().to_vec(),
        DataType::Int64 => (value.round() as i64).to_le_bytes().to_vec(),
        DataType::Uint64 => (value.max(0.0).round() as u64).to_le_bytes().to_vec(),
        DataType::Float32 => (value as f32).to_le_bytes().to_vec(),
        DataType::Float64 => value.to_le_bytes().to_vec(),
    };
    Ok(pack_le_bytes_to_units(&raw_bytes, address_unit_bits, target_bit_size))
}

pub fn raw_to_engineering(raw: RawScalar, fmt: DisplayFormat, iq_q_bits: u32) -> f64 {
    if fmt == DisplayFormat::Iq {
        let denom = (1u64 << iq_q_bits.min(62)) as f64;
        return raw.as_f64() / denom;
    }
    raw.as_f64()
}

pub fn engineering_to_raw(eng: f64, dtype: DataType, fmt: DisplayFormat, iq_q_bits: u32) -> f64 {
    if fmt == DisplayFormat::Iq && !dtype.is_float() {
        let scale = (1u64 << iq_q_bits.min(62)) as f64;
        return (eng * scale).round();
    }
    eng
}

pub fn format_value(raw: Option<RawScalar>, dtype: DataType, fmt: DisplayFormat, iq_q_bits: u32) -> String {
    let Some(r) = raw else {
        return "--".to_string();
    };
    match fmt {
        DisplayFormat::Float => format!("{:.5}", r.as_f64()),
        DisplayFormat::Iq => format!("{:.6}", raw_to_engineering(r, fmt, iq_q_bits)),
        DisplayFormat::Hex => {
            let bits = dtype.bit_size();
            let u = match r {
                RawScalar::Uint(v) => v,
                RawScalar::Int(v) => (v as u64) & if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 },
                RawScalar::Float(v) => (v as f32).to_bits() as u64,
            };
            let width = (bits / 4) as usize;
            format!("0x{u:0width$X}")
        }
        DisplayFormat::Bin => {
            let bits = dtype.bit_size().min(32) as usize;
            let u = match r {
                RawScalar::Uint(v) => v,
                RawScalar::Int(v) => v as u64,
                RawScalar::Float(v) => (v as f32).to_bits() as u64,
            };
            format!("0b{u:0bits$b}")
        }
        DisplayFormat::Dec => match r {
            RawScalar::Int(v) => format!("{v}"),
            RawScalar::Uint(v) => format!("{v}"),
            RawScalar::Float(v) => format!("{v:.6}"),
        },
    }
}

pub fn parse_numeric_input(text: &str) -> Result<f64, String> {
    let clean = text.trim().replace('_', "");
    if clean.is_empty() {
        return Err("Empty input".into());
    }
    if let Some(hex) = clean.strip_prefix("0x").or_else(|| clean.strip_prefix("0X")) {
        let v = u64::from_str_radix(hex, 16).map_err(|e| e.to_string())?;
        return Ok(v as f64);
    }
    if let Some(bin) = clean.strip_prefix("0b").or_else(|| clean.strip_prefix("0B")) {
        let v = u64::from_str_radix(bin, 2).map_err(|e| e.to_string())?;
        return Ok(v as f64);
    }
    let f: f64 = clean.parse().map_err(|_| format!("Invalid number '{text}'"))?;
    if !f.is_finite() {
        return Err(format!("Non-finite input '{text}'"));
    }
    Ok(f)
}

pub fn clamp_value(val: f64, min_val: Option<f64>, max_val: Option<f64>) -> Result<(f64, bool), String> {
    if !val.is_finite() {
        return Err(format!("Non-finite value {val}"));
    }
    if let (Some(lo), Some(hi)) = (min_val, max_val) {
        if !lo.is_finite() || !hi.is_finite() || lo > hi {
            return Err(format!("Invalid clamp range [{lo}, {hi}]"));
        }
    }
    let mut out = val;
    let mut clamped = false;
    if let Some(lo) = min_val {
        if out < lo {
            out = lo;
            clamped = true;
        }
    }
    if let Some(hi) = max_val {
        if out > hi {
            out = hi;
            clamped = true;
        }
    }
    Ok((out, clamped))
}
