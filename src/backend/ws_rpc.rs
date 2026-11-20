//! Zero-dependency RFC 6455 localhost WebSocket JSON-RPC client for TI CCS 21 CloudAgent.
//!
//! Speaks TI CloudAgent's native wire protocol directly over `ws://127.0.0.1:<port>`:
//! - Request:  `{"id": 1, "command": "scripting.configure", "data": [...]}`
//! - Response: `{"response": 1, "data": ...}` or `{"error": 1, "data": {"message": ...}}`
//! - Events:   `{"event": "...", "data": ...}` (ignored while awaiting synchronous command reply)
//! - BigInt:   recursively revives `"!bi:<digits>"` strings into JSON numbers.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

pub struct WsRpcClient {
    reader: BufReader<TcpStream>,
    next_id: u64,
    mask_seed: u64,
}

impl WsRpcClient {
    pub fn connect(port: u16, sub_protocol: Option<&str>, timeout: Duration) -> Result<Self, String> {
        let addr = format!("127.0.0.1:{port}");
        let mut stream = TcpStream::connect(&addr).map_err(|e| format!("WebSocket TCP connect {addr}: {e}"))?;
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(timeout));
        let _ = stream.set_write_timeout(Some(timeout));

        // Exact 16-byte nonce ("C2000JtagStudio2") encoded as 24-char RFC 6455 base64
        let key = "QzIwMDBKdGFnU3R1ZGlvMg==";
        let mut req = format!(
            "GET / HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );
        if let Some(proto) = sub_protocol {
            req.push_str(&format!("Sec-WebSocket-Protocol: {proto}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes()).map_err(|e| format!("WS handshake write: {e}"))?;

        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.read_line(&mut status_line).map_err(|e| format!("WS handshake read: {e}"))?;
        if !status_line.contains("101") {
            return Err(format!("WS upgrade rejected: {}", status_line.trim()));
        }
        loop {
            let mut hdr = String::new();
            let n = reader.read_line(&mut hdr).map_err(|e| e.to_string())?;
            if n == 0 || hdr == "\r\n" || hdr == "\n" {
                break;
            }
        }
        Ok(Self {
            reader,
            next_id: 1,
            mask_seed: 0x9E37_79B9_7F4A_7C15,
        })
    }

    pub fn set_timeout(&self, timeout: Duration) {
        let _ = self.reader.get_ref().set_read_timeout(Some(timeout));
        let _ = self.reader.get_ref().set_write_timeout(Some(timeout));
    }

    fn next_mask(&mut self) -> [u8; 4] {
        self.mask_seed = self.mask_seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (self.mask_seed >> 32).to_le_bytes()[0..4].try_into().unwrap()
    }

    fn send_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), String> {
        let mut frame = Vec::with_capacity(payload.len() + 14);
        frame.push(0x80 | (opcode & 0x0F));
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | (len as u8));
        } else if len <= 65535 {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        let mask = self.next_mask();
        frame.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
        }
        self.reader.get_mut().write_all(&frame).map_err(|e| format!("WS send: {e}"))
    }

    fn read_text_frame(&mut self) -> Result<String, String> {
        let mut assembled = Vec::new();
        loop {
            let mut hdr = [0u8; 2];
            self.reader.read_exact(&mut hdr).map_err(|e| format!("WS read header: {e}"))?;
            let fin = (hdr[0] & 0x80) != 0;
            let opcode = hdr[0] & 0x0F;
            let masked = (hdr[1] & 0x80) != 0;
            let mut len = (hdr[1] & 0x7F) as u64;
            if len == 126 {
                let mut ext = [0u8; 2];
                self.reader.read_exact(&mut ext).map_err(|e| e.to_string())?;
                len = u16::from_be_bytes(ext) as u64;
            } else if len == 127 {
                let mut ext = [0u8; 8];
                self.reader.read_exact(&mut ext).map_err(|e| e.to_string())?;
                len = u64::from_be_bytes(ext);
            }
            let mut mask = [0u8; 4];
            if masked {
                self.reader.read_exact(&mut mask).map_err(|e| e.to_string())?;
            }
            let mut payload = vec![0u8; len as usize];
            self.reader.read_exact(&mut payload).map_err(|e| format!("WS read payload: {e}"))?;
            if masked {
                for (i, b) in payload.iter_mut().enumerate() {
                    *b ^= mask[i & 3];
                }
            }
            match opcode {
                0x8 => return Err("CloudAgent WebSocket closed".into()),
                0x9 => {
                    // Ping -> Pong
                    let _ = self.send_frame(0xA, &payload);
                    continue;
                }
                0xA => continue, // Pong
                0x1 | 0x0 => {
                    assembled.extend_from_slice(&payload);
                    if fin {
                        return String::from_utf8(assembled).map_err(|e| e.to_string());
                    }
                }
                _ => continue,
            }
        }
    }

    /// Execute a CloudAgent module RPC command synchronously and revive `!bi:` BigInts.
    pub fn call(&mut self, command: &str, args: Vec<Value>, timeout: Duration) -> Result<Value, String> {
        let id = self.next_id;
        self.next_id += 1;
        let msg = json!({
            "id": id,
            "command": command,
            "data": args,
        });
        let text = serde_json::to_string(&msg).map_err(|e| e.to_string())?;
        self.set_timeout(timeout);
        self.send_frame(0x1, text.as_bytes())?;

        let deadline = Instant::now() + timeout;
        loop {
            if Instant::now() > deadline {
                return Err(format!("CloudAgent RPC '{command}' timed out"));
            }
            let raw = self.read_text_frame()?;
            let mut parsed: Value = serde_json::from_str(&raw).map_err(|e| format!("Bad CloudAgent JSON: {e}"))?;
            revive_bigints(&mut parsed);

            if parsed.get("response").and_then(Value::as_u64) == Some(id) {
                return Ok(parsed.get("data").cloned().unwrap_or(Value::Null));
            }
            if parsed.get("error").and_then(Value::as_u64) == Some(id) {
                let err_msg = parsed
                    .get("data")
                    .and_then(|d| d.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown CloudAgent RPC error");
                return Err(err_msg.to_string());
            }
            // Async event frame (statusMessage / gelOutput / targetState) — keep reading until matching id
        }
    }

    pub fn create_sub_module(&mut self, name: &str, timeout: Duration) -> Result<WsRpcClient, String> {
        let info = self.call("createSubModule", vec![json!(name)], timeout)?;
        let port = info
            .get("port")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("createSubModule({name}) returned no port: {info}"))? as u16;
        let sub_proto = info.get("subProtocol").and_then(Value::as_str);
        Self::connect(port, sub_proto, timeout)
    }

    pub fn close(mut self) {
        let _ = self.send_frame(0x1, br#"{"command":"close"}"#);
        let _ = self.send_frame(0x8, &[]);
    }
}

fn revive_bigints(val: &mut Value) {
    match val {
        Value::String(s) => {
            if let Some(digits) = s.strip_prefix("!bi:") {
                if let Ok(u) = digits.parse::<u64>() {
                    *val = json!(u);
                } else if let Ok(i) = digits.parse::<i64>() {
                    *val = json!(i);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                revive_bigints(item);
            }
        }
        Value::Object(map) => {
            for (_k, v) in map.iter_mut() {
                revive_bigints(v);
            }
        }
        _ => {}
    }
}
