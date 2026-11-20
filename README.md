# C2000 JTAG Studio v2 — Native Rust Edition

Hardware-safe, zero-Python-dependency real-time JTAG tuning studio and bench oscilloscope for **TI TMS320F28069M** and **TMS320F28388D**, defaulting to the **Classic White Eclipse Workbench** visual system (`eframe`/`egui`).

## Key Capabilities
- **Direct TI CCS 21 CloudAgent Protocol (Pure Rust)**: Pure-Rust RFC 6455 localhost WebSocket JSON-RPC client (`src/backend/ws_rpc.rs`, `src/backend/ccs21.rs`) communicating directly with `C:\ti\ccs2101\ccs\ccs_base\cloudagent\node.exe src/main.js` inside a Windows Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`).
- **5-Gate Hardware-Safe Write Firewall**: Enforces Stale-Image Lockout, Read-Only / Bitfield RMW Lock, Silicon Deny-Matrix (EtherCAT ESC, DCSM OTP, MMIO, Flash, `.scratchpad`, directional MSGRAM, live `MemCfg` `LSxCLAPGM`/`GSxMSEL`), finite safety clamping, and mandatory raw-unit bit-for-bit readback verification.
- **Preemptive Emergency Revert (`Ctrl+Shift+R`)**: Purges queued normal writes and restores verified Safe Baseline parameters on the `URGENT` priority lane.
- **TI COFF & EABI DWARF Parser + Flash Fingerprinting**: Streaming `xml-rs` parser for `ofd2000`/`tiarmofd` with `DW_TAG_TI_far_type`, C++ inheritance/namespaces, TU static disambiguation, native ELF32/COFF 16-word Flash fingerprint verification, and 100 MB / 24-entry zlib LRU cache.
- **Bench-Grade Oscilloscope**: 1–3 synchronized panes, peak-preserving min/max decimation, Free/Auto/Single/On-Write triggers, vertical A/B cursors, XY phase plane, `NaN`-safe Hann-windowed FFT & THD %, bounded-ZOH CSV export, and pure-Rust PNG export.
- **Phase-B Firmware Companion**: Pure C99 header [`firmware/c2000_studio_agent.h`](firmware/c2000_studio_agent.h) (C28x EABI & COFF ABI compatible).

## Build & Run
```powershell
cargo test -- --nocapture
cargo build --release
.\launch.bat
# Or auto-attach to the offline closed-loop Buck/Inverter simulator:
.\launch.bat --sim
```
