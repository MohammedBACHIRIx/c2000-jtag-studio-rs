@echo off
setlocal
cd /d "%~dp0"
if exist "target\release\c2000-jtag-studio.exe" (
    start "" "target\release\c2000-jtag-studio.exe" %*
) else (
    cargo run --release -- %*
)
