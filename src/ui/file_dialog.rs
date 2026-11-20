//! Zero-dependency native Windows Open/Save file dialogs via Win32 comdlg32 (GetOpenFileNameW / GetSaveFileNameW).

use std::ffi::OsString;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use windows_sys::Win32::UI::Controls::Dialogs::{
    GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR,
    OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
};

fn to_wide_z(s: &str) -> Vec<u16> {
    std::ffi::OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn build_filter(pairs: &[(&str, &str)]) -> Vec<u16> {
    let mut out = Vec::new();
    for (desc, pat) in pairs {
        out.extend(std::ffi::OsStr::new(desc).encode_wide());
        out.push(0);
        out.extend(std::ffi::OsStr::new(pat).encode_wide());
        out.push(0);
    }
    out.push(0);
    out
}

pub fn open_file_dialog(title: &str, filters: &[(&str, &str)]) -> Option<PathBuf> {
    let mut buf = vec![0u16; 1024];
    let title_w = to_wide_z(title);
    let filter_w = build_filter(filters);
    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.lpstrFilter = filter_w.as_ptr();
    ofn.lpstrFile = buf.as_mut_ptr();
    ofn.nMaxFile = buf.len() as u32;
    ofn.lpstrTitle = title_w.as_ptr();
    ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    let ok = unsafe { GetOpenFileNameW(&mut ofn) };
    if ok != 0 {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(PathBuf::from(OsString::from_wide(&buf[..end])))
    } else {
        None
    }
}

pub fn save_file_dialog(title: &str, default_name: &str, default_ext: &str, filters: &[(&str, &str)]) -> Option<PathBuf> {
    let mut buf = vec![0u16; 1024];
    let init = to_wide_z(default_name);
    let copy_n = init.len().min(buf.len() - 1);
    buf[..copy_n].copy_from_slice(&init[..copy_n]);
    let title_w = to_wide_z(title);
    let ext_w = to_wide_z(default_ext);
    let filter_w = build_filter(filters);

    let mut ofn: OPENFILENAMEW = unsafe { std::mem::zeroed() };
    ofn.lStructSize = std::mem::size_of::<OPENFILENAMEW>() as u32;
    ofn.lpstrFilter = filter_w.as_ptr();
    ofn.lpstrFile = buf.as_mut_ptr();
    ofn.nMaxFile = buf.len() as u32;
    ofn.lpstrTitle = title_w.as_ptr();
    ofn.lpstrDefExt = ext_w.as_ptr();
    ofn.Flags = OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    let ok = unsafe { GetSaveFileNameW(&mut ofn) };
    if ok != 0 {
        let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
        Some(PathBuf::from(OsString::from_wide(&buf[..end])))
    } else {
        None
    }
}
