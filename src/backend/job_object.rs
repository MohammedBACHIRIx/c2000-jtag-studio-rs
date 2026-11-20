//! Windows Job Object child containment (JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE) & 1 ms timer RAII guard.

use std::os::windows::io::AsRawHandle;
use std::process::Child;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Media::{timeBeginPeriod, timeEndPeriod};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

pub struct WindowsJobObject {
    handle: HANDLE,
}

unsafe impl Send for WindowsJobObject {}

impl WindowsJobObject {
    pub fn create() -> Option<Self> {
        unsafe {
            let h = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if h == 0 {
                return None;
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == 0 {
                CloseHandle(h);
                return None;
            }
            Some(Self { handle: h })
        }
    }

    pub fn assign_child(&self, child: &Child) -> bool {
        unsafe { AssignProcessToJobObject(self.handle, child.as_raw_handle() as HANDLE) != 0 }
    }

    pub fn terminate(&mut self) {
        if self.handle != 0 {
            unsafe {
                TerminateJobObject(self.handle, 1);
            }
        }
    }
}

impl Drop for WindowsJobObject {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                CloseHandle(self.handle);
            }
            self.handle = 0;
        }
    }
}

pub struct HighResTimerGuard {
    active: bool,
}

impl HighResTimerGuard {
    pub fn new() -> Self {
        let ok = unsafe { timeBeginPeriod(1) == 0 };
        Self { active: ok }
    }
}

impl Default for HighResTimerGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for HighResTimerGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                timeEndPeriod(1);
            }
        }
    }
}
