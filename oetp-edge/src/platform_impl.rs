// OS-specific platform implementation (Linux)
use oetp_core::error::{Error, Result};
use oetp_core::platform::ProcessGuard;
use oetp_core::zeroize::MemoryLocker;

pub struct LinuxProcessGuard;

impl ProcessGuard for LinuxProcessGuard {
    fn disable_core_dumps(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            let r = libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
            if r != 0 {
                return Err(Error::Memory("prctl PR_SET_DUMPABLE failed".into()));
            }
        }
        Ok(())
    }

    fn restrict_ptrace(&self) -> Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            // PR_SET_PTRACER with 0 means only the calling process can ptrace itself
            let r = libc::prctl(libc::PR_SET_PTRACER, 0, 0, 0, 0);
            if r != 0 {
                return Err(Error::Memory("prctl PR_SET_PTRACER failed".into()));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct LinuxMemoryLocker;

impl MemoryLocker for LinuxMemoryLocker {
    fn try_lock(&self, ptr: *mut u8, len: usize) -> Result<bool> {
        #[cfg(target_os = "linux")]
        {
            let ret = unsafe { libc::mlock(ptr as *const libc::c_void, len) };
            if ret == 0 {
                return Ok(true);
            }
            unsafe {
                if *libc::__errno_location() == libc::ENOMEM {
                    return Err(Error::Memory("mlock failed: ENOMEM".into()));
                }
            }
        }
        Ok(false)
    }

    fn unlock(&self, ptr: *mut u8, len: usize) -> Result<()> {
        #[cfg(target_os = "linux")]
        unsafe {
            libc::munlock(ptr as *const libc::c_void, len);
        }
        Ok(())
    }
}
