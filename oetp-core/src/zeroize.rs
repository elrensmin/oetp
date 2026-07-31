// secures sensitive buffers in memory (mlock + zeroize-on-drop)
use crate::error::{Error, Result};
use std::sync::Arc;
use zeroize::Zeroize;

pub trait MemoryLocker: Send + Sync + std::fmt::Debug {
    fn try_lock(&self, ptr: *mut u8, len: usize) -> Result<bool>;
    fn unlock(&self, ptr: *mut u8, len: usize) -> Result<()>;
}

#[derive(Debug)]
pub struct LockedBuffer {
    ptr: *mut u8,
    len: usize,
    locked: bool,
    locker: Option<Arc<dyn MemoryLocker>>,
}

impl LockedBuffer {
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn new(len: usize, locker: Arc<dyn MemoryLocker>) -> Result<Self> {
        if len == 0 {
            return Err(Error::InvalidInput("buffer length must be non-zero".into()));
        }

        let layout = std::alloc::Layout::from_size_align(len, 4096)
            .map_err(|e| Error::Memory(format!("layout error: {}", e)))?;

        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            return Err(Error::Memory("allocation failed".into()));
        }

        let locked = match locker.try_lock(ptr, len) {
            Ok(true) => true,
            Ok(false) => {
                tracing::warn!("mlock failed, continuing with zeroize-only");
                false
            }
            Err(e) => {
                tracing::warn!("mlock error ({}), continuing with zeroize-only", e);
                false
            }
        };

        Ok(Self {
            ptr,
            len,
            locked,
            locker: Some(locker),
        })
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    pub fn as_slice(&self) -> &[u8] {
        unsafe { std::slice::from_raw_parts(self.ptr, self.len) }
    }
}

impl Drop for LockedBuffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                std::slice::from_raw_parts_mut(self.ptr, self.len).zeroize();
            }
            #[allow(clippy::collapsible_if)]
            if self.locked {
                if let Some(ref locker) = self.locker {
                    let _ = locker.unlock(self.ptr, self.len);
                }
            }
            let layout = std::alloc::Layout::from_size_align(self.len, 4096).unwrap();
            unsafe {
                std::alloc::dealloc(self.ptr, layout);
            }
        }
    }
}

unsafe impl Send for LockedBuffer {}
unsafe impl Sync for LockedBuffer {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug)]
    struct TestLocker {
        lock_calls: Mutex<Vec<(usize, usize)>>,
        unlock_calls: Mutex<Vec<(usize, usize)>>,
        should_fail: bool,
    }
    impl TestLocker {
        fn new(should_fail: bool) -> Self {
            Self {
                lock_calls: Mutex::new(Vec::new()),
                unlock_calls: Mutex::new(Vec::new()),
                should_fail,
            }
        }
    }
    impl MemoryLocker for TestLocker {
        fn try_lock(&self, ptr: *mut u8, len: usize) -> Result<bool> {
            self.lock_calls.lock().unwrap().push((ptr as usize, len));
            if self.should_fail {
                Err(Error::Memory("lock failed".into()))
            } else {
                Ok(true)
            }
        }
        fn unlock(&self, ptr: *mut u8, len: usize) -> Result<()> {
            self.unlock_calls.lock().unwrap().push((ptr as usize, len));
            Ok(())
        }
    }

    #[test]
    fn test_locked_buffer_new() {
        let locker = Arc::new(TestLocker::new(false));
        let buf = LockedBuffer::new(64, locker).unwrap();
        assert_eq!(buf.len(), 64);
        assert!(buf.is_locked());
    }

    #[test]
    fn test_locked_buffer_zeroize_on_drop() {
        let locker = Arc::new(TestLocker::new(false));
        let mut buf = LockedBuffer::new(16, locker.clone()).unwrap();
        buf.as_mut_slice().copy_from_slice(&[0xAAu8; 16]);

        assert_eq!(buf.as_slice(), &[0xAAu8; 16]);

        drop(buf);
        assert_eq!(locker.unlock_calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn test_locked_buffer_lock_failure_continues() {
        let locker = Arc::new(TestLocker::new(true));
        let buf = LockedBuffer::new(64, locker).unwrap();
        assert_eq!(buf.len(), 64);
        assert!(!buf.is_locked());
    }

    #[test]
    fn test_locked_buffer_zero_length_rejected() {
        let locker = Arc::new(TestLocker::new(false));
        let err = LockedBuffer::new(0, locker).unwrap_err();
        assert!(matches!(err, Error::InvalidInput(_)));
    }

    #[test]
    fn test_locked_buffer_write_and_read() {
        let locker = Arc::new(TestLocker::new(false));
        let mut buf = LockedBuffer::new(32, locker).unwrap();
        buf.as_mut_slice()[..4].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(buf.as_slice()[..4], [1, 2, 3, 4]);
    }

    #[test]
    fn test_locked_buffer_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LockedBuffer>();
    }
}
