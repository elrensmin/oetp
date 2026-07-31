use std::time::{SystemTime, UNIX_EPOCH};

static mut CLOCK_OVERRIDE: Option<u64> = None;

pub fn current_timestamp_secs() -> u64 {
    unsafe {
        if let Some(ts) = CLOCK_OVERRIDE {
            return ts;
        }
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn set_clock(ts: u64) {
    unsafe {
        CLOCK_OVERRIDE = Some(ts);
    }
}

pub fn reset_clock() {
    unsafe {
        CLOCK_OVERRIDE = None;
    }
}
