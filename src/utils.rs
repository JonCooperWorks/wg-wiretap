use std::time::{SystemTime, UNIX_EPOCH};

pub fn timestamp() -> u64 {
    return SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs();
}
