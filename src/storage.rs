use std::time::Duration;

pub struct Config {
    pub max_packets_per_log: usize,
    pub packet_log_interval: Duration,
}
