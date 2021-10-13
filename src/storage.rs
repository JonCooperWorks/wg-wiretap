use serde::Serialize;
use std::net::IpAddr;
use std::time::Duration;

pub struct Config {
    pub max_packets_per_log: usize,
    pub packet_log_interval: Duration,
    pub storage_bucket: String,
}

#[derive(Serialize)]
pub struct FlowLog {
    pub src: IpAddr,
    pub src_port: u16,
    pub dst: IpAddr,
    pub dst_port: u16,
    pub l3_protocol: u8,
    pub timestamp: u64,
}

unsafe impl Send for FlowLog {}
