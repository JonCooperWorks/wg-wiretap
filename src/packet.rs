use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use pcap::stream::PacketCodec;
use pcap::{Error::PcapError, Packet};
use serde::Serialize;

use crate::utils;

#[derive(Serialize)]
pub struct FlowLog {
    pub src: IpAddr,
    pub src_port: Option<u16>,
    pub dst: IpAddr,
    pub dst_port: Option<u16>,
    pub l3_protocol: u8,
    pub size: u32,
    pub timestamp: u128,
}

unsafe impl Send for FlowLog {}

pub struct FlowLogCodec;

impl PacketCodec for FlowLogCodec {
    type Type = FlowLog;

    fn decode(&mut self, packet: Packet) -> Result<Self::Type, pcap::Error> {
        let size = packet.header.len;
        match PacketHeaders::from_ip_slice(&packet) {
            Ok(packet) => {
                let (src, dst, l3_protocol) = match packet.ip {
                    Some(IpHeader::Version4(ipv4)) => (
                        IpAddr::V4(Ipv4Addr::from(ipv4.source)),
                        IpAddr::V4(Ipv4Addr::from(ipv4.destination)),
                        ipv4.protocol,
                    ),
                    Some(IpHeader::Version6(ipv6)) => (
                        IpAddr::V6(Ipv6Addr::from(ipv6.source)),
                        IpAddr::V6(Ipv6Addr::from(ipv6.destination)),
                        ipv6.next_header,
                    ),

                    _ => return Err(PcapError("unsupported packet type".to_string())),
                };

                let (src_port, dst_port) = match packet.transport {
                    Some(TransportHeader::Udp(udp)) => {
                        (Some(udp.source_port), Some(udp.destination_port))
                    }
                    Some(TransportHeader::Tcp(tcp)) => {
                        (Some(tcp.source_port), Some(tcp.destination_port))
                    }
                    None => (None, None),
                };

                let timestamp = utils::timestamp();
                let log = FlowLog {
                    src,
                    src_port,
                    dst,
                    dst_port,
                    l3_protocol,
                    size,
                    timestamp,
                };
                Ok(log)
            }

            Err(err) => Err(PcapError(err.to_string())),
        }
    }
}
