use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use dns_parser::Packet as DnsPacket;
use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use pcap::stream::PacketCodec;
use pcap::{Error::PcapError, Packet};
use serde::Serialize;

use crate::utils;

/// A `FlowLog` is a CSV record of a packet sent over a Wireguard network interface.
/// The dns field should contain a base64 encoded DNS packet.
#[derive(Serialize)]
pub struct FlowLog {
    pub src: IpAddr,
    pub src_port: Option<u16>,
    pub dst: IpAddr,
    pub dst_port: Option<u16>,
    pub l3_protocol: u8,
    pub size: u32,
    pub timestamp: u128,
    pub dns: Option<String>,
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
                    Some(IpHeader::Version4(ipv4, _)) => (
                        IpAddr::V4(Ipv4Addr::from(ipv4.source)),
                        IpAddr::V4(Ipv4Addr::from(ipv4.destination)),
                        ipv4.protocol,
                    ),
                    Some(IpHeader::Version6(ipv6, _)) => (
                        IpAddr::V6(Ipv6Addr::from(ipv6.source)),
                        IpAddr::V6(Ipv6Addr::from(ipv6.destination)),
                        ipv6.next_header,
                    ),

                    _ => return Err(PcapError("unsupported packet type".to_string())),
                };

                let (src_port, dst_port, dns) = match packet.transport {
                    Some(TransportHeader::Udp(udp)) => (
                        Some(udp.source_port),
                        Some(udp.destination_port),
                        base64_dns_packet(packet.payload),
                    ),
                    Some(TransportHeader::Tcp(tcp)) => (
                        Some(tcp.source_port),
                        Some(tcp.destination_port),
                        base64_dns_packet(packet.payload),
                    ),
                    None => (None, None, None),
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
                    dns,
                };
                Ok(log)
            }

            Err(err) => Err(PcapError(err.to_string())),
        }
    }
}

fn base64_dns_packet(packet: &[u8]) -> Option<String> {
    match DnsPacket::parse(packet) {
        Ok(_) => Some(base64::encode(packet)),
        Err(_) => None,
    }
}
