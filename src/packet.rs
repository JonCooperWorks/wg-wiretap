use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pcap::stream::PacketCodec;
use pcap::Packet;
use etherparse::{IpHeader, PacketHeaders, TransportHeader};

use crate::{storage, utils};


pub struct FlowLogCodec;

impl PacketCodec for FlowLogCodec {
    type Type = storage::FlowLog;

    fn decode(&mut self, packet: Packet) -> Result<Self::Type, pcap::Error> {
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

                    _ => panic!("unsupported packet type")
                };
    
                let (src_port, dst_port) = match packet.transport {
                    Some(TransportHeader::Udp(udp)) => (udp.source_port, udp.destination_port),
                    Some(TransportHeader::Tcp(tcp)) => (tcp.source_port, tcp.destination_port),
                    None => (0u16, 0u16),
                };
    
                let log = storage::FlowLog {
                    src: src,
                    src_port: src_port,
                    dst: dst,
                    dst_port: dst_port,
                    l3_protocol: l3_protocol,
                    timestamp: utils::timestamp(),
                };
                Ok(log)
            }

            // TODO: handle this better
            Err(err) => Err(pcap::Error::PcapError(err.to_string())),
        }
    }
}