use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str;

use bson::DateTime;
use dns_parser::rdata::RData;
use dns_parser::Packet as DnsPacket;
use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use pcap::stream::PacketCodec;
use pcap::{Error::PcapError, Packet};
use serde::{Deserialize, Serialize};

use crate::utils;

#[derive(Serialize, Deserialize, Clone)]
pub struct DnsInfo {
    pub name: Option<String>,
    pub answers: Vec<ResourceRecord>,
    pub nameservers: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

impl DnsInfo {
    pub fn new(packet: &DnsPacket) -> DnsInfo {
        let name = if packet.questions.is_empty() {
            None
        } else {
            Some(packet.questions[0].qname.to_string())
        };

        let answers = packet
            .answers
            .iter()
            .map(|answer| ResourceRecord::new(answer))
            .collect::<Vec<_>>();

        let nameservers = packet
            .nameservers
            .iter()
            .map(|nameserver| ResourceRecord::new(nameserver))
            .collect::<Vec<_>>();

        let additional = packet
            .additional
            .iter()
            .map(|additional| ResourceRecord::new(additional))
            .collect::<Vec<_>>();

        Self {
            name,
            answers,
            nameservers,
            additional,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ResourceRecord {
    pub name: String,
    pub record_type: String,
    pub rdata: String,
}

impl ResourceRecord {
    pub fn new(record: &dns_parser::ResourceRecord) -> ResourceRecord {
        let name = record.name.to_string();
        let (rdata, record_type) = match &record.data {
            RData::A(ip_address) => (ip_address.0.to_string(), "A".to_string()),
            RData::AAAA(ip_address) => (ip_address.0.to_string(), "AAAA".to_string()),
            RData::CNAME(name) => (name.to_string(), "CNAME".to_string()),
            RData::MX(record) => (record.exchange.to_string(), "MX".to_string()),
            RData::NS(name) => (name.to_string(), "NS".to_string()),
            RData::PTR(name) => (name.to_string(), "PTR".to_string()),
            RData::SRV(record) => (
                format!("{}:{}", record.target, record.port),
                "SRV".to_string(),
            ),
            RData::TXT(record) => {
                let mut rdata = String::from("");
                while let Some(txt) = record.iter().next() {
                    match str::from_utf8(txt) {
                        Ok(txt) => rdata.push_str(txt),
                        Err(_) => continue,
                    }
                    rdata.push('\n');
                }
                (rdata, "TXT".to_string())
            }
            RData::SOA(record) => (
                format!("{} ({})", record.primary_ns, record.mailbox),
                "SOA".to_string(),
            ),
            RData::Unknown(unknown) => (base64::encode(unknown), "UNKNOWN".to_string()),
        };

        Self {
            name,
            record_type,
            rdata,
        }
    }
}

/// A `FlowLog` is a record of a packet sent over a Wireguard network interface.
/// It will have DNS lookup info for DNS packets.
#[derive(Serialize, Deserialize, Clone)]
pub struct FlowLog {
    pub src: String,
    pub src_port: Option<u16>,
    pub dst: String,
    pub dst_port: Option<u16>,
    pub l3_protocol: u8,
    pub size: u32,
    pub timestamp: DateTime,
    pub dns: Option<DnsInfo>,
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
                        IpAddr::V4(Ipv4Addr::from(ipv4.source)).to_string(),
                        IpAddr::V4(Ipv4Addr::from(ipv4.destination)).to_string(),
                        ipv4.protocol,
                    ),
                    Some(IpHeader::Version6(ipv6)) => (
                        IpAddr::V6(Ipv6Addr::from(ipv6.source)).to_string(),
                        IpAddr::V6(Ipv6Addr::from(ipv6.destination)).to_string(),
                        ipv6.next_header,
                    ),

                    _ => return Err(PcapError("unsupported packet type".to_string())),
                };

                let (src_port, dst_port, dns) = match packet.transport {
                    Some(TransportHeader::Udp(udp)) => (
                        Some(udp.source_port),
                        Some(udp.destination_port),
                        parse_dns_packet(packet.payload),
                    ),
                    Some(TransportHeader::Tcp(tcp)) => (
                        Some(tcp.source_port),
                        Some(tcp.destination_port),
                        parse_dns_packet(packet.payload),
                    ),
                    None => (None, None, None),
                };

                let timestamp = DateTime::from_system_time(utils::timestamp());
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

fn parse_dns_packet(packet: &[u8]) -> Option<DnsInfo> {
    match DnsPacket::parse(packet) {
        Ok(packet) => Some(DnsInfo::new(&packet)),
        Err(_) => None,
    }
}
