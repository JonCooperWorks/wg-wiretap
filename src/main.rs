use csv_async::AsyncSerializer;
use etherparse::{IpHeader, PacketHeaders, TransportHeader};
use futures_batch::ChunksTimeoutStreamExt;
use rusoto_core::Region;
use rusoto_s3::{PutObjectRequest, S3Client, S3};
use pcap::Capture;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::thread;
use std::time::Duration;
use structopt::StructOpt;
use tokio::{signal, sync::mpsc, task};
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::StreamExt;

mod storage;
mod utils;

#[derive(Debug, StructOpt)]
struct Opt {
    #[structopt(long, default_value = "wg0")]
    iface: String,

    #[structopt(long)]
    storage_region: String,

    #[structopt(long)]
    storage_endpoint: String,

    #[structopt(long)]
    storage_bucket: String,

    #[structopt(long, default_value = "1000000")]
    max_packets_per_log: usize,

    #[structopt(long, default_value = "5")]
    packet_log_interval: u64,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    // Set up S3 compatible cloud storage
    let region = Region::Custom {
        name: opt.storage_region,
        endpoint: opt.storage_endpoint,
    };
    let s3 = S3Client::new(region);

    let config = storage::Config {
        max_packets_per_log: opt.max_packets_per_log,
        packet_log_interval: Duration::from_secs(opt.packet_log_interval * 60),
        storage_bucket: opt.storage_bucket,
    };

    let (packet_tx, packet_rx) = mpsc::channel::<storage::FlowLog>(config.max_packets_per_log);
    let iface = opt.iface.clone();
    thread::spawn(move || {
        let mut cap = Capture::from_device(iface.as_str()).unwrap()
            .promisc(false)
            .open()
            .unwrap();

        while let Ok(packet) = cap.next() {
            let packet = PacketHeaders::from_ip_slice(&packet).unwrap();
            let (src, dst, l3_protocol) = match packet.ip.unwrap() {
                IpHeader::Version4(ipv4) => {
                    (IpAddr::V4(Ipv4Addr::from(ipv4.source)), IpAddr::V4(Ipv4Addr::from(ipv4.destination)), ipv4.protocol)
                } 
                IpHeader::Version6(ipv6) => {
                    (IpAddr::V6(Ipv6Addr::from(ipv6.source)), IpAddr::V6(Ipv6Addr::from(ipv6.destination)), ipv6.next_header)
                }
            };

            let (src_port, dst_port) = match packet.transport.unwrap() {
                TransportHeader::Udp(udp) => {
                    (udp.source_port, udp.destination_port)
                }
                TransportHeader::Tcp(tcp) => {
                    (tcp.source_port, tcp.destination_port)
                }
            };

            let log = storage::FlowLog{
                src: src,
                src_port: src_port,
                dst: dst,
                dst_port: dst_port,
                l3_protocol: l3_protocol,
                timestamp: utils::timestamp(),
            };
            packet_tx.blocking_send(log).ok();
        }
    });

    // Send packet logs to cloud storage.
    task::spawn(async move {
        // Wrap rx in a stream and split it into chunks of max_packets_per_log
        let mut packet_events = ReceiverStream::new(packet_rx)
            .chunks_timeout(config.max_packets_per_log, config.packet_log_interval);

        while let Some(packet_logs) = packet_events.next().await {
            let mut serializer = AsyncSerializer::from_writer(vec![]);

            for log in &packet_logs {
                serializer.serialize(&log).await.unwrap();
            }
            let body = serializer.into_inner().await.unwrap();
            let timestamp = utils::timestamp();
            let filename = format!("{}.csv", timestamp);
            let req = PutObjectRequest {
                bucket: config.storage_bucket.to_owned(),
                key: filename.to_owned(),
                body: Some(body.into()),
                ..Default::default()
            };

            // TODO: handle errors from S3
            let _res = s3.put_object(req).await.unwrap();

            for log in packet_logs {
                println!(
                    "{}: {} {}:{} -> {}:{}",
                    log.timestamp,
                    log.l3_protocol,
                    log.src,
                    log.src_port,
                    log.dst,
                    log.dst_port,
                );
            }
            println!("Saved {}", filename);
        }
    });

    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
