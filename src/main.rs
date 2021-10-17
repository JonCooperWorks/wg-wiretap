use csv_async::AsyncSerializer;
use futures::StreamExt;
use futures_batch::ChunksTimeoutStreamExt;
use pcap::Capture;
use rusoto_core::Region;
use rusoto_s3::{PutObjectRequest, S3Client, S3};

use std::time::Duration;
use structopt::StructOpt;
use tokio::{signal, task};

mod storage;
mod packet;
mod utils;
use packet::FlowLogCodec;

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

    let cap = Capture::from_device(opt.iface.as_str())?
            .immediate_mode(false)
            .open()?
            .setnonblock()?;
    
    // Split logs into chunks of max_packets_per_log
    let mut packet_events = cap.stream(FlowLogCodec{})?
        .chunks_timeout(config.max_packets_per_log, config.packet_log_interval);

    while let Some(packet_logs) = packet_events.next().await {
        let s3 = s3.clone();
        let bucket = config.storage_bucket.clone();
        // Send packet logs to cloud storage.
        task::spawn(async move {
            let mut serializer = AsyncSerializer::from_writer(vec![]);

            for result in &packet_logs {
                match result {
                    Ok(log) => {
                        serializer.serialize(&log).await.unwrap();
                        println!(
                            "{}: {} {}:{} -> {}:{}",
                            log.timestamp, log.l3_protocol, log.src, log.src_port, log.dst, log.dst_port,
                        );
                    }
                    Err(err) => {
                        println!("Error parsing packet: {}", err);
                        continue;
                    }
                }
                
            }
            let body = serializer.into_inner().await.unwrap();
            let timestamp = utils::timestamp();
            let filename = format!("{}.csv", timestamp);
            let req = PutObjectRequest {
                bucket: bucket.to_owned(),
                key: filename.to_owned(),
                body: Some(body.into()),
                ..Default::default()
            };

            // TODO: handle errors from S3
            let _res = s3.put_object(req).await.unwrap();
            println!("Saved {}", filename);
        });
    }

    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
