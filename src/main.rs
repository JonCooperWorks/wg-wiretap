use std::sync::Arc;
use std::time::Duration;

use csv_async::AsyncSerializer;
use futures::StreamExt;
use futures_batch::ChunksTimeoutStreamExt;
use pcap::Capture;
use rusoto_core::Region;
use rusoto_s3::{PutObjectRequest, S3Client, S3};
use structopt::StructOpt;
use tokio::{signal, task};

mod errors;
use errors::ErrorHandler;
mod packet;
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

    #[structopt(long)]
    sentry_dsn: Option<String>,
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
    let s3 = Arc::new(s3);

    let config = storage::Config {
        max_packets_per_log: opt.max_packets_per_log,
        packet_log_interval: Duration::from_secs(opt.packet_log_interval * 60),
        storage_bucket: opt.storage_bucket,
    };

    // Set up error handling
    let error_handler = ErrorHandler {
        sentry_dsn: opt.sentry_dsn,
    };
    let error_handler = Arc::new(error_handler);

    // Open the interface and begin streaming packet captures
    let cap = Capture::from_device(opt.iface.as_str())?
        .immediate_mode(true)
        .open()?
        .setnonblock()?;

    // Split logs into chunks of max_packets_per_log
    let mut packet_events = cap
        .stream(packet::FlowLogCodec {})?
        .chunks_timeout(config.max_packets_per_log, config.packet_log_interval);

    while let Some(packet_chunk) = packet_events.next().await {
        let s3 = Arc::clone(&s3);
        let bucket = config.storage_bucket.clone();
        let error_handler = Arc::clone(&error_handler);

        // Send packet logs to cloud storage.
        task::spawn(async move {
            let mut serializer = AsyncSerializer::from_writer(vec![]);

            for result in packet_chunk {
                match result {
                    Ok(log) => serializer.serialize(&log).await.unwrap(),
                    Err(err) => {
                        let msg = format!("Error parsing packet: {}", err);
                        error_handler.error(msg.as_str());
                    }
                }
            }

            let body = serializer.into_inner().await.unwrap();
            let timestamp = utils::timestamp();
            let filename = format!("{}.csv", timestamp);
            let req = PutObjectRequest {
                bucket: bucket.clone(),
                key: filename.clone(),
                body: Some(body.into()),
                ..PutObjectRequest::default()
            };

            match s3.put_object(req).await {
                Ok(_) => println!("Saved {}", filename),
                Err(err) => {
                    let msg = format!("Error saving to S3: {}", err.to_string());
                    error_handler.error(msg.as_str());
                }
            }
        });
    }

    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
