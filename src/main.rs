use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use futures_batch::ChunksTimeoutStreamExt;
use mongodb::{options::ClientOptions, Client};
use pcap::Capture;
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

    #[structopt(long, default_value = "500000")]
    max_packets_per_log: usize,

    #[structopt(long, default_value = "1")]
    packet_log_interval: u64,

    #[structopt(long)]
    connection_string: String,

    #[structopt(long)]
    database: String,

    #[structopt(long)]
    collection: String,

    #[structopt(long)]
    sentry_dsn: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::from_args();

    let config = storage::Config {
        max_packets_per_log: opt.max_packets_per_log,
        packet_log_interval: Duration::from_secs(opt.packet_log_interval * 60),
    };

    // Set up mongodb-compatible database
    let client_options = ClientOptions::parse(&opt.connection_string).await?;
    let collection = Client::with_options(client_options)?
        .database(&opt.database)
        .collection(&opt.collection);

    // Configure indexes for TTL and timestamp queries

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
    let packet_events = cap.stream(packet::FlowLogCodec {})?;
    let mut packet_events = Box::pin(packet_events.filter_map(|result| async {
        match result {
            Ok(packet) => Some(packet),
            Err(err) => {
                let msg = format!("Error parsing packet: {}", err);
                error_handler.error(msg.as_str());
                None
            }
        }
    }))
    .chunks_timeout(config.max_packets_per_log, config.packet_log_interval);

    while let Some(packet_chunk) = packet_events.next().await {
        let error_handler = Arc::clone(&error_handler);
        let collection = collection.clone();

        task::spawn(async move {
            // Send packet logs to MongoDB compatible storage
            match collection.insert_many(packet_chunk, None).await {
                Ok(_) => println!("Saved packets"),
                Err(err) => {
                    let msg = format!("Error saving packet chunk: {}", err);
                    error_handler.error(msg.as_str());
                }
            }
        });
    }

    signal::ctrl_c().await.expect("failed to listen for event");
    Ok::<_, anyhow::Error>(())
}
