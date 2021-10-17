# wg-wiretap
`wg-wiretap` is a simple PCAP flow logger that will listen on a Wireguard interface and log IP packets.
Since Wireguard doesn't send ethernet frames, `wg-wiretap` will not interpret them and will fail on any interface that sends them.
Check out [wiretap](https://github.com/JonCooperWorks/wiretap) for an example of logging ethernet frames using eBPF.
I use this to let me take per-client logs through my Wireguard VPNs.
`wg-wiretap` will take flow logs from a Wireguard interface and store them to AWS S3 compatible cloud storage as CSV.
The S3 credentials should be set as environment variables with the following names:

```
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
```

`wg-wiretap` is meant to help me learn and should not be used in a production environment.

## Prerequisites

### Setup
This was done on a [DigitalOcean](https://m.do.co/c/515db03705b4) Droplet with 2GB of RAM.

#### Ubuntu 21.04
First, install dependencies with the following commands:

```
# First update package lists and packages.
sudo apt-get update
sudo apt-get upgrade

# Then install PCAP dependencies
sudo apt-get install -y sudo build-essential libpcap-dev

# Install Rust
curl https://sh.rustup.rs -sSf | sh  -s -- -y

# Use rustup to install stable toolchain
rustup install stable
```

## Build

```bash
cargo build
```

## Run

`wg-wiretap` can be configured to send flow logs for a particular interface to [S3](https://aws.amazon.com/s3/) compatible storage.
By default, it will log from `wg0`, but can be made to listen to any interface with the `--iface` flag.

### S3 Storage
`wg-wiretap` expects AWS credentials to be passed the environment variables:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`

Pass the bucket, endpoint and region for S3 compatible storage using the `--storage-bucket`, `--storage-endpoint` and `--storage-region` flags.

### Log Intervals
`wg-wiretap` can be made to log packets to S3 compatible storage at intervals.
By default, it will log every million (1000000) packets or 5 minutes, whichever comes first.
You can change these with the `--max-packets-per-log` and `--packet-log-interval` flags.

```bash
AWS_ACCESS_KEY_ID=AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
=AWS_SECRET_KEY cargo run --bin wg-wiretap -- --iface wg0 --storage-bucket bucket-name --storage-endpoint https://s3-storage-endpoint --storage-region s3-region --max-packets-per-log 1000000 --packet-log-interval 5
```
