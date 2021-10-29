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

## Build Prerequisites

### Setup
This was done on a [DigitalOcean](https://m.do.co/c/515db03705b4) Droplet with 2GB of RAM.

#### Ubuntu 21.04
First, install dependencies with the following commands:

```bash
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
# Generate development build
cargo build

# Generate release build
cargo build --release
```

## Run
`wg-wiretap` can be configured to send flow logs for a particular interface to [S3](https://aws.amazon.com/s3/) compatible storage.
By default, it will log from `wg0`, but can be made to listen to any interface with the `--iface` flag.
You can run this without root by setting the `CAP_NET_RAW,CAP_NET_ADMIN=+eip` capabilities on the `wg-wiretap` binary.

```bash
sudo setcap CAP_NET_RAW,CAP_NET_ADMIN=+eip wg-wiretap
```

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
AWS_ACCESS_KEY_ID=AWS_ACCESS_KEY_ID \
AWS_SECRET_ACCESS_KEY=AWS_SECRET_KEY \
cargo run --bin wg-wiretap -- \
--iface wg0 \
--storage-bucket bucket-name \
--storage-endpoint https://s3-storage-endpoint \
--storage-region s3-region \
--max-packets-per-log 1000000 \
--packet-log-interval 5
```

## Log Format
`wg-wiretap` stores logs as CSV to a provided S3 bucket.
Each log has the following fields:

- `src` - A packet's source IP address
- `src_port` - The source port a packet was sent from.
- `dst` - The IP address a packet is destined to
- `dst_port` - The port the packet is destined to
- `l3_protocol` - Layer 3 protocol of the packet, such as TCP, UDP or ICMP.
- `size` - The size of the packet in bytes
- `timestamp` - The [unix timestamp](https://en.wikipedia.org/wiki/Unix_time) the packet was received by `wg-wiretap` in nanoseconds.
- `dns` - A base64 encoded DNS packet. This field is optional and will only be populated for DNS traffic.