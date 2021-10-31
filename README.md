# wg-wiretap
`wg-wiretap` is a simple PCAP flow logger that will listen on a Wireguard interface and log IP packets.
Since Wireguard doesn't send ethernet frames, `wg-wiretap` will not interpret them and will fail on any interface that sends them.
Check out [wiretap](https://github.com/JonCooperWorks/wiretap) for an example of logging ethernet frames using eBPF.
I use this to let me take per-client logs through my Wireguard VPNs.
`wg-wiretap` will take flow logs from a Wireguard interface and store them to MongoDB compatible cloud storage.

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
`wg-wiretap` can be configured to send flow logs for a particular interface to MongoDB compatible storage.
By default, it will log from `wg0`, but can be made to listen to any interface with the `--iface` flag.
You can run this without root by setting the `CAP_NET_RAW,CAP_NET_ADMIN=+eip` capabilities on the `wg-wiretap` binary.

```bash
sudo setcap CAP_NET_RAW,CAP_NET_ADMIN=+eip wg-wiretap
```

### MongoDB Storage
`wg-wiretap` accepts MongoDB connection information via flags.
Pass the connection string, database and collection for MongoDB compatible storage using the `--connection-string`, `--database` and `--collection` flags.

### Log Intervals
`wg-wiretap` can be made to log packets to MongoDB compatible storage at intervals.
By default, it will log every half million (500000) packets or 1 minute, whichever comes first.
You can change these with the `--max-packets-per-log` and `--packet-log-interval` flags.

```bash
cargo run --bin wg-wiretap -- \
--iface wg0 \
--connection-string mongodb://connnection-string \
--database database \
--collection collection \
--max-packets-per-log 500000 \
--packet-log-interval 1
```

### Sentry
`wg-wiretap` logs errors to `stderr` and it can optionally send errors to [Sentry](https://sentry.io).
To enable Sentry, pass a Sentry DSN using the `--sentry-dsn` flag.

## Log Format
`wg-wiretap` stores logs to a provided MongoDB compatible database.
Each log has the following fields:

- `src` - A packet's source IP address
- `src_port` - The source port a packet was sent from. This field is optional as not all protocols use port numbers.
- `dst` - The IP address a packet is destined to
- `dst_port` - The port the packet is destined to. This field is optional as not all protocols use port numbers.
- `l3_protocol` - Layer 3 [protocol number](https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers) of the packet, such as TCP, UDP or ICMP. 
- `size` - The size of the packet in bytes
- `timestamp` - The [unix timestamp](https://en.wikipedia.org/wiki/Unix_time) the packet was received by `wg-wiretap` in milliseconds.
- `dns` - Information from DNS packet. This field is optional and will only be populated for DNS traffic.