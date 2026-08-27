# Fluere

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere?ref=badge_shield)
[![Rust](https://github.com/SkuldNorniern/fluere/actions/workflows/rust.yml/badge.svg)](https://github.com/SkuldNorniern/fluere/actions/workflows/rust.yml)
[![Drone Build Status](https://drone.nornity.com/api/badges/SkuldNorniern/fluere/status.svg)](https://drone.nornity.com/SkuldNorniern/fluere)

## Cross-platform packet capture and network flow analysis

Fluere captures network traffic and turns it into FluereFlow records: bidirectional flow records with per-flow byte and packet counts, TCP flag counters, packet-size and TTL ranges, and tunnel-aware keys. It reads live interfaces or existing pcap files, and exports to CSV or to Lua plugins.

FluereFlow is Fluere's own flow format. It is not NetFlow, and Fluere is not a NetFlow collector or exporter.

- AWS flow logging using AWS Traffic Mirroring
- Local Server's Active firewall implementation using a plugin
- Logging your Server's Flows 

### Key Features:
- Cross-platform support (Windows, macOS, Linux)
- Live and offline flow record generation, exported as CSV
- Packet capture in pcap format
- Terminal User Interface (TUI) for real-time feedback during live capture

<div align="center">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white"/>
  <img alt="MacOS" src="https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0"/>
  <img alt="Linux" src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black"/>
  <br>
  Windows, MacOS, and Linux are All Supported! YAY!
</div>

<div align="center">
    <img src="https://github.com/SkuldNorniern/fluere/blob/main/images/help_image.png" alt="Help Image"></img>
    <img src="https://github.com/SkuldNorniern/fluere/blob/main/images/TUI Screen.png" alt="TUI Screen"></img>
    <br>
    <i>Public IPs are masked to prevent privacy issues (except for DNS & Local broadcast)</i>
</div>

## How it works

```text
Live interface / pcap file
            |
            v
         paccel                packet decode
            |
            v
   PacketObservation           one decode per packet
            |
            +---------- ParserState
            |              fragment reassembly
            |              QUIC connection identity
            v
       FlowEngine              keying, aggregation, expiry
            |
            v
     FluereFlow::Flow
         /       \
        v         v
      CSV       Plugins
```

A flow is keyed on the addresses, ports and protocol of the first packet seen
for it, plus the VLAN and tunnel that carried it. Separate segments reuse the
same private ranges, so keying on addresses alone would put unrelated traffic in
one record.

See [Architecture](https://github.com/SkuldNorniern/fluere/wiki) in the wiki for
the longer version.

## Getting started

Install `libpcap` (Linux/macOS) or `npcap` in WinPcap-compatible mode (Windows),
then:

```sh
cargo install fluere
```

Capture live traffic from an interface:

```sh
fluere capture -i eth0 -c flows
```

With a terminal UI:

```sh
fluere capture -i eth0 --tui
```

Convert a pcap file:

```sh
fluere convert -f input.pcap -c flows
```

List the interfaces available:

```sh
fluere devices
```

`fluere capture --help` lists the options. If you have scripts built against
0.7, see [Migrating from 0.7](https://github.com/SkuldNorniern/fluere/wiki/Migrating-from-0.7):
the old command names still work.

For more detailed information and guidance, refer to the [Fluere Wiki](https://github.com/SkuldNorniern/fluere/wiki).
