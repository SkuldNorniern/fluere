# Fluere

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere?ref=badge_shield)
[![Rust](https://github.com/SkuldNorniern/fluere/actions/workflows/rust.yml/badge.svg)](https://github.com/SkuldNorniern/fluere/actions/workflows/rust.yml)
[![Drone Build Status](https://drone.nornity.com/api/badges/SkuldNorniern/fluere/status.svg)](https://drone.nornity.com/SkuldNorniern/fluere)
## Cross Platform Packet Capture, pcap to Netflow Conversion, Live Netflow Capture Tool

<p align="center" align="right">
  Supported Platforms
</p>
<p align="center" align="right">
  <img alt="Windows" src="https://img.shields.io/badge/Windows-0078D6?style=for-the-badge&logo=windows&logoColor=white"/>
  <img alt="MacOS" src="https://img.shields.io/badge/mac%20os-000000?style=for-the-badge&logo=macos&logoColor=F0F0F0"/>
  <img alt="Linux" src="https://img.shields.io/badge/Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black"/>
</p>
<p align="center" align="right">
  Windows, MacOS, and Linux are All Supported! YAY!


<div align="center">
    <img src="https://github.com/SkuldNorniern/fluere/blob/main/images/help_image.png" alt="Help Image" width="770" height="401"></img>
</div>
<div align="center">
    <img src="https://github.com/SkuldNorniern/fluere/blob/main/images/TUI Screen.png" alt="Help Image" width="770" height="401"></img>
</div> 
<p align="center" align="right">
  public ips are masked cause of the privacy issue (except of the DNS & Local broadcast)


## Project Description

Fluere is a powerful and versatile tool designed for network monitoring and analysis. It is capable of capturing network packets in pcap format and converting them into NetFlow data, providing a comprehensive view of network traffic. Fluere supports both live capture and offline conversion of NetFlow data, making it suitable for a wide range of use cases. Additionally, Fluere offers a terminal user interface for live feedback during online capture. Fluere is cross-platform compatible, running on Windows, macOS, and Linux operating systems.

The project is implemented in Rust and uses the `libpcap` library for packet capture and the `clap` library for command line argument parsing. The main functionality of the project is defined in the `main.rs` file, which includes the definition of the command line interface and the handling of the different commands and options.

## Arguments

The following table provides detailed information about each argument:

| Argument | Purpose | Usage |
| --- | --- | --- |
| csv | Title of the exported csv file | `-c` or `--csv` |
| list | List of network interfaces | `-l` or `--list` |
| interface | Select network interface to use | `-i` or `--interface` |
| duration | Set capture duration, in milliseconds | `-d` or `--duration` |
| timeout | Set flow timeout, in milliseconds | `-t` or `--timeout` |
| useMACaddress | Set use MAC address on Key value | `-M` or `--useMAC` |
| interval | Set export interval, in milliseconds | `-I` or `--interval` |
| sleep_windows | Set interval of thread pause for (only)MS Windows per n packet | `-s` or `--sleep` |
| verbose | Set verbosity level | `-v` or `--verbose` |



## Prerequisites

Ensure that you have installed `libpcap` on Linux and macOS or `npcap` on Windows.
- you need to install `npcap` in `winpcap compatible mode` 

## Installation

```sh
cargo install fluere
```

## Examples of Common Use Cases

1. **Live NetFlow Capture and Conversion**: To capture NetFlow data in real-time from a specific network interface, use the `online` subcommand. For example:

```sh
fluere online -i eth0 -d 1000 -t 600000 -I 1800000 -v 1
```

This command captures NetFlow data from the `eth0` interface for a duration of 1000 milliseconds, with a flow timeout of 600000 milliseconds and an export interval of 1800000 milliseconds. The verbosity level is set to 1.

2. **Offline pcap to NetFlow Conversion**: To convert a pcap file into NetFlow data, use the `offline` subcommand. For example:

```sh
fluere offline -f input.pcap -c output
```

This command converts the `input.pcap` file into NetFlow data and exports the data to a CSV file named `output.csv`.

3. **Packet Capture in pcap Format**: To capture packets in pcap format from a specific network interface, use the `pcap` subcommand. For example:

```sh
fluere pcap -i eth0 -d 1000
```

This command captures packets from the `eth0` interface for a duration of 1000 milliseconds and saves the packets in a pcap file.

4. **Live Fluereflow Capture and Conversion**: To capture Fluereflow data in real-time with TUI feedback in realtime from a specific network interface, use the `live` subcommand. For example:

```sh
fluere live -i eth0 -d 1000 -t 600000 -I 1800000 -v 1
```

This command captures Fluereflow data from the `eth0` interface for a duration of 1000 milliseconds, with a flow timeout of 600000 milliseconds and an export interval of 1800000 milliseconds. The verbosity level is set to 1.

