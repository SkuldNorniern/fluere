# Fluere

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere?ref=badge_shield)
[![Rust](https://github.com/SkuldNorniern/fluere/actions/workflows/rust.yml/badge.svg)](https://github.com/SkuldNorniern/fluere/actions/workflows/rust.yml)
[![Drone Build Status](https://drone.nornity.com/api/badges/SkuldNorniern/fluere/status.svg)](https://drone.nornity.com/SkuldNorniern/fluere)

## Your Comprehensive Network Monitoring and Analysis Tool

Fluere is a robust tool designed for comprehensive network monitoring and analysis. It facilitates the capture of network packets in pcap format and their conversion into NetFlow data, offering a detailed view of network traffic dynamics. With support for both live and offline data capture, Fluere stands as a versatile solution suitable for a myriad of use cases.

### Key Features:
- Cross-platform support (Windows, macOS, Linux)
- Live and offline NetFlow data capture and conversion
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

## Technical Overview

Fluere is built with Rust and leverages the `libpcap` library for packet capture. The core functionalities are encapsulated within the `main.rs` file, which defines the command-line interface and handles various commands and options.

## Command Line Arguments

Customize your Fluere experience using the following command-line arguments:

| Argument       | Description                          | Usage Example          |
|----------------|--------------------------------------|------------------------|
| `csv`          | Title of the exported CSV file       | `-c` or `--csv`        |
| `list`         | List available network interfaces    | `-l` or `--list`       |
| `interface`    | Select network interface to use      | `-i` or `--interface`  |
| `duration`     | Set capture duration (in ms)         | `-d` or `--duration`   |
| `timeout`      | Set flow timeout (in ms)             | `-t` or `--timeout`    |
| `useMACaddress`| Use MAC address as key value         | `-M` or `--useMAC`     |
| `interval`     | Set export interval (in ms)          | `-I` or `--interval`   |
| `sleep_windows`| Set thread pause interval for Windows| `-s` or `--sleep`      |
| `verbose`      | Set verbosity level                  | `-v` or `--verbose`    |

## Getting Started

### Prerequisites

Before installing Fluere, ensure to install `libpcap` (Linux/macOS) or `npcap` (Windows) in winpcap compatible mode.

### Installation

Install Fluere using the following command:

```sh
cargo install fluere
```

## Usage Examples

Explore the diverse functionalities of Fluere with the following examples:

1. **Live NetFlow Capture and Conversion**
   ```sh
   fluere online -i eth0 -d 1000 -t 600000 -I 1800000 -v 1
   ```

2. **Offline pcap to NetFlow Conversion**
   ```sh
   fluere offline -f input.pcap -c output
   ```

3. **Packet Capture in pcap Format**
   ```sh
   fluere pcap -i eth0 -d 1000
   ```

4. **Live Fluereflow Capture and Conversion**
   ```sh
   fluere live -i eth0 -d 1000 -t 600000 -I 1800000 -v 1
   ```

For more detailed information and guidance, refer to the [Fluere Wiki](https://github.com/SkuldNorniern/fluere/wiki).
