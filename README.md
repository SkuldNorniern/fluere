# Fluere

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere.svg?type=shield)](https://app.fossa.com/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere?ref=badge_shield)
[![Rust](https://github.com/SkuldNorniern/fluere/actions/workflows/rust.yml/badge.svg)](https://github.com/SkuldNorniern/fluere/actions/workflows/rust.yml)
[![Codacy Badge](https://app.codacy.com/project/badge/Grade/9bb831ce9bab4ed394763bf9d6583773)](https://www.codacy.com/gh/SkuldNorniern/fluere/dashboard?utm_source=github.com&utm_medium=referral&utm_content=SkuldNorniern/fluere&utm_campaign=Badge_Grade)

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
</p>

<div align="center">
    <img src="https://github.com/SkuldNorniern/fluere/blob/main/images/main.png" alt="Help Image" width="770" height="401"></img>
</div>

## Description

This tool is designed to capture network packets into pcap format and convert them to NetFlow data. It also allows for live capture and conversion of NetFlow data. The tool is cross-platform supported and can run on Windows, MacOS, and Linux operating systems.

## Installation
you need to install libpcap on Linux and macOS or npcap on Windows

Download the latest release of the tool from the releases page.

- Windows

  - Run the installer.exe file and check if the environment variable has been set up correctly (there is a bug)

- MacOS

  - Intel

    ```
    brew tap SkuldNorniern/fluere
    brew install fluere
    ```

- Linux

  - Debian

    ```
    sudo dpkg -i fluere_x.x.x_amd64.deb
    ```

## Usage

Run the tool by entering the `fluere` command in the terminal.

list the interfaces using

```
  fluere online -l
```

or

```
  fluere pcap -l
```

Choose between capturing packets in pcap format or converting live NetFlow data.

```
  online
  offline
  pcap
```

Set the desired capture duration.

```
  -d 1000 // in ms
```

Set the name for the files

```
  -c file_name
```

The captured packets or netflow data will be saved in the "output" directory in the tool's installation location.

## Additional Features

Make sure to run the tool with administrator privileges on Linux and macOS operating systems.
Make sure to have enough storage space on your machine to save the captured packets or NetFlow data.

## Support

Please contact the developer at skuldnorniern@gmail.com or make a issue on the github for any support or bug reports. Thank you for using our tool!

## License

[![FOSSA Status](https://app.fossa.com/api/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere.svg?type=large)](https://app.fossa.com/projects/git%2Bgithub.com%2FSkuldNorniern%2Ffluere?ref=badge_large)
