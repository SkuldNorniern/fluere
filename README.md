# Fluere
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
  Windows, MacOS, Linux All Supported! YAY! 
</p>
 

```
Netflow Capture Tool

Usage: fluere.exe `<COMMAND>`

Commands:
  online   Capture netflow online
  offline  convet pcap files to netflow
  pcap     collect pcket and save to .pcap file
  help     Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help information
  -V, --version  Print version information
```


## Description
This tool is designed to capture network packets into pcap format and convert them to netflow data. It also allows for live capture and conversion of netflow data. The tool is cross-platform supported and can run on Windows, MacOS, and Linux operating systems.

## Installation
Download the latest release of the tool from the releases page.
``` MacOS, Linux installation will be provided in the future ``` 

- Windows

Run the installer.exe file and check if the enviroment variable has been setup correctly (there is a bug)

- MacOS
WIP

Use ths Cargo Build --release to get the program or Cargo run 
- Linux
WIP

Use ths Cargo Build --release to get the program or Cargo run

## Usage

Run the tool by entering the ```fluere``` command in the terminal.

list the interfaces using 
``` 
  fluere online -l
```
or 
```
  fluere pcap -l
```

Choose between capturing packets in pcap format or converting live netflow data.
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

Make sure to run the tool with administrator privileges on Linux operating systems.
On linux you may need to install libpcap-dev or npcap on Windows
Make sure to have enough storage space on your machine to save the captured packets or netflow data.

## Support
Please contact the developer at [skuldnorniern@gmail.com] or make a issue on the github for any support or bug reports. Thank you for using our tool!



