extern crate rpcap;
extern crate pnet;
extern crate byteorder;

use std::env;
use std::fs::File;
use std::io::Write;
use std::net::Ipv4Addr;
use std::str;
use std::time::{SystemTime, UNIX_EPOCH};
use byteorder::{ByteOrder, NetworkEndian};

use rpcap::read::PcapReader;
use pnet::packet::Packet;
use pnet::packet::ip::{IpNextHeaderProtocols, IpNextHeaderProtocol};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

#[derive(Debug)]
struct NetFlowRecord {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    protocol: IpNextHeaderProtocol,
    packet_count: u64,
    byte_count: u64,
    // Other NetFlow fields as needed
}
impl NetFlowRecord {
    fn new(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, protocol: IpNextHeaderProtocol,packet_count: u64, byte_count: u64) -> NetFlowRecord {
        NetFlowRecord {
            src_ip: src_ip,
            dst_ip: dst_ip,
            src_port: src_port,
            dst_port: dst_port,
            protocol: protocol,
            packet_count: 0,
            byte_count: 0,
        }
    }
}

pub fn netflow(pcap_file: &str, csv_file: &str) {
    // Parse the command-line arguments
    //let args: Vec<String> = env::args().collect();
    //if args.len() != 3 {
        //println!("Usage: pcap_to_netflow <input_file.pcap> <output_file.csv>");
        //return;
    //}
    //let pcap_file = &args[1];
    //let csv_file = &args[2];
       
    let infile = File::open("example.pcap").unwrap();
    let reader = BufReader::new(infile);
    let (file_opts, mut pcapr) = PcapReader::new(reader).unwrap();

    // Process the packets in the PCAP file
    let mut netflow_records = Vec::new();
    for pcap in capture {
        let packet = pcap.unwrap();
        // Parse and extract information from the packet as before
        let ipv4_packet = Ipv4Packet::new(packet).unwrap();
        // Extract the source and destination IP addresses from the IPv4 packet
        let src_ip = ipv4_packet.get_source();
        let dst_ip = ipv4_packet.get_destination();
        // Extract the protocol from the IPv4 packet
        let packet_protocol = ipv4_packet.get_next_level_protocol();
        
        let (src_port, dst_port, packet_count, byte_count) = match packet_protocol {
            IpNextHeaderProtocols::Tcp => {
                // Parse the packet payload as a TCP packet
                let tcp_packet = TcpPacket::new(ipv4_packet.payload()).unwrap();
                (tcp_packet.get_source(), tcp_packet.get_destination(), 1, tcp_packet.packet().len() as u64)
            },
            IpNextHeaderProtocols::Udp => {
                // Parse the packet payload as a UDP packet
                let udp_packet = UdpPacket::new(ipv4_packet.payload()).unwrap();
                (udp_packet.get_source(), udp_packet.get_destination(), 1, udp_packet.packet().len() as u64)
            },
            _ => {
                // Unknown protocol, skip this packet
                return;
            }
        };

        // Create a NetFlow record from the extracted information
        let netflow_record = NetFlowRecord::new(src_ip, dst_ip, src_port, dst_port, packet_protocol, packet_count, byte_count);
        
        // Add the NetFlow record to the list
        netflow_records.push(netflow_record);
    }

    // Open the output file for writing
    let mut csv_file = File::create(csv_file).unwrap();

    // Write the NetFlow records to the output file in CSV format
    for netflow_record in netflow_records {
        let line = format!("{},{},{},{},{},{},{}\n", netflow_record.src_ip, netflow_record.dst_ip, netflow_record.src_port, netflow_record.dst_port, netflow_record.protocol, netflow_record.packet_count, netflow_record.byte_count);
        csv_file.write_all(line.as_bytes()).unwrap();
    }

    // Close the files
    csv_file.flush().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_netflow() {
        netflow("test.pcap", "test.csv");
        
    }
}