use pnet::datalink::{self, DataLinkReceiver, NetworkInterface,Channel};
use pnet::packet::{Packet, MutablePacket};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::tcp::{TcpPacket, MutableTcpPacket};
use pnet::packet::udp::{UdpPacket, MutableUdpPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use std::env;
use std::io::{self, Write};
use std::net::IpAddr;

pub fn packet_capture(interface_name: &str){
    println!("Capturing on interface: {}", interface_name);
    // Parse the interface str into NetworkInterface
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();
    
    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("An error occurred when creating the datalink channel: {}", e),
    };

    loop {
        match rx.next() {
            Ok(packet) => {
                // Process the packet
                let ethernet_packet = EthernetPacket::new(packet).unwrap();
                let protocol = ethernet_packet.get_ethertype();
                match protocol {
                    EtherTypes::Ipv4 => {
                        // Parse the IP packet
                        let ipv4_packet = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
                        let src_ip = ipv4_packet.get_source();
                        let dst_ip = ipv4_packet.get_destination();
                        let packet_protocol = ipv4_packet.get_next_level_protocol();
                        println!("IP packet: {} > {}", src_ip, dst_ip);
                    }
                    _ => {
                        println!("Other packet: {:?}", protocol)
                        // Ignore other packet types
                    }
                }   
            }
            Err(e) => {
                // An error occurred while reading the packet
                panic!("An error occurred while reading: {}", e);
            }
        }
    }
}
