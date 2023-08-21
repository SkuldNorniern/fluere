use super::types::C_Ipv4Packet;
use pnet::datalink::{self, Channel, DataLinkReceiver, NetworkInterface};

use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

fn process_packets(rx: &mut Box<dyn DataLinkReceiver>) -> Result<Vec<C_Ipv4Packet>, NetError> {
    let mut packets = Vec::new();
    loop {
        match rx.next() {
            Ok(packet) => {
                // Process the packet
                let ethernet_packet = EthernetPacket::new(packet).unwrap();

                let protocol = ethernet_packet.get_ethertype();
                match protocol {
                    EtherTypes::Ipv4 => {
                        // Parse the IP packet
                        let ipv4_packet = Ipv4Packet::new(ethernet_packet.packet()).unwrap();
                        let c_packet = C_Ipv4Packet::new(ipv4_packet);
                        let src_ip = c_packet.get_source();
                        let dst_ip = c_packet.get_destination();
                        let protocol = c_packet.get_next_level_protocol();
                        let mut src_port = 0;
                        let mut dst_port = 0;
                        //println!("protocol: {:?}", c_packet.get_next_level_protocol());
                        match protocol.0 {
                            6 => {
                                let tcp_packet = TcpPacket::new(c_packet.get_payload()).unwrap();
                                src_port = tcp_packet.get_source();
                                dst_port = tcp_packet.get_destination();
                                println!(
                                    "TCP packet: {}:{} > {}:{}",
                                    src_ip, src_port, dst_ip, dst_port
                                );
                            }
                            17 => {
                                let udp_packet = UdpPacket::new(c_packet.get_payload()).unwrap();
                                src_port = udp_packet.get_source();
                                dst_port = udp_packet.get_destination();
                                println!(
                                    "UDP packet: {}:{} > {}:{}",
                                    src_ip, src_port, dst_ip, dst_port
                                );
                            }
                            // Add other protocol cases here
                            _ => {
                                // Ignore other protocols
                            }
                        }

                        println!(
                            "protocol: {} packet: {}:{} > {}:{}",
                            protocol, src_ip, src_port, dst_ip, dst_port
                        );
                        packets.push(c_packet.clone());
                    }
                    _ => {
                        println!("Other packet: {:?}", protocol)
                        // Ignore other packet types
                    }
                }
            }
            Err(e) => {
                // An error occurred while reading the packet
                return Err(NetError::PacketReadError { source: e });
            }
        }
    }
    println!("Packets: {:?}", packets);
    packets
}

pub fn packet_capture(interface_name: &str) -> Result<(), NetError> {
    println!("Capturing on interface: {}", interface_name);

    // Parse the interface str into NetworkInterface
    let interface_names_match = |iface: &NetworkInterface| iface.name == interface_name;
    let interfaces = datalink::interfaces();
    let interface = interfaces.into_iter().find(interface_names_match).unwrap();

    // Create a channel to receive on
    let (_, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => return Err(NetError::UnhandledChannelType),
        Err(e) => return Err(NetError::ChannelCreationError { source: e }),
    };

    // Process packets
    let _packets = process_packets(&mut rx);
    //packets
}
