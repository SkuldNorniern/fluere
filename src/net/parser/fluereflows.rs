use pcap;

use crate::net::parser::{
    dscp_to_tos, parse_flags, parse_microseconds, parse_ports, protocol_to_number,
};
use crate::net::NetError;
use fluereflow::FluereRecord;
use pnet::packet::{
    arp::ArpPacket,
    ethernet::{EtherTypes, EthernetPacket},
    ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
    udp::UdpPacket,
    Packet, PacketSize,
};

const VXLAN_HEADER: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00];

fn decapsulate_vxlan(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.starts_with(&VXLAN_HEADER) {
        //println!("Decapsulating VXLAN");
        Some(payload[VXLAN_HEADER.len()..].to_vec())
    } else {
        None
    }
}

pub fn parse_fluereflow(packet: pcap::Packet) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
    if packet.is_empty() {
        return Err(NetError::EmptyPacket);
    }

    let ethernet_packet_raw = EthernetPacket::new(packet.data);
    let ethernet_packet_unpack = match ethernet_packet_raw {
        None => return Err(NetError::EmptyPacket),
        Some(e) => e,
    };

    let is_udp: bool = match ethernet_packet_unpack.get_ethertype() {
        EtherTypes::Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet_unpack.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }
            let is_udp = UdpPacket::new(i.payload()).is_some();

            is_udp
        }
        EtherTypes::Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet_unpack.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            let is_udp = UdpPacket::new(i.payload()).is_some();

            is_udp
        }
        _ => false,
    };
    let mut decapsulated_data: Option<Vec<u8>> = None;

    if is_udp {
        let udp_payload = match ethernet_packet_unpack.get_ethertype() {
            EtherTypes::Ipv6 => {
                let i = Ipv6Packet::new(ethernet_packet_unpack.payload()).unwrap();
                if i.payload().is_empty() {
                    return Err(NetError::EmptyPacket);
                }

                UdpPacket::new(i.payload()).unwrap().payload().to_vec()
            }
            EtherTypes::Ipv4 => {
                let i = Ipv4Packet::new(ethernet_packet_unpack.payload()).unwrap();
                if i.payload().is_empty() {
                    return Err(NetError::EmptyPacket);
                }

                UdpPacket::new(i.payload()).unwrap().payload().to_vec()
            }
            _ => Vec::new(),
        };
        if udp_payload.is_empty() {
            return Err(NetError::EmptyPacket);
        }
        //UdpPacket::new(ethernet_packet_unpack.payload()).unwrap().payload().to_vec();
        //println!("UDP payload: {:?}", udp_payload);
        decapsulated_data = decapsulate_vxlan(&udp_payload);
    }

    let ethernet_packet_decapsulated = if let Some(data) = &decapsulated_data {
        match EthernetPacket::new(data) {
            None => return Err(NetError::EmptyPacket),
            Some(e) => e,
        }
    } else {
        ethernet_packet_unpack
    };

    let ethernet_packet = ethernet_packet_decapsulated;

    let time = parse_microseconds(
        packet.header.ts.tv_sec as u64,
        packet.header.ts.tv_usec as u64,
    );

    let record_result = match ethernet_packet.get_ethertype() {
        EtherTypes::Ipv4 => {
            let i = Ipv4Packet::new(ethernet_packet.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            ipv4_packet(time, i)
        }
        EtherTypes::Ipv6 => {
            let i = Ipv6Packet::new(ethernet_packet.payload()).unwrap();
            if i.payload().is_empty() {
                return Err(NetError::EmptyPacket);
            }

            ipv6_packet(time, i)
        }
        EtherTypes::Arp => {
            let i = ArpPacket::new(ethernet_packet.payload()).unwrap();
            //if i.payload().is_empty() {
            //    return Err(NetError::EmptyPacket);
            //}

            arp_packet(time, i)
        }
        _ => {
            return Err(NetError::UnknownEtherType(
                ethernet_packet.get_ethertype().to_string(),
            ))
        }
    };

    match record_result {
        Ok(_) => {}
        Err(e) => return Err(e),
    }
    let (doctets, raw_flags, record) = record_result.unwrap();
    Ok((doctets, raw_flags, record))
}
fn arp_packet(time: u64, packet: ArpPacket) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
    let src_ip = packet.get_sender_proto_addr();
    let dst_ip = packet.get_target_proto_addr();

    // ports parsing
    let src_port = 0;
    let dst_port = 0;
    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = parse_flags(4, packet.payload());

    //	Autonomous system number of the source and destination, either origin or peer
    let doctets = packet.packet_size();

    Ok((
        doctets,
        flags,
        FluereRecord::new(
            std::net::IpAddr::V4(src_ip),
            std::net::IpAddr::V4(dst_ip),
            0,
            0,
            time,
            time,
            src_port,
            dst_port,
            packet.packet_size() as u32,
            packet.packet_size() as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            4,
            0,
        ),
    ))
}

fn ipv4_packet(time: u64, packet: Ipv4Packet) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
    let protocol = protocol_to_number(packet.get_next_level_protocol());
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();

    // ports parsing
    let (src_port, dst_port) = parse_ports(protocol, packet.payload())?;

    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = parse_flags(protocol, packet.payload());

    //	Autonomous system number of the source and destination, either origin or peer
    let doctets = packet.packet_size();
    let tos_convert_result = dscp_to_tos(packet.get_dscp());
    let tos = tos_convert_result.unwrap_or(0);

    Ok((
        doctets,
        flags,
        FluereRecord::new(
            std::net::IpAddr::V4(src_ip),
            std::net::IpAddr::V4(dst_ip),
            0,
            0,
            time,
            time,
            src_port,
            dst_port,
            packet.get_total_length() as u32,
            packet.get_total_length() as u32,
            packet.get_ttl(),
            packet.get_ttl(),
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            protocol,
            tos,
        ),
    ))
}

fn ipv6_packet(time: u64, packet: Ipv6Packet) -> Result<(usize, [u8; 9], FluereRecord), NetError> {
    let protocol = protocol_to_number(packet.get_next_header());
    let src_ip = packet.get_source();
    let dst_ip = packet.get_destination();

    // ports parsing
    let (src_port, dst_port) = parse_ports(protocol, packet.payload())?;
    // TCP flags Fin Syn Rst Psh Ack Urg Ece Cwr Ns
    let flags = parse_flags(protocol, packet.payload());

    //	Autonomous system number of the source and destination, either origin or peer
    let doctets = packet.packet_size();
    //first six bits in the 8-bit Traffic Class field
    let dscp = packet.get_traffic_class() >> 2;
    let tos_convert_result = dscp_to_tos(dscp);
    let tos = tos_convert_result.unwrap_or(0);

    Ok((
        doctets,
        flags,
        FluereRecord::new(
            std::net::IpAddr::V6(src_ip),
            std::net::IpAddr::V6(dst_ip),
            0,
            0,
            time,
            time,
            src_port,
            dst_port,
            packet.get_payload_length() as u32,
            packet.get_payload_length() as u32,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            protocol,
            tos,
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::Packet;
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet, Ipv4Flags};
    use pnet::packet::ipv6::MutableIpv6Packet;
    use pnet::packet::arp::ArpOperation;
    use pnet::packet::{MutablePacket, Packet as PnetPacket};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use chrono::format::Numeric::Timestamp;

    // Helper function to create a basic IPv4 packet
    fn create_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 20 + payload.len()];
        let mut pkt = MutableIpv4Packet::new(&mut buf).unwrap();
        pkt.set_version(4);
        pkt.set_header_length(5);
        pkt.set_total_length(20 + payload.len() as u16);
        pkt.set_source(src);
        pkt.set_destination(dst);
        pkt.set_payload(payload);
        buf
    }

    // Helper function to create a basic IPv6 packet
    fn create_ipv6_packet(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut buf = vec![0u8; 40 + payload.len()];
        let mut pkt = MutableIpv6Packet::new(&mut buf).unwrap();
        pkt.set_version(6);
        pkt.set_payload_length(payload.len() as u16);
        pkt.set_next_header(pnet::packet::ip::IpNextHeaderProtocol(59)); // No Next Header
        pkt.set_hop_limit(64);
        pkt.set_source(src);
        pkt.set_destination(dst);
        pkt.set_payload(payload);
        buf
    }

    #[test]
    fn test_empty_packet() {
        let packet = Packet {
            data: &[],
            header: &pcap::PacketHeader {
                ts: Timestamp { tv_sec: 0, tv_usec: 0 },
                caplen: 0,
                len: 0,
            },
        };
        assert!(matches!(parse_fluereflow(packet), Err(NetError::EmptyPacket)));
    }

    #[test]
    fn test_unsupported_ethertype() {
        let payload = [0u8; 10]; // Dummy payload
        let eth_buf = create_ethernet_packet(EtherTypes::Loopback, &payload);
        let packet = Packet {
            data: &eth_buf,
            header: &pcap::PacketHeader {
                ts: Timestamp { tv_sec: 0, tv_usec: 0 },
                caplen: eth_buf.len() as u32,
                len: eth_buf.len() as u32,
            },
        };
        assert!(matches!(parse_fluereflow(packet), Err(NetError::UnknownEtherType(_))));
    }

    #[test]
    fn test_ipv4_fluere_record() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let payload = [1, 2, 3, 4]; // Example payload
        let ipv4_packet = create_ipv4_packet(src_ip, dst_ip, &payload);
        let eth_packet = create_ethernet_packet(EtherTypes::Ipv4, &ipv4_packet);

        let packet = Packet {
            data: &eth_packet,
            header: &pcap::PacketHeader {
                ts: Timestamp { tv_sec: 1_561_011_200, tv_usec: 0 },
                caplen: eth_packet.len() as u32,
                len: eth_packet.len() as u32,
            },
        };

        if let Ok((_, _, fluere_record)) = parse_fluereflow(packet) {
            assert_eq!(fluere_record.source, std::net::IpAddr::V4(src_ip));
            assert_eq!(fluere_record.destination, std::net::IpAddr::V4(dst_ip));
            // Add more assertions here based on the expected FluereRecord fields
        } else {
            panic!("Failed to parse IPv4 packet");
        }
    }

    #[test]
    fn test_ipv6_fluere_record() {
        let src_ip = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 0x1);
        let dst_ip = Ipv6Addr::new(0x2001, 0x0db8, 0x85a3, 0, 0, 0, 0, 0x2);
        let payload = [1, 2, 3, 4]; // Example payload
        let ipv6_packet = create_ipv6_packet(src_ip, dst_ip, &payload);
        let eth_packet = create_ethernet_packet(EtherTypes::Ipv6, &ipv6_packet);

        let packet = Packet {
            data: &eth_packet,
            header: &pcap::PacketHeader {
                ts: Timestamp { tv_sec: 1_561_011_200, tv_usec: 0 },
                caplen: eth_packet.len() as u32,
                len: eth_packet.len() as u32,
            },
        };

        if let Ok((_, _, fluere_record)) = parse_fluereflow(packet) {
            assert_eq!(fluere_record.source, std::net::IpAddr::V6(src_ip));
            assert_eq!(fluere_record.destination, std::net::IpAddr::V6(dst_ip));
            // Add more assertions here based on the expected FluereRecord fields
        } else {
            panic!("Failed to parse IPv6 packet");
        }
    }

    #[test]
    fn test_arp_fluere_record() {
        let src_ip = Ipv4Addr::new(192, 168, 1, 1);
        let dst_ip = Ipv4Addr::new(192, 168, 1, 2);
        let arp_packet = vec![0u8; 28]; // Example ARP packet
        let eth_packet = create_ethernet_packet(EtherTypes::Arp, &arp_packet);

        let packet = Packet {
            data: &eth_packet,
            header: &pcap::PacketHeader {
                ts: Timestamp { tv_sec: 1_561_011_200, tv_usec: 0 },
                caplen: eth_packet.len() as u32,
                len: eth_packet.len() as u32,
            },
        };

        if let Ok((_, _, fluere_record)) = parse_fluereflow(packet) {
            assert_eq!(fluere_record.source, std::net::IpAddr::V4(src_ip));
            assert_eq!(fluere_record.destination, std::net::IpAddr::V4(dst_ip));
            // Add more assertions here based on the expected FluereRecord fields
        } else {
            panic!("Failed to parse ARP packet");
        }
    }

    // Implement similar tests for VXLAN decapsulation.
}
