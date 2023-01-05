use super::types::C_Ipv4Packet;
use std::fs::File;
use std::time::{SystemTime, UNIX_EPOCH};
use pcap::{Capture, PacketHeader, Packet};

pub fn write_pcap(packets: Vec<C_Ipv4Packet>, file_name: &str) {
    let file = File::create(file_name).unwrap();
    let mut capture = Capture::dead(2048);
    capture.write_pcap_header().unwrap();
    for packet in packets {
        let packet_header = PacketHeader {
            ts_sec: packet.timestamp.duration_since(UNIX_EPOCH).unwrap().as_secs() as u32,
            ts_usec: packet.timestamp.timestamp_subsec_micros() as u32,
            incl_len: packet.data.len() as u32,
            orig_len: packet.data.len() as u32,
        };
        capture.write_packet(&packet_header, &packet.data).unwrap();
    }
}