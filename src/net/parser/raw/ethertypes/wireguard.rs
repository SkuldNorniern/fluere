use super::super::RawProtocolHeader;
use log::{debug, trace};

const WIREGUARD_PORT: u16 = 51820; // Default WireGuard port

// WireGuard message types
const MESSAGE_HANDSHAKE_INITIATION: u8 = 1;
const MESSAGE_HANDSHAKE_RESPONSE: u8 = 2;
const MESSAGE_HANDSHAKE_COOKIE: u8 = 3;
const MESSAGE_DATA: u8 = 4;

pub fn parse_wireguard(payload: &[u8]) -> Option<RawProtocolHeader> {
    if payload.len() < 4 {
        trace!("Payload too short for WireGuard packet");
        return None;
    }

    let message_type = payload[0];
    let length = payload.len() as u16;

    // Create base header with common fields
    let mut header = RawProtocolHeader::new(
        None,           // src_ip
        None,           // dst_ip
        0,              // src_port will be set if available
        WIREGUARD_PORT, // dst_port (default WireGuard port)
        message_type,   // protocol
        length,         // packet length
        Some(payload.to_vec()),
    );

    match message_type {
        MESSAGE_HANDSHAKE_INITIATION => {
            debug!("WireGuard: Handshake Initiation message");
            // Handshake initiation is 148 bytes
            if payload.len() != 148 {
                trace!("Invalid handshake initiation length");
                return None;
            }
            header = header.with_flags(1); // Mark as handshake packet
        }
        MESSAGE_HANDSHAKE_RESPONSE => {
            debug!("WireGuard: Handshake Response message");
            // Handshake response is 92 bytes
            if payload.len() != 92 {
                trace!("Invalid handshake response length");
                return None;
            }
            header = header.with_flags(2); // Mark as response packet
        }
        MESSAGE_HANDSHAKE_COOKIE => {
            debug!("WireGuard: Handshake Cookie message");
            // Cookie message is 64 bytes
            if payload.len() != 64 {
                trace!("Invalid cookie message length");
                return None;
            }
            header = header.with_flags(3); // Mark as cookie packet
        }
        MESSAGE_DATA => {
            debug!("WireGuard: Data message");
            // Data message minimum size is 16 bytes
            if payload.len() < 16 {
                trace!("Invalid data message length");
                return None;
            }
            header = header.with_flags(4); // Mark as data packet
        }
        _ => {
            trace!("Unknown WireGuard message type: {}", message_type);
            return None;
        }
    }

    // Add WireGuard-specific metadata
    header = header
        .with_version(1) // WireGuard protocol version 1
        .with_ethertype(0x88B8); // WireGuard ethertype

    Some(header)
}

pub fn is_wireguard_packet(ethertype: u16) -> bool {
    ethertype == 0x88B8 // WireGuard's assigned ethertype
}
