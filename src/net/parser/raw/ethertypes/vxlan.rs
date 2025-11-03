use crate::net::parser::raw::RawProtocolHeader;
use log::{debug, trace, warn};

// VXLAN header format (RFC 7348)
const VXLAN_HEADER: [u8; 8] = [0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x64, 0x00];
const VXLAN_PORT: u16 = 4789;

pub fn parse_vxlan(payload: &[u8]) -> Option<RawProtocolHeader> {
    trace!("Attempting to parse VXLAN packet");

    if payload.len() < VXLAN_HEADER.len() {
        warn!("VXLAN packet too short: {} bytes", payload.len());
        return None;
    }

    // VXLAN Header Format (RFC 7348):
    // 0                   1                   2                   3
    // 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |R|R|R|R|I|R|R|R|            Reserved                           |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |                VXLAN Network Identifier (VNI) |   Reserved     |
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    if !payload.starts_with(&VXLAN_HEADER) {
        debug!("Packet does not start with VXLAN header");
        return None;
    }

    trace!("Found valid VXLAN header");

    let vni = ((payload[4] as u32) << 16) | ((payload[5] as u32) << 8) | payload[6] as u32;

    debug!("Parsed VXLAN VNI: {}", vni);

    let inner_payload = payload[VXLAN_HEADER.len()..].to_vec();
    trace!("Extracted inner payload of {} bytes", inner_payload.len());

    Some(RawProtocolHeader::new(
        None,
        None,
        VXLAN_PORT,
        vni as u16,
        0x12, // VXLAN protocol identifier
        payload.len() as u16,
        Some(inner_payload),
    ))
}
