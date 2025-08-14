use super::super::RawProtocolHeader;
use log::{debug, info, trace, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// Constants for VPN protocols
const VPN_DATA_PORT: u16 = 2186; // SFTP/VPN data port
const VPN_CONTROL_PORT: u16 = 19301; // VPN control channel port
const VPN_DATA_PROTOCOL: u8 = 21; // FTP/SFTP protocol
const VPN_CONTROL_PROTOCOL: u8 = 22; // SSH/Control protocol

// VPN packet structure constants
const MIN_HEADER_SIZE: usize = 4; // Reduced from 8 to match actual packet structure
const IP_HEADER_OFFSET: usize = 8; // Typical offset where IP header might start
const MIN_IP_HEADER_SIZE: usize = 20; // Minimum size of IPv4 header

pub(crate) fn parse_vpn_data(payload: &[u8]) -> Option<RawProtocolHeader> {
    trace!("Parsing VPN data channel packet (0x0A08)");
    if payload.len() < MIN_HEADER_SIZE {
        warn!("VPN data packet too short: {} bytes", payload.len());
        return None;
    }

    // Extract version and flags
    let version = payload[0];
    let flags = payload[1];

    // Try to extract IP addresses from the encapsulated payload
    let (src_ip, dst_ip) = extract_ip_addresses(&payload[MIN_HEADER_SIZE..]);

    debug!(
        "VPN data packet - Version: {}, Flags: 0x{:02x}, Length: {}, SrcIP: {:?}, DstIP: {:?}",
        version,
        flags,
        payload.len(),
        src_ip,
        dst_ip
    );

    // Extract sequence number if present
    let seq_num = if payload.len() >= 4 {
        ((payload[2] as u16) << 8) | payload[3] as u16
    } else {
        0
    };

    trace!(
        "Creating VPN data channel header for SFTP traffic - Seq: {}",
        seq_num
    );

    Some(RawProtocolHeader::new(
        src_ip, // Now passing extracted source IP
        dst_ip, // Now passing extracted destination IP
        VPN_DATA_PORT,
        seq_num, // Use sequence number as destination port for tracking
        VPN_DATA_PROTOCOL,
        payload.len() as u16,
        Some(payload[MIN_HEADER_SIZE..].to_vec()),
    ))
}

pub(crate) fn parse_vpn_control(payload: &[u8]) -> Option<RawProtocolHeader> {
    trace!("Parsing VPN control channel packet (0x4B65)");
    if payload.len() < MIN_HEADER_SIZE {
        warn!("VPN control packet too short: {} bytes", payload.len());
        return None;
    }

    // Extract control packet type and flags
    let packet_type = payload[0];
    let flags = payload[1];

    // Try to extract IP addresses from the encapsulated payload
    let (src_ip, dst_ip) = extract_ip_addresses(&payload[MIN_HEADER_SIZE..]);

    debug!(
        "VPN control packet - Type: 0x{:02x}, Flags: 0x{:02x}, Length: {}, SrcIP: {:?}, DstIP: {:?}",
        packet_type,
        flags,
        payload.len(),
        src_ip,
        dst_ip
    );

    // Extract message ID if present
    let msg_id = if payload.len() >= 4 {
        ((payload[2] as u16) << 8) | payload[3] as u16
    } else {
        0
    };

    info!("Creating VPN control channel header - MsgID: {}", msg_id);

    Some(RawProtocolHeader::new(
        src_ip, // Now passing extracted source IP
        dst_ip, // Now passing extracted destination IP
        VPN_CONTROL_PORT,
        msg_id, // Use message ID as destination port for tracking
        VPN_CONTROL_PROTOCOL,
        payload.len() as u16,
        Some(payload[MIN_HEADER_SIZE..].to_vec()),
    ))
}

// Helper function to check if a packet might be encapsulated
pub(crate) fn is_vpn_packet(ethertype: u16) -> bool {
    matches!(ethertype, 0x0A08 | 0x4B65)
}

// Helper function to get protocol name
pub(crate) fn get_vpn_protocol_name(ethertype: u16) -> &'static str {
    match ethertype {
        0x0A08 => "VPN Data Channel (SFTP)",
        0x4B65 => "VPN Control Channel",
        _ => "Unknown VPN Protocol",
    }
}

// Helper function to dump packet details for debugging
#[cfg(debug_assertions)]
fn dump_packet_details(payload: &[u8], prefix: &str) {
    debug!("{} packet dump:", prefix);
    for (i, chunk) in payload.chunks(16).enumerate() {
        let hex = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");
        debug!("[{:04x}] {}", i * 16, hex);
    }
}

// Helper function to try extracting IP addresses from payload
fn extract_ip_addresses(payload: &[u8]) -> (Option<IpAddr>, Option<IpAddr>) {
    if payload.len() < MIN_IP_HEADER_SIZE {
        return (None, None);
    }

    // Check for IPv4 header (Version should be 4 in first 4 bits)
    if (payload[0] >> 4) == 4 {
        let src_ip = IpAddr::V4(Ipv4Addr::new(
            payload[12],
            payload[13],
            payload[14],
            payload[15],
        ));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(
            payload[16],
            payload[17],
            payload[18],
            payload[19],
        ));

        trace!("Found IPv4 addresses - Src: {}, Dst: {}", src_ip, dst_ip);
        return (Some(src_ip), Some(dst_ip));
    }

    // Check for IPv6 (Version should be 6 in first 4 bits)
    if (payload[0] >> 4) == 6 && payload.len() >= 40 {
        let src_ip = IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([payload[8], payload[9]]),
            u16::from_be_bytes([payload[10], payload[11]]),
            u16::from_be_bytes([payload[12], payload[13]]),
            u16::from_be_bytes([payload[14], payload[15]]),
            u16::from_be_bytes([payload[16], payload[17]]),
            u16::from_be_bytes([payload[18], payload[19]]),
            u16::from_be_bytes([payload[20], payload[21]]),
            u16::from_be_bytes([payload[22], payload[23]]),
        ));
        let dst_ip = IpAddr::V6(Ipv6Addr::new(
            u16::from_be_bytes([payload[24], payload[25]]),
            u16::from_be_bytes([payload[26], payload[27]]),
            u16::from_be_bytes([payload[28], payload[29]]),
            u16::from_be_bytes([payload[30], payload[31]]),
            u16::from_be_bytes([payload[32], payload[33]]),
            u16::from_be_bytes([payload[34], payload[35]]),
            u16::from_be_bytes([payload[36], payload[37]]),
            u16::from_be_bytes([payload[38], payload[39]]),
        ));

        trace!("Found IPv6 addresses - Src: {}, Dst: {}", src_ip, dst_ip);
        return (Some(src_ip), Some(dst_ip));
    }

    (None, None)
}
