mod arp;
mod mpls;
mod vpn;
mod vxlan;
mod wireguard;

use log::{debug, trace, warn};

pub trait EtherTypeParser {
    /// Parse a packet for a specific EtherType
    fn parse_packet(&self, packet: &[u8]) -> Option<super::RawProtocolHeader>;

    /// Check if this parser can handle the given EtherType
    fn can_parse(&self, ethertype: u16) -> bool;

    /// Get the name of the protocol
    fn protocol_name(&self) -> &'static str;
}

pub fn parse_ethertype(packet: &[u8], ethertype: u16) -> Option<super::RawProtocolHeader> {
    trace!("Attempting to parse ethertype: 0x{:04x}", ethertype);

    // Add packet dump for debugging unknown types
    if !is_known_ethertype(ethertype) {
        debug!("Unknown EtherType: 0x{:04x}", ethertype);
        dump_packet_details(packet, "Unknown EtherType");
    }

    if vpn::is_vpn_packet(ethertype) {
        debug!(
            "Detected {} (0x{:04x})",
            vpn::get_vpn_protocol_name(ethertype),
            ethertype
        );
        match ethertype {
            0x0A08 => vpn::parse_vpn_data(packet),
            0x4B65 => vpn::parse_vpn_control(packet),
            _ => None,
        }
    } else {
        match ethertype {
            0x0806 => arp::parse_arp(packet),
            //0x8847 | 0x8848 => mpls::parse_mpls(packet),
            // 0x12B5 => vxlan::parse_vxlan(packet),
            // 0x88B8 => wireguard::parse_wireguard(packet),
            // Add common experimental/vendor-specific ranges
            0xB800..=0xBFFF => {
                debug!("Experimental ethertype: 0x{:04x}", ethertype);
                parse_custom_protocol(packet)
            }
            0x3600..=0x36FF => {
                debug!("Vendor-specific ethertype: 0x{:04x}", ethertype);
                parse_custom_protocol(packet)
            }
            _ => {
                trace!("Unhandled ethertype: 0x{:04x}", ethertype);
                None
            }
        }
    }
}

// Helper function to identify known ethertypes
fn is_known_ethertype(ethertype: u16) -> bool {
    matches!(
        ethertype,
        0x0806 | // ARP
        0x8847 | 0x8848 | // MPLS
        0x12B5 | // VXLAN
        0x88B8 | // WireGuard
        0x0A08 | // VPN Data
        0x4B65 // VPN Control
    )
}

// Move dump_packet_details to mod.rs since it's useful for all ethertype parsers
pub(crate) fn dump_packet_details(packet: &[u8], prefix: &str) {
    debug!("{} packet dump:", prefix);
    debug!("Packet length: {} bytes", packet.len());

    // Print first few bytes as potential header
    if packet.len() >= 4 {
        debug!(
            "Potential header: {:02x} {:02x} {:02x} {:02x}",
            packet[0], packet[1], packet[2], packet[3]
        );
    }

    // Full packet dump in chunks
    for (i, chunk) in packet.chunks(16).enumerate() {
        let hex = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ");

        // Also show ASCII representation where possible
        let ascii: String = chunk
            .iter()
            .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
            .collect();

        debug!("[{:04x}] {:<48} {}", i * 16, hex, ascii);
    }
}

fn parse_custom_protocol(packet: &[u8]) -> Option<super::RawProtocolHeader> {
    if packet.len() < 4 {
        warn!("Custom protocol packet too short: {} bytes", packet.len());
        dump_packet_details(packet, "Short custom protocol packet");
        return None;
    }

    // First try to identify if this is a header-only packet or contains payload
    let (header_size, has_payload) = analyze_packet_structure(packet);

    // Extract the payload if it exists
    let payload = if has_payload && packet.len() > header_size {
        Some(packet[header_size..].to_vec())
    } else {
        None
    };

    // Create header with the packet information
    Some(super::RawProtocolHeader::new(
        None,
        None,
        ((packet[0] as u16) << 8) | packet[1] as u16, // First two bytes often indicate source
        ((packet[2] as u16) << 8) | packet[3] as u16, // Next two bytes often indicate destination
        packet[0],                                    // First byte might indicate protocol type
        packet.len() as u16,
        payload,
    ))
}

fn analyze_packet_structure(packet: &[u8]) -> (usize, bool) {
    // Common packet patterns analysis
    match packet[0] {
        // Check for common header patterns
        0xB8..=0xBF => {
            debug!("Possible experimental protocol header");
            (8, true) // 8-byte header with payload
        }
        0x36..=0x37 => {
            debug!("Possible vendor-specific protocol header");
            (6, true) // 6-byte header with payload
        }
        0x6C => {
            debug!("Possible custom encapsulation protocol");
            (4, true) // 4-byte header with payload
        }
        _ => {
            // Default assumption: 4-byte header, rest is payload
            debug!("Unknown protocol structure, using default parsing");
            dump_packet_details(packet, "Unknown protocol structure");
            (4, packet.len() > 4)
        }
    }
}
