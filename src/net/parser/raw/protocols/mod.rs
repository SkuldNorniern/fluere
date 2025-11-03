mod ah;
mod bgp;
mod eigrp;
mod esp;
mod gre;
mod icmp;
mod igmp;
mod ipx;
mod isis;
mod l2tp;
mod ospf;
mod pim;
mod sctp;
mod vrrp;
mod openvpn;

use super::RawProtocolHeader;

pub use icmp::IcmpParser;
pub use openvpn::OpenVpnParser;

pub trait ProtocolParser {
    /// Parse a protocol packet and return a RawProtocolHeader if successful
    ///
    /// # Arguments
    /// * `payload` - The packet payload to parse
    /// * `protocol_number` - The protocol number (e.g., 6 for TCP, 17 for UDP)
    fn parse_packet(payload: &[u8], protocol_number: u8) -> Option<RawProtocolHeader>;

    /// Get the protocol number this parser handles
    fn protocol_number() -> u8;

    /// Add default methods for common parsing tasks
    fn validate_length(payload: &[u8], min_length: usize) -> bool {
        payload.len() >= min_length
    }

    fn parse_header_length(payload: &[u8], offset: usize) -> Option<u16> {
        if payload.len() >= offset + 2 {
            Some(u16::from_be_bytes([payload[offset], payload[offset + 1]]))
        } else {
            None
        }
    }
}

// Update the parse_protocol function to use the trait
pub fn parse_protocol(packet: &[u8], protocol: u8) -> Option<RawProtocolHeader> {
    // First, try all known IANA-assigned protocol numbers
    let header = match protocol {
        // 0x1D => IpxParser::parse_packet(packet, protocol),
        1    => IcmpParser::parse_packet(packet, protocol),
        // 2    => IgmpParser::parse_packet(packet, protocol),
        // 47   => GreParser::parse_packet(packet, protocol),
        // 50   => EspParser::parse_packet(packet, protocol),
        // 51   => AhParser::parse_packet(packet, protocol),
        // 89   => OspfParser::parse_packet(packet, protocol),
        // 103  => PimParser::parse_packet(packet, protocol),
        // 112  => VrrpParser::parse_packet(packet, protocol),
        // 115  => l2tp::parse_l2tp(packet),
        // 124  => isis::parse_isis(packet),
        // 132  => SctpParser::parse_packet(packet, protocol),
        // 179  => bgp::parse_bgp(packet),
        // For non-IANA protocols we reserve a range. For example, OpenVPN is internally mapped
        // to protocol numbers 170‒172. If the number appears in that range, use the OpenVPN parser.
        n if (170..=172).contains(&n) => OpenVpnParser::parse_packet(packet, protocol),
        _ => None,
    };

    // If a match was found, immediately return it.
    if header.is_some() {
        return header;
    }

    // Fallback: Some protocols (like OpenVPN) don't have standardized protocol numbers.
    // In case OpenVPN (or another non-IANA protocol) gets encoded outside its expected range,
    // try to parse the packet using its parser as a heuristic.
    if let Some(openvpn_header) = OpenVpnParser::parse_packet(packet, protocol) {
        return Some(openvpn_header);
    }

    // Future fallback: Add additional non-IANA protocol parsers here as needed.
    None
}
