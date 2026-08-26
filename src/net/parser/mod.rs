mod fluereflows;
mod keys;
mod observation;
mod raw;
mod time;
mod tos;

pub use fluereflows::parse_fluereflow;
pub use keys::parse_keys;
pub use observation::{PacketObservation, observe};
pub use time::microseconds_to_timestamp;
pub use time::parse_microseconds;
pub use tos::dscp_to_tos;

use crate::error::ParseError;
use paccel::engine::{BuiltinPacketParser, ParseConfig, ParsedPacket, StopLayer};

/// Ports fluere reports for protocols that carry none of their own.
///
/// ICMPv6 puts its type and code in the port slots, and a GRE tunnel whose
/// inner flow paccel could not decode reports its inner protocol type. Both the
/// flow key and the flow record read this, so a flow cannot be keyed one way
/// and reported another.
fn pseudo_ports(parsed: &ParsedPacket, protocol: u8) -> Option<(u16, u16)> {
    match protocol {
        // SCTP has real ports; they just do not arrive through
        // `TransportSegment`, which only covers TCP and UDP.
        132 => parsed
            .sctp
            .as_ref()
            .map(|sctp| (sctp.source_port, sctp.destination_port)),
        58 => parsed
            .icmpv6
            .as_ref()
            .map(|icmpv6| (u16::from(icmpv6.icmp_type), u16::from(icmpv6.icmp_code))),
        // Only meaningful when there is no decoded inner flow; a decoded
        // tunnel reports the inner protocol instead.
        47 => parsed.gre.as_ref().map(|gre| (gre.protocol_type, 0)),
        _ => None,
    }
}

/// Decode one captured frame with paccel.
///
/// Every parser in this module works from the result of this single call, so a
/// frame is never decoded more than once on the capture path.
fn parse_frame(data: &[u8], linktype: u16) -> Result<ParsedPacket, ParseError> {
    let config = ParseConfig {
        stop_after: StopLayer::Transport,
        ..Default::default()
    };

    BuiltinPacketParser::parse_with_config_and_linktype(data, config, Some(linktype))
        .map_err(|_| ParseError::InvalidPacket)
}
