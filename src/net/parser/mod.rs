mod fluereflows;
mod fragments;
mod keys;
mod observation;
mod raw;
mod time;
mod tos;

pub use fluereflows::parse_fluereflow;
pub use fragments::FragmentTracker;
pub use keys::parse_keys;
pub use observation::{PacketObservation, observe};
pub use time::microseconds_to_timestamp;
pub use time::parse_microseconds;
pub use tos::dscp_to_tos;

use crate::error::ParseError;
use paccel::engine::{BuiltinPacketParser, ParseConfig, ParsedPacket, StopLayer};

/// Ports fluere reports for protocols that carry none of their own.
///
/// SCTP reports the ports paccel does not surface through `TransportSegment`,
/// and a GRE tunnel whose inner flow could not be decoded reports its inner
/// protocol type. Both the flow key and the flow record read this, so a flow
/// cannot be keyed one way and reported another.
///
/// ICMP is deliberately absent. Its type and code identify a direction rather
/// than an endpoint, so putting them here would make an echo request and its
/// reply two flows instead of the two directions of one. They belong in a typed
/// endpoint field, which the record does not have yet.
fn pseudo_ports(parsed: &ParsedPacket, protocol: u8) -> Option<(u16, u16)> {
    match protocol {
        // An IPsec SPI names the security association a packet belongs to, so
        // it discriminates flows the way a port pair does. It is per-direction
        // by design: the return traffic of an SA carries a different SPI and is
        // a separate flow, which is what IPsec means by a one-way association.
        50 => parsed.esp.as_ref().map(|esp| split_spi(esp.spi)),
        51 => parsed.ah.as_ref().map(|ah| split_spi(ah.spi)),
        // SCTP has real ports; they just do not arrive through
        // `TransportSegment`, which only covers TCP and UDP.
        132 => parsed
            .sctp
            .as_ref()
            .map(|sctp| (sctp.source_port, sctp.destination_port)),
        // Only meaningful when there is no decoded inner flow; a decoded
        // tunnel reports the inner protocol instead.
        47 => parsed.gre.as_ref().map(|gre| (gre.protocol_type, 0)),
        _ => None,
    }
}

/// Spread a 32-bit SPI across the two 16-bit slots the record has.
///
/// Both halves are needed to tell two associations apart, and the record has
/// nowhere else to put them yet.
fn split_spi(spi: u32) -> (u16, u16) {
    ((spi >> 16) as u16, (spi & 0xFFFF) as u16)
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
