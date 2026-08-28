mod expiry;
mod fluereflows;
mod fragments;
mod keys;
mod observation;
mod properties;
mod quic;
mod raw;
mod time;
mod tos;

pub use fragments::FragmentTracker;
pub use keys::parse_keys;
pub use observation::{PacketObservation, ParserState, observe};
pub use quic::QuicTracker;
pub use time::unix_seconds_to_timestamp;
pub use time::parse_microseconds;
pub use tos::dscp_to_tos;

use crate::error::ParseError;
use fluereflow::Endpoints;
use paccel::engine::{BuiltinPacketParser, ParseConfig, ParsedPacket, StopLayer};

/// Ports fluere reports for protocols that carry none of their own.
///
/// What identifies this packet's endpoints.
///
/// Most protocols report transport ports. The ones that do not are named for
/// what they actually carry: an IPsec association by its SPI, an undecodable
/// GRE tunnel by the protocol it was carrying.
///
/// ICMP is deliberately absent. Its type and code identify a direction rather
/// than an endpoint, so keying on them would make an echo request and its reply
/// two flows instead of the two directions of one. They are recorded as a
/// measurement on the flow record instead.
fn endpoints_of(parsed: &ParsedPacket, protocol: u8, ports: (u16, u16)) -> Endpoints {
    match protocol {
        // IPsec associations are one-way by design: the return traffic carries
        // a different SPI and is a separate flow.
        50 => parsed.esp.as_ref().map_or(Endpoints::None, |esp| {
            Endpoints::SecurityAssociation(esp.spi)
        }),
        51 => parsed
            .ah
            .as_ref()
            .map_or(Endpoints::None, |ah| Endpoints::SecurityAssociation(ah.spi)),
        // SCTP has real ports; they just do not arrive through
        // `TransportSegment`, which only covers TCP and UDP.
        132 => parsed
            .sctp
            .as_ref()
            .map_or(Endpoints::None, |sctp| Endpoints::Ports {
                source: sctp.source_port,
                destination: sctp.destination_port,
            }),
        // Only meaningful when there is no decoded inner flow; a decoded tunnel
        // reports the inner protocol instead.
        47 => parsed.gre.as_ref().map_or(Endpoints::None, |gre| {
            Endpoints::GreProtocol(gre.protocol_type)
        }),
        // None of these have endpoints of their own: 0 is traffic with no IP
        // protocol number at all, such as ARP; ICMP identifies a direction by
        // type and code, which the record carries; and a key of 4 means an
        // IP-in-IP tunnel whose inner flow could not be decoded, so there is
        // nothing below it to read ports from.
        0 | 1 | 4 | 58 => Endpoints::None,
        _ => Endpoints::Ports {
            source: ports.0,
            destination: ports.1,
        },
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
