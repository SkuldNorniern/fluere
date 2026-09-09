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

pub use fluereflows::CaptureResolution;
pub use fragments::FragmentTracker;
pub use keys::parse_keys;
pub use observation::{PacketObservation, ParserState, observe};
pub use quic::QuicTracker;
pub use time::parse_microseconds;
pub use time::unix_seconds_to_timestamp;
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
        // A transport protocol whose header did not survive the capture. The
        // ports are unknown, which is not the same as port 0.
        //
        // The innermost packet, not the outer one: a tunnel carrying TCP has
        // no transport of its own, and reading that as missing ports would
        // strip the ports off every tunnelled flow.
        6 | 17 if fluereflows::innermost(parsed).transport.is_none() => Endpoints::None,
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

/// Decode one captured frame with paccel, into a buffer the caller owns.
///
/// Every parser in this module works from the result of this single call, so a
/// frame is never decoded more than once on the capture path.
///
/// `out` is reset by the parser, so a reused buffer never carries a field over
/// from the packet before it. Reusing one is what keeps a parse from moving the
/// whole `ParsedPacket` per packet.
fn parse_frame_into(data: &[u8], linktype: u16, out: &mut ParsedPacket) -> Result<(), ParseError> {
    let config = ParseConfig {
        stop_after: StopLayer::Transport,
        ..Default::default()
    };

    // paccel refuses a linktype it does not know rather than guessing, which
    // is right for a parser but wrong for a capture tool: libpcap reports
    // whatever the interface says, and a link paccel has no case for is still
    // worth a look. Sniffing is the fallback, not the first choice.
    if BuiltinPacketParser::parse_into(data, config, Some(linktype), out).is_ok() {
        return Ok(());
    }
    BuiltinPacketParser::parse_into(data, config, None, out).map_err(ParseError::Unparsable)
}

#[cfg(test)]
mod linktype_tests {
    use super::parse_frame_into;
    use paccel::engine::ParsedPacket;

    /// An ethernet frame carrying IPv4/UDP.
    fn frame() -> Vec<u8> {
        let mut frame = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0x08, 0x00];
        frame.extend([0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 64, 17, 0, 0]);
        frame.extend([10, 0, 0, 1, 10, 0, 0, 2]);
        frame.extend([0x04, 0xd2, 0x00, 0x35, 0x00, 0x08, 0x00, 0x00]);
        frame
    }

    /// paccel 0.4 refuses a linktype it has no case for rather than guessing.
    /// libpcap reports whatever the interface says, so a capture on such a
    /// link would otherwise yield no flows at all.
    #[test]
    fn an_unknown_linktype_still_parses() {
        let mut parsed = ParsedPacket::default();
        // 9 is LINKTYPE_PPP, which paccel has no case for.
        assert!(parse_frame_into(&frame(), 9, &mut parsed).is_ok());
        assert!(parsed.ipv4.is_some(), "the fallback sniffed the frame");
    }

    #[test]
    fn a_known_linktype_is_used_as_given() {
        let mut parsed = ParsedPacket::default();
        assert!(parse_frame_into(&frame(), 1, &mut parsed).is_ok());
        assert_eq!(
            parsed.ipv4.expect("addresses").source.to_string(),
            "10.0.0.1"
        );
    }

    /// The fallback is a fallback: bytes that are not a frame under either
    /// reading are still refused.
    #[test]
    fn nonsense_is_still_refused() {
        let mut parsed = ParsedPacket::default();
        assert!(parse_frame_into(&[0, 1, 2], 9, &mut parsed).is_err());
    }
}
