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
