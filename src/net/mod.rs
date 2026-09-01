pub mod capture;
pub mod capture_tui;
pub mod convert;
mod device;
mod flow_engine;
pub mod identity;
pub mod parser;
#[cfg(test)]
pub(crate) mod scenarios;
mod source;
pub mod types;
mod write_pcap;

pub use device::CaptureDevice;
pub use device::find_device;
pub use fluereflow::Flow;
pub use write_pcap::write_pcap;

use log::debug;

/// Decode one captured frame, skipping anything that cannot be parsed.
///
/// Shared by every capture mode so a frame is decoded exactly once and all
/// modes agree on what a malformed packet means.
pub(crate) fn observe_packet(
    packet: pcap::Packet<'_>,
    use_mac: bool,
    linktype: u16,
    state: &mut parser::ParserState,
) -> Option<parser::PacketObservation> {
    match parser::observe(packet, use_mac, linktype, state) {
        Ok(observation) => Some(observation),
        Err(error) => {
            debug!("Skipping unparsable packet: {error}");
            None
        }
    }
}
