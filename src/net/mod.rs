mod capture;
mod flow;
mod flow_engine;
mod flows;
pub mod live_fluereflow;
mod offline_fluereflows;
pub mod online_fluereflow;
mod packet_pcap;
pub mod parser;
#[cfg(test)]
mod scenarios;
pub mod types;

pub use capture::CaptureDevice;
pub use capture::find_device;
pub use flow::Flow;
pub use offline_fluereflows::fluereflow_fileparse;
pub use packet_pcap::pcap_capture;

use log::debug;

/// Decode one captured frame, skipping anything that cannot be parsed.
///
/// Shared by every capture mode so a frame is decoded exactly once and all
/// modes agree on what a malformed packet means.
pub(crate) fn observe_packet(
    packet: pcap::Packet<'_>,
    use_mac: bool,
    linktype: u16,
    fragments: &mut parser::FragmentTracker,
) -> Option<parser::PacketObservation> {
    match parser::observe(packet, use_mac, linktype, fragments) {
        Ok(observation) => Some(observation),
        Err(error) => {
            debug!("Skipping unparsable packet: {}", error);
            None
        }
    }
}
