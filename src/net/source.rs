//! One interpretation of a capture read, shared by every mode.
//!
//! libpcap reports "nothing arrived before the timeout", "the file is finished"
//! and "the capture is broken" through the same `Result`. Each capture mode
//! used to interpret that itself, and each did it differently: live capture
//! treated every error as a retry, which turned a permanent failure into a busy
//! loop; raw pcap writing treated a routine timeout as a fatal error; offline
//! conversion treated a read failure as end of file, so a damaged capture
//! produced partial output and still reported success.

use pcap::{Activated, Capture, Packet};

/// What one read produced.
pub enum Read<'a> {
    /// A packet, ready to decode.
    Packet(Packet<'a>),
    /// Nothing arrived before the read timed out. Normal on a quiet interface,
    /// and the moment to check whether the capture should stop.
    Timeout,
    /// The capture is finished. A file has no more packets in it.
    Eof,
    /// The capture cannot continue. Retrying would spin.
    Fatal(pcap::Error),
}

/// Read one packet, saying which of the four things happened.
pub fn read<T: Activated + ?Sized>(capture: &mut Capture<T>) -> Read<'_> {
    match capture.next_packet() {
        Ok(packet) => Read::Packet(packet),
        Err(pcap::Error::TimeoutExpired) => Read::Timeout,
        Err(pcap::Error::NoMorePackets) => Read::Eof,
        // A live capture with no reader attached also reports this, and it is
        // not fatal there; treating it as a timeout keeps the loop polling
        // rather than ending the capture.
        Err(pcap::Error::NonNonBlock) => Read::Timeout,
        Err(error) => Read::Fatal(error),
    }
}
