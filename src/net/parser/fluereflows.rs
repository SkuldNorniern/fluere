use crate::net::parser::parse_microseconds;

use paccel::engine::ParsedPacket;

/// Return the deepest packet decoded by paccel.
///
/// Flow records intentionally describe the innermost traffic for every tunnel
/// paccel understands, so VXLAN, GRE, GENEVE, MPLS, and IP-in-IP flows use the
/// real inner IP and transport fields rather than their encapsulating headers.
pub(super) fn innermost(parsed: &ParsedPacket) -> &ParsedPacket {
    match parsed.inner.as_deref() {
        Some(inner) => innermost(inner),
        None => parsed,
    }
}

/// The frame's length on the wire.
///
/// `data` is only what the snaplen let through; `header.len` is what was
/// actually on the wire, so counting captured bytes would under-report traffic.
/// Sources that do not report a wire length send 0, so fall back to what was
/// captured.
pub(super) fn wire_length(packet: &pcap::Packet) -> usize {
    if packet.header.len > 0 {
        packet.header.len as usize
    } else {
        packet.data.len()
    }
}

/// The capture timestamp.
///
/// libpcap reports microseconds, which the model widens to nanoseconds while
/// recording that microseconds is all the source could resolve.
pub(super) fn packet_time(packet: &pcap::Packet) -> fluereflow::Timestamp {
    fluereflow::Timestamp::from_micros(parse_microseconds(
        packet.header.ts.tv_sec as u64,
        packet.header.ts.tv_usec as u64,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::{Packet, PacketHeader};

    fn header(captured: u32, wire: u32, sec: i64, usec: i64) -> PacketHeader {
        PacketHeader {
            ts: libc::timeval {
                tv_sec: sec as _,
                tv_usec: usec as _,
            },
            caplen: captured,
            len: wire,
        }
    }

    /// A short snaplen leaves the wire length in the header, which is what
    /// byte accounting must use, because counting captured bytes under-reports.
    #[test]
    fn wire_length_is_what_was_on_the_wire() {
        let data = [0u8; 64];
        let header = header(64, 1_500, 1, 0);
        assert_eq!(wire_length(&Packet::new(&header, &data)), 1_500);
    }

    /// Some sources report no wire length at all.
    #[test]
    fn wire_length_falls_back_to_what_was_captured() {
        let data = [0u8; 64];
        let header = header(64, 0, 1, 0);
        assert_eq!(wire_length(&Packet::new(&header, &data)), 64);
    }

    #[test]
    fn a_microsecond_capture_widens_to_nanoseconds() {
        let data = [0u8; 4];
        let header = header(4, 4, 7, 8);
        let time = packet_time(&Packet::new(&header, &data));

        assert_eq!(time.micros(), 7_000_008);
        assert_eq!(time.nanos(), 7_000_008_000);
    }
}
