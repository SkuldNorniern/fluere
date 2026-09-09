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
/// How finely the capture this packet came from records time.
///
/// libpcap reports the sub-second field in whichever unit the file was opened
/// with, and says nothing about which. A nanosecond capture read as if it were
/// microseconds is a thousand times off, so the unit travels with the reader
/// that chose it rather than being guessed from the value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum CaptureResolution {
    #[default]
    Microseconds,
    Nanoseconds,
}

impl CaptureResolution {
    pub fn to_flow_resolution(self) -> fluereflow::TimeResolution {
        match self {
            CaptureResolution::Microseconds => fluereflow::TimeResolution::Microseconds,
            CaptureResolution::Nanoseconds => fluereflow::TimeResolution::Nanoseconds,
        }
    }
}

pub(super) fn packet_time(
    packet: &pcap::Packet,
    resolution: CaptureResolution,
) -> fluereflow::Timestamp {
    // A capture file stores its seconds unsigned and 32 bits wide, and libpcap
    // widens that into a signed `tv_sec` by sign extension. Every stamp from
    // 2038-01-19 on therefore arrives negative: `0x8000_0000` reads as
    // -2147483648. Casting that straight to `u64` made it an enormous positive
    // number that then overflowed the multiply, and rejecting it outright put
    // the packet at the epoch. Mask it back to the unsigned value it was
    // written as instead.
    //
    // A live capture's clock is a real `time_t` and stays positive, so it takes
    // the first branch and keeps its full range.
    let seconds = u64::try_from(packet.header.ts.tv_sec)
        .or_else(|_| u64::try_from(packet.header.ts.tv_sec & 0xFFFF_FFFF))
        .unwrap_or(0);
    let subsecond = u64::try_from(packet.header.ts.tv_usec).unwrap_or(0);

    match resolution {
        CaptureResolution::Microseconds => {
            fluereflow::Timestamp::from_micros(parse_microseconds(seconds, subsecond))
        }
        CaptureResolution::Nanoseconds => fluereflow::Timestamp::from_nanos(
            seconds
                .saturating_mul(1_000_000_000)
                .saturating_add(subsecond.min(999_999_999)),
        ),
    }
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
        let time = packet_time(
            &Packet::new(&header, &data),
            CaptureResolution::Microseconds,
        );

        assert_eq!(time.micros(), 7_000_008);
        assert_eq!(time.nanos(), 7_000_008_000);
    }

    /// The same field means nanoseconds in a capture opened that way, and
    /// reading it as microseconds would put the packet a thousand times too far
    /// into the second.
    #[test]
    fn a_nanosecond_capture_keeps_its_sub_microsecond_digits() {
        let data = [0u8; 4];
        let header = header(4, 4, 7, 8_000_500);
        let time = packet_time(&Packet::new(&header, &data), CaptureResolution::Nanoseconds);

        assert_eq!(time.nanos(), 7_008_000_500);
        // The same field read the other way would have been 7008000500000.
        assert_ne!(
            time.nanos(),
            packet_time(
                &Packet::new(&header, &data),
                CaptureResolution::Microseconds
            )
            .nanos()
        );
    }

    /// A capture file holds its seconds unsigned and 32 bits wide, and libpcap
    /// sign-extends that into `tv_sec`. Every stamp from 2038-01-19 on arrives
    /// negative, so the boundary has to stay continuous rather than wrapping to
    /// an enormous number or collapsing to the epoch.
    #[test]
    fn a_stamp_past_2038_keeps_its_time() {
        let data = [0u8; 4];
        // 0x7FFF_FFFF, then 0x8000_0000 as libpcap delivers it.
        let before = header(4, 4, 2_147_483_647, 0);
        let after = header(4, 4, -2_147_483_648, 0);

        assert_eq!(
            packet_time(
                &Packet::new(&before, &data),
                CaptureResolution::Microseconds
            )
            .micros(),
            2_147_483_647_000_000
        );
        assert_eq!(
            packet_time(&Packet::new(&after, &data), CaptureResolution::Microseconds).micros(),
            2_147_483_648_000_000
        );
    }

    /// The largest second a capture file can hold, delivered as -1.
    #[test]
    fn the_last_second_a_capture_file_can_hold_is_read_whole() {
        let data = [0u8; 4];
        let header = header(4, 4, -1, 0);

        assert_eq!(
            packet_time(
                &Packet::new(&header, &data),
                CaptureResolution::Microseconds
            )
            .micros(),
            4_294_967_295_000_000
        );
    }
}
