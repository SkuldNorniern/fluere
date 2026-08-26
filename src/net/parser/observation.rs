use pcap::Packet;

use crate::error::ParseError;
use crate::net::types::{Key, TcpFlags};
use fluereflow::FluereRecord;

use super::fluereflows::{packet_time, record_from_parsed, wire_length};
use super::keys::keys_from_parsed;

/// Everything one captured frame contributes to a flow.
///
/// Produced by a single decode of the frame: the flow keys and the opening
/// record both come from the same parse, rather than each parser decoding the
/// packet again for itself.
#[derive(Debug, Clone, Copy)]
pub struct PacketObservation {
    /// Flow key in the direction this packet travelled.
    pub key: Key,
    /// The same flow key with source and destination swapped.
    pub reverse_key: Key,
    /// A flow's opening state, with every aggregate counter still at zero.
    pub record: FluereRecord,
    /// The frame's length on the wire.
    pub doctets: usize,
    /// TCP flags seen on this packet.
    pub flags: TcpFlags,
    /// Capture timestamp, in microseconds since the epoch.
    pub packet_time: u64,
}

/// Decode one captured frame into the pieces the flow engine needs.
///
/// `use_mac` keeps MAC addresses in the flow key; without it the keys are
/// zeroed so that traffic between the same endpoints stays one flow regardless
/// of the link-layer hops it took.
pub fn observe(
    packet: Packet<'_>,
    use_mac: bool,
    linktype: u16,
) -> Result<PacketObservation, ParseError> {
    if packet.is_empty() {
        return Err(ParseError::EmptyPacket);
    }

    let parsed = super::parse_frame(packet.data, linktype)?;

    let (mut key, mut reverse_key) = keys_from_parsed(&parsed, packet.data)?;
    if !use_mac {
        key.mac_defaultate();
        reverse_key.mac_defaultate();
    }

    let packet_time = packet_time(&packet);
    let (doctets, raw_flags, record) =
        record_from_parsed(&parsed, packet.data, wire_length(&packet), packet_time)?;

    Ok(PacketObservation {
        key,
        reverse_key,
        record,
        doctets,
        flags: TcpFlags::new(raw_flags),
        packet_time,
    })
}

#[cfg(test)]
mod tests {
    use pcap::PacketHeader;

    use super::observe;
    use crate::net::parser::{parse_fluereflow, parse_keys};

    const SRC_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const DST_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn tcp_frame() -> Vec<u8> {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        frame.extend_from_slice(&[0x45, 0x28]);
        frame.extend_from_slice(&40u16.to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 42, 6, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 1]);
        frame.extend_from_slice(&[198, 51, 100, 2]);

        frame.extend_from_slice(&12_345u16.to_be_bytes());
        frame.extend_from_slice(&443u16.to_be_bytes());
        frame.extend_from_slice(&[0; 8]);
        frame.extend_from_slice(&[0x50, 0x02, 0x20, 0x00, 0, 0, 0, 0]);
        frame
    }

    fn header(frame: &[u8]) -> PacketHeader {
        PacketHeader {
            ts: libc::timeval {
                tv_sec: 7,
                tv_usec: 8,
            },
            caplen: frame.len() as u32,
            len: frame.len() as u32,
        }
    }

    /// One decode has to produce exactly what the two standalone parsers did.
    #[test]
    fn matches_the_standalone_parsers() {
        let frame = tcp_frame();
        let header = header(&frame);

        let observation = observe(pcap::Packet::new(&header, &frame), true, 1).expect("observed");

        let (key, reverse_key) =
            parse_keys(pcap::Packet::new(&header, &frame), 1).expect("keys parse");
        let (doctets, raw_flags, record) =
            parse_fluereflow(pcap::Packet::new(&header, &frame), 1).expect("record parses");

        assert_eq!(observation.key, key);
        assert_eq!(observation.reverse_key, reverse_key);
        assert_eq!(observation.record, record);
        assert_eq!(observation.doctets, doctets);
        assert_eq!(observation.flags.syn, raw_flags[1]);
        assert_eq!(observation.packet_time, 7_000_008);
    }

    #[test]
    fn without_use_mac_the_key_ignores_link_addresses() {
        let frame = tcp_frame();
        let header = header(&frame);

        let with_mac = observe(pcap::Packet::new(&header, &frame), true, 1).expect("observed");
        let without = observe(pcap::Packet::new(&header, &frame), false, 1).expect("observed");

        assert_ne!(with_mac.key, without.key);
        assert_eq!(without.key.src_mac.0, [0; 6]);
        assert_eq!(without.key.dst_mac.0, [0; 6]);
        assert_eq!(without.reverse_key.src_mac.0, [0; 6]);
    }

    /// The flow key and the flow record must report the same endpoints. They
    /// derive them separately, and ICMPv6 is where they used to disagree: the
    /// key carried the type and code while the record reported 0/0, so an echo
    /// exchange produced two rows that looked identical.
    #[test]
    fn the_record_reports_the_same_endpoints_as_the_key() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x86DDu16.to_be_bytes());

        // IPv6 header, next header 58 (ICMPv6), 8-byte payload.
        frame.extend_from_slice(&[0x60, 0, 0, 0, 0, 8, 58, 64]);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        frame.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        // Echo request: type 128, code 0.
        frame.extend_from_slice(&[128, 0, 0, 0, 0, 0, 0, 0]);

        let header = header(&frame);
        let observation = observe(pcap::Packet::new(&header, &frame), true, 1).expect("observed");

        assert_eq!(observation.record.prot, 58);
        assert_eq!(
            (observation.record.src_port, observation.record.dst_port),
            (observation.key.src_port, observation.key.dst_port),
            "record endpoints must match the key"
        );
        assert_eq!(observation.key.src_port, 128, "ICMPv6 type");
        assert_eq!(observation.key.dst_port, 0, "ICMPv6 code");
    }

    /// SCTP carries ports like TCP and UDP do, but paccel reports them on
    /// `parsed.sctp` rather than through `TransportSegment`, so fluere used to
    /// key every SCTP association between two hosts as a single flow.
    #[test]
    fn sctp_ports_reach_both_the_key_and_the_record() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        // IPv4, protocol 132 (SCTP), 12-byte common header + no chunks.
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&(20u16 + 12).to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 64, 132, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 1]);
        frame.extend_from_slice(&[198, 51, 100, 2]);
        frame.extend_from_slice(&50_005u16.to_be_bytes());
        frame.extend_from_slice(&38_412u16.to_be_bytes());
        frame.extend_from_slice(&[0; 8]); // verification tag + checksum

        let header = header(&frame);
        let observation = observe(pcap::Packet::new(&header, &frame), true, 1).expect("observed");

        assert_eq!(observation.record.prot, 132);
        assert_eq!(
            (observation.key.src_port, observation.key.dst_port),
            (50_005, 38_412)
        );
        assert_eq!(
            (observation.record.src_port, observation.record.dst_port),
            (observation.key.src_port, observation.key.dst_port)
        );
    }

    /// Both ICMP families report type and code the same way, so an echo
    /// exchange is grouped identically whichever address family it uses.
    #[test]
    fn icmpv4_reports_type_and_code_like_icmpv6() {
        let mut frame = Vec::new();
        frame.extend_from_slice(&DST_MAC);
        frame.extend_from_slice(&SRC_MAC);
        frame.extend_from_slice(&0x0800u16.to_be_bytes());

        // IPv4, protocol 1 (ICMP), 8-byte echo request header.
        frame.extend_from_slice(&[0x45, 0x00]);
        frame.extend_from_slice(&(20u16 + 8).to_be_bytes());
        frame.extend_from_slice(&[0, 1, 0, 0, 64, 1, 0, 0]);
        frame.extend_from_slice(&[192, 0, 2, 1]);
        frame.extend_from_slice(&[198, 51, 100, 2]);
        frame.extend_from_slice(&[8, 0, 0, 0, 0, 0, 0, 0]); // type 8, code 0

        let header = header(&frame);
        let observation = observe(pcap::Packet::new(&header, &frame), true, 1).expect("observed");

        assert_eq!(observation.record.prot, 1);
        assert_eq!(observation.key.src_port, 8, "ICMP type");
        assert_eq!(observation.key.dst_port, 0, "ICMP code");
        assert_eq!(
            (observation.record.src_port, observation.record.dst_port),
            (observation.key.src_port, observation.key.dst_port)
        );
    }

    #[test]
    fn an_empty_packet_is_rejected() {
        let header = header(&[]);
        assert!(observe(pcap::Packet::new(&header, &[]), true, 1).is_err());
    }
}
