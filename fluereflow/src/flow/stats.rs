//! What a flow accumulated.

/// The smallest and largest value seen.
///
/// An `Option<Range<T>>` rather than a pair seeded from the first packet: a
/// range with no observations behind it has no meaningful min or max, and
/// seeding one from zero silently reports a minimum nothing ever measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Range<T> {
    pub min: T,
    pub max: T,
}

impl<T: Copy + Ord> Range<T> {
    pub fn at(value: T) -> Self {
        Range {
            min: value,
            max: value,
        }
    }

    pub fn extend(&mut self, value: T) {
        self.min = self.min.min(value);
        self.max = self.max.max(value);
    }
}

/// Widen `range`, starting it if this is the first observation.
pub fn observe<T: Copy + Ord>(range: &mut Option<Range<T>>, value: T) {
    match range {
        Some(range) => range.extend(value),
        None => *range = Some(Range::at(value)),
    }
}

/// Which TCP control bits a packet carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlags {
    pub fin: bool,
    pub syn: bool,
    pub rst: bool,
    pub psh: bool,
    pub ack: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

/// How many packets in one direction carried each TCP control bit.
///
/// Per direction, unlike the previous model: a one-sided reset storm is
/// invisible when both directions share a counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TcpFlagCounts {
    pub fin: u64,
    pub syn: u64,
    pub rst: u64,
    pub psh: u64,
    pub ack: u64,
    pub urg: u64,
    pub ece: u64,
    pub cwr: u64,
    pub ns: u64,
}

impl TcpFlagCounts {
    fn count(&mut self, flags: TcpFlags) {
        self.fin += u64::from(flags.fin);
        self.syn += u64::from(flags.syn);
        self.rst += u64::from(flags.rst);
        self.psh += u64::from(flags.psh);
        self.ack += u64::from(flags.ack);
        self.urg += u64::from(flags.urg);
        self.ece += u64::from(flags.ece);
        self.cwr += u64::from(flags.cwr);
        self.ns += u64::from(flags.ns);
    }
}

/// What one direction of a flow carried.
///
/// "Forward" is the direction of the flow's first packet and "reverse" the
/// other; neither means ingress or egress, which are interface properties this
/// model does not describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DirectionStats {
    pub packets: u64,
    /// Bytes on the wire, including link and tunnel framing.
    pub frame_octets: u64,
    /// Wire size of the smallest and largest packet, `None` if none were seen.
    pub packet_length: Option<Range<u32>>,
    pub tcp_flags: TcpFlagCounts,
}

impl DirectionStats {
    /// Fold one packet into this direction.
    pub fn observe(&mut self, frame_octets: u32, flags: TcpFlags) {
        self.packets += 1;
        self.frame_octets += u64::from(frame_octets);
        observe(&mut self.packet_length, frame_octets);
        self.tcp_flags.count(flags);
    }

    /// Whether this direction was ever seen.
    pub fn is_empty(&self) -> bool {
        self.packets == 0
    }
}

/// Network-layer properties observed across the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NetworkStats {
    /// Time to live, as IPv4 calls it. IPv6 calls the same octet the hop
    /// limit, and both are reported here - the previous model recorded zero for
    /// IPv6, which read as a genuine measurement.
    pub ttl: Option<Range<u8>>,
    /// Differentiated services code point, from the first packet.
    pub dscp: u8,
    /// Explicit congestion notification bits, from the first packet.
    pub ecn: u8,
    /// EtherType of the traffic this flow carried.
    ///
    /// Names the network protocol for traffic that has no IP protocol number
    /// of its own. ARP used to be reported as IP protocol 4, which is IANA's
    /// number for IP-in-IP - a marker that read as a genuine measurement.
    pub ethertype: Option<u16>,
}

/// Transport details that are not endpoints.
///
/// ICMP has no ports; its type and code identify the message. They are recorded
/// here, as a measurement, rather than being squeezed into fields named for
/// ports - which is what the previous model did, and what made an echo request
/// and its reply look like different endpoints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TransportStats {
    /// ICMP or ICMPv6 type and code, from the flow's first packet.
    pub icmp: Option<(u8, u8)>,
}

/// How much of the traffic the capture actually saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CaptureStats {
    /// Bytes handed to the parser, which is less than the wire length whenever
    /// a snaplen truncated the frame.
    pub captured_octets: u64,
    /// Whether any packet in this flow was truncated by the snaplen.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn syn() -> TcpFlags {
        TcpFlags {
            syn: true,
            ..TcpFlags::default()
        }
    }

    #[test]
    fn a_direction_with_no_packets_reports_no_range() {
        let stats = DirectionStats::default();
        assert!(stats.is_empty());
        assert_eq!(stats.packet_length, None);
        assert_eq!(stats.frame_octets, 0);
    }

    #[test]
    fn observing_packets_accumulates_counts_and_widens_the_range() {
        let mut stats = DirectionStats::default();
        stats.observe(54, syn());
        stats.observe(1_500, TcpFlags::default());
        stats.observe(120, TcpFlags::default());

        assert_eq!(stats.packets, 3);
        assert_eq!(stats.frame_octets, 54 + 1_500 + 120);
        assert_eq!(
            stats.packet_length,
            Some(Range {
                min: 54,
                max: 1_500
            })
        );
        assert_eq!(stats.tcp_flags.syn, 1);
        assert_eq!(stats.tcp_flags.fin, 0);
    }

    /// Flag counts are per direction, so a one-sided burst is visible.
    #[test]
    fn flag_counts_do_not_leak_between_directions() {
        let mut forward = DirectionStats::default();
        let mut reverse = DirectionStats::default();

        let rst = TcpFlags {
            rst: true,
            ..TcpFlags::default()
        };
        for _ in 0..5 {
            reverse.observe(54, rst);
        }
        forward.observe(54, syn());

        assert_eq!(forward.tcp_flags.rst, 0);
        assert_eq!(reverse.tcp_flags.rst, 5);
    }

    #[test]
    fn a_range_starts_at_its_first_observation() {
        let mut range = None;
        observe(&mut range, 42u8);
        assert_eq!(range, Some(Range { min: 42, max: 42 }));

        observe(&mut range, 7);
        observe(&mut range, 200);
        assert_eq!(range, Some(Range { min: 7, max: 200 }));
    }

    /// Counters are `u64`, so a long-lived flow cannot wrap the way a `u32`
    /// packet count would at about 4.3 billion.
    #[test]
    fn counters_hold_more_than_a_u32_could() {
        let mut stats = DirectionStats {
            packets: u64::from(u32::MAX),
            ..DirectionStats::default()
        };
        stats.observe(1, TcpFlags::default());
        assert_eq!(stats.packets, u64::from(u32::MAX) + 1);
    }
}
