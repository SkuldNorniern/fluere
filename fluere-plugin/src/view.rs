//! A runtime-neutral view of a flow record.
//!
//! Every plugin runtime marshals from this rather than reaching into
//! [`FluereRecord`] itself, so the field list is written down once instead of
//! once per supported language.

use std::net::IpAddr;

use fluereflow::{FlowRecord, Range};

/// Version of the field set below.
///
/// Plugins see this as `schema_version` and can branch on it. Bump it whenever
/// a field is added, removed, renamed, or changes type.
///
/// - 1: the flow record's own fields.
/// - 2: added `vlan`, `encap`, `tunnel_id` and `tunnel_endpoints`.
/// - 3: the FluereFlow record. Counters are per direction with derived totals,
///   timestamps are nanoseconds, `mid_stream` became `start_state`, and
///   `end_reason`, `ecn` and hop limits arrived. `tos` is gone: it was `dscp`
///   shifted, and `dscp` is now reported directly.
pub const SCHEMA_VERSION: u32 = 3;

/// One field's value, in the few shapes a flow record actually uses.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    /// An address or other textual value.
    Text(String),
    /// A count, size, port, or timestamp.
    Unsigned(u64),
    /// A flag.
    Bool(bool),
}

/// What separated a flow from another with the same addresses and ports.
///
/// Two tenants on different VLANs or tunnels produce records that are identical
/// field for field. This is the part that says they are different traffic.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FlowIdentity {
    /// VLAN tags, outermost first. Empty when the traffic was untagged.
    pub vlan: Vec<u16>,
    /// Kind of tunnel that carried the flow, if any: `vxlan`, `gre`, ...
    pub encapsulation: Option<String>,
    /// The tunnel's segment, key, label or session. Zero when it has none.
    pub tunnel_id: u32,
    /// The tunnel's own endpoints, for tunnels that run over IP.
    pub tunnel_endpoints: Option<(IpAddr, IpAddr)>,
}

/// A flow record flattened into named, typed fields.
#[derive(Debug, Clone)]
pub struct FlowView {
    pub schema_version: u32,
    pub fields: Vec<(&'static str, FieldValue)>,
}

impl FlowView {
    pub fn new(record: &FlowRecord, identity: &FlowIdentity) -> Self {
        use FieldValue::{Bool, Text, Unsigned};

        let vlan = identity
            .vlan
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(".");
        let endpoints = identity
            .tunnel_endpoints
            .map_or_else(String::new, |(source, destination)| {
                format!("{}->{}", source, destination)
            });

        let bound = |range: Option<Range<u32>>, take_max: bool| {
            Unsigned(range.map_or(0, |r| u64::from(if take_max { r.max } else { r.min })))
        };
        let flags = &record.forward.tcp_flags;
        let reverse_flags = &record.reverse.tcp_flags;
        let both = |forward: u64, reverse: u64| Unsigned(forward + reverse);

        FlowView {
            schema_version: SCHEMA_VERSION,
            fields: vec![
                ("packets", Unsigned(record.packets())),
                ("frame_octets", Unsigned(record.frame_octets())),
                ("fwd_packets", Unsigned(record.forward.packets)),
                ("rev_packets", Unsigned(record.reverse.packets)),
                ("fwd_octets", Unsigned(record.forward.frame_octets)),
                ("rev_octets", Unsigned(record.reverse.frame_octets)),
                ("first", Unsigned(record.time.start.nanos())),
                ("last", Unsigned(record.time.end.nanos())),
                ("duration", Unsigned(record.time.duration())),
                ("fwd_min_pkt", bound(record.forward.packet_length, false)),
                ("fwd_max_pkt", bound(record.forward.packet_length, true)),
                ("rev_min_pkt", bound(record.reverse.packet_length, false)),
                ("rev_max_pkt", bound(record.reverse.packet_length, true)),
                (
                    "min_ttl",
                    Unsigned(record.network.ttl.map_or(0, |r| u64::from(r.min))),
                ),
                (
                    "max_ttl",
                    Unsigned(record.network.ttl.map_or(0, |r| u64::from(r.max))),
                ),
                ("fin_cnt", both(flags.fin, reverse_flags.fin)),
                ("syn_cnt", both(flags.syn, reverse_flags.syn)),
                ("rst_cnt", both(flags.rst, reverse_flags.rst)),
                ("psh_cnt", both(flags.psh, reverse_flags.psh)),
                ("ack_cnt", both(flags.ack, reverse_flags.ack)),
                ("urg_cnt", both(flags.urg, reverse_flags.urg)),
                ("ece_cnt", both(flags.ece, reverse_flags.ece)),
                ("cwr_cnt", both(flags.cwr, reverse_flags.cwr)),
                ("ns_cnt", both(flags.ns, reverse_flags.ns)),
                ("dscp", Unsigned(u64::from(record.network.dscp))),
                ("ecn", Unsigned(u64::from(record.network.ecn))),
                (
                    "start_state",
                    Text(format!("{:?}", record.time.start_state).to_lowercase()),
                ),
                (
                    "end_reason",
                    Text(
                        record.time.end_reason.map_or_else(String::new, |reason| {
                            format!("{:?}", reason).to_lowercase()
                        }),
                    ),
                ),
                ("truncated", Bool(record.capture.truncated)),
                ("vlan", Text(vlan)),
                (
                    "encap",
                    Text(identity.encapsulation.clone().unwrap_or_default()),
                ),
                ("tunnel_id", Unsigned(u64::from(identity.tunnel_id))),
                ("tunnel_endpoints", Text(endpoints)),
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{FieldValue, FlowIdentity, FlowView, SCHEMA_VERSION};
    use fluereflow::{
        Direction, FlowRecord, PacketFacts, StartState, TcpFlags, TimeResolution, Timestamp,
    };

    /// A flow with traffic in both directions, for exercising the view.
    fn record() -> FlowRecord {
        let mut record = FlowRecord::open(
            Timestamp::from_micros(1_000),
            TimeResolution::Microseconds,
            StartState::SynObserved,
        );
        record.network.dscp = 10;
        record.network.ecn = 1;

        let syn = TcpFlags {
            syn: true,
            ..TcpFlags::default()
        };
        record.observe(
            Direction::Forward,
            PacketFacts {
                time: Timestamp::from_micros(1_000),
                frame_octets: 54,
                captured_octets: 54,
                ttl: Some(64),
                tcp_flags: Some(syn),
            },
        );
        record.observe(
            Direction::Reverse,
            PacketFacts {
                time: Timestamp::from_micros(2_000),
                frame_octets: 120,
                captured_octets: 120,
                ttl: Some(52),
                tcp_flags: Some(syn),
            },
        );
        record
    }

    fn field(view: &FlowView, name: &str) -> FieldValue {
        view.fields
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.clone())
            .unwrap_or_else(|| panic!("missing field {}", name))
    }

    #[test]
    fn every_record_field_is_present_exactly_once() {
        let view = FlowView::new(&record(), &FlowIdentity::default());

        assert_eq!(
            view.fields.len(),
            33,
            "one entry per record field, plus what identified the flow"
        );
        assert_eq!(view.schema_version, SCHEMA_VERSION);

        let mut names: Vec<&str> = view.fields.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let unique = names.len();
        names.dedup();
        assert_eq!(names.len(), unique, "field names must not repeat");
    }

    /// The identity fields describe the flow key, not the record, and are what
    /// tell two tenants apart when every counter matches.
    #[test]
    fn identity_reaches_plugins() {
        let identity = FlowIdentity {
            vlan: vec![10, 20],
            encapsulation: Some("vxlan".to_string()),
            tunnel_id: 100,
            tunnel_endpoints: Some((
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2)),
            )),
        };
        let view = FlowView::new(&record(), &identity);

        assert_eq!(field(&view, "vlan"), FieldValue::Text("10.20".into()));
        assert_eq!(field(&view, "encap"), FieldValue::Text("vxlan".into()));
        assert_eq!(field(&view, "tunnel_id"), FieldValue::Unsigned(100));
        assert_eq!(
            field(&view, "tunnel_endpoints"),
            FieldValue::Text("203.0.113.1->203.0.113.2".into())
        );
    }

    /// Untagged, untunnelled traffic reports empty rather than absent fields,
    /// so a plugin can read them unconditionally.
    #[test]
    fn plain_traffic_reports_empty_identity() {
        let view = FlowView::new(&record(), &FlowIdentity::default());

        assert_eq!(field(&view, "vlan"), FieldValue::Text(String::new()));
        assert_eq!(field(&view, "encap"), FieldValue::Text(String::new()));
        assert_eq!(field(&view, "tunnel_id"), FieldValue::Unsigned(0));
    }

    #[test]
    fn values_keep_their_natural_types() {
        let view = FlowView::new(&record(), &FlowIdentity::default());

        assert_eq!(field(&view, "packets"), FieldValue::Unsigned(2));
        assert_eq!(field(&view, "frame_octets"), FieldValue::Unsigned(174));
        assert_eq!(field(&view, "fwd_packets"), FieldValue::Unsigned(1));
        assert_eq!(field(&view, "rev_octets"), FieldValue::Unsigned(120));
        assert_eq!(field(&view, "dscp"), FieldValue::Unsigned(10));
        assert_eq!(
            field(&view, "start_state"),
            FieldValue::Text("synobserved".into())
        );
        assert_eq!(field(&view, "truncated"), FieldValue::Bool(false));
    }
}
