//! A runtime-neutral view of a flow record.
//!
//! Every plugin runtime marshals from this rather than reaching into
//! [`FluereRecord`] itself, so the field list is written down once instead of
//! once per supported language.

use std::net::IpAddr;

use fluereflow::FluereRecord;

/// Version of the field set below.
///
/// Plugins see this as `schema_version` and can branch on it. Bump it whenever
/// a field is added, removed, renamed, or changes type.
///
/// - 1: the flow record's own fields.
/// - 2: added `vlan`, `encap`, `tunnel_id` and `tunnel_endpoints`.
pub const SCHEMA_VERSION: u32 = 2;

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
    pub fn new(record: &FluereRecord, identity: &FlowIdentity) -> Self {
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

        FlowView {
            schema_version: SCHEMA_VERSION,
            fields: vec![
                ("source", Text(record.source.to_string())),
                ("destination", Text(record.destination.to_string())),
                ("d_pkts", Unsigned(u64::from(record.d_pkts))),
                ("d_octets", Unsigned(record.d_octets as u64)),
                ("first", Unsigned(record.first)),
                ("last", Unsigned(record.last)),
                ("src_port", Unsigned(u64::from(record.src_port))),
                ("dst_port", Unsigned(u64::from(record.dst_port))),
                ("min_pkt", Unsigned(u64::from(record.min_pkt))),
                ("max_pkt", Unsigned(u64::from(record.max_pkt))),
                ("min_ttl", Unsigned(u64::from(record.min_ttl))),
                ("max_ttl", Unsigned(u64::from(record.max_ttl))),
                ("in_pkts", Unsigned(u64::from(record.in_pkts))),
                ("out_pkts", Unsigned(u64::from(record.out_pkts))),
                ("in_bytes", Unsigned(record.in_bytes as u64)),
                ("out_bytes", Unsigned(record.out_bytes as u64)),
                ("fin_cnt", Unsigned(u64::from(record.fin_cnt))),
                ("syn_cnt", Unsigned(u64::from(record.syn_cnt))),
                ("rst_cnt", Unsigned(u64::from(record.rst_cnt))),
                ("psh_cnt", Unsigned(u64::from(record.psh_cnt))),
                ("ack_cnt", Unsigned(u64::from(record.ack_cnt))),
                ("urg_cnt", Unsigned(u64::from(record.urg_cnt))),
                ("ece_cnt", Unsigned(u64::from(record.ece_cnt))),
                ("cwr_cnt", Unsigned(u64::from(record.cwr_cnt))),
                ("ns_cnt", Unsigned(u64::from(record.ns_cnt))),
                ("prot", Unsigned(u64::from(record.prot))),
                ("tos", Unsigned(u64::from(record.tos))),
                ("mid_stream", Bool(record.mid_stream)),
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
    use fluereflow::FluereRecord;

    fn record() -> FluereRecord {
        FluereRecord::new(
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            7,
            420,
            1_000,
            2_000,
            12_345,
            443,
            54,
            120,
            64,
            64,
            3,
            4,
            180,
            240,
            1,
            1,
            0,
            0,
            5,
            0,
            0,
            0,
            0,
            6,
            40,
            true,
        )
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
            32,
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

        assert_eq!(field(&view, "source"), FieldValue::Text("192.0.2.1".into()));
        assert_eq!(field(&view, "d_pkts"), FieldValue::Unsigned(7));
        assert_eq!(field(&view, "d_octets"), FieldValue::Unsigned(420));
        assert_eq!(field(&view, "src_port"), FieldValue::Unsigned(12_345));
        assert_eq!(field(&view, "mid_stream"), FieldValue::Bool(true));
    }
}
