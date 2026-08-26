//! A runtime-neutral view of a flow record.
//!
//! Every plugin runtime marshals from this rather than reaching into
//! [`FluereRecord`] itself, so the field list is written down once instead of
//! once per supported language.

use fluereflow::FluereRecord;

/// Version of the field set below.
///
/// Plugins see this as `schema_version` and can branch on it. Bump it whenever
/// a field is added, removed, renamed, or changes type.
pub const SCHEMA_VERSION: u32 = 1;

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

/// A flow record flattened into named, typed fields.
#[derive(Debug, Clone)]
pub struct FlowView {
    pub schema_version: u32,
    pub fields: Vec<(&'static str, FieldValue)>,
}

impl FlowView {
    pub fn new(record: &FluereRecord) -> Self {
        use FieldValue::{Bool, Text, Unsigned};

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
            ],
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{FieldValue, FlowView, SCHEMA_VERSION};
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
        let view = FlowView::new(&record());

        assert_eq!(view.fields.len(), 28, "one entry per FluereRecord field");
        assert_eq!(view.schema_version, SCHEMA_VERSION);

        let mut names: Vec<&str> = view.fields.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        let unique = names.len();
        names.dedup();
        assert_eq!(names.len(), unique, "field names must not repeat");
    }

    #[test]
    fn values_keep_their_natural_types() {
        let view = FlowView::new(&record());

        assert_eq!(field(&view, "source"), FieldValue::Text("192.0.2.1".into()));
        assert_eq!(field(&view, "d_pkts"), FieldValue::Unsigned(7));
        assert_eq!(field(&view, "d_octets"), FieldValue::Unsigned(420));
        assert_eq!(field(&view, "src_port"), FieldValue::Unsigned(12_345));
        assert_eq!(field(&view, "mid_stream"), FieldValue::Bool(true));
    }
}
