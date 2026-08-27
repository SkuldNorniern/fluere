use fluereflow::FlowRecord;

use crate::net::types::Key;

/// A finished flow: what identified it, alongside what it accumulated.
///
/// The record holds the counters. Everything that distinguishes one flow from
/// another - the VLAN it arrived on, the tunnel that carried it - lives on the
/// key, so exporters need both. Two tenants on different segments produce
/// records that are identical field for field; only the key says they are
/// different traffic.
#[derive(Debug, Clone, Copy)]
pub struct Flow {
    pub key: Key,
    pub record: FlowRecord,
}

impl From<&Flow> for fluere_plugin::FlowIdentity {
    fn from(flow: &Flow) -> Self {
        let encapsulation = flow.key.encapsulation;

        fluere_plugin::FlowIdentity {
            vlan: flow.key.vlan.tags().to_vec(),
            encapsulation: encapsulation.map(|e| e.kind.as_str().to_string()),
            tunnel_id: encapsulation.map_or(0, |e| e.id),
            tunnel_endpoints: encapsulation.and_then(|e| e.outer),
        }
    }
}

impl Flow {
    pub fn new(key: Key, record: FlowRecord) -> Self {
        Flow { key, record }
    }

    /// The VLAN tags, outermost first, as a `.`-separated list. Empty when the
    /// traffic was untagged.
    pub fn vlan(&self) -> String {
        self.key
            .vlan
            .tags()
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(".")
    }

    /// The kind of tunnel that carried the flow, or empty when it was not
    /// tunnelled.
    pub fn encapsulation(&self) -> &'static str {
        self.key
            .encapsulation
            .map_or("", |encapsulation| encapsulation.kind.as_str())
    }

    /// The tunnel's segment, key, label or session. Empty when the flow was not
    /// tunnelled, or the tunnel carries no such field.
    pub fn tunnel_id(&self) -> String {
        match self.key.encapsulation {
            Some(encapsulation) if encapsulation.id != 0 => encapsulation.id.to_string(),
            _ => String::new(),
        }
    }

    /// The tunnel's own endpoints, `->`-separated. Empty for encapsulations
    /// that sit below IP and have no addresses of their own.
    pub fn tunnel_endpoints(&self) -> String {
        match self.key.encapsulation.and_then(|e| e.outer) {
            Some((source, destination)) => format!("{}->{}", source, destination),
            None => String::new(),
        }
    }
}
