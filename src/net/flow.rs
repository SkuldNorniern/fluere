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

/// EtherType for address resolution, which has no IP protocol number.
const ETHERTYPE_ARP: u16 = 0x0806;

impl Flow {
    /// Readable name of the protocol this flow carried.
    ///
    /// Empty when the protocol has no well-known name; `prot` still carries the
    /// number in that case.
    pub fn protocol_name(&self) -> &'static str {
        if self.key.encapsulation.is_none() && self.record.network.ethertype == Some(ETHERTYPE_ARP)
        {
            return "arp";
        }

        match self.key.protocol {
            1 => "icmp",
            2 => "igmp",
            6 => "tcp",
            17 => "udp",
            41 => "ipv6",
            47 => "gre",
            50 => "esp",
            51 => "ah",
            58 => "icmpv6",
            89 => "ospf",
            112 => "vrrp",
            132 => "sctp",
            _ => "",
        }
    }

    /// Whether the protocol carries transport ports of its own.
    pub fn has_ports(&self) -> bool {
        !matches!(self.key.protocol, 1 | 4 | 47 | 50 | 51 | 58)
    }

    /// Whether this flow carried an IP protocol at all.
    ///
    /// ARP does not, and used to report IP protocol 4 - IANA's number for
    /// IP-in-IP - purely as a flow-keying marker.
    pub fn is_ip(&self) -> bool {
        self.record.network.ethertype != Some(ETHERTYPE_ARP)
    }

    /// The EtherType, for traffic that is not IP. Empty otherwise, where the
    /// address family already says it.
    pub fn ethertype(&self) -> String {
        match self.record.network.ethertype {
            Some(ethertype) if !self.is_ip() => format!("0x{:04x}", ethertype),
            _ => String::new(),
        }
    }
}

impl From<&Flow> for fluere_plugin::FlowIdentity {
    fn from(flow: &Flow) -> Self {
        let encapsulation = flow.key.encapsulation;

        // Only real ports go in `ports`; anything a protocol puts in their place
        // is reported under its own name, the same way the CSV columns do.
        let ports = flow
            .has_ports()
            .then_some((flow.key.src_port, flow.key.dst_port));
        let spi = matches!(flow.key.protocol, 50 | 51)
            .then(|| (u32::from(flow.key.src_port) << 16) | u32::from(flow.key.dst_port));
        let gre_protocol =
            (flow.key.protocol == 47 && flow.key.src_port != 0).then_some(flow.key.src_port);

        fluere_plugin::FlowIdentity {
            source: Some(flow.key.src_ip),
            destination: Some(flow.key.dst_ip),
            ports,
            icmp: flow.record.transport.icmp,
            spi,
            gre_protocol,
            protocol: flow.protocol_name().to_string(),
            protocol_number: flow.is_ip().then_some(flow.key.protocol),
            ethertype: (!flow.is_ip())
                .then_some(flow.record.network.ethertype)
                .flatten(),
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
