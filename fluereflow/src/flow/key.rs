//! What identifies a flow.

use std::net::IpAddr;

use super::encapsulation::Encapsulation;
use super::link::MacAddress;
use super::vlan::VlanTags;

/// What identifies the two ends of a flow.
///
/// Most protocols have transport ports. The ones that do not put something else
/// in their place, and each is named for what it actually is rather than
/// sharing a pair of fields called "port" and meaning different things by row.
///
/// ICMP is deliberately absent. Its type and code identify a direction rather
/// than an endpoint: an echo request and its reply carry different ones, so
/// keying on them would split one exchange into two flows. They are recorded as
/// a measurement on the flow record instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum Endpoints {
    /// TCP, UDP and SCTP.
    Ports { source: u16, destination: u16 },
    /// An IPsec security association, named by its SPI. Associations are
    /// one-way by design, so each direction is its own flow.
    SecurityAssociation(u32),
    /// A GRE tunnel whose inner flow could not be decoded, named by the
    /// protocol it was carrying.
    GreProtocol(u16),
    /// ARP, ICMP, and anything else with no endpoints of its own.
    None,
}

impl Endpoints {
    /// Transport ports, for the protocols that have them.
    pub fn ports(self) -> Option<(u16, u16)> {
        match self {
            Endpoints::Ports {
                source,
                destination,
            } => Some((source, destination)),
            _ => None,
        }
    }

    pub fn security_association(self) -> Option<u32> {
        match self {
            Endpoints::SecurityAssociation(spi) => Some(spi),
            _ => None,
        }
    }

    pub fn gre_protocol(self) -> Option<u16> {
        match self {
            Endpoints::GreProtocol(protocol) => Some(protocol),
            _ => None,
        }
    }

    /// The same endpoints seen from the other direction.
    ///
    /// Only ports swap. An SPI names one association and a GRE protocol names
    /// the tunnel's payload; neither has a counterpart to swap with.
    pub fn reversed(self) -> Self {
        match self {
            Endpoints::Ports {
                source,
                destination,
            } => Endpoints::Ports {
                source: destination,
                destination: source,
            },
            other => other,
        }
    }
}

/// Everything that distinguishes one flow from another.
///
/// Addresses and protocol are the obvious part. The rest matters because
/// separate segments routinely reuse the same private ranges: without the VLAN
/// and the tunnel, two tenants' traffic would land in one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct FlowKey {
    /// Address of the endpoint that sent the packet which opened the flow.
    pub source: IpAddr,
    /// The other endpoint.
    pub destination: IpAddr,
    pub endpoints: Endpoints,
    /// IANA protocol number, or `0` for traffic with no IP protocol of its
    /// own. Such traffic is identified by `ethertype` instead.
    pub protocol: u8,
    /// EtherType, for traffic that is not IP.
    ///
    /// `None` for IP traffic, where the address family already says what this
    /// is. ARP used to be keyed as IP protocol 4, IANA's number for IP-in-IP,
    /// purely as a marker, which meant an ARP flow and a genuine IP-in-IP flow
    /// between the same addresses shared a key.
    pub ethertype: Option<u16>,
    /// Link-layer addresses, when the capture was asked to key on them.
    pub source_mac: MacAddress,
    pub destination_mac: MacAddress,
    /// The VLAN segment this flow arrived on. Untagged frames carry none.
    pub vlan: VlanTags,
    /// The tunnel this flow arrived inside, when it arrived inside one.
    pub encapsulation: Option<Encapsulation>,
}

impl FlowKey {
    /// The same flow seen from the other direction.
    ///
    /// Addresses, ports and MACs swap. The VLAN and the tunnel do not: return
    /// traffic comes back on the same segment, through the same tunnel.
    pub fn reversed(&self) -> Self {
        FlowKey {
            source: self.destination,
            destination: self.source,
            endpoints: self.endpoints.reversed(),
            protocol: self.protocol,
            ethertype: self.ethertype,
            source_mac: self.destination_mac,
            destination_mac: self.source_mac,
            vlan: self.vlan,
            encapsulation: self.encapsulation,
        }
    }

    /// Forget the link-layer addresses, so traffic between the same endpoints
    /// stays one flow regardless of the hops it took.
    pub fn forget_link_addresses(&mut self) {
        self.source_mac = MacAddress::new([0; 6]);
        self.destination_mac = MacAddress::new([0; 6]);
    }

    /// Transport ports, or `(0, 0)` for protocols without them.
    pub fn ports(&self) -> (u16, u16) {
        self.endpoints.ports().unwrap_or((0, 0))
    }

    /// Readable name of the protocol this flow carried, or empty when it has
    /// no well-known one.
    pub fn protocol_name(&self) -> &'static str {
        if self.ethertype == Some(super::ETHERTYPE_ARP) {
            return "arp";
        }

        match self.protocol {
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

    /// `4` or `6`, or `None` for traffic that is not IP.
    ///
    /// Derived rather than stored: the addresses already carry it, and a stored
    /// copy could disagree with them. Reported so consumers need not inspect an
    /// address to find out.
    ///
    /// ARP has no IP version. Its addresses are the sender and target protocol
    /// addresses, which are IPv4 addresses inside an ARP packet, so reading the
    /// family off them said 4 for a packet that is not IP at all.
    pub fn ip_version(&self) -> Option<u8> {
        if self.ethertype.is_some() {
            return None;
        }

        Some(if self.source.is_ipv6() { 6 } else { 4 })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn key(endpoints: Endpoints) -> FlowKey {
        FlowKey {
            source: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)),
            endpoints,
            protocol: 6,
            ethertype: None,
            source_mac: MacAddress::new([1; 6]),
            destination_mac: MacAddress::new([2; 6]),
            vlan: VlanTags::default(),
            encapsulation: None,
        }
    }

    #[test]
    fn reversing_swaps_the_addresses_and_ports() {
        let forward = key(Endpoints::Ports {
            source: 40_001,
            destination: 443,
        });
        let reverse = forward.reversed();

        assert_eq!(reverse.source, forward.destination);
        assert_eq!(reverse.destination, forward.source);
        assert_eq!(reverse.ports(), (443, 40_001));
        assert_eq!(reverse.source_mac, forward.destination_mac);
    }

    #[test]
    fn reversing_twice_gives_back_the_original() {
        let forward = key(Endpoints::Ports {
            source: 40_001,
            destination: 443,
        });
        assert_eq!(forward.reversed().reversed(), forward);
    }

    /// An IPsec association is one-way: the return traffic carries a different
    /// SPI, so there is nothing to swap and it is a separate flow.
    #[test]
    fn an_association_is_not_swapped_by_reversing() {
        let forward = key(Endpoints::SecurityAssociation(0xdead_beef));
        let reverse = forward.reversed();

        assert_eq!(reverse.endpoints.security_association(), Some(0xdead_beef));
        assert_eq!(reverse.ports(), (0, 0));
    }

    /// ICMP has no endpoints, so an echo request and its reply reverse onto
    /// each other and stay one flow.
    #[test]
    fn traffic_without_endpoints_reverses_onto_itself() {
        let request = key(Endpoints::None);
        let reply = request.reversed();

        assert_eq!(reply.endpoints, Endpoints::None);
        assert_eq!(reply.reversed(), request);
    }

    #[test]
    fn the_ip_version_follows_the_addresses() {
        let mut key = key(Endpoints::None);
        assert_eq!(key.ip_version(), Some(4));

        key.source = IpAddr::V6("2001:db8::1".parse().expect("valid address"));
        assert_eq!(key.ip_version(), Some(6));
    }

    /// ARP addresses are IPv4 addresses, so reading the family off them said
    /// version 4 for a packet that is not IP at all.
    #[test]
    fn traffic_that_is_not_ip_has_no_ip_version() {
        let mut key = key(Endpoints::None);
        key.ethertype = Some(super::super::ETHERTYPE_ARP);

        assert_eq!(key.ip_version(), None);
    }

    #[test]
    fn forgetting_link_addresses_leaves_the_rest_alone() {
        let mut key = key(Endpoints::Ports {
            source: 40_001,
            destination: 443,
        });
        let before = key;
        key.forget_link_addresses();

        assert_eq!(key.source_mac, MacAddress::new([0; 6]));
        assert_eq!(key.destination_mac, MacAddress::new([0; 6]));
        assert_eq!(key.source, before.source);
        assert_eq!(key.endpoints, before.endpoints);
    }
}
