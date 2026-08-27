use std::net::IpAddr;

/// The kind of tunnel a flow arrived inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum EncapKind {
    Vxlan,
    Geneve,
    Gre,
    Mpls,
    Pppoe,
    /// IP directly inside IP, with no tunnel header of its own.
    IpInIp,
    /// A tunnel paccel decoded through but that is none of the above.
    Other,
}

impl EncapKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EncapKind::Vxlan => "vxlan",
            EncapKind::Geneve => "geneve",
            EncapKind::Gre => "gre",
            EncapKind::Mpls => "mpls",
            EncapKind::Pppoe => "pppoe",
            EncapKind::IpInIp => "ipinip",
            EncapKind::Other => "tunnel",
        }
    }
}

/// The tunnel carrying a flow, as far as flow identity is concerned.
///
/// Flow keys are built from the innermost addresses, which is what makes
/// tunnelled traffic readable. On its own that merges every tunnel between the
/// same pair of inner endpoints into one flow. Different tenants reuse the same
/// private ranges, so their traffic would land in one record. Including the
/// carrier keeps them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Encapsulation {
    pub kind: EncapKind,
    /// The tunnel's own endpoints, for tunnels that run over IP.
    ///
    /// `None` for encapsulations that sit below IP and so have no addresses of
    /// their own, such as MPLS and PPPoE.
    pub outer: Option<(IpAddr, IpAddr)>,
    /// What distinguishes this encapsulation from another of the same kind
    /// between the same endpoints: a VXLAN or Geneve VNI, a GRE key, an MPLS
    /// label, a PPPoE session. Zero when the encapsulation has no such field.
    pub id: u32,
}
