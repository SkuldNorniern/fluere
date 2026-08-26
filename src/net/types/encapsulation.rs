use std::net::IpAddr;

/// The kind of tunnel a flow arrived inside.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum EncapKind {
    Vxlan,
    Geneve,
    Gre,
    Mpls,
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
            EncapKind::IpInIp => "ipinip",
            EncapKind::Other => "tunnel",
        }
    }
}

/// The tunnel carrying a flow, as far as flow identity is concerned.
///
/// Flow keys are built from the innermost addresses, which is what makes
/// tunnelled traffic readable. On its own that merges every tunnel between the
/// same pair of inner endpoints into one flow - and different tenants routinely
/// reuse the same private ranges, so two tenants' traffic would land in one
/// record. Including the carrier keeps them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct Encapsulation {
    pub kind: EncapKind,
    /// Outermost addresses, which identify the tunnel endpoints.
    pub outer_src: IpAddr,
    pub outer_dst: IpAddr,
    /// Segment identifier, for tunnels that carry one. Zero otherwise.
    pub vni: u32,
}
