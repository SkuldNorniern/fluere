#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    pub source: u16,
    pub dest: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp {
    pub ports: Ports,
    pub length: u16,
    pub checksum: u16,
}
