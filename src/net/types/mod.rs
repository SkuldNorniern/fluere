mod encapsulation;
mod ether;
mod flags;
mod key;
mod vlan;

pub use encapsulation::{EncapKind, Encapsulation};
pub use ether::MacAddress;
pub use flags::TcpFlags;
pub use key::Key;
pub use vlan::VlanTags;
