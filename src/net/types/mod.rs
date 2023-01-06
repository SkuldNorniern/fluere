pub mod ether;
pub mod ipv4;
pub mod protocols;

mod netflowv5;
//mod v4packet_pnet;

pub use netflowv5::V5Netflow;
//pub use v4packet_pnet::C_Ipv4Packet;
