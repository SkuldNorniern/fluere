//! FluereFlow: Fluere's own network flow format.
//!
//! A flow is one conversation: [`FlowKey`] says which one, and [`FlowRecord`]
//! says what it carried. [`Flow`] pairs them, which is what an exporter or a
//! plugin receives.
//!
//! This is not NetFlow. The shape is chosen for what a passive capture can
//! actually observe, and it records things NetFlow has no field for, such as
//! the VLAN or tunnel a flow arrived on and the endpoints it moved between.

pub mod flow;

pub use flow::{
    CaptureStats, Direction, DirectionStats, EncapKind, Encapsulation, EndReason, Endpoints, Flow,
    FlowKey, FlowRecord, FlowTime, MacAddress, NetworkStats, PacketFacts, Paths, Range, StartState,
    TcpFlagCounts, TcpFlags, TimeResolution, Timestamp, TransportStats, VlanTags, SCHEMA_VERSION,
};
