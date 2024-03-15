// This file is part of the fluereflow library, which provides data structures and functions for working with NetFlow data.
// It exports the FluereFlow, FluereHeader, and FluereRecord data structures, which represent different aspects of NetFlow data.
mod types;

// The FluereFlow data structure represents a single flow of network traffic.
// It includes fields for the source and destination IP addresses, the source and destination ports, the protocol, and other information about the flow.
pub use types::FluereFlow;
// The FluereHeader data structure represents the header of a NetFlow record.
// It includes fields for the version of the NetFlow protocol, the count of records in the flow, and other information about the flow.
pub use types::FluereHeader;
// The FluereRecord data structure represents a single record in a NetFlow flow.
// It includes fields for the source and destination IP addresses, the source and destination ports, the protocol, and other information about the record.
pub use types::FluereRecord;
mod cisco_export;
mod netflow_v5;
mod netflow_v9;
