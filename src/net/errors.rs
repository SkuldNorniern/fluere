use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum NetError {
    #[snafu(display("unexpected empty packet"))]
    EmptyPacket,
    #[snafu(display("unknown Protocol `{protocol}`"))]
    UnknownProtocol { protocol: String },
    #[snafu(display("unknown IP version `{version}`"))]
    UnknownIPVersion { version: String },
    #[snafu(display("an error occurred while reading: `{source}`"))]
    PacketReadError { source: pnet::datalink::DataLinkError },
    #[snafu(display("unhandled channel type"))]
    UnhandledChannelType,
    #[snafu(display("an error occurred when creating the datalink channel: `{source}`"))]
    ChannelCreationError { source: pnet::datalink::ChannelError },
}
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ParseError {
    #[snafu(display("unexpected dscp `{dscp}`"))]
    UnknownDSCP { dscp: u8 },
}
