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
    #[snafu(display("general error `{message}`"))]
    GeneralError { message: String },
}
#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum ParseError {
    #[snafu(display("unexpected dscp `{dscp}`"))]
    UnknownDSCP { dscp: u8 },
}
