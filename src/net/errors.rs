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
}
