//! Shared argument definitions.
//!
//! Each option is described once here and reused by every command that takes
//! it, so the same flag cannot drift into meaning different things depending on
//! which subcommand you reached it through.

use clap::{Arg, ArgAction};

pub fn interface() -> Arg {
    Arg::new("interface")
        .help("Network interface to capture from [required]")
        .short('i')
        .long("interface")
        .required_unless_present("list")
}

/// Output CSV name. `capture` defaults it; `convert` leaves it unset so it can
/// fall back to a name derived from the input file.
pub fn csv(with_default: bool) -> Arg {
    let arg = Arg::new("csv")
        .short('c')
        .long("csv")
        .value_parser(plain_file_name);

    if with_default {
        arg.help("Name of the exported csv file, written under ./output")
            .default_value("output")
    } else {
        arg.help("Name of the exported csv file, written under ./output (default: <pcap name>_converted)")
    }
}

/// Accept a file name, not a path.
///
/// The name is joined onto the output directory, so a path given here used to
/// produce something like `./output//tmp/somewhere/name.csv` and fail with an
/// error about a directory the reader never asked for.
fn plain_file_name(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Err("cannot be empty".to_owned());
    }

    if value.contains(['/', '\\']) {
        return Err(format!(
            "expected a file name, not a path: {value}\n\
             Exports are written under ./output, so give the name alone."
        ));
    }

    Ok(value.to_owned())
}

pub fn file() -> Arg {
    Arg::new("file")
        .help("Input pcap file to convert [required]")
        .short('f')
        .long("file")
        .required(true)
}

pub fn duration() -> Arg {
    Arg::new("duration")
        .help("Capture duration, in milliseconds (0: until interrupted)")
        .default_value("0")
        .short('d')
        .long("duration")
}

pub fn timeout() -> Arg {
    Arg::new("timeout")
        .help("Flow idle timeout, in milliseconds (0: flows never time out)")
        .default_value("600000")
        .short('t')
        .long("timeout")
}

pub fn interval() -> Arg {
    Arg::new("interval")
        .help("Export interval, in milliseconds")
        .default_value("1800000")
        .short('I')
        .long("interval")
}

pub fn snaplen() -> Arg {
    Arg::new("snaplen")
        .help("Bytes captured per packet; smaller values truncate payloads")
        .default_value("65535")
        .short('s')
        .long("snaplen")
}

pub fn use_mac() -> Arg {
    Arg::new("useMACaddress")
        .help("Include MAC addresses in the flow key")
        .short('M')
        .long("useMAC")
        .action(ArgAction::SetTrue)
}

pub fn tui() -> Arg {
    Arg::new("tui")
        .help("Show live flow activity in a terminal UI")
        .long("tui")
        .action(ArgAction::SetTrue)
        .conflicts_with("write_pcap")
}

pub fn write_pcap() -> Arg {
    Arg::new("write_pcap")
        .help("Write raw packets to this pcap file instead of producing flow records")
        .short('p')
        .long("pcap")
        .conflicts_with("csv")
}

pub fn verbose() -> Arg {
    // 0: Error, 1: Warn, 2: Info, 3: Debug, 4: Trace
    Arg::new("verbose")
        .help("Verbosity level: 0 error, 1 warn, 2 info, 3 debug, 4 trace")
        .default_value("2")
        .short('v')
        .long("verbose")
}

/// Interface listing as a flag. Superseded by the `devices` command and kept
/// only so the retired subcommands keep working.
pub fn list() -> Arg {
    Arg::new("list")
        .help("List network interfaces and exit")
        .short('l')
        .long("list")
        .action(ArgAction::SetTrue)
}
