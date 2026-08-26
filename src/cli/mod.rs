//! Command line interface.
//!
//! Three commands describe what Fluere does: [`capture`](capture_command) takes
//! traffic off an interface, [`convert`](convert_command) reads a pcap file,
//! and `devices` lists the interfaces available. How a capture is presented -
//! a terminal UI, or raw packets written to a pcap file - is a flag on
//! `capture` rather than a command of its own, because those all capture the
//! same way and differ only in what comes out.
//!
//! The names Fluere used before (`online`, `live`, `pcap`, `offline`) are kept
//! as hidden commands that map onto the same modes, so existing scripts keep
//! working.

mod args;
mod devices;
mod parse;

use clap::{ArgMatches, Command, crate_version};

use crate::types::Args;
use crate::{ConfigError, Mode};

/// A resolved command line: what to run, with what.
pub struct Invocation {
    pub mode: Mode,
    pub args: Args,
    pub verbosity: u8,
}

pub fn cli_template() -> Command {
    Command::new("fluere")
        .version(crate_version!())
        .author("Skuld Norniern. <skuldnorniern@gmail.com>")
        .about("Cross-platform packet capture and network flow analysis")
        .subcommand_required(true)
        .subcommand(capture_command())
        .subcommand(convert_command())
        .subcommand(devices_command())
        .subcommands(retired_commands())
}

fn capture_command() -> Command {
    Command::new("capture")
        .about("Capture live traffic and export flow records")
        .arg(args::interface())
        .arg(args::csv(true))
        .arg(args::duration())
        .arg(args::timeout())
        .arg(args::interval())
        .arg(args::snaplen())
        .arg(args::use_mac())
        .arg(args::tui())
        .arg(args::write_pcap())
        .arg(args::verbose())
        .arg(args::list().hide(true))
}

fn convert_command() -> Command {
    Command::new("convert")
        .about("Convert a pcap file into flow records")
        .arg(args::file())
        .arg(args::csv(false))
        .arg(args::timeout())
        .arg(args::use_mac())
        .arg(args::verbose())
}

fn devices_command() -> Command {
    Command::new("devices")
        .about("List the network interfaces available to capture from")
        .visible_alias("list")
}

/// The pre-0.8 command names, hidden from help but still accepted.
fn retired_commands() -> Vec<Command> {
    vec![
        capture_command()
            .name("online")
            .about("Retired: use `fluere capture`")
            .hide(true),
        capture_command()
            .name("live")
            .about("Retired: use `fluere capture --tui`")
            .hide(true),
        capture_command()
            .name("pcap")
            .about("Retired: use `fluere capture --pcap <file>`")
            .hide(true),
        convert_command()
            .name("offline")
            .about("Retired: use `fluere convert`")
            .hide(true),
    ]
}

/// Resolve the matched command line.
///
/// `Ok(None)` means the command finished its own work and there is nothing
/// further to run.
pub fn dispatch(matches: &ArgMatches) -> Result<Option<Invocation>, ConfigError> {
    let Some((command, args)) = matches.subcommand() else {
        return Ok(None);
    };

    if command == "devices" {
        devices::list()?;
        return Ok(None);
    }

    // Retired commands still accept -l/--list.
    if args.try_get_one::<bool>("list").is_ok() && args.get_flag("list") {
        devices::list()?;
        return Ok(None);
    }

    let verbosity = parse::verbosity(args)?;

    let (mode, parsed) = match command {
        "capture" | "online" | "live" | "pcap" => resolve_capture(command, args)?,
        "convert" | "offline" => (Mode::Offline, parse::convert(args)?),
        other => {
            return Err(ConfigError::Argument(format!(
                "Unsupported command: {}",
                other
            )));
        }
    };

    Ok(Some(Invocation {
        mode,
        args: parsed,
        verbosity,
    }))
}

/// Decide which capture mode a `capture` invocation means.
///
/// Writing a pcap file and showing a terminal UI are mutually exclusive, which
/// clap enforces; the retired names pick their mode by which name was used.
fn resolve_capture(command: &str, args: &ArgMatches) -> Result<(Mode, Args), ConfigError> {
    let write_pcap = parse::optional_string(args, "write_pcap");
    let tui = args.get_flag("tui");

    match command {
        "pcap" => {
            let output = write_pcap.ok_or_else(|| {
                ConfigError::Missing("an output pcap file (-p/--pcap)".to_string())
            })?;
            Ok((Mode::Pcap, parse::write_pcap(args, output)?))
        }
        "live" => Ok((Mode::Live, parse::capture(args)?)),
        _ => match write_pcap {
            Some(output) => Ok((Mode::Pcap, parse::write_pcap(args, output)?)),
            None if tui => Ok((Mode::Live, parse::capture(args)?)),
            None => Ok((Mode::Online, parse::capture(args)?)),
        },
    }
}
