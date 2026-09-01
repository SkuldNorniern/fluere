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

    let verbosity = parse::verbosity(args)?;

    let (mode, parsed) = match command {
        // Only these define -l/--list, so only these may be asked for it:
        // querying a flag a command does not declare panics inside clap.
        "capture" | "online" | "live" | "pcap" => {
            if args.get_flag("list") {
                devices::list()?;
                return Ok(None);
            }
            resolve_capture(command, args)?
        }
        "convert" | "offline" => (Mode::Offline, parse::convert(args)?),
        other => {
            return Err(ConfigError::Argument(format!(
                "Unsupported command: {other}"
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

#[cfg(test)]
mod tests {
    use super::*;

    fn dispatch_argv(argv: &[&str]) -> Result<Option<Invocation>, ConfigError> {
        let matches = cli_template()
            .try_get_matches_from(argv)
            .expect("arguments parse");
        dispatch(&matches)
    }

    fn mode_of(argv: &[&str]) -> Mode {
        dispatch_argv(argv)
            .expect("dispatch succeeds")
            .expect("a mode to run")
            .mode
    }

    #[test]
    fn capture_flags_pick_the_mode() {
        assert_eq!(mode_of(&["fluere", "capture", "-i", "eth0"]), Mode::Online);
        assert_eq!(
            mode_of(&["fluere", "capture", "-i", "eth0", "--tui"]),
            Mode::Live
        );
        assert_eq!(
            mode_of(&["fluere", "capture", "-i", "eth0", "--pcap", "out.pcap"]),
            Mode::Pcap
        );
    }

    #[test]
    fn retired_names_map_onto_the_same_modes() {
        assert_eq!(mode_of(&["fluere", "online", "-i", "eth0"]), Mode::Online);
        assert_eq!(mode_of(&["fluere", "live", "-i", "eth0"]), Mode::Live);
        assert_eq!(
            mode_of(&["fluere", "pcap", "-i", "eth0", "-p", "out.pcap"]),
            Mode::Pcap
        );
        assert_eq!(
            mode_of(&["fluere", "offline", "-f", "in.pcap"]),
            Mode::Offline
        );
    }

    #[test]
    fn convert_reaches_offline_mode() {
        let invocation = dispatch_argv(&["fluere", "convert", "-f", "in.pcap"])
            .expect("dispatch succeeds")
            .expect("a mode to run");

        assert_eq!(invocation.mode, Mode::Offline);
        assert_eq!(invocation.args.files.file.as_deref(), Some("in.pcap"));
        // No -c given, so the name is derived from the capture file later.
        assert!(invocation.args.files.csv.is_none());
    }

    /// `list` is only declared on the capture commands. Asking any other
    /// command for it panics inside clap, and `try_get_one` does not catch that
    /// outside debug builds, so dispatch must never probe for it.
    #[test]
    fn commands_without_a_list_flag_are_never_asked_for_one() {
        for argv in [
            vec!["fluere", "convert", "-f", "in.pcap"],
            vec!["fluere", "offline", "-f", "in.pcap"],
        ] {
            dispatch_argv(&argv).expect("dispatch must not fail");
        }
    }

    #[test]
    fn capture_carries_its_options_through() {
        let invocation = dispatch_argv(&[
            "fluere", "capture", "-i", "eth0", "-c", "flows", "-t", "1000", "-d", "50", "-I",
            "200", "-s", "1500", "-M",
        ])
        .expect("dispatch succeeds")
        .expect("a mode to run");

        assert_eq!(invocation.args.interface.as_deref(), Some("eth0"));
        assert_eq!(invocation.args.files.csv.as_deref(), Some("flows"));
        assert_eq!(invocation.args.parameters.timeout, Some(1000));
        assert_eq!(invocation.args.parameters.duration, Some(50));
        assert_eq!(invocation.args.parameters.interval, Some(200));
        assert_eq!(invocation.args.parameters.snaplen, Some(1500));
        assert_eq!(invocation.args.parameters.use_mac, Some(true));
    }

    #[test]
    fn writing_a_pcap_conflicts_with_a_terminal_ui() {
        assert!(
            cli_template()
                .try_get_matches_from(["fluere", "capture", "-i", "eth0", "--tui", "--pcap", "x"])
                .is_err()
        );
    }

    #[test]
    fn the_command_definition_is_internally_consistent() {
        cli_template().debug_assert();
    }
}
