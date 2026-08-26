//! Turning matched arguments into the values the capture modes take.

use std::str::FromStr;

use clap::ArgMatches;

use crate::ConfigError;
use crate::types::{Args, Files, Parameters};

pub fn value<T: FromStr>(args: &ArgMatches, name: &str) -> Result<T, ConfigError> {
    let raw = args
        .get_one::<String>(name)
        .ok_or_else(|| ConfigError::Missing(name.to_string()))?;

    raw.parse::<T>().map_err(|_| ConfigError::InvalidValue {
        field: name.to_string(),
        value: raw.clone(),
    })
}

pub fn string(args: &ArgMatches, name: &str) -> Result<String, ConfigError> {
    args.get_one::<String>(name)
        .cloned()
        .ok_or_else(|| ConfigError::Missing(name.to_string()))
}

/// Optional string: absent means the caller did not pass the flag.
pub fn optional_string(args: &ArgMatches, name: &str) -> Option<String> {
    args.get_one::<String>(name).cloned()
}

pub fn verbosity(args: &ArgMatches) -> Result<u8, ConfigError> {
    match args.get_one::<String>("verbose") {
        Some(_) => value(args, "verbose"),
        None => Ok(0),
    }
}

/// Arguments for capturing flow records from an interface.
pub fn capture(args: &ArgMatches) -> Result<Args, ConfigError> {
    Ok(Args::new(
        Some(string(args, "interface")?),
        Files::new(Some(string(args, "csv")?), None, None),
        Parameters::new(
            Some(args.get_flag("useMACaddress")),
            Some(value(args, "timeout")?),
            Some(value(args, "duration")?),
            Some(value(args, "interval")?),
            Some(value(args, "snaplen")?),
        ),
    ))
}

/// Arguments for writing raw packets to a pcap file.
pub fn write_pcap(args: &ArgMatches, output: String) -> Result<Args, ConfigError> {
    Ok(Args::new(
        Some(string(args, "interface")?),
        Files::new(None, None, Some(output)),
        Parameters::new(
            None,
            None,
            Some(value(args, "duration")?),
            Some(value(args, "interval")?),
            Some(value(args, "snaplen")?),
        ),
    ))
}

/// Arguments for converting a pcap file into flow records.
pub fn convert(args: &ArgMatches) -> Result<Args, ConfigError> {
    Ok(Args::new(
        None,
        Files::new(
            optional_string(args, "csv"),
            Some(string(args, "file")?),
            None,
        ),
        Parameters::new(
            Some(args.get_flag("useMACaddress")),
            Some(value(args, "timeout")?),
            None,
            None,
            None,
        ),
    ))
}
