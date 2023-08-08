#[derive(Debug,Default)]
pub struct Args {
    pub interface: Option<String>,
    pub files: Files,
    pub parameters: Parameters,
    pub verbose: Option<u8>,
}

impl Args {
    pub fn new(
        interface: Option<String>,
        files: Files,
        parameters: Parameters,
        verbose: Option<u8>,
    ) -> Self {
        Self {
            interface,
            files,
            parameters,
            verbose,
        }
    }
}

#[derive(Debug, Default)]
pub struct Files{
    pub csv: Option<String>,
    pub file: Option<String>,
    pub pcap: Option<String>,
}

impl Files {
    pub fn new(
        csv: Option<String>,
        file: Option<String>,
        pcap: Option<String>,
    ) -> Self {
        Self {
            csv,
            file,
            pcap,
        }
    }
}

#[derive(Debug, Default)]
pub struct Parameters {
    pub use_mac: Option<bool>,
    pub timeout: Option<u64>,
    pub duration: Option<u64>,
    pub interval: Option<u64>,
    pub sleep_windows: Option<u64>,
}

impl Parameters {
    pub fn new(
        use_mac: Option<bool>,
        timeout: Option<u64>,
        duration: Option<u64>,
        interval: Option<u64>,
        sleep_windows: Option<u64>,
    ) -> Self {
        Self {
            use_mac,
            timeout,
            duration,
            interval,
            sleep_windows,
        }
    }
}
