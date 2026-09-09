#[derive(Debug, Default)]
pub struct Args {
    pub interface: Option<String>,
    pub files: Files,
    pub parameters: Parameters,
    // pub verbose: Option<u8>,
}

impl Args {
    pub fn new(
        interface: Option<String>,
        files: Files,
        parameters: Parameters,
        // verbose: Option<u8>,
    ) -> Self {
        Self {
            interface,
            files,
            parameters,
            // verbose,
        }
    }
}

#[derive(Debug, Default)]
pub struct Files {
    pub csv: Option<String>,
    pub file: Option<String>,
    pub pcap: Option<String>,
}

impl Files {
    pub fn new(csv: Option<String>, file: Option<String>, pcap: Option<String>) -> Self {
        Self { csv, file, pcap }
    }
}

#[derive(Debug, Default)]
pub struct Parameters {
    pub use_mac: Option<bool>,
    /// Reassemble TCP streams to identify what each session carries.
    ///
    /// Off by default: paccel 0.4.0 spends roughly 250 microseconds a packet
    /// doing it, which is seventy times the cost of the rest of a parse, so it
    /// is a deliberate choice rather than something a capture pays for silently.
    pub classify_l7: Option<bool>,
    pub timeout: Option<u64>,
    pub duration: Option<u64>,
    pub interval: Option<u64>,
    /// Bytes captured per packet (libpcap snaplen).
    pub snaplen: Option<u64>,
}

impl Parameters {
    pub fn new(
        use_mac: Option<bool>,
        timeout: Option<u64>,
        duration: Option<u64>,
        interval: Option<u64>,
        snaplen: Option<u64>,
    ) -> Self {
        Self {
            use_mac,
            timeout,
            duration,
            interval,
            snaplen,
            classify_l7: None,
        }
    }

    /// The same parameters, asking for session classification.
    ///
    /// Set separately rather than as a sixth positional argument, which is
    /// already more than reads clearly at a call site.
    pub fn classifying_l7(mut self, classify_l7: bool) -> Self {
        self.classify_l7 = Some(classify_l7);
        self
    }
}
