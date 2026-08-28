use std::fs;
use std::time::{Duration, Instant};

use crate::error::{CaptureError, FluereError, OptionExt};
use crate::net::{CaptureDevice, find_device, source};
use crate::types::Args;
use crate::utils::cur_time_file;

use log::{debug, error, trace};

pub async fn write_pcap(args: Args) -> Result<(), FluereError> {
    let pcap_file = args.files.pcap.required("pcap")?;
    let interface_name = args.interface.required("interface")?;
    let duration = args.parameters.duration.required("duration")?;
    let _interval = args.parameters.interval.required("interval")?;
    let snaplen = args.parameters.snaplen.required("snaplen")?;

    let interface = find_device(interface_name.as_str())?;
    let mut cap_device = CaptureDevice::new(interface, snaplen)?;
    let cap = &mut cap_device.capture;

    let file_dir = "./output";
    // let mut packet_count = 0;
    fs::create_dir_all(file_dir)?;
    debug!("Created directory: {}", file_dir);

    let file_path = cur_time_file(pcap_file.as_str(), file_dir, ".pcap");
    let mut file: pcap::Savefile = cap.savefile(file_path.as_ref())?;

    let start = Instant::now();

    loop {
        // Checked before the read, so a quiet interface still stops on time.
        if start.elapsed() >= Duration::from_millis(duration) && duration != 0 {
            break;
        }

        match source::read(cap) {
            source::Read::Packet(packet) => {
                trace!("received packet");
                file.write(&packet);
            }
            // A quiet interface, not a failure. Ending the capture here is what
            // the old code did, because it read a routine timeout as an error.
            source::Read::Timeout => continue,
            source::Read::Eof => break,
            source::Read::Fatal(error) => {
                error!("Capture failed: {}", error);
                return Err(FluereError::Capture(CaptureError::Pcap(error)));
            }
        }
    }

    // Buffered packets reach the file here rather than in a destructor, so a
    // write failure is the caller's to see.
    file.flush()
        .map_err(|error| FluereError::Capture(CaptureError::Pcap(error)))?;

    debug!("Captured in {:?}", start.elapsed());
    Ok(())
}
