use crate::net::Flow;
use log::{debug, error};
use std::{fmt::Display, fmt::Write as _, fs::File};

/// Columns, in order. Kept next to the row builder so the two cannot drift.
const COLUMNS: [&str; 48] = [
    "source",
    "destination",
    "ip_version",
    "src_port",
    "dst_port",
    "icmp_type",
    "icmp_code",
    "spi",
    "gre_protocol",
    "protocol",
    "prot",
    "ethertype",
    "packets",
    "frame_octets",
    "captured_octets",
    "truncated",
    "fwd_packets",
    "rev_packets",
    "fwd_octets",
    "rev_octets",
    "first",
    "last",
    "duration",
    "fwd_min_pkt",
    "fwd_max_pkt",
    "rev_min_pkt",
    "rev_max_pkt",
    "min_ttl",
    "max_ttl",
    "fin_cnt",
    "syn_cnt",
    "rst_cnt",
    "psh_cnt",
    "ack_cnt",
    "urg_cnt",
    "ece_cnt",
    "cwr_cnt",
    "ns_cnt",
    "dscp",
    "ecn",
    "start_state",
    "end_reason",
    "path_count",
    "paths",
    "vlan",
    "encap",
    "tunnel_id",
    "tunnel_endpoints",
];

/// Writes flows to a CSV as they finish.
///
/// A conversion used to hold every flow it had ever seen in a vector and write
/// the lot at the end, so peak memory grew with the whole capture rather than
/// with the flows open at one moment. Rows now leave as they are produced.
///
/// The cost is that a run failing part way through leaves the rows it had
/// already written, where before it left an empty file. The failure is still
/// reported, so a partial CSV is never mistaken for a whole one.
pub struct CsvExporter {
    writer: csv::Writer<File>,
    row: RowBuffer,
    written: u64,
}

impl CsvExporter {
    /// Opens the CSV and writes its header, so a run that produces no flows
    /// still leaves a readable file.
    pub fn create(file: File) -> Result<Self, csv::Error> {
        let mut writer = csv::Writer::from_writer(file);
        writer.write_record(COLUMNS).map_err(|error| {
            error!("Failed to write CSV header: {error}");
            error
        })?;

        Ok(CsvExporter {
            writer,
            row: RowBuffer::new(),
            written: 0,
        })
    }

    pub fn write(&mut self, flow: &Flow) -> Result<(), csv::Error> {
        self.row.rewind();
        row(flow, &mut self.row);
        self.writer
            .write_record(self.row.fields())
            .map_err(|error| {
                error!("Failed to write CSV record: {error}");
                error
            })?;
        self.written += 1;

        Ok(())
    }

    /// How many rows have been written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Flush explicitly: relying on the writer's destructor would swallow a
    /// failure on the last buffered rows, which is exactly when the caller most
    /// needs to hear about it.
    pub fn finish(mut self) -> Result<u64, csv::Error> {
        self.writer.flush().map_err(|error| {
            error!("Failed to flush CSV output: {error}");
            csv::Error::from(error)
        })?;

        debug!("Wrote {} records", self.written);
        Ok(self.written)
    }
}

/// Writes a batch of flows to their own file, for the interval-rotated exports
/// the capture path produces. The batch is already bounded by the rotation, so
/// it is held whole.
pub async fn fluere_exporter(records: Vec<Flow>, file: File) -> Result<(), csv::Error> {
    debug!("Writing {} records", records.len());
    let mut exporter = CsvExporter::create(file)?;
    for flow in records.iter() {
        exporter.write(flow)?;
    }
    exporter.finish()?;

    Ok(())
}

/// The columns of one row, reused across every row written.
///
/// A row used to be a fresh `Vec` of 48 `String`s, so exporting a million flows
/// allocated forty-odd million times for text that was written and dropped
/// immediately. The buffer keeps each column's capacity between rows instead.
struct RowBuffer {
    fields: Vec<String>,
    next: usize,
}

impl RowBuffer {
    fn new() -> Self {
        RowBuffer {
            fields: vec![String::new(); COLUMNS.len()],
            next: 0,
        }
    }

    /// Start a new row. The columns keep their capacity and are cleared as
    /// they are filled, so a column left unwritten cannot carry the previous
    /// row's value: `fields` is only read back once every column is filled.
    fn rewind(&mut self) {
        self.next = 0;
    }

    /// The next column, emptied and ready to be written into.
    fn column(&mut self) -> &mut String {
        let index = self.next;
        self.next += 1;
        let field = &mut self.fields[index];
        field.clear();
        field
    }

    fn put(&mut self, value: impl Display) {
        let field = self.column();
        // Writing into a String cannot fail.
        let _ = write!(field, "{value}");
    }

    /// An absent value, which the CSV spells as an empty column. Absence is
    /// distinct from zero throughout the record and stays distinct here.
    fn absent(&mut self) {
        self.column();
    }

    fn put_or_absent(&mut self, value: Option<impl Display>) {
        match value {
            Some(value) => self.put(value),
            None => self.absent(),
        }
    }

    fn fields(&self) -> &[String] {
        debug_assert_eq!(self.next, COLUMNS.len(), "a column was left unwritten");
        &self.fields
    }
}

/// One flow as text, in `COLUMNS` order.
///
/// Totals come from the record's accessors rather than a stored field, so a row
/// cannot report a total that disagrees with its own directions.
fn row(flow: &Flow, out: &mut RowBuffer) {
    let record = &flow.record;
    let key = &flow.key;
    let flags = &record.forward.tcp_flags;
    let reverse_flags = &record.reverse.tcp_flags;

    out.put(key.source);
    out.put(key.destination);
    out.put_or_absent(key.ip_version());

    // Each endpoint kind is read from the key's own typed endpoint rather than
    // guessed from the protocol number, so this cannot drift from how the flow
    // was actually keyed. Protocols without ports have columns of their own, so
    // a value never means one thing in one row and something else in the next.
    match key.endpoints.ports() {
        Some((source, destination)) => {
            out.put(source);
            out.put(destination);
        }
        None => {
            out.absent();
            out.absent();
        }
    }
    // ICMP type and code are a measurement, not an endpoint: they identify the
    // direction, and an echo exchange is one flow.
    match record.transport.icmp {
        Some((icmp_type, code)) => {
            out.put(icmp_type);
            out.put(code);
        }
        None => {
            out.absent();
            out.absent();
        }
    }
    match key.endpoints.security_association() {
        Some(spi) => {
            let _ = write!(out.column(), "0x{spi:08x}");
        }
        None => out.absent(),
    }
    match key.endpoints.gre_protocol() {
        Some(protocol) => {
            let _ = write!(out.column(), "0x{protocol:04x}");
        }
        None => out.absent(),
    }

    out.put(flow.protocol_name());
    // Empty for traffic with no IP protocol number of its own.
    out.put_or_absent(flow.is_ip().then_some(key.protocol));
    out.put(crate::net::identity::ethertype(flow));

    out.put(record.packets());
    out.put(record.frame_octets());
    // What the capture actually kept, against the wire length above. A short
    // snaplen makes the two differ, and `truncated` says whether it did.
    out.put(record.capture.captured_octets);
    out.put(u8::from(record.capture.truncated));

    out.put(record.forward.packets);
    out.put(record.reverse.packets);
    out.put(record.forward.frame_octets);
    out.put(record.reverse.frame_octets);

    out.put(record.time.start.nanos());
    out.put(record.time.end.nanos());
    out.put(record.time.duration());

    out.put_or_absent(record.forward.packet_length.map(|range| range.min));
    out.put_or_absent(record.forward.packet_length.map(|range| range.max));
    out.put_or_absent(record.reverse.packet_length.map(|range| range.min));
    out.put_or_absent(record.reverse.packet_length.map(|range| range.max));
    out.put_or_absent(record.network.ttl.map(|range| range.min));
    out.put_or_absent(record.network.ttl.map(|range| range.max));

    // Flag counters are per direction now; the columns keep reporting the
    // conversation's total so existing consumers still add up.
    out.put(flags.fin + reverse_flags.fin);
    out.put(flags.syn + reverse_flags.syn);
    out.put(flags.rst + reverse_flags.rst);
    out.put(flags.psh + reverse_flags.psh);
    out.put(flags.ack + reverse_flags.ack);
    out.put(flags.urg + reverse_flags.urg);
    out.put(flags.ece + reverse_flags.ece);
    out.put(flags.cwr + reverse_flags.cwr);
    out.put(flags.ns + reverse_flags.ns);

    out.put_or_absent(record.network.dscp);
    out.put_or_absent(record.network.ecn);

    out.put(record.time.start_state.as_str());
    out.put_or_absent(record.time.end_reason.map(fluereflow::EndReason::as_str));

    out.put(record.paths.count());
    out.put(crate::net::identity::paths(flow));
    out.put(crate::net::identity::vlan(flow));
    out.put(crate::net::identity::encapsulation(flow));
    out.put(crate::net::identity::tunnel_id(flow));
    out.put(crate::net::identity::tunnel_endpoints(flow));
}
