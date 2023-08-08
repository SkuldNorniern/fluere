use crate::net::types::ipv4::{IPProtocol, IPv4};
use nom::{bytes::complete::take, IResult};
use std::net::Ipv4Addr;

pub fn _parse_ipv4(payload: &[u8]) -> IResult<&[u8], IPv4> {
    let (payload, version_header_length) = take(1usize)(payload)?;
    let version = version_header_length[0] >> 4;
    let header_length = version_header_length[0] & 15;
    let (payload, type_of_service) = take(1usize)(payload)?;
    let (payload, length) = take(2usize)(payload)?;
    let (payload, id) = take(2usize)(payload)?;
    let (payload, flag_frag_offset) = take(2usize)(payload)?;
    let flags = ((flag_frag_offset[0] as u32) >> 13) as u8;
    let fragment_offset: u32 = (flag_frag_offset[0] as u32) & 8191;
    let (payload, ttl) = take(1usize)(payload)?;
    let (payload, protocol) = take(1usize)(payload)?;
    let (payload, checksum) = take(2usize)(payload)?;
    let (payload, source_addr) = take(4usize)(payload)?;
    let source_addr = Ipv4Addr::new(
        source_addr[0],
        source_addr[1],
        source_addr[2],
        source_addr[3],
    );
    let (payload, dest_addr) = take(4usize)(payload)?;
    let dest_addr = Ipv4Addr::new(dest_addr[0], dest_addr[1], dest_addr[2], dest_addr[3]);

    let (payload, _) = if header_length > 5 {
        take((header_length - 5) * 4)(payload)?
    } else {
        (payload, &[] as &[u8])
    };

    let v4packet = IPv4 {
        version,
        header_length,
        type_of_service: u8::from_be_bytes([type_of_service[0]]),
        length: u16::from_be_bytes([length[0], length[1]]),
        id: u16::from_be_bytes([id[0], id[1]]),
        flags,
        fragment_offset,
        ttl: u8::from_be_bytes([ttl[0]]),
        protocol: IPProtocol::from(u8::from_be_bytes([protocol[0]])),
        checksum: u16::from_be_bytes([checksum[0], checksum[1]]),
        source_addr,
        dest_addr,
    };
    Ok((payload, v4packet))
}

#[cfg(test)]
mod tests {
    use super::super::_parse_etherprotocol;
    use super::*;
    use pcap::{Packet, PacketHeader};
    use std::os::raw::c_long;

    fn to_libc_timeval(ts: f64) -> libc::timeval {
        let secs = ts as c_long;
        let usecs = 100000; //dummy value
        libc::timeval {
            tv_sec: secs,
            tv_usec: usecs, // On OS X this use i32 instead of i64
        }
    }
    #[test]
    fn ipv4() {
        let packet: Packet = Packet {
            header: &PacketHeader {
                ts: to_libc_timeval(1_672_986_985.831_39),
                caplen: 554,
                len: 554,
            },
            data: &[
                88, 17, 34, 21, 6, 24, 12, 157, 146, 128, 74, 92, 8, 0, 69, 0, 2, 28, 34, 47, 0, 0,
                128, 17, 0, 0, 192, 168, 50, 241, 1, 209, 175, 116, 162, 169, 162, 169, 2, 8, 166,
                248, 4, 0, 0, 0, 137, 95, 64, 27, 80, 16, 0, 0, 0, 0, 0, 0, 18, 41, 197, 30, 68,
                41, 223, 24, 32, 92, 92, 45, 73, 234, 169, 78, 89, 51, 179, 83, 60, 112, 148, 129,
                171, 217, 233, 156, 139, 104, 246, 41, 19, 128, 251, 85, 246, 111, 255, 21, 226,
                41, 51, 90, 112, 248, 40, 169, 251, 27, 115, 3, 178, 30, 116, 184, 52, 138, 128,
                235, 121, 62, 239, 197, 138, 12, 146, 223, 17, 9, 143, 232, 102, 150, 39, 73, 64,
                203, 20, 220, 164, 106, 104, 134, 83, 190, 176, 59, 5, 185, 78, 158, 30, 240, 21,
                104, 133, 23, 5, 40, 18, 218, 29, 13, 194, 165, 16, 152, 158, 119, 196, 255, 125,
                255, 5, 21, 61, 154, 26, 38, 141, 238, 7, 236, 120, 62, 254, 72, 67, 181, 121, 245,
                250, 96, 187, 206, 25, 245, 6, 197, 99, 232, 246, 10, 34, 86, 158, 175, 255, 36,
                30, 116, 183, 234, 146, 80, 141, 137, 233, 29, 104, 245, 21, 17, 158, 124, 42, 177,
                191, 182, 216, 43, 117, 109, 127, 52, 246, 23, 180, 52, 211, 0, 248, 163, 252, 6,
                52, 116, 182, 132, 41, 210, 207, 15, 108, 234, 62, 10, 196, 155, 45, 130, 72, 87,
                42, 127, 171, 62, 134, 175, 36, 86, 149, 200, 242, 147, 67, 24, 61, 178, 3, 163,
                190, 82, 33, 214, 232, 26, 26, 167, 78, 128, 208, 253, 226, 161, 165, 140, 38, 2,
                244, 86, 197, 131, 55, 239, 80, 150, 94, 97, 199, 235, 179, 233, 251, 168, 18, 233,
                239, 164, 247, 233, 247, 122, 7, 235, 52, 160, 6, 228, 169, 68, 201, 179, 208, 85,
                235, 21, 186, 242, 188, 12, 32, 32, 46, 210, 24, 147, 5, 15, 148, 213, 6, 162, 9,
                83, 195, 159, 46, 135, 253, 210, 186, 17, 126, 101, 27, 84, 169, 146, 225, 58, 52,
                17, 167, 53, 226, 32, 72, 94, 105, 27, 94, 17, 103, 57, 86, 195, 174, 150, 230, 84,
                213, 93, 113, 150, 98, 218, 243, 102, 252, 193, 0, 216, 140, 114, 145, 178, 80, 70,
                63, 52, 236, 193, 62, 24, 144, 53, 231, 193, 148, 166, 250, 113, 2, 59, 247, 48,
                93, 30, 26, 15, 80, 247, 216, 112, 172, 122, 141, 237, 130, 69, 149, 141, 159, 168,
                109, 95, 125, 223, 32, 244, 160, 213, 12, 91, 81, 26, 109, 113, 153, 173, 74, 102,
                212, 92, 122, 31, 182, 132, 8, 131, 227, 167, 75, 255, 40, 31, 71, 164, 12, 171,
                177, 139, 37, 144, 119, 33, 87, 231, 80, 137, 67, 103, 100, 25, 248, 11, 205, 200,
                205, 228, 55, 243, 19, 158, 138, 55, 65, 182, 158, 220, 199, 253, 142, 132, 113,
                218, 66, 225, 65, 141, 250, 48, 144, 231, 73, 38, 58, 148, 239, 199, 110, 168, 198,
                206, 17, 135, 232, 2, 7, 110, 37, 135, 143, 157, 72, 147, 69, 163, 146, 76, 19, 8,
                157, 51,
            ],
        };
        let (payload, frame) = _parse_etherprotocol(packet.data).unwrap();
        println!("{:?}", frame);
        let (_payload2, etherprot) =_parse_ipv4(payload).unwrap();
        println!("{:?}", etherprot);
        assert_eq!(etherprot.version, 4);
        assert_eq!(etherprot.type_of_service, 0);
        assert_eq!(etherprot.length, 540);
        assert_eq!(etherprot.id, 8751);
        assert_eq!(etherprot.flags, 0);
        assert_eq!(etherprot.fragment_offset, 0);
        assert_eq!(etherprot.ttl, 128);
        assert_eq!(etherprot.protocol, IPProtocol::Udp);
        assert_eq!(etherprot.checksum, 0);
        assert_eq!(etherprot.source_addr.to_string(), "192.168.50.241");
        assert_eq!(etherprot.dest_addr.to_string(), "1.209.175.116");
    }
}
