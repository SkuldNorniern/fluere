use pnet::packet::ip::IpNextHeaderProtocol;

pub fn protocol_to_number(protocol: IpNextHeaderProtocol) -> u8 {
    protocol.0
}
