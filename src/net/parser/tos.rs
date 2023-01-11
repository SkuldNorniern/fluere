const DSCP_MASK: u8 = 0b1111_1100;
const TOS_MASK: u8 = 0b0000_0011;

pub fn dscp_to_tos(dscp: u8) -> u8 {
    (dscp << 2) & TOS_MASK
}