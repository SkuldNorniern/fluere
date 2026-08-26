#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct MacAddress(pub [u8; 6]);

impl MacAddress {
    pub fn new(mac: [u8; 6]) -> Self {
        Self(mac)
    }
}
impl From<&[u8]> for MacAddress {
    fn from(mac: &[u8]) -> Self {
        let mut mac_array = [0; 6];
        mac_array.copy_from_slice(mac);
        MacAddress(mac_array)
    }
}
