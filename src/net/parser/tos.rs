use crate::net::NetError;

pub fn dscp_to_tos(dscp: u8) -> Result<u8, NetError> {
    let tos = match dscp {
        0 => 0,
        8 => 32,
        10 => 40,
        12 => 48,
        14 => 56,
        16 => 64,
        18 => 72,
        20 => 80,
        22 => 88,
        24 => 96,
        26 => 104,
        28 => 112,
        30 => 120,
        32 => 128,
        34 => 136,
        36 => 144,
        38 => 152,
        40 => 160,
        46 => 184,
        48 => 192,
        56 => 224,
        _ => return Err(NetError::UnknownDSCP(dscp)),
    };

    Ok(tos)
}
