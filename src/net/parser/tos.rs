/// Convert a 6-bit DSCP value into the ToS byte fluere records.
///
/// The DS field occupies the upper six bits of the IPv4 ToS byte / IPv6
/// traffic class, so the conversion is a two-bit shift. This used to be a
/// lookup table covering 21 well-known code points, which turned every other
/// valid DSCP - including whole ranges of the AF and CS space, and any local
/// use value - into an error that callers silently mapped to zero.
///
/// The low two bits (ECN) are not part of DSCP and are reported as zero here.
#[inline]
pub fn dscp_to_tos(dscp: u8) -> u8 {
    (dscp & 0x3F) << 2
}

#[cfg(test)]
mod tests {
    use super::dscp_to_tos;

    #[test]
    fn well_known_code_points_keep_their_historical_values() {
        // Same results the old lookup table produced.
        for (dscp, tos) in [
            (0u8, 0u8),
            (8, 32),
            (10, 40),
            (18, 72),
            (26, 104),
            (34, 136),
            (46, 184),
            (48, 192),
            (56, 224),
        ] {
            assert_eq!(dscp_to_tos(dscp), tos);
        }
    }

    #[test]
    fn code_points_missing_from_the_old_table_now_convert() {
        // 44 is VOICE-ADMIT; 4 and 6 are valid local-use values. All three
        // used to return an error and be recorded as ToS 0.
        assert_eq!(dscp_to_tos(44), 176);
        assert_eq!(dscp_to_tos(4), 16);
        assert_eq!(dscp_to_tos(6), 24);
    }

    #[test]
    fn values_wider_than_six_bits_are_masked() {
        assert_eq!(dscp_to_tos(0xFF), 252);
    }
}
