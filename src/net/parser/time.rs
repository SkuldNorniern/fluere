pub fn parse_microseconds(sec: u64, usec:u64) -> u64{
    sec * 1000000 + usec
}