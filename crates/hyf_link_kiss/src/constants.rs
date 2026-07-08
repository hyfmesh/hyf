pub const KISS_FEND: u8 = 0xc0;
pub const KISS_FESC: u8 = 0xdb;
pub const KISS_TFEND: u8 = 0xdc;
pub const KISS_TFESC: u8 = 0xdd;
pub const KISS_CMD_DATA: u8 = 0x00;
pub const KISS_CMD_READY: u8 = 0x0f;

#[cfg(test)]
mod tests {
    use super::{KISS_CMD_DATA, KISS_CMD_READY, KISS_FEND, KISS_FESC, KISS_TFEND, KISS_TFESC};

    #[test]
    fn kiss_constants_match_profile_values() {
        assert_eq!(KISS_FEND, 0xc0);
        assert_eq!(KISS_FESC, 0xdb);
        assert_eq!(KISS_TFEND, 0xdc);
        assert_eq!(KISS_TFESC, 0xdd);
        assert_eq!(KISS_CMD_DATA, 0x00);
        assert_eq!(KISS_CMD_READY, 0x0f);
    }
}
