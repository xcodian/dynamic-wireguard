const MAGIC: u8 = 0xAA;

pub fn make(encrypt_bit: bool) -> u8 {
    if encrypt_bit {
        return MAGIC | 0x1;
    }

    return MAGIC;
}

pub fn parse(magic: u8) -> Option<bool> {
    // validate 7 bits of magic
    if (magic & MAGIC) != MAGIC {
        // invalid magic
        return None;
    }

    // return whether the encryption bit is set
    // true  = following data encrypted
    // false = following data not encrypted
    Some((magic & 0x01) == 0x01)
}