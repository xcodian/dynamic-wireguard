#[derive(Debug)]
pub struct ConnReq<'l> {
    pub password: &'l str,
    pub pub_key: [u8; 32],
}

impl ConnReq<'_> {
    pub fn from_packet(data: &[u8]) -> Option<ConnReq> {
        /*
            Client Connection Request:
            +--------------------------------+--------------------------------+
            | public key (32 bytes)          | username (up to 32 bytes)      |
            +--------------------------------+--------------------------------+
        */

        if data.len() >= 64 {
            println!("connection request too big: {} bytes", data.len());
            return None;
        }

        if data.len() < (32 + 1) {
            println!("connection request too short: {} bytes", data.len());
            return None;
        }

        let pub_key: [u8; 32] = data[..32].try_into().expect("wrong public key size");

        return Some(ConnReq {
            pub_key: pub_key,
            password: std::str::from_utf8(&data[32..]).ok()?,
        });
    }
}