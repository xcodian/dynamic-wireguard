use std::net::Ipv4Addr;
use x25519_dalek::{PublicKey, StaticSecret};
use libaes::Cipher;

pub struct ConnRsp {
    pub wg_endpoint_host: Ipv4Addr,
    pub wg_endpoint_port: u16,
    pub gateway_addr: Ipv4Addr,
    pub client_addr: Ipv4Addr,
}

impl ConnRsp {
    pub fn assemble_into(
        &self,
        client_key: [u8; 32],
        private_key: &StaticSecret,
        out: &mut [u8; 32 + 16],
    ) {
        let ep_host = self.wg_endpoint_host.octets();
        let ep_port = self.wg_endpoint_port.to_be_bytes(); // u16 -> u8u8 big endian

        let gw_host = self.gateway_addr.octets();
        let cl_host = self.client_addr.octets();

        // parse client key
        let client_key = PublicKey::from(client_key);

        // compute server public key
        let public_key = PublicKey::from(private_key).to_bytes();

        // fill buffer
        out[0..32].copy_from_slice(&public_key); // 32 bytes public key (first 16 reused as IV)
        out[32..36].copy_from_slice(&ep_host); // 4 bytes endpoint host
        out[36..38].copy_from_slice(&ep_port); // 2 bytes endpoint port
        out[38..42].copy_from_slice(&gw_host); // 4 bytes gateway ip
        out[42..46].copy_from_slice(&cl_host); // 4 bytes client ip

        // compute shared secret with DH
        let shared_secret = private_key.diffie_hellman(&client_key).to_bytes();

        // println!("shared secret: {}", hex::encode(shared_secret));
        // println!("payload: {}", hex::encode(&out[32..46]));

        // re-encrypt the last part of the buffer with the shared secret
        let cipher = Cipher::new_256(&shared_secret);

        let encrypted = cipher.cbc_encrypt(
            &out[0..16], // reuse first 16 bytes of public key as IV
            &out[32..46] // input 14 bytes of data
        );

        // copy data back in (will be 16 bytes instead of 14 thanks to AES)
        out[32..48].copy_from_slice(encrypted.as_slice());
    }
}
