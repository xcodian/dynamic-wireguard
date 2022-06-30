use std::net::Ipv4Addr;
use libaes::Cipher;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::user_input;
use std::process::exit;

pub struct ConnRsp {
    pub wg_endpoint_host: Ipv4Addr,
    pub wg_endpoint_port: u16,
    pub gateway_addr: Ipv4Addr,
    pub client_addr: Ipv4Addr,
    pub server_public_key: [u8; 32]
}

impl ConnRsp {
    pub async fn decode_and_verify(input: &[u8; 48], private_key: &StaticSecret) -> Option<ConnRsp> {
        let server_public_key: [u8; 32] = input[..32].try_into().ok()?;

        if !user_input::verify_key_fingerprint(&server_public_key) {
            println!("Identity verifiction declined, exiting now.");
            exit(1);
        }

        let server_key = PublicKey::from(server_public_key);

        // compute shared secret from server public key
        let shared_secret = private_key.diffie_hellman(&server_key).to_bytes();

        // decrypt the payload with the shared secret
        let cipher = Cipher::new_256(&shared_secret);

        let payload = cipher.cbc_decrypt(
            &input[..16], // reuse first 16 bytes of public key as IV
            &input[32..], // input last 32 bytes of encrypted data
        );

        // vec to slice
        let payload = payload.as_slice();

        let ep_host = ip_from_slice(&payload[0..4])?;

        // read u16 from payload bytes
        let ep_port: u16 = ((payload[4] as u16) << 8) | payload[5] as u16;

        let gw_host = ip_from_slice(&payload[6..10])?;
        let cl_host = ip_from_slice(&payload[10..14])?;
        
        // println!("endpoint: {}:{}", ep_host, ep_port);
        // println!("peer: {}", gw_host);
        // println!("me: {}", cl_host);

        return Some(ConnRsp{
            wg_endpoint_host: ep_host,
            wg_endpoint_port: ep_port,
            gateway_addr: gw_host,
            client_addr: cl_host,
            server_public_key: server_public_key
        })
    }
}

fn ip_from_slice(slice: &[u8]) -> Option<Ipv4Addr> {
    let sized_buf: [u8; 4] = slice.try_into().ok()?;
    return sized_buf.try_into().ok();
}