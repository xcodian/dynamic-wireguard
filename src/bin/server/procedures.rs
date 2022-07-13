use std::error::Error;
use std::io::IoSlice;
use std::net::Ipv4Addr;
use std::str::FromStr;

use dynamic_wireguard::conv::Conversation;
use dynamic_wireguard::wgconfig::WgAddrConfig;
use dynamic_wireguard::{crypto, magic};

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use x25519_dalek::PublicKey;

pub async fn process_packet(
    conv: &mut Conversation<'_>,
    msg: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let magic = *msg.get(0).ok_or("no header to parse")?;

    let is_encrypted = magic::parse(magic).ok_or("invalid magic")?;

    let encrypted = &mut msg[1..]; // strip 1 byte magic

    if !is_encrypted {
        // this packet must be a key + counter request (handshake)
        return keyex_reply(conv, encrypted).await;
    }

    println!(
        "encrypted data ({} bytes): {}",
        encrypted.len(),
        hex::encode(&encrypted)
    );

    // this packet must be encrypted
    let decrypted = crypto::decrypt_payload(conv, encrypted)?;

    println!(
        "decrypted data ({} bytes): {}",
        decrypted.len(),
        hex::encode(&decrypted)
    );

    let packet_id = decrypted[0];
    println!("packet id: {}", packet_id);

    {
        // strip packet id
        let msg = &decrypted[1..];

        // echo decrypted data back
        // conv.socket.write_all(decrypted.as_slice()).await?;

        match packet_id {
            // config request
            1 => {
                println!("client requested config");
                config_reply(conv, msg).await?;
            }
            _ => {
                println!("unknown packet id: {}", packet_id)
            }
        }
    }

    return Ok(());
}

pub async fn keyex_reply(conv: &mut Conversation<'_>, msg: &mut [u8]) -> Result<(), Box<dyn Error>> {
    if let Some(_) = conv.counter {
        // counter is already initialized but this is a key request??
        // drop the connection
        Err("keys already initialized")?;
    }

    // read client's key
    if msg.len() != 32 {
        Err("invalid handshake size (expected 32 bytes)")?;
    }

    let pub_key: [u8; 32] = msg[0..32].try_into().unwrap();
    let pub_key = PublicKey::from(pub_key);

    // take lower bits of random number and use as counter
    let counter_init = OsRng.next_u32() as u16;

    // derive shared secret with diffie hellman
    let shared_secret = conv.local_private_key.diffie_hellman(&pub_key);

    // set the values into the conversation
    conv.remote_public_key = Some(pub_key);
    conv.counter = Some(counter_init);
    conv.shared_secret = Some(shared_secret);

    // compute public key
    let server_public_key = PublicKey::from(conv.local_private_key);

    conv.auth_method = Some(0x01u8); // auth method: password

    // send public key & counter initializer to the client
    let size = conv.socket
        .write_vectored(&[
            IoSlice::new(&[magic::make(false)]),
            IoSlice::new(server_public_key.as_bytes()),
            IoSlice::new(&counter_init.to_be_bytes()),
            IoSlice::new(&[conv.auth_method.unwrap()]),
        ])
        .await?;

    println!("keyex reply: sent {} bytes", size);

    return Ok(());
}

pub async fn config_reply(conv: &mut Conversation<'_>, msg: &[u8]) -> Result<(), Box<dyn Error>> {
    // TODO: verify authentication properly!
    // assert_eq!(msg, b"SomeHashedToken123");
    // println!("    authorization: {}", std::str::from_utf8(msg).unwrap());
    if msg != b"SomeHashedToken123" {
        Err("invalid credentials, denying connection")?;
    }

    // make config
    let config = WgAddrConfig {
        wg_endpoint_host: Ipv4Addr::from_str("123.45.67.89").unwrap(),
        wg_endpoint_port: 4000u16,
        internal_gateway: Ipv4Addr::from_str("10.8.0.1").unwrap(),
        assigned_address: Ipv4Addr::from_str("10.8.0.69").unwrap(),
    }
    // pack into bytes
    .serialize();

    // encrypt
    let data = crypto::encrypt_payload(conv, &config)?;

    // send
    conv.socket
        .write_vectored(&[
            IoSlice::new(&[magic::make(true)]),
            IoSlice::new(&data)
        ])
        .await?;

    return Ok(());
}
