use std::error::Error;
use std::io::IoSlice;
use std::net::Ipv4Addr;
use std::str::FromStr;

use dynamic_wireguard::auth::AuthMethod;
use dynamic_wireguard::conv::Conversation;
use dynamic_wireguard::wgconfig::WgAddrConfig;
use dynamic_wireguard::{crypto, magic};

use log::{debug, warn, info};
use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use x25519_dalek::PublicKey;

use crate::config::ServerConfig;
use crate::interface::add_peer_to_interface;
use crate::verifyauth::verify;

pub async fn process_packet(
    conv: &mut Conversation<'_>,
    conf: &ServerConfig,
    msg: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let magic = *msg.get(0).ok_or("no header to parse")?;

    let is_encrypted = magic::parse(magic).ok_or("header: invalid magic")?;

    let encrypted = &mut msg[1..]; // strip 1 byte magic

    if !is_encrypted {
        // this packet must be a key + counter request (handshake)
        let res = keyex_reply(conv, encrypted).await;

        return match res {
            Ok(_) => Ok(()),
            Err(e) => Err("keyex: ".to_string() + e.to_string().as_str())?,
        };
    }

    // this packet must be encrypted
    let decrypted = crypto::decrypt_payload(conv, encrypted)?;

    let packet_id = decrypted[0];

    {
        // strip packet id
        let msg = &decrypted[1..];

        // echo decrypted data back
        // conv.socket.write_all(decrypted.as_slice()).await?;

        match packet_id {
            // config request
            1 => {
                info!("client requested config");
                let remote_config = config_reply(conv, msg).await?;

                // make local interface
                add_peer_to_interface(&conf, remote_config.assigned_address, &conv.remote_public_key.unwrap()).await?;
            }
            _ => {
                warn!("unknown packet id: {}", packet_id)
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

    conv.auth_method = Some(AuthMethod::UsernamePassword);

    // send public key & counter initializer to the client
    info!("keyex: sending handshake reply");
    conv.socket
        .write_vectored(&[
            IoSlice::new(&[magic::make(false)]),
            IoSlice::new(server_public_key.as_bytes()),
            IoSlice::new(&counter_init.to_be_bytes()),
            IoSlice::new(&[conv.auth_method.unwrap().to_u8()]),
        ])
        .await?;

    return Ok(());
}

pub async fn config_reply(conv: &mut Conversation<'_>, msg: &[u8]) -> Result<WgAddrConfig, Box<dyn Error>> {
    // verify authentication method
    if !verify(msg, conv) {
        Err(format!("authentication failed ({})", conv.auth_method.unwrap().name()))?;
    }

    // make config
    let config = WgAddrConfig {
        wg_endpoint_port: 4000u16,
        internal_gateway: Ipv4Addr::from_str("10.8.0.1").unwrap(),
        assigned_address: Ipv4Addr::from_str("10.8.0.69").unwrap(),
    };

    // pack into bytes & encrypt
    let data = crypto::encrypt_payload(conv, &config.serialize())?;

    // send
    conv.socket
        .write_vectored(&[
            IoSlice::new(&[magic::make(true)]),
            IoSlice::new(&data)
        ])
        .await?;

    return Ok(config);
}
