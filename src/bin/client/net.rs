use std::error::Error;
use std::io::IoSlice;
use std::time::Duration;

use colored::Colorize;
use dynamic_wireguard::auth::AuthMethod;
use dynamic_wireguard::wgconfig::WgAddrConfig;
use dynamic_wireguard::{conv::Conversation, crypto};
use dynamic_wireguard::magic;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;


use x25519_dalek::PublicKey;

// use common::magic;

pub async fn key_exchange(conv: &mut Conversation<'_>) -> Result<(), Box<dyn Error>> {
    let client_public_key = PublicKey::from(conv.local_private_key);

    // send magic & client public key
    conv.socket
        .write_vectored(&[
            IoSlice::new(&[magic::make(false)]),
            IoSlice::new(&client_public_key.to_bytes()),
        ])
        .await?;

    //                header
    //                |   server public
    //                |   |    counter initial value
    //                |   |    |   authentication method
    let mut buf = [0; 1 + 32 + 2 + 1];

    // read from the socket
    let size = conv.socket.read(&mut buf).await.expect("Could not read on socket");

    // ensure exact size for handshake
    if size != 1 + 32 + 2 + 1 {
        Err("Invalid handshake response size")?;
    }

    let is_encrypted = magic::parse(buf[0]).ok_or("invalid magic")?;

    if is_encrypted {
        // should not be encrypted yet
        Err("Handshake marked as encrypted")?;
    }

    // strip header
    let buf = &mut buf[1..];

    let server_public_key: [u8; 32] = buf[0..32].try_into().unwrap();
    
    conv.remote_public_key = Some(
        PublicKey::from(server_public_key)
    );

    conv.shared_secret = Some(
        conv.local_private_key.diffie_hellman(&conv.remote_public_key.unwrap())
    );

    conv.counter = Some(
        u16::from_be_bytes(buf[32..32 + 2].try_into().unwrap())
    );

    conv.auth_method = Some(
        AuthMethod::from_u8(buf[32 + 2])?
    );

    return Ok(());
}

pub async fn obtain_config(conv: &mut Conversation<'_>, auth: &[u8]) -> Result<WgAddrConfig, Box<dyn Error>> {
    let mut data: Vec<u8> = Vec::with_capacity(1 + auth.len());
    data.push(0x01); // packet id: CONFIG_REQ
    data.extend_from_slice(auth);

    // encrypt the data
    let encrypted = crypto::encrypt_payload(conv, data.as_slice())?;

    // send the encrypted data
    conv.socket.write_vectored(&[
        // magic (encrypt = yes)
        IoSlice::new(&[magic::make(true)]),
        // encrypted data
        IoSlice::new(&encrypted),
    ]).await?;

    // allocate a buffer for responses
    let mut buf = [0; 64]; // shouldn't be bigger really idk :/
    
    // wait for the response (5s)
    let result = timeout(Duration::from_secs(5), conv.socket.read(&mut buf)).await;

    if let Err(_) = result {
        Err("Timed out waiting for response from remote")?;
    }

    let size = result.unwrap()?;

    if size == 0 {
        Err(format!("Permission denied ({})", conv.auth_method.unwrap().name()))?;
    }

    let buf = &mut buf[..size];
    let is_encrypted = magic::parse(buf[0]).ok_or("invalid magic")?;
    if !is_encrypted {
        Err("Received unencrypted response")?;
    }

    let buf = &mut buf[1..]; // strip magic

    let decrypted = crypto::decrypt_payload(conv, buf)?;

    // parse out into a config object
    let config = WgAddrConfig::deserialize(decrypted)?;

    println!(
        "Your internal IP: {}", 
        config.assigned_address.to_string().green()
    );

    return Ok(config);
}
