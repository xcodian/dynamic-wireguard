use std::error::Error;
use std::io::IoSlice;

use rand::rngs::OsRng;
use rand::RngCore;
use tokio::io::AsyncWriteExt;
use x25519_dalek::PublicKey;

use common::conv::Conversation;
use common::crypto;
use common::magic;

pub async fn process_packet(
    conv: &mut Conversation<'_>,
    msg: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let magic = *msg.get(0).ok_or("no header to parse")?;

    let is_encrypted = magic::parse(magic).ok_or("invalid magic")?;

    let buf = &mut msg[1..]; // strip 1 byte magic

    if !is_encrypted {
        // this packet must be a key + counter request (handshake)
        conv_keyex_reply(conv, buf).await?;

        println!(
            "counter: {} secret: {}",
            conv.counter.unwrap(),
            hex::encode(conv.shared_secret.as_ref().unwrap().as_bytes())
        );

        return Ok(());
    }

    // this packet must be encrypted
    let decrypted = crypto::conv_decrypt_payload(conv, buf)?;

    println!("received {} bytes of encrypted data", decrypted.len());

    let packet_id = decrypted[0];
    println!("packet id: {}", packet_id);

    // echo decrypted data back
    conv.socket.write_all(decrypted.as_slice()).await?;

    // match packet_id {
    //     // echo
    //     0 => {
    //         conv.socket.write_all(buf).await;
    //     }
    //     _ => {
    //         println!("unknown packet id: {}", packet_id)
    //     }
    // }

    return Ok(());
}

pub async fn conv_keyex_reply(
    conv: &mut Conversation<'_>,
    msg: &mut [u8],
) -> Result<(), Box<dyn Error>> {
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

    // send public key & counter initializer to the client
    conv.socket
        .write_vectored(&[
            IoSlice::new(&[magic::make(false)]),
            IoSlice::new(server_public_key.as_bytes()),
            IoSlice::new(&counter_init.to_be_bytes()),
        ])
        .await?;

    return Ok(());
}