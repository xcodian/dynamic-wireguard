use std::error::Error;
use std::io::IoSlice;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use tokio::io::AsyncWriteExt;
use x25519_dalek::PublicKey;

use crate::conv::Conversation;
use crate::magic;

pub async fn process_packet(
    conv: &mut Conversation<'_>,
    buf: &mut [u8],
) -> Result<(), Box<dyn Error>> {
    let magic = *buf.get(0).ok_or("no header to parse")?;

    let is_encrypted = magic::parse(magic).ok_or("invalid magic")?;

    let buf = &mut buf[1..]; // strip 1 byte magic

    if !is_encrypted {
        // this packet must be a key + counter request (handshake)
        if let Some(_) = conv.counter {
            // counter is already initialized but this is a key request??
            // drop the connection
            Err("keys already initialized")?;
        }

        // read client's key
        if buf.len() != 32 {
            Err("invalid handshake size (expected 32 bytes)")?;
        }

        let pub_key: [u8; 32] = buf[0..32].try_into().unwrap();
        let pub_key = PublicKey::from(pub_key);

        // take lower bits of random number and use as counter
        let counter_init = OsRng.next_u32() as u16;

        // derive shared secret with diffie hellman
        let shared_secret = conv.server_private_key.diffie_hellman(&pub_key);

        // set the values into the conversation
        conv.client_public_key = Some(pub_key);
        conv.counter = Some(counter_init);
        conv.shared_secret = Some(shared_secret);

        // compute public key
        let server_public_key = PublicKey::from(conv.server_private_key);

        // send public key & counter initializer to the client
        conv.socket
            .write_vectored(&[
                IoSlice::new(&[magic::make(false)]),
                IoSlice::new(server_public_key.as_bytes()),
                IoSlice::new(&counter_init.to_be_bytes()),
            ])
            .await?;

        println!(
            "counter: {} secret: {}",
            counter_init,
            hex::encode(conv.shared_secret.as_ref().unwrap().as_bytes())
        );

        return Ok(());
    }

    // if shared secret exists decrypt otherwise error
    decrypt(buf, conv.shared_secret.as_ref().unwrap().as_bytes())?;

    // strip chacha20 12-byte nonce to leave only decrypted data
    let buf = &mut buf[12..];

    // get encrypted packet counter
    if buf.len() < 2 {
        Err("no counter in decrypted data (2 bytes)")?;
    }

    let packet_counter: [u8; 2] = buf[0..2].try_into().unwrap();
    let packet_counter = u16::from_be_bytes(packet_counter);

    if conv.counter.unwrap().wrapping_add(1) != packet_counter {
        // invalid counter, packet must be replayed
        // drop connection
        Err("invalid counter, packet possibly replayed?")?;
    }

    conv.counter = Some(conv.counter.unwrap().wrapping_add(1));

    // strip counter
    let buf = &mut buf[2..];

    println!("received {} bytes of encrypted data", buf.len());

    // echo decrypted data back
    conv.socket.write_all(buf).await?;

    // let packet_id = buf[0];

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

/*
    Decrypt a message sent by the client
*/
fn decrypt(buf: &mut [u8], key: &[u8; 32]) -> Result<(), Box<dyn Error>> {
    if buf.len() < 12 {
        Err("no chacha20 nonce, message too short")?
    }

    // read key first
    let key = Key::from_slice(key); // 32-bytes key
    let nonce = Nonce::from_slice(&buf[..12]); // 12-bytes; unique per message

    let cipher = ChaCha20Poly1305::new(key);

    // todo: this could be optimized by doing it in-place somehow
    let decrypted = cipher
        .decrypt(nonce, &buf[12..])
        .or(Err("decryption failure"))?;

    (&mut buf[12..]).copy_from_slice(decrypted.as_slice());

    return Ok(());
}
