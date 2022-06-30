use std::io::IoSlice;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand_core::{OsRng, RngCore};
use tokio::io::AsyncWriteExt;
use x25519_dalek::PublicKey;

use crate::conv::Conversation;

const MAGIC: u8 = 0xAA;

pub async fn process_packet(conv: &mut Conversation<'_>, buf: &mut [u8]) -> Option<()> {
    let header = buf[0];

    // validate 7 bits of magic
    if (header & MAGIC) != MAGIC {
        // invalid magic, drop the connection
        return None;
    }

    let buf = &mut buf[1..]; // strip header

    // check if encrypt bit is not set
    if (header << 7) != 0x80 {
        // this packet must be a key + counter request
        if let Some(_) = conv.counter {
            // counter is already initialized but this is a key request??
            // drop the connection
            return None;
        }

        // read client's key
        let pub_key: [u8; 32] = buf[0..32].try_into().ok()?;
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
                IoSlice::new(server_public_key.as_bytes()),
                IoSlice::new(&counter_init.to_be_bytes()),
            ])
            .await
            .ok()?;

        return Some(());
    }

    // if shared secret exists decrypt otherwise error
    decrypt(buf, conv.shared_secret.as_ref()?.as_bytes());

    // strip chacha20 12-byte nonce to leave only decrypted data
    let buf = &mut buf[12..];

    // get encrypted packet counter
    let packet_counter = u16::from_be_bytes(buf[0..2].try_into().ok()?);

    if conv.counter?.wrapping_add(1) != packet_counter {
        // invalid counter, packet must be replayed
        // drop connection
        return None;
    }

    conv.counter = Some(conv.counter?.wrapping_add(1));

    let packet_id = buf[0];

    match packet_id {
        // echo
        0 => {
            conv.socket.write_all(buf).await;
        }
        _ => {
            println!("unknown packet id: {}", packet_id)
        }
    }

    return Some(());
}

/*
    Decrypt a message sent by the client
*/
async fn decrypt(buf: &mut [u8], key: &[u8; 32]) -> Option<()> {
    // read key first
    let key = Key::from_slice(key); // 32-bytes key
    let nonce = Nonce::from_slice(&buf[..12]); // 12-bytes; unique per message

    let cipher = ChaCha20Poly1305::new(key);

    // todo: this could be optimized by doing it in-place somehow
    let decrypted = cipher.decrypt(nonce, &buf[12..]).ok()?;
    (&mut buf[12..]).copy_from_slice(decrypted.as_slice());

    return Some(());
}
