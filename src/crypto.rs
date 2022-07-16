use std::error::Error;

use chacha20poly1305::aead::{Aead, NewAead};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use rand::RngCore;

use crate::conv::Conversation;

use argon2;

static ARGON2_CONFIG: argon2::Config = argon2::Config {
    variant: argon2::Variant::Argon2id,
    version: argon2::Version::Version13,
    mem_cost: 4096,
    time_cost: 1,
    lanes: 2,
    thread_mode: argon2::ThreadMode::Parallel,
    secret: &[],
    ad: &[],
    hash_length: 32
};

pub fn symmetric_decrypt(encrypted: &[u8], nonce: &[u8; 12], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = Key::from_slice(key); // 32-bytes key
    let nonce = Nonce::from_slice(nonce); // 12-bytes; unique per message

    let cipher = ChaCha20Poly1305::new(key);

    // todo: this could be optimized by doing it in-place somehow
    let decrypted = cipher
        .decrypt(nonce, encrypted)
        .or(Err("decryption failure"))?;

    return Ok(decrypted);
}

pub fn symmetric_encrypt(plain: &[u8], nonce: &[u8; 12], key: &[u8; 32]) -> Result<Vec<u8>, Box<dyn Error>> {
    let nonce = Nonce::from_slice(nonce); // 12-bytes; unique per message
    let key = Key::from_slice(key); // 32-bytes key
    let cipher = ChaCha20Poly1305::new(key);

    // todo: this could be optimized by doing it in-place somehow
    let encrypted = cipher.encrypt(nonce, plain).or(Err("encryption failure"))?;

    return Ok(encrypted);
}

pub fn generate_12b_nonce() -> [u8; 12] {
    // generate a random nonce
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    return nonce;
}


/**
    Decrypt a packet with ChaCha20Poly1305, then verify its counter against the
    conversation's, and update the conversation counter ready for new packets.

    The input message must have NO MAGIC ATTACHED TO IT.
*/
pub fn decrypt_payload<'a>(
    conv: &mut Conversation<'_>,
    // chacha20poly1305(counter + message) + nonce
    msg: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {

    // check for shared secret
    if conv.shared_secret.is_none() {
        Err("shared secret not initialized")?;
    }
    
    if msg.len() <= 12 {
        Err("incoming packet size too small")?;
    }

    // get nonce from packet: nonce is last 12 bytes of message
    let nonce = &msg[msg.len()-12..];
    let nonce: &[u8; 12] = nonce.try_into().unwrap();

    // data is everything before nonce
    let encrypted = &msg[..msg.len() - 12];

    // if shared secret exists decrypt otherwise error
    let decrypted = symmetric_decrypt(
        encrypted,
        nonce,
        conv.shared_secret.as_ref().unwrap().as_bytes(),
    )?;

    // make sure the decrypted message is big enough to even have a counter
    if decrypted.len() < 2 {
        Err("no counter in decrypted data (2 bytes)")?;
    }

    // get encrypted packet counter
    let packet_counter: [u8; 2] = decrypted[0..2].try_into().unwrap();
    let packet_counter = u16::from_be_bytes(packet_counter);

    // compare the counters
    if conv.counter.unwrap() != packet_counter {
        // invalid counter, packet must be replayed
        // drop connection
        Err(format!("invalid counter, packet possibly replayed? expected: {}, got: {}", conv.counter.unwrap(), packet_counter))?;
    }

    // update conversation counter (+1)
    conv.counter = Some(conv.counter.unwrap().wrapping_add(1));

    return Ok(decrypted[2..].to_vec());
}

/**
    Attach the conversation's counter to the front of the message, then encrypt
    with ChaCha20Poly1305, attaching a randomly generated nonce to the end of the message.
*/
pub fn encrypt_payload<'a>(
    conv: &mut Conversation<'_>,
    plain: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    // prepend counter to the plaintext
    let mut msg = vec![];
    msg.extend_from_slice(&conv.counter.unwrap().to_be_bytes());
    msg.extend_from_slice(plain);

    // update conversation counter (+1)
    conv.counter = Some(conv.counter.unwrap().wrapping_add(1));

    // make a nonce
    let nonce = generate_12b_nonce();

    // encrypt the (counter+plaintext)
    let mut body = symmetric_encrypt(
        msg.as_slice(),
        &nonce,
        conv.shared_secret.as_ref().unwrap().as_bytes(),
    )?;

    body.extend_from_slice(nonce.as_slice());

    return Ok(body); // chacha20poly1305(counter + message) + nonce
}

pub fn hash_hash(plaintext: &[u8]) -> String {
    let salt = generate_12b_nonce();

    let hashed = argon2::hash_encoded(plaintext, &salt, &ARGON2_CONFIG).unwrap();
    return hashed;
}

pub fn hash_verify(plaintext: &[u8], hash: &str) -> bool {
    return argon2::verify_encoded(hash, plaintext).unwrap();
}