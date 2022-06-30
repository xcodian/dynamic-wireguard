use std::error::Error;
use tokio::net::TcpStream;

use rand_core::OsRng;
use x25519_dalek::StaticSecret;

use crate::user_input::verify_key_fingerprint;

pub mod magic;
pub mod packet;
pub mod user_input;

#[tokio::main]
async fn main() {
    println!("Connecting to remote...");
    let mut socket = TcpStream::connect("127.0.0.1:8000").await.unwrap();

    let client_private_key = StaticSecret::new(&mut OsRng);
    // let public = PublicKey::from(&private).to_bytes();

    println!("[1] -- do keyex with remote...");
    let res = packet::handshake(&mut socket, &client_private_key).await;

    if let Err(e) = res {
        println!("keyex failure: {}", e);
        return;
    }

    let (server_public_key, counter_init) = res.unwrap();

    let server_trusted = verify_key_fingerprint(server_public_key.as_bytes());

    if !server_trusted {
        return;
    }

    let shared_secret = client_private_key.diffie_hellman(&server_public_key);

    println!(
        "counter: {} secret: {}",
        counter_init,
        hex::encode(shared_secret.as_bytes())
    );

    // do real data sending

    // create_interface(&rsp, &private).await;
}