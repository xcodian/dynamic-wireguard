use std::sync::Arc;

use rand_core::{OsRng, RngCore};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::{io::AsyncReadExt, net::TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod conv;
pub mod packet;

use sha1::{Digest, Sha1};

#[tokio::main]
async fn main() {
    #[cfg(not(debug_assertions))]
    panic::set_hook(Box::new(|panic_info| {
        if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            println!("error: {}", s);
        } else {
            println!("error");
        }
    }));

    // generate private key
    let private_key = StaticSecret::new(&mut OsRng);
    // wrap in an arc
    let private_key = Arc::new(private_key);

    // show the key fingerprint as server
    print_key_fingerprint(&PublicKey::from(private_key.as_ref()).to_bytes());

    // bind a tcp listener
    let listener = TcpListener::bind(format!("127.0.0.1:{}", 8000))
        .await
        .expect("could not bind");

    println!("listening for connections");

    loop {
        // accept a connection
        let (socket, _) = listener.accept().await.unwrap();
        // increment arc ref count
        let private_key = private_key.clone();

        tokio::spawn(async move {
            let mut buf = [0; 256]; // alloc 256 bytes for incoming data

            let mut conv = conv::Conversation {
                socket: socket,
                server_private_key: &private_key,
                client_public_key: None,
                shared_secret: None,
                counter: None,
            };

            loop {
                // read from the socket
                let size = conv.socket.read(&mut buf).await.expect("could not read");

                // process the packet
                let res = packet::process_packet(&mut conv, &mut buf[..size]).await;

                if let None = res {
                    // terminate connection if process_packet returns None
                    break;
                }
            }
        });
    }
}

fn print_key_fingerprint(key: &[u8]) {
    // compute fingerprint
    let mut hasher = Sha1::new();
    hasher.update(key);

    let fingerprint = hasher.finalize();
    println!("public key:\n    {}", hex::encode(key));
    println!("public key fingerprint:\n    {}", hex::encode(fingerprint));
}
