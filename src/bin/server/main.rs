use std::sync::Arc;

use dynamic_wireguard::conv;

use rand::rngs::OsRng;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use x25519_dalek::{PublicKey, StaticSecret};

pub mod fingerprint;
pub mod procedures;

use crate::fingerprint::print_fingerprint;

#[tokio::main]
async fn main() {
    // #[cfg(not(debug_assertions))]
    // panic::set_hook(Box::new(|panic_info| {
    //     if let Some(s) = panic_info.payload().downcast_ref::<String>() {
    //         println!("error: {}", s);
    //     } else {
    //         println!("error");
    //     }
    // }));

    // generate private key
    let private_key = StaticSecret::new(&mut OsRng);
    // wrap in an arc
    let private_key = Arc::new(private_key);

    // show the key fingerprint as server
    print_fingerprint(&PublicKey::from(private_key.as_ref()).to_bytes());

    // bind a tcp listener
    let listener = TcpListener::bind("127.0.0.1:8000")
        .await
        .expect("could not bind");

    println!("Listening for connections...");

    loop {
        // accept a connection
        let (_sock, _) = listener.accept().await.unwrap();
        // increment arc ref count
        let private_key = private_key.clone();

        tokio::spawn(async move {
            let mut buf = [0; 256]; // alloc 256 bytes for incoming data

            let mut conv = conv::Conversation {
                socket: _sock,
                local_private_key: &private_key,
                remote_public_key: None,
                shared_secret: None,
                counter: None,
                auth_method: None,
            };

            loop {
                // read from the socket
                let size = conv.socket.read(&mut buf).await.expect("could not read");

                if size == 0 {
                    // socket shutdown
                    break;
                }

                // process the packet
                let res = procedures::process_packet(&mut conv, &mut buf[..size]).await;

                if let Err(e) = res {
                    // terminate connection if process_packet returns None
                    let id;
                    if let Some(k) = conv.remote_public_key {
                        id = hex::encode(k.as_bytes())[..8].to_string();
                    } else {
                        id = "unknown?".to_string();
                    }

                    println!("error[{}]: {}", id, e);
                    break;
                }
            }
        });
    }
}
