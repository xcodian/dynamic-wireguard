use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::Arc;

use colored::Colorize;
use dynamic_wireguard::conv;

use futures::{select, FutureExt};
use interface::delete_interface;
use rand::rngs::OsRng;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use tokio::signal::ctrl_c;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod config;
pub mod fingerprint;
pub mod interface;
pub mod net;
pub mod verifyauth;

use crate::config::ServerConfig;
use crate::fingerprint::print_fingerprint;
use crate::interface::create_server_interface;

#[tokio::main]
async fn main() {
    // generate private key
    let private_key = StaticSecret::new(&mut OsRng);

    // create server config in an Arc to share it with the workers
    let conf = Arc::new(ServerConfig {
        if_name: "wgd0".to_string(),
        public_key: PublicKey::from(&private_key),
        private_key: private_key,
        gateway: Ipv4Addr::from_str("10.8.0.1").unwrap(),
        wg_port: 4000,
        cidr: 24,
    });

    if let Err(e) = create_server_interface(&conf).await {
        println!("{} {}", "error:".bright_red().bold(), e);
        return;
    };

    // show the key fingerprint as server
    print_fingerprint(&conf.public_key.to_bytes());

    // bind a tcp listener
    let listener = TcpListener::bind("0.0.0.0:8000")
        .await
        .expect("could not bind");

    println!("Listening for connections...");

    loop {
        // wait for either to happen
        select! {
            // someone wants to shut the server down
            _ = ctrl_c().fuse() => {
                println!();
                break;
            },
            // there is a new connection
            try_accept = listener.accept().fuse() => {
                let (_sock, _) = try_accept.unwrap();
                println!("+connection");

                // increment arc ref count
                let conf = conf.clone();

                let new_conversation = async move {
                    let mut buf = [0; 256]; // alloc 256 bytes for incoming data

                    let mut conv = conv::Conversation {
                        socket: _sock,
                        local_private_key: &conf.private_key,
                        remote_public_key: None,
                        shared_secret: None,
                        counter: None,
                        auth_method: None,
                    };

                    // read forever
                    loop {
                        let size = conv.socket.read(&mut buf).await.expect("could not read");

                        if size == 0 {
                            // socket shutdown
                            break;
                        }

                        // process the packet
                        let res = net::process_packet(&mut conv, &conf, &mut buf[..size]).await;

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
                };

                tokio::spawn(new_conversation);
            }
        }
    }

    println!("Cleaning up...");
    if let Err(e) = delete_interface(conf.if_name.clone()).await {
        println!("{} failed to delete interface: {}", "warn(cleanup):".bright_yellow().bold(), e);
    };
}
