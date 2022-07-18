use std::sync::Arc;
use clap::Parser;
use dynamic_wireguard::{auth::AuthMethod, conv, logger};

use futures::{select, FutureExt};
use interface::delete_interface;
use log::warn;
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use tokio::signal::ctrl_c;
use x25519_dalek::PublicKey;

pub mod config;
pub mod fingerprint;
pub mod interface;
pub mod key;
pub mod leasing;
pub mod net;
pub mod verifyauth;
pub mod cli;

use crate::cli::Cli;
use crate::config::ServerConfig;
use crate::fingerprint::print_fingerprint;
use crate::interface::create_server_interface;
use crate::key::get_key;

use log::{error, info};

#[tokio::main]
async fn main() {
    logger::init().unwrap();

    let cli = Cli::parse();

    // get a private key
    let private_key = match get_key(&cli.key_file, cli.gen_key) {
        Ok(k) => k,
        Err(e) => return error!("read private key: {}", e),
    };

    let subnet = cli.subnet.unwrap_or("10.100.0.0/24".parse().unwrap());

    // create server config in an Arc to share it with the workers
    let conf = Arc::new(ServerConfig {
        if_name: cli.if_name.unwrap_or("wgd0s".to_string()),
        public_key: PublicKey::from(&private_key),
        private_key: private_key,
        gateway: cli
            .gateway
            // try to get a .1 address or if you must .0
            .unwrap_or(subnet.nth(1).unwrap_or(subnet.nth(0).unwrap())),
        subnet: subnet,
        wg_port: cli.wg_port.unwrap_or(51820),
        auth_method: cli.auth.unwrap_or(AuthMethod::Open),
    });

    if !conf.subnet.contains(conf.gateway) {
        return error!(
            "gateway address {} is outside of internal subnet {} (use -s or -g to change)",
            conf.gateway, conf.subnet
        );
    }

    if conf.auth_method == AuthMethod::Open {
        warn!("auth method is set to open; anyone may connect to this server (change with -a)");
    } else {
        info!("authenticating clients with {}", conf.auth_method);
    }

    if let Err(e) = create_server_interface(&conf).await {
        return error!("{}", e);
    };

    // show the key fingerprint as server
    print_fingerprint(&conf.public_key.to_bytes());

    // bind a tcp listener
    let listener =
        match TcpListener::bind(cli.bind.unwrap_or("0.0.0.0:7575".parse().unwrap())).await {
            Ok(listener) => listener,
            Err(e) => {
                return error!("{}", e);
            }
        };

    info!("listening for connections...");

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
                info!("connection opened: {}", _sock.peer_addr().unwrap());

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
                                id = "unidentified".to_string();
                            }

                            error!("[{}]: {}", id, e);
                            break;
                        }
                    }

                    // FIXME: this is stupid
                    info!("connection closed: {}", match conv.socket.peer_addr() { Ok(addr) => addr.to_string(), Err(_) => "no address (disconnected)".to_string() });
                };

                tokio::spawn(new_conversation);
            }
        }
    }

    info!("Cleaning up...");
    if let Err(e) = delete_interface(conf.if_name.clone()).await {
        error!("cleanup: failed to delete interface: {}", e);
    };
}
