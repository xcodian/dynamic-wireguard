use clap::Parser;
use cli::ComplexHost;
use dynamic_wireguard::{conv, logger};
use log::{error, info};
use rand::rngs::OsRng;
use tokio::net::TcpStream;

use x25519_dalek::StaticSecret;

use crate::{cli::Cli, fingerprint::verify_fingerprint};

pub mod cli;
pub mod fingerprint;
pub mod getauth;
pub mod interface;
pub mod net;

#[tokio::main]
async fn main() {
    logger::init().unwrap();

    let cli = Cli::parse();

    match cli.command {
        cli::Commands::Connect { host, interface } => {
            // todo: make this increment the number
            connect(host, interface.unwrap_or(String::from("wgdyn0"))).await;
        }
        cli::Commands::Disconnect { host } => todo!(),
        cli::Commands::Prune { host, interface } => todo!(),
    };
}

async fn connect(host: ComplexHost, if_name: String) {
    info!("Connecting to {}...", host.exact);
    let socket = TcpStream::connect(host.addrs.as_slice()).await;

    if let Err(ref e) = socket {
        error!("failed to connect: {}", e);
        return;
    }

    let socket = socket.unwrap();

    let remote_ip = match socket.peer_addr().unwrap() {
        std::net::SocketAddr::V4(addr) => addr.ip().clone(),
        std::net::SocketAddr::V6(_) => unimplemented!("IPv6 not supported yet"),
    };

    let client_private_key = StaticSecret::new(&mut OsRng);

    // create conversation object
    let mut conv = conv::Conversation {
        socket: socket,
        local_private_key: &client_private_key,
        remote_public_key: None,
        shared_secret: None,
        counter: None,
        auth_method: None,
    };

    if let Err(e) = net::key_exchange(&mut conv).await {
        return error!("{}", e);
    }

    if !verify_fingerprint(
        &remote_ip.to_string(),
        conv.remote_public_key.unwrap().as_bytes(),
    ) {
        // server key not trusted
        error!("Remote identity cannot be trusted, aborting.");
        return;
    }

    let credential = match getauth::get_auth(&conv.auth_method.unwrap()) {
        Ok(c) => c,
        Err(e) => return error!("{}", e),
    };

    // obtain configuration
    let addr_config = match net::obtain_config(&mut conv, credential.as_slice()).await {
        Ok(c) => c,
        Err(e) => return error!("{}", e),
    };

    interface::create_interface(
        &if_name,
        &addr_config,
        &client_private_key,
        &conv.remote_public_key.unwrap(),
        remote_ip,
    )
    .await;
}
