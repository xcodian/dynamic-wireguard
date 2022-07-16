use dynamic_wireguard::{conv, logger};
use log::{debug, error, info};
use rand::rngs::OsRng;
use tokio::net::TcpStream;

use x25519_dalek::StaticSecret;

use crate::fingerprint::verify_fingerprint;

pub mod fingerprint;
pub mod getauth;
pub mod interface;
pub mod net;

#[tokio::main]
async fn main() {
    logger::init().unwrap();

    debug!("connecting...");
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:8000".to_string());

    let socket = TcpStream::connect(target).await;

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

    let res = net::key_exchange(&mut conv).await;

    if let Err(e) = res {
        error!("{}", e);
        return;
    }

    if !verify_fingerprint(
        &remote_ip.to_string(),
        conv.remote_public_key.unwrap().as_bytes(),
    ) {
        // server key not trusted
        error!("Remote identity cannot be trusted, aborting.");
        return;
    }

    let credential = getauth::get_auth(&conv.auth_method.unwrap());

    if let Err(e) = credential {
        error!("{}", e);
        return;
    }

    let credential = credential.unwrap();

    // obtain configuration
    let config = net::obtain_config(&mut conv, credential.as_slice()).await;

    if let Err(e) = config {
        error!("{}", e);
        return;
    }

    let config = config.unwrap();

    interface::create_interface(
        &config,
        &client_private_key,
        &conv.remote_public_key.unwrap(),
        remote_ip,
    )
    .await;
}
