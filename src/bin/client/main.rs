use colored::Colorize;
use dynamic_wireguard::conv;
use rand::rngs::OsRng;
use tokio::net::TcpStream;

use x25519_dalek::StaticSecret;

use crate::fingerprint::ask_user_to_verify_fingerprint;

pub mod fingerprint;
pub mod procedures;

#[tokio::main]
async fn main() {
    // println!("Connecting to remote...");
    let socket = TcpStream::connect("127.0.0.1:8000").await;

    if let Err(ref e) = socket {
        println!("failed to connect: {}", e);
        return;
    }

    let client_private_key = StaticSecret::new(&mut OsRng);
    
    // create conversation object
    let mut conv = conv::Conversation {
        socket: socket.unwrap(),
        local_private_key: &client_private_key,
        remote_public_key: None,
        shared_secret: None,
        counter: None,
        auth_method: None
    };

    let res = procedures::key_exchange(&mut conv).await;

    if let Err(e) = res {
        println!("{} {}", "error:".bright_red(), e);
        return;
    }

    if !ask_user_to_verify_fingerprint(conv.remote_public_key.unwrap().as_bytes()) {
        // server key not trusted
        println!("Aborting connection.");
        return;
    }

    println!("Obtaining configuration...");

    conv.shared_secret = Some(
        client_private_key.diffie_hellman(&conv.remote_public_key.unwrap())
    );

    // do real data sending
    let config = procedures::obtain_config(&mut conv).await;

    if let Err(e) = config {
        println!("{} {}", "error:".bright_red(), e);
        return;
    }

    let config = config.unwrap();

    // create_interface(&rsp, &private).await;
}
