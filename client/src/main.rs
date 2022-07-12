use rand::rngs::OsRng;
use tokio::net::TcpStream;

use x25519_dalek::StaticSecret;

use crate::fingerprint::ask_user_to_verify_fingerprint;

pub mod fingerprint;
pub mod packet;

#[tokio::main]
async fn main() {
    // println!("Connecting to remote...");
    let socket = TcpStream::connect("127.0.0.1:8000").await;

    if let Err(ref e) = socket {
        println!("failed to connect: {}", e);
        return;
    }

    let mut socket = socket.unwrap();

    let client_private_key = StaticSecret::new(&mut OsRng);
    // let public = PublicKey::from(&private).to_bytes();

    let res = packet::key_exchange(&mut socket, &client_private_key).await;

    if let Err(e) = res {
        println!("keyex failure: {}", e);
        return;
    }

    let (server_public_key, counter_init) = res.unwrap();

    if !ask_user_to_verify_fingerprint(server_public_key.as_bytes()) {
        // server key not trusted
        println!("Aborting connection.");
        return;
    }

    println!("Obtaining configuration...");

    let shared_secret = client_private_key.diffie_hellman(&server_public_key);

    println!(
        "    counter: {} secret: {}",
        counter_init,
        hex::encode(shared_secret.as_bytes())
    );

    // do real data sending
    packet::obtain_config(&mut socket, &shared_secret, counter_init).await;

    // create_interface(&rsp, &private).await;
}
