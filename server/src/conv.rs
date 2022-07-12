
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub struct Conversation<'a> {
    pub socket: TcpStream,
    pub server_private_key: &'a StaticSecret,
    pub client_public_key: Option<PublicKey>,
    pub shared_secret: Option<SharedSecret>,
    pub counter: Option<u16>,
}
