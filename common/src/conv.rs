
use tokio::net::TcpStream;
use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};

pub struct Conversation<'a> {
    pub socket: TcpStream,
    pub local_private_key: &'a StaticSecret,
    pub remote_public_key: Option<PublicKey>,
    pub shared_secret: Option<SharedSecret>,
    pub counter: Option<u16>,
}
