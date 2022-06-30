use std::net::{Ipv4Addr, IpAddr};
use std::str::FromStr;
use std::sync::Arc;

use rand_core::OsRng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::{io::AsyncReadExt, net::TcpStream};
use x25519_dalek::{PublicKey, StaticSecret, SharedSecret};

pub struct Conversation<'a> {
    pub socket: TcpStream,
    pub server_private_key: &'a StaticSecret,
    pub client_public_key: Option<PublicKey>,
    pub shared_secret: Option<SharedSecret>,
    pub counter: Option<u16>,
}