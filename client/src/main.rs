use std::error::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

pub mod conn_rsp;
pub mod user_input;
pub mod interface;

use crate::conn_rsp::ConnRsp;
use crate::interface::create_interface;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("Connecting to remote...");
    let mut socket = TcpStream::connect("127.0.0.1:8000").await?;

    let private = StaticSecret::new(&mut OsRng);
    let public = PublicKey::from(&private).to_bytes();

    println!("Obtaining configuration...");
    let mut buf = Vec::with_capacity(1 + public.len() + 32);
    buf.extend_from_slice(b"\0");
    buf.extend_from_slice(&public);
    buf.extend_from_slice(b"Secret123");

    socket.write_all(buf.as_slice()).await?;

    // allocate 48 bytes
    let mut buf = [0; 48];

    // read from the socket
    let size = socket.read(&mut buf).await.expect("could not read");
    assert_eq!(size, 48);

    let rsp = ConnRsp::decode_and_verify(&buf, &private).await.ok_or("cannot decode")?;
    create_interface(&rsp, &private).await;

    Ok(())
}