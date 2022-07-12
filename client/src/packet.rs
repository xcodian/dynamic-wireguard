use std::error::Error;
use std::io::IoSlice;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use x25519_dalek::PublicKey;
use x25519_dalek::StaticSecret;

use crate::magic;

pub async fn key_exchange(
    socket: &mut TcpStream,
    client_private_key: &StaticSecret,
) -> Result<(PublicKey, u16), Box<dyn Error>> {
    let client_public_key = PublicKey::from(client_private_key);

    // send magic & client public key
    socket
        .write_vectored(&[
            IoSlice::new(&[magic::make(false)]),
            IoSlice::new(&client_public_key.to_bytes()),
        ])
        .await?;

    //                header
    //                |   server public
    //                |   |    counter initial value
    //                |   |    |
    let mut buf = [0; 1 + 32 + 2];

    // read from the socket
    let size = socket.read(&mut buf).await.expect("could not read");

    // ensure exact size for handshake
    if size != 1 + 32 + 2 {
        Err("invalid handshake response size")?;
    }

    let is_encrypted = magic::parse(buf[0]).ok_or("invalid magic")?;

    if is_encrypted {
        // should not be encrypted yet
        Err("handshake marked as encrypted")?;
    }

    // strip header
    let buf = &mut buf[1..];

    let server_public_key: [u8; 32] = buf[0..32].try_into().unwrap();
    let server_public_key = PublicKey::from(server_public_key);

    let counter_init = u16::from_be_bytes(buf[32..32 + 2].try_into().unwrap());

    return Ok((server_public_key, counter_init));
}
