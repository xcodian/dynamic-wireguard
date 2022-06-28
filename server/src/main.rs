use std::net::Ipv4Addr;
use std::str::FromStr;

use rand_core::OsRng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::{io::AsyncReadExt, net::TcpStream};
use x25519_dalek::{PublicKey, StaticSecret};

pub mod conn_req;
pub mod conn_rsp;

use crate::conn_req::ConnReq;
use crate::conn_rsp::ConnRsp;

use sha1::{Digest, Sha1};

const PORT: u16 = 8000;

async fn process_packet(
    socket: &mut TcpStream,
    buf: &mut [u8],
    private_key: &StaticSecret,
) -> Option<()> {
    let packet_id = buf[0];

    match packet_id {
        // connection request
        0 => {
            let req = ConnReq::from_packet(&buf[1..])?;

            println!(
                "connection request from {} with password {}",
                base64::encode(req.pub_key),
                req.password
            );

            let rsp = ConnRsp {
                wg_endpoint_host: Ipv4Addr::from_str("123.45.67.89").unwrap(),
                wg_endpoint_port: PORT,
                gateway_addr: Ipv4Addr::from_str("10.0.0.1").unwrap(),
                client_addr: Ipv4Addr::from_str("10.0.0.69").unwrap(),
            };

            let mut buf = [0u8; 32 + 16];
            rsp.assemble_into(req.pub_key, private_key, &mut buf);

            // println!("{}", hex::encode(&buf));

            socket.write_all(&buf).await.expect("failed to write");
        }
        _ => {
            println!("unknown packet id: {}", packet_id)
        }
    }

    return Some(());
}

fn print_key_fingerprint(key: &[u8]) {
    // compute fingerprint
    let mut hasher = Sha1::new();
    hasher.update(key);

    let fingerprint = hasher.finalize();
    println!("public key:\n    {}", hex::encode(key));
    println!("public key fingerprint:\n    {}", hex::encode(fingerprint));
}

#[tokio::main]
async fn main() {
    #[cfg(not(debug_assertions))]
    panic::set_hook(Box::new(|panic_info| {
        if let Some(s) = panic_info.payload().downcast_ref::<String>() {
            println!("error: {}", s);
        } else {
            println!("error");
        }
    }));

    // bind a tcp listener
    let listener = TcpListener::bind(format!("127.0.0.1:{}", PORT))
        .await
        .expect("could not bind");

    println!("[ok] listening for connections");

    let private_key = StaticSecret::new(&mut OsRng);
    print_key_fingerprint(&PublicKey::from(&private_key).to_bytes());

    loop {
        // accept a connection
        let (mut socket, _) = listener.accept().await.unwrap();

        let mut buf = [0; 256]; // read 256 bytes off the socket

        // read from the socket
        let size = socket.read(&mut buf).await.expect("could not read");

        process_packet(&mut socket, &mut buf[..size], &private_key).await;
    }
}
