use std::net::Ipv4Addr;

use x25519_dalek::{StaticSecret, PublicKey};

pub struct ServerConfig {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
    
    pub if_name: String,
    
    pub gateway: Ipv4Addr,
    pub cidr: u8,

    pub wg_port: u16
}