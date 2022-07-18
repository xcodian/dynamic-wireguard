use std::net::Ipv4Addr;

use dynamic_wireguard::auth::AuthMethod;
use x25519_dalek::{StaticSecret, PublicKey};

pub struct ServerConfig {
    pub private_key: StaticSecret,
    pub public_key: PublicKey,
    
    pub if_name: String,
    
    pub gateway: Ipv4Addr,
    pub subnet: ipnetwork::Ipv4Network,
    pub wg_port: u16,

    pub auth_method: AuthMethod
}