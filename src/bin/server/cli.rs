use std::net::Ipv4Addr;
use std::net::SocketAddr;

use clap::Parser;
use dynamic_wireguard::auth::AuthMethod;
use ipnetwork::Ipv4Network;

#[derive(Debug, Parser)]
#[clap(name = "dynamic-wireguard server")]
pub struct Cli {
    #[clap(
        short = 'b',
        long = "bind",
        value_name = "ip:port",
        help = "Bind to this TCP address, default: 0.0.0.0:7575"
    )]
    pub bind: Option<SocketAddr>,

    #[clap(
        short = 'k',
        long = "key",
        value_name = "path",
        help = "Read X25519 private key from this file"
    )]
    pub key_file: String,

    #[clap(
        short = 'i',
        long = "iface",
        value_name = "name",
        help = "WireGuard interface to use/create, default: wgd0s"
    )]
    pub if_name: Option<String>,

    #[clap(
        short = 's',
        long = "subnet",
        value_name = "ipv4/prefix",
        help = "Internal subnet used to assign IPs to clients, default: 10.100.0.0/24"
    )]
    pub subnet: Option<Ipv4Network>,

    #[clap(
        short = 'g',
        long = "gateway",
        value_name = "ipv4",
        help = "Internal IP of the server on the VPN subnet, default: 10.100.0.1"
    )]
    pub gateway: Option<Ipv4Addr>,

    #[clap(
        short = 'p',
        long = "wg-port",
        value_name = "port",
        help = "Port that WireGuard should listen on (0-65535) default: 51820"
    )]
    pub wg_port: Option<u16>,

    #[clap(
        short = 'a',
        long = "auth",
        value_name = "method",
        help = "Authentication method for clients (open|password|username+password), default: open"
    )]
    pub auth: Option<AuthMethod>,

    #[clap(
        long = "genkey",
        help = "Generate an X25519 key into the key file if it doesn't exist"
    )]
    pub gen_key: bool
}
