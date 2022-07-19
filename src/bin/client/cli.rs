use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::str::FromStr;

use clap::Parser;
use clap::Subcommand;

use dynamic_wireguard::DYNWG_PORT_DEFAULT;

#[derive(Debug, Parser)]
#[clap(name = "dynamic-wireguard server")]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,

    #[clap(short = 'f', long, help = "Show the server's fingeprint on connection")]
    pub print_fingerprint: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[clap(arg_required_else_help = true, about = "Connect to a dynamic tunnel")]
    Connect {
        #[clap(
            value_parser,
            help = "Host to connect to, optionally user can be specified",
            value_name = "[user@]hostname[:port]"
        )]
        host: ComplexHost,

        #[clap(
            short,
            long = "iface",
            value_name = "name",
            help = "WireGuard interface to create, default: wgdyn0, wgdyn1, wgdyn2, (...)"
        )]
        interface: Option<String>,
    },

    #[clap(
        arg_required_else_help = true,
        about = "Disconnect from a dynamic tunnel"
    )]
    Disconnect {
        #[clap(
            value_parser,
            help = "Host to disconnect from",
            value_name = "[user@]hostname[:port]"
        )]
        host: ComplexHost,
    },

    #[clap(
        arg_required_else_help = true,
        about = "Remove unconnected dynamic interfaces"
    )]
    Prune {
        #[clap(
            short,
            long,
            help = "Optionally restrict to specific host",
            value_name = "hostname[:port]"
        )]
        host: Option<ComplexHost>,

        #[clap(
            short,
            long = "iface",
            help = "Optionally restrict to specific inteface(s) with regex, default: wgdyn\\d+",
            value_name = "regex"
        )]
        interface: Option<String>,
    },
}

pub mod errors {
    use std::fmt;
    use std::fmt::Display;

    #[derive(Debug, Clone)]
    pub struct HostParseError(pub HostParseErrorType);

    impl fmt::Display for HostParseError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    impl std::error::Error for HostParseError {}

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum HostParseErrorType {
        BadFormat,
        InvalidSockAddr(String),
    }

    impl Display for HostParseErrorType {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                HostParseErrorType::BadFormat => {
                    write!(f, "invalid host, expected [user@]host[:port]")
                }
                HostParseErrorType::InvalidSockAddr(e) => write!(f, "{e}"),
            }
        }
    }
}

/// struct to allow clap to directly return user, host:port
#[derive(Debug, Clone)]
pub struct ComplexHost {
    pub user: Option<String>,
    pub exact: String,
    pub addrs: Vec<SocketAddr>,
}

impl FromStr for ComplexHost {
    type Err = errors::HostParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let split: Vec<&str> = s.split('@').collect();

        let (user, mut host) = match split.len() {
            1 => (None, split[0].to_string()),
            2 => (Some(split[0].to_string()), split[1].to_string()),
            _ => {
                return Err(errors::HostParseError(
                    errors::HostParseErrorType::BadFormat,
                ));
            }
        };

        let split: Vec<&str> = host.split(':').collect();

        host = match split.len() {
            1 => format!("{}:{}", host, DYNWG_PORT_DEFAULT),
            2 => host,
            _ => {
                return Err(errors::HostParseError(
                    errors::HostParseErrorType::BadFormat,
                ));
            }
        };

        let addrs: Vec<SocketAddr> = match host.to_socket_addrs() {
            Ok(s) => Ok(s),
            Err(e) => Err(errors::HostParseError(
                errors::HostParseErrorType::InvalidSockAddr(e.to_string()),
            )),
        }?
        .filter(|a| a.is_ipv4()) // ipv4 only
        .collect();

        return Ok(ComplexHost {
            user,
            exact: host,
            addrs,
        });
    }
}
