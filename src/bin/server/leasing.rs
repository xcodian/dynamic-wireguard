use std::{fmt, net::Ipv4Addr};

use rand::Rng;

use crate::config::ServerConfig;

#[derive(Debug, Clone)]
pub struct NoFreeAddressError;

impl fmt::Display for NoFreeAddressError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "No free address in subnet")
    }
}

impl std::error::Error for NoFreeAddressError {}

pub fn get_free_address(conf: &ServerConfig) -> Result<Ipv4Addr, NoFreeAddressError> {
    // TODO: make a better system for leasing, this will 100% collide

    // this is extremely stupid, but it works: when the subnet is nth(1),
    // it will work, but if it's not, the "free" address can collide with the gateway's

    // this needs to be done better ASAP

    match conf
        .subnet
        // spin the wheel lmao
        .nth(rand::thread_rng().gen_range(2, conf.subnet.size()))
    {
        Some(ip) => Ok(ip),
        None => Err(NoFreeAddressError),
    }
}
