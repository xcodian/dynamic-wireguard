use std::{net::Ipv4Addr, error::Error};

#[derive(Debug)]
pub struct WgAddrConfig {
    pub wg_endpoint_port: u16,
    pub internal_gateway: Ipv4Addr,
    pub assigned_address: Ipv4Addr,
}

impl WgAddrConfig {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out: Vec<u8> = Vec::with_capacity(11);

        out.push(0x02);                                                   //   1
        out.extend_from_slice(&self.wg_endpoint_port.to_be_bytes());      // + 2
        out.extend_from_slice(&self.internal_gateway.octets());           // + 4
        out.extend_from_slice(&self.assigned_address.octets());           // + 4
                                                                          // = 11
        return out;
    }

    pub fn deserialize(buf: Vec<u8>) -> Result<Self, Box<dyn Error>> {
        if buf.len() != 11 {
            Err("invalid config payload size (expected 11 bytes)")?;
        }

        if buf[0] != 0x02 {
            Err("invalid config packet id (expected 0x02)")?;
        }

        let mut buf = &buf[1..];
        let wg_endpoint_port = u16::from_be_bytes(buf[..2].try_into()?);
        
        buf = &buf[2..];
        let internal_gateway = ip_from_slice(&buf[..4])?;
        
        buf = &buf[4..];
        let assigned_address = ip_from_slice(&buf[..4])?;
        
        return Ok(WgAddrConfig {
            wg_endpoint_port,
            internal_gateway,
            assigned_address,
        });
    }
}

fn ip_from_slice(slice: &[u8]) -> Result<Ipv4Addr, Box<dyn Error>> {
    if slice.len() != 4 {
        Err("invalid ipv4 address length")?;
    }

    let sized_buf: [u8; 4] = slice.try_into().unwrap();    
    return Ok(sized_buf.try_into()?);
}