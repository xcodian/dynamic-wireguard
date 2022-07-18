use std::{
    error::Error,
    fs::OpenOptions,
    io::{self, BufRead},
};

use x25519_dalek::StaticSecret;

pub fn get_key(path: &str) -> Result<StaticSecret, Box<dyn Error>> {
    let file = OpenOptions::new().read(true).open(path)?;
    let mut file = io::BufReader::new(file);

    let mut ln = String::new();
    file.read_line(&mut ln)?;
    ln = ln.trim().to_string();

    if ln.len() == 0 {
        Err("empty key file")?;
    }

    // decode line with base64
    let key = base64::decode(ln)?;

    if key.len() != 32 {
        Err("invalid key length")?;
    }

    let key: [u8; 32] = key.as_slice().try_into()?;

    return Ok(StaticSecret::from(key));
}
