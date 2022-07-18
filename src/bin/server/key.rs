use std::{
    error::Error,
    fs::OpenOptions,
    io::{self, BufRead, Write, ErrorKind},
};

use log::info;
use rand::rngs::OsRng;
use x25519_dalek::StaticSecret;

pub fn get_key(path: &str, make_if_not_found: bool) -> Result<StaticSecret, Box<dyn Error>> {
    let file = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(e) => {
            if e.kind() == ErrorKind::NotFound {
                if make_if_not_found {
                    // file doesn't exist, then make it
                    info!("private key file not found, generating");
                    return gen_key(path);
                } else {
                    Err("private key file not found (re-run with --genkey to generate)")?
                }
            }
            Err(e)?
        },
    };

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

pub fn gen_key(path: &str) -> Result<StaticSecret, Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(path)?;

    let secret = StaticSecret::new(&mut OsRng);

    file.write_all((base64::encode(secret.to_bytes()) + "\n").as_bytes())?;

    return Ok(secret);
}
