use std::error::Error;
use std::io;
use std::io::Write;
use std::vec;

use dynamic_wireguard::auth::AuthMethod;
use dynamic_wireguard::crypto::hash_hash;

pub fn get_auth<'a>(method: &AuthMethod) -> Result<Vec<u8>, Box<dyn Error>> {
    match method {
        AuthMethod::Open => Ok(vec![]),
        AuthMethod::Passphrase => Ok(get_passphrase()?.as_bytes().to_vec()),
        AuthMethod::UsernamePassword => Ok(get_username_password()?.as_bytes().to_vec()),
        // _ => Err(MethodNotSupportedError)?,
    }
}

fn get_username_password() -> Result<String, Box<dyn Error>> {
    print!("Username: ");
    std::io::stdout().flush()?;

    let mut secret = String::new();
    let size = std::io::stdin().read_line(&mut secret)?;

    if size == 0 {
        Err("empty username")?;
    }

    secret = secret.trim().to_string();

    // check if username is valid
    if !secret
        .chars()
        .all(|x| x.is_ascii_alphanumeric() || ['_', '-', '.'].contains(&x))
    {
        Err("disallowed characters in username")?;
    }

    // concatenate the password
    secret.push_str(":");
    secret.push_str(rpassword::prompt_password("Password: ")?.as_str());

    println!("{}", secret);

    return Ok(hash_hash(secret.as_bytes()));
}

fn get_passphrase() -> io::Result<String> {
    let pwd = rpassword::prompt_password("Password: ")?;

    // hash password
    return Ok(hash_hash(pwd.as_bytes()));
}
