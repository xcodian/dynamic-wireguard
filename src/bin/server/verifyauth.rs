use dynamic_wireguard::{conv::Conversation, auth::AuthMethod, crypto::hash_verify};

pub fn verify(attempt: &[u8], conv: &Conversation) -> bool {
    let method = conv.auth_method.unwrap();

    let verdict = match method {
        AuthMethod::Open => true,
        AuthMethod::Password => {
            let hash = std::str::from_utf8(attempt);
            if hash.is_err() {
                return false;
            }
            
            authenticate_passphrase(hash.unwrap(), &conv)
        },
        AuthMethod::UsernamePassword => {
            let hash = std::str::from_utf8(attempt);
            if hash.is_err() {
                return false;
            }
            
            authenticate_username_password(hash.unwrap(), &conv)
        },
    };


    return verdict;
}

pub fn authenticate_passphrase(hash: &str, conv: &Conversation) -> bool {
    // TODO: get a password from some db or something

    let stored_password = "password123";
    return hash_verify(stored_password.as_bytes(), hash);
}

pub fn authenticate_username_password(hash: &str, conv: &Conversation) -> bool {
    // TODO: get a password from some db or something
    let user = "admin";
    let stored_password = "secret456";

    let secret = user.to_string() + ":" + &stored_password;

    return hash_verify(secret.as_bytes(), hash);
}
