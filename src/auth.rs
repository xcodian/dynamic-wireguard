use std::fmt;

#[derive(Copy, Clone)]
pub enum AuthMethod {
    Open = 0,
    Passphrase = 1,
    UsernamePassword = 2,
}

impl AuthMethod {
    pub fn from_u8(val: u8) -> Result<AuthMethod, MethodNotSupportedError> {
        match val {
            0 => Ok(AuthMethod::Open),
            1 => Ok(AuthMethod::Passphrase),
            2 => Ok(AuthMethod::UsernamePassword),
            _ => Err(MethodNotSupportedError),
        }
    }

    pub fn to_u8(&self) -> u8 {
        *self as u8
    }

    pub fn name(&self) -> &'static str {
        match self {
            AuthMethod::Open => "open",
            AuthMethod::Passphrase => "passphrase",
            AuthMethod::UsernamePassword => "username+password",
        }
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug, Clone)]
pub struct MethodNotSupportedError;

impl fmt::Display for MethodNotSupportedError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unsupported authentication method")
    }
}

impl std::error::Error for MethodNotSupportedError {}
