use std::fmt;
use std::str::FromStr;

#[derive(Debug, Copy, Clone)]
pub enum AuthMethod {
    Open = 0,
    Password = 1,
    UsernamePassword = 2,
}

impl AuthMethod {
    pub fn from_u8(val: u8) -> Result<AuthMethod, MethodNotSupportedError> {
        match val {
            0 => Ok(AuthMethod::Open),
            1 => Ok(AuthMethod::Password),
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
            AuthMethod::Password => "password",
            AuthMethod::UsernamePassword => "username+password",
        }
    }
}

impl fmt::Display for AuthMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl FromStr for AuthMethod {
    type Err = InvalidMethodError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "open" => Ok(AuthMethod::Open),
            "password" => Ok(AuthMethod::Password),
            "username+password" => Ok(AuthMethod::UsernamePassword),
            _ => Err(InvalidMethodError)
        }
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


#[derive(Debug, Clone)]
pub struct InvalidMethodError;

impl fmt::Display for InvalidMethodError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "valid values: open, passphrase, username+password")
    }
}

impl std::error::Error for InvalidMethodError {}
