use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct KeyNotFoundError {
    pub details: String,
}

impl KeyNotFoundError {
    fn new(message: &str) -> KeyNotFoundError {
        KeyNotFoundError {
            details: message.to_string(),
        }
    }
}

impl fmt::Display for KeyNotFoundError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "couldn't find key matching provided key id")
    }
}

impl Error for KeyNotFoundError {
    fn description(&self) -> &str {
        &self.details
    }
}

#[derive(Debug, Clone)]
pub struct InvalidKeyError {
    pub details: String,
}

impl InvalidKeyError {
    pub fn new(message: &str) -> InvalidKeyError {
        InvalidKeyError {
            details: message.to_string(),
        }
    }
}

impl fmt::Display for InvalidKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "provided key failed validation")
    }
}

impl Error for InvalidKeyError {
    fn description(&self) -> &str {
        &self.details
    }
}
