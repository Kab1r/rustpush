use std::{fmt::Display, io};

use openssl::{aes::KeyError, error::ErrorStack};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PushError {
    SSLError(ErrorStack),
    PlistError(plist::Error),
    RequestError(reqwest::Error),
    AuthError(plist::Value),
    CertError(plist::Dictionary),
    RegisterFailed(u64),
    IoError(io::Error),
    LookupFailed(u64),
    KeyError(KeyError),
    TwoFaError,
    KeyNotFound(String),
    APNSConnectError,
    TLSError(rustls::Error),
    StatusError(reqwest::StatusCode /* code */),
    AlbertCertParseError,
}

impl Display for PushError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", format!("{:?}", self))
    }
}

impl From<rustls::Error> for PushError {
    fn from(value: rustls::Error) -> Self {
        PushError::TLSError(value)
    }
}

impl From<KeyError> for PushError {
    fn from(value: KeyError) -> Self {
        PushError::KeyError(value)
    }
}

impl From<io::Error> for PushError {
    fn from(value: io::Error) -> Self {
        PushError::IoError(value)
    }
}

impl From<ErrorStack> for PushError {
    fn from(value: ErrorStack) -> Self {
        PushError::SSLError(value)
    }
}

impl From<plist::Error> for PushError {
    fn from(value: plist::Error) -> Self {
        PushError::PlistError(value)
    }
}

impl From<reqwest::Error> for PushError {
    fn from(value: reqwest::Error) -> Self {
        PushError::RequestError(value)
    }
}
