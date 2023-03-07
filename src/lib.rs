#![doc = include_str!("../README.md")]
#![allow(clippy::or_fun_call)]

#[macro_use]
pub extern crate asn1_der;
mod de;
mod misc;
mod ser;

#[cfg(feature = "any")]
mod any;

pub use crate::{
    de::{from_bytes, from_reader, from_source},
    ser::{to_sink, to_vec, to_writer},
};

#[cfg(feature = "any")]
pub use crate::any::AnyObject;

pub use asn1_der::VecBacking;
pub use serde;

use asn1_der::Asn1DerError;
use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

/// A `serde_asn1_der` error
#[derive(Debug)]
pub enum SerdeAsn1DerError {
    Asn1DerError(Asn1DerError),
    SerdeError(String),
}
impl Display for SerdeAsn1DerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SerdeAsn1DerError::Asn1DerError(e) => e.fmt(f),
            SerdeAsn1DerError::SerdeError(s) => write!(f, "Serde error: {}", s),
        }
    }
}
impl Error for SerdeAsn1DerError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SerdeAsn1DerError::Asn1DerError(e) => e.source(),
            _ => None,
        }
    }
}
impl serde::de::Error for SerdeAsn1DerError {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        SerdeAsn1DerError::SerdeError(msg.to_string())
    }
}
impl serde::ser::Error for SerdeAsn1DerError {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        SerdeAsn1DerError::SerdeError(msg.to_string())
    }
}
impl From<Asn1DerError> for SerdeAsn1DerError {
    fn from(e: Asn1DerError) -> Self {
        SerdeAsn1DerError::Asn1DerError(e)
    }
}

/// Syntactic sugar for `Result<T, Asn1DerError>`
pub type Result<T> = std::result::Result<T, SerdeAsn1DerError>;
