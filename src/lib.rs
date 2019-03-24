//! [![License](https://img.shields.io/badge/License-BSD--2--Clause-blue.svg)](https://opensource.org/licenses/BSD-2-Clause)
//! [![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
//! [![Travis CI](https://travis-ci.org/KizzyCode/serde_asn1_der.svg?branch=master)](https://travis-ci.org/KizzyCode/serde_asn1_der)
//! [![AppVeyor CI](https://ci.appveyor.com/api/projects/status/github/KizzyCode/serde_asn1_der?svg=true)](https://ci.appveyor.com/project/KizzyCode/serde-asn1-der)
//!
//!
//! # serde_asn1_der
//! This crate implements an ASN.1-DER subset for serde.
//!
//! The following types have built-in support:
//!  - `bool`: The ASN.1-BOOLEAN-type
//!  - `u8`, `u16`, `u32`, `u64`, `u128`, `usize`: The ASN.1-INTEGER-type
//!  - `()`: The ASN.1-NULL-type
//!  - `&[u8]`, `Vec<u8>`: The ASN.1-OctetString-type
//!  - `&str`, `String`: The ASN.1-UTF8String-type
//!  - And everything sequence-like combined out of this types
//!
//! With the `serde_derive`-crate you can derive `Serialize` and `Deserialize` for all non-primitive
//! elements:
//! ```rust
//! use serde_derive::{ Serialize, Deserialize };
//!
//! #[derive(Serialize, Deserialize)] // Now our struct supports all DER-conversion-traits
//! struct Address {
//! 	street: String,
//! 	house_number: u128,
//! 	postal_code: u128,
//! 	state: String,
//! 	country: String
//! }
//!
//! #[derive(Serialize, Deserialize)] // Now our struct supports all DER-conversion-traits too
//! struct Customer {
//! 	name: String,
//! 	e_mail_address: String,
//! 	postal_address: Address
//! }
//! ```
//!
//!
//! # Example
//! ```rust
//! use serde_asn1_der::{ to_vec, from_bytes };
//! use serde_derive::{ Serialize, Deserialize };
//!
//! #[derive(Serialize, Deserialize)]
//! struct TestStruct {
//! 	number: u8,
//! 	#[serde(with = "serde_bytes")]
//! 	vec: Vec<u8>,
//! 	tuple: (usize, ())
//! }
//!
//! fn main() {
//! 	let plain = TestStruct{ number: 7, vec: b"Testolope".to_vec(), tuple: (4, ()) };
//! 	let serialized = to_vec(&plain).unwrap();
//! 	let deserialized: TestStruct = from_bytes(&serialized).unwrap();
//! }
//! ```

mod misc;
mod ser;
mod de;

pub use crate::{
	de::{ Deserializer, from_bytes, from_reader },
	ser::{ Serializer, to_vec, to_bytes, to_byte_buf, to_writer }
};
pub use serde;
use std::{
	io, error::Error,
	fmt::{ self, Display, Formatter }
};


/// A `serde_asn1_der`-related error
#[derive(Debug)]
pub enum SerdeAsn1DerError {
	/// The data is truncated
	TruncatedData,
	/// The data is invalid
	InvalidData,
	
	/// The value may be valid but is unsupported (e.g. an integer that is too large)
	UnsupportedValue,
	/// The data type is not supported by the (de-)serializer
	UnsupportedType,
	
	/// The provided sink is unable to accept all bytes
	InvalidSink,
	/// A custom message produced by `serde`
	Message(String),
	/// Some other underlying error (e.g. an IO error)
	Other(Box<dyn Error + 'static>)
}
impl Display for SerdeAsn1DerError {
	fn fmt(&self, t: &mut Formatter) -> fmt::Result {
		write!(t, "{:?}", self)
	}
}
impl Error for SerdeAsn1DerError {
	fn source(&self) -> Option<&(dyn Error + 'static)> {
		match self {
			SerdeAsn1DerError::Other(source) => Some(source.as_ref()),
			_ => None
		}
	}
}
impl serde::de::Error for SerdeAsn1DerError {
	fn custom<T: Display>(msg: T) -> Self {
		SerdeAsn1DerError::Message(msg.to_string())
	}
}
impl serde::ser::Error for SerdeAsn1DerError {
	fn custom<T: Display>(msg: T) -> Self {
		SerdeAsn1DerError::Message(msg.to_string())
	}
}
impl From<io::Error> for SerdeAsn1DerError {
	fn from(io_error: io::Error) -> Self {
		match io_error.kind() {
			io::ErrorKind::UnexpectedEof => SerdeAsn1DerError::TruncatedData,
			io::ErrorKind::WriteZero => SerdeAsn1DerError::InvalidSink,
			_ => SerdeAsn1DerError::Other(Box::new(io_error))
		}
	}
}

/// Syntactic sugar for `Result<T, SerdeAsn1DerError>`
pub type Result<T> = std::result::Result<T, SerdeAsn1DerError>;