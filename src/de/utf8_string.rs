use crate::{ Result, SerdeAsn1DerError };
use std::str;


/// A deserializer for UTF-8 strings
pub struct Utf8String;
impl Utf8String {
	/// The DER tag for the `UTF8String` type
	pub const TAG: u8 = 0x0c;
	
	/// The deserialized string for `data`
	pub fn deserialize(data: &[u8]) -> Result<&str> {
		str::from_utf8(data).map_err(|_| SerdeAsn1DerError::InvalidData)
	}
}