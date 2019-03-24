use crate::Result;


/// A deserializer for octet strings
pub struct OctetString;
impl OctetString {
	/// The DER tag for the `OctetString` type
	pub const TAG: u8 = 0x04;
	
	/// The deserialized bytes for `data`
	pub fn deserialize(data: &[u8]) -> Result<&[u8]> {
		Ok(data)
	}
}