use crate::{ Result, SerdeAsn1DerError };


/// A deserializer for booleans
pub struct Boolean;
impl Boolean {
	/// The DER tag for the `Boolean` type
	pub const TAG: u8 = 0x01;
	
	/// The deserialized boolean for `data`
	pub fn deserialize(data: &[u8]) -> Result<bool> {
		// Check lengths
		if data.is_empty() { Err(SerdeAsn1DerError::TruncatedData)? }
		if data.len() > 1 { Err(SerdeAsn1DerError::InvalidData)? }
		
		// Parse the boolean
		Ok(match data[0] {
			0x00 => {
				debug_log!("false!");
				false
			},
			0xff => {
				debug_log!("true!");
				true
			},
			_ => Err(SerdeAsn1DerError::InvalidData)?
		})
	}
}