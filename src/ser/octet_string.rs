use crate::{
	Result,
	misc::{ WriteExt, Length }
};
use std::io::Write;


/// A serializer for octet strings
pub struct OctetString;
impl OctetString {
	/// Serializes `value` into `writer`
	pub fn serialize(value: &[u8], mut writer: impl Write) -> Result<usize> {
		// Write tag, length and data
		let mut written = writer.write_one(0x04)?;
		written += Length::serialize(value.len(), &mut writer)?;
		written += writer.write_exact(value)?;
		
		Ok(written)
	}
}