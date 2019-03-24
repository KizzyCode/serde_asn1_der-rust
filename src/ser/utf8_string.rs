use crate::{
	Result,
	misc::{ WriteExt, Length }
};
use std::io::Write;


/// A serializer for UTF-8 strings
pub struct Utf8String;
impl Utf8String {
	/// Serializes `value` into `writer`
	pub fn serialize(value: &str, mut writer: impl Write) -> Result<usize> {
		// Write tag, length and data
		let mut written = writer.write_one(0x0c)?;
		written += Length::serialize(value.len(), &mut writer)?;
		written += writer.write_exact(value.as_bytes())?;
		
		Ok(written)
	}
}