use crate::{
	Result,
	misc::{ WriteExt, Length }
};
use std::io::Write;


/// A serializer for booleans
pub struct Boolean;
impl Boolean {
	/// Serializes `value` into `writer`
	pub fn serialize(value: bool, mut writer: impl Write) -> Result<usize> {
		// Write tag and length
		let mut written = writer.write_one(0x01)?;
		written += Length::serialize(1, &mut writer)?;
		
		// Serialize the value
		written += match value {
			true => writer.write_one(0xff)?,
			false => writer.write_one(0x00)?
		};
		Ok(written)
	}
}