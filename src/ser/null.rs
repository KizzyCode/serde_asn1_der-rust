use crate::{
	Result,
	misc::{ WriteExt, Length }
};
use std::io::Write;


/// A serializer for the `Null` type
pub struct Null;
impl Null {
	/// Serializes a `Null` into `_writer`
	pub fn serialize(mut writer: impl Write) -> Result<usize> {
		// Write tag and length
		let mut written = writer.write_one(0x05)?;
		written += Length::serialize(0, &mut writer)?;
		
		Ok(written)
	}
}