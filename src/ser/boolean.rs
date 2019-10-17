use crate::{Result, misc::{WriteExt, Length}, Serializer};

/// A serializer for booleans
pub struct Boolean;
impl Boolean {
	/// Serializes `value` into `writer`
	pub fn serialize(value: bool, ser: &mut Serializer) -> Result<usize> {
		let mut written = ser.__write_encapsulator(3)?;

		// Write tag and length
		written += ser.writer.write_one(0x01)?;
		written += Length::serialize(1, &mut ser.writer)?;
		
		// Serialize the value
		written += match value {
			true => ser.writer.write_one(0xff)?,
			false => ser.writer.write_one(0x00)?
		};
		Ok(written)
	}
}