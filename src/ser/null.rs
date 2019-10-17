use crate::{Result, misc::{WriteExt, Length}, Serializer};

/// A serializer for the `Null` type
pub struct Null;
impl Null {
	/// Serializes a `Null` into `_writer`
	pub fn serialize(ser: &mut Serializer) -> Result<usize> {
		let mut written = ser.__write_encapsulator(2)?;

		// Write tag and length
		written += ser.writer.write_one(0x05)?;
		written += Length::serialize(0, &mut ser.writer)?;
		
		Ok(written)
	}
}