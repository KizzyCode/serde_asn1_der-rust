use crate::{
    misc::{Length, WriteExt},
    Result, Serializer,
};

/// A serializer for UTF-8 strings
pub struct Utf8String;
impl Utf8String {
    /// Serializes `value` into `writer`
    pub fn serialize(value: &str, ser: &mut Serializer) -> Result<usize> {
        let mut written =
            ser.__write_encapsulator(Length::encoded_len(value.len()) + value.len() + 1)?;

        // Write tag, length and data
        written += ser.writer.write_one(0x0c)?;
        written += Length::serialize(value.len(), &mut ser.writer)?;
        written += ser.writer.write_exact(value.as_bytes())?;

        Ok(written)
    }
}
