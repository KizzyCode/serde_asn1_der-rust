use crate::{ SerdeAsn1DerError };
use std::{
	mem::size_of,
	io::{ self, Read, Write }
};


/// The byte size of an `usize`
const USIZE_LEN: usize = size_of::<usize>();


/// An extension for `io::Read`
pub trait ReadExt {
	/// Reads the next byte
	fn read_one(&mut self) -> io::Result<u8>;
}
impl<T: Read> ReadExt for T {
	fn read_one(&mut self) -> io::Result<u8> {
		let mut buf = [0];
		self.read_exact(&mut buf)?;
		Ok(buf[0])
	}
}
/// An extension for `io::Write`
pub trait WriteExt {
	/// Writes on `byte`
	fn write_one(&mut self, byte: u8) -> io::Result<usize>;
	/// Writes all bytes in `data`
	fn write_exact(&mut self, data: &[u8]) -> io::Result<usize>;
}
impl<T: Write> WriteExt for T {
	fn write_one(&mut self, byte: u8) -> io::Result<usize> {
		self.write_exact(&[byte])
	}
	fn write_exact(&mut self, data: &[u8]) -> io::Result<usize> {
		self.write_all(data)?;
		Ok(data.len())
	}
}


/// A peekable reader
pub struct PeekableReader<R: Read> {
	reader: R,
	last: Option<u8>,
	pos: usize
}
impl<R: Read> PeekableReader<R> {
	/// Creates a new `PeekableReader` with `reader` as source
	pub fn new(reader: R) -> Self {
		Self{ reader, last: None, pos: 0 }
	}
	
	/// Peeks one byte without removing it from the `read`-queue
	///
	/// Multiple successive calls to `peek_one` will always return the same next byte
	pub fn peek_one(&mut self) -> io::Result<u8> {
		// Check if we already have peeked one byte
		if let Some(last) = self.last { return Ok(last) }
		
		// Read byte
		let mut buf = [0];
		self.reader.read_exact(&mut buf)?;
		self.last = Some(buf[0]);
		
		Ok(buf[0])
	}
	/// The current position (amount of bytes read)
	pub fn pos(&self) -> usize {
		self.pos
	}
}
impl<R: Read> Read for PeekableReader<R> {
	fn read(&mut self, mut buf: &mut[u8]) -> io::Result<usize> {
		// Check for zero-sized buffer
		if buf.is_empty() { return Ok(0) }
		let mut read = 0;
		
		// Move peeked byte if any
		if let Some(last) = self.last.take() {
			buf[0] = last;
			buf = &mut buf[1..];
			read += 1;
		}
		
		// Read remaining bytes
		read += self.reader.read(buf)?;
		self.pos += read;
		Ok(read)
	}
}


/// An implementation of the ASN.1-DER length
pub struct Length;
impl Length {
	/// Deserializes a length from `reader`
	pub fn deserialized(mut reader: impl Read) -> Result<usize, SerdeAsn1DerError> {
		// Deserialize length
		Ok(match reader.read_one()? {
			n @ 128..=255 => {
				// Deserialize the amount of length bytes
				let len = n as usize & 127;
				if len > USIZE_LEN { Err(SerdeAsn1DerError::UnsupportedValue)? }
				
				// Deserialize value
				let mut num = [0; USIZE_LEN];
				reader.read_exact(&mut num[USIZE_LEN - len ..])?;
				usize::from_be_bytes(num)
			},
			n => n as usize
		})
	}
	
	/// Serializes `len` to `writer`
	pub fn serialize(len: usize, mut writer: impl Write) -> Result<usize, SerdeAsn1DerError> {
		// Determine the serialized length
		let written = match len {
			0..=127 => writer.write_one(len as u8)?,
			_ => {
				let to_write = USIZE_LEN - (len.leading_zeros() / 8) as usize;
				// Write number of bytes used to encode length
				let mut written = writer.write_one(to_write as u8 | 0x80)?;

				// Write length
				let mut buf = [0; USIZE_LEN];
				buf.copy_from_slice(&len.to_be_bytes());
				written += writer.write_exact(&buf[USIZE_LEN - to_write..])?;

				written
			},
		};

		Ok(written)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn asn1_short_form_length() {
		let mut writer: Vec<u8> = Vec::new();
		let written = Length::serialize(10, &mut writer).expect("serialization failed");
		assert_eq!(written, 1);
		assert_eq!(writer.len(), 1);
		assert_eq!(writer[0], 10);
	}

	#[test]
	fn asn1_long_form_length_1_byte() {
		let mut writer: Vec<u8> = Vec::new();
		let written = Length::serialize(129, &mut writer).expect("serialization failed");
		assert_eq!(written, 2);
		assert_eq!(writer.len(), 2);
		assert_eq!(writer[0], 0x81);
		assert_eq!(writer[1], 0x81);
	}

	#[test]
	fn asn1_long_form_length_2_bytes() {
		let mut writer: Vec<u8> = Vec::new();
		let written = Length::serialize(290, &mut writer).expect("serialization failed");
		assert_eq!(written, 3);
		assert_eq!(writer.len(), 3);
		assert_eq!(writer[0], 0x82);
		assert_eq!(writer[1], 0x01);
		assert_eq!(writer[2], 0x22);
	}
}
