use crate::{
	Result, SerdeAsn1DerError, misc::Length,
	ser::{ Serializer, to_writer }
};
use serde::Serialize;
use std::io::Cursor;
use crate::misc::WriteExt;


/// A serializer for sequences
pub struct Sequence<'a, 'se> {
	ser: &'a mut Serializer<'se>,
	buf: Cursor<Vec<u8>>,
	tag: u8,
}
impl<'a, 'se> Sequence<'a, 'se> {
	/// Creates a lazy serializer that will serialize the sequence's sub-elements to `writer`
	pub fn serialize_lazy(ser: &'a mut Serializer<'se>, tag: u8) -> Self {
		Self {
			ser,
			buf: Cursor::new(Vec::new()),
			tag,
		}
	}
	
	/// Writes the next `value` to the internal buffer
	fn write_object<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
		to_writer(value, &mut self.buf)?;
		Ok(())
	}
	/// Finalizes the sequence
	fn finalize(self) -> Result<usize> {
		// Reclaim buffer
		let buf = self.buf.into_inner();

		let mut written = self.ser.__write_encapsulator(Length::encoded_len(buf.len()) + buf.len() + 1)?;

		// Write tag, length and value
		written += self.ser.writer.write_one(self.tag)?;
		written += Length::serialize(buf.len(), &mut self.ser.writer)?;
		written += self.ser.writer.write_exact(&buf)?;
		
		Ok(written)
	}
}
impl<'a, 'se> serde::ser::SerializeSeq for Sequence<'a, 'se> {
	type Ok = usize;
	type Error = SerdeAsn1DerError;
	
	fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
		self.write_object(value)
	}
	fn end(self) -> Result<Self::Ok> {
		self.finalize()
	}
}
impl<'a, 'se> serde::ser::SerializeTuple for Sequence<'a, 'se> {
	type Ok = usize;
	type Error = SerdeAsn1DerError;
	
	fn serialize_element<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
		self.write_object(value)
	}
	fn end(self) -> Result<Self::Ok> {
		self.finalize()
	}
}
impl<'a, 'se> serde::ser::SerializeStruct for Sequence<'a, 'se> {
	type Ok = usize;
	type Error = SerdeAsn1DerError;
	
	fn serialize_field<T: ?Sized + Serialize>(&mut self, _key: &'static str, value: &T)
		-> Result<()>
	{
		self.write_object(value)
	}
	fn end(self) -> Result<Self::Ok> {
		self.finalize()
	}
}
impl<'a, 'se> serde::ser::SerializeTupleStruct for Sequence<'a, 'se> {
	type Ok = usize;
	type Error = SerdeAsn1DerError;
	
	fn serialize_field<T: ?Sized + Serialize>(&mut self, value: &T) -> Result<()> {
		self.write_object(value)
	}
	fn end(self) -> Result<Self::Ok> {
		self.finalize()
	}
}