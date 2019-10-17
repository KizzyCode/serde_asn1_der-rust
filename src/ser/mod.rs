mod boolean;
mod integer;
mod null;
mod sequence;
mod utf8_string;

#[cfg(feature = "complex_types")]
use crate::asn1_wrapper::*;
use crate::{
	Result, SerdeAsn1DerError,
	ser::{
		boolean::Boolean, integer::UnsignedInteger, null::Null,
		sequence::Sequence, utf8_string::Utf8String
	}
};
use serde::Serialize;
use std::io::{ Write, Cursor };
use crate::misc::{Length, WriteExt};


/// Serializes `value`
pub fn to_vec<T: ?Sized + Serialize>(value: &T) -> Result<Vec<u8>> {
	let mut buf = Vec::new();
	to_byte_buf(value, &mut buf)?;
	Ok(buf)
}
/// Serializes `value` to `buf` and returns the amount of serialized bytes
pub fn to_bytes<T: ?Sized + Serialize>(value: &T, buf: &mut[u8]) -> Result<usize> {
	let mut serializer = Serializer::new_to_bytes(buf);
	value.serialize(&mut serializer)
}
/// Serializes `value` to `buf` and returns the amount of serialized bytes
pub fn to_byte_buf<T: ?Sized + Serialize>(value: &T, buf: &mut Vec<u8>) -> Result<usize> {
	let mut serializer = Serializer::new_to_byte_buf(buf);
	value.serialize(&mut serializer)
}
/// Serializes `value` to `writer` and returns the amount of serialized bytes
pub fn to_writer<T: ?Sized + Serialize>(value: &T, writer: impl Write) -> Result<usize> {
	let mut serializer = Serializer::new_to_writer(writer);
	value.serialize(&mut serializer)
}


/// An ASN.1-DER serializer for `serde`
pub struct Serializer<'se> {
	writer: Box<dyn Write + 'se>,
	tag_for_next_bytes: u8,
	encapsulated: bool,
}
impl<'se> Serializer<'se> {
	/// Creates a new serializer that writes to `buf`
	pub fn new_to_bytes(buf: &'se mut[u8]) -> Self {
		Self::new_to_writer(Cursor::new(buf))
	}
	/// Creates a new serializer that writes to `buf`
	pub fn new_to_byte_buf(buf: &'se mut Vec<u8>) -> Self {
		Self::new_to_writer(Cursor::new(buf))
	}
	/// Creates a new serializer that writes to `writer`
	pub fn new_to_writer(writer: impl Write + 'se) -> Self {
		Self{
			writer: Box::new(writer),
			tag_for_next_bytes: 0x04,
			encapsulated: false
		}
	}

	fn __write_encapsulator(&mut self, encapsulated_size: usize) -> Result<usize> {
		let mut written = 0;
		if self.encapsulated { // encapsulated in a bit string
			written += self.writer.write_one(BitStringAsn1Container::<()>::TAG)?;
			written += Length::serialize(encapsulated_size, &mut self.writer)?;
			written += self.writer.write_one(0x00)?; // no unused bits

			self.encapsulated = false; // reset encapsulation state
		}
		Ok(written)
	}

	fn __serialize_bytes_with_tag(&mut self, bytes: &[u8]) -> Result<usize> {
		let mut written = self.__write_encapsulator(bytes.len() + Length::encoded_len(bytes.len()) + 1)?;

		// Write tag, length and data
		written += self.writer.write_one(self.tag_for_next_bytes)?;
		written += Length::serialize(bytes.len(), &mut self.writer)?;
		written += self.writer.write_exact(bytes)?;

		self.tag_for_next_bytes = 0x04; // reset to octet string

		Ok(written)
	}
}
//noinspection RsTraitImplementation
impl<'a, 'se> serde::ser::Serializer for &'a mut Serializer<'se> {
	type Ok = usize;
	type Error = SerdeAsn1DerError;
	
	type SerializeSeq = Sequence<'a, 'se>;
	type SerializeTuple = Sequence<'a, 'se>;
	type SerializeTupleStruct = Sequence<'a, 'se>;
	type SerializeTupleVariant = Self;
	type SerializeMap = Self;
	type SerializeStruct = Sequence<'a, 'se>;
	type SerializeStructVariant = Self;
	
	fn serialize_bool(self, v: bool) -> Result<Self::Ok> {
		Boolean::serialize(v, self)
	}
	
	fn serialize_i8(self, _v: i8) -> Result<Self::Ok> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_i16(self, _v: i16) -> Result<Self::Ok> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_i32(self, _v: i32) -> Result<Self::Ok> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_i64(self, _v: i64) -> Result<Self::Ok> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	//noinspection RsTraitImplementation
	fn serialize_i128(self, _v: i128) -> Result<Self::Ok> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_u8(self, v: u8) -> Result<Self::Ok> {
		self.serialize_u128(v as u128)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u16(self, v: u16) -> Result<Self::Ok> {
		self.serialize_u128(v as u128)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
		self.serialize_u128(v as u128)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
		self.serialize_u128(v as u128)
	}
	//noinspection RsTraitImplementation
	fn serialize_u128(self, v: u128) -> Result<Self::Ok> {
		UnsignedInteger::serialize(v, self)
	}
	
	fn serialize_f32(self, _v: f32) -> Result<Self::Ok> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_f64(self, _v: f64) -> Result<Self::Ok> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_char(self, v: char) -> Result<Self::Ok> {
		let mut buf = [0; 4];
		self.serialize_str(v.encode_utf8(&mut buf))
	}
	fn serialize_str(self, v: &str) -> Result<Self::Ok> {
		Utf8String::serialize(v, self)
	}
	
	fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
		self.__serialize_bytes_with_tag(v)
	}
	
	fn serialize_none(self) -> Result<Self::Ok> {
		Null::serialize(self)
	}
	fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_unit(self) -> Result<Self::Ok> {
		self.serialize_none()
	}
	//noinspection RsUnresolvedReference
	fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok> {
		self.serialize_none()
	}
	
	fn serialize_unit_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str) -> Result<Self::Ok>
	{
		Err(SerdeAsn1DerError::UnsupportedType)
	}

	#[cfg(not(feature = "complex_types"))]
	fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _name: &'static str, value: &T)
		-> Result<Self::Ok>
	{
		value.serialize(self)
	}

	#[cfg(feature = "complex_types")]
	fn serialize_newtype_struct<T: ?Sized + Serialize>(mut self, name: &'static str, value: &T)
		-> Result<Self::Ok>
	{
		match name {
			ObjectIdentifierAsn1::NAME => {
				self.tag_for_next_bytes = ObjectIdentifierAsn1::TAG;
				value.serialize(self)
			}
			BitStringAsn1::NAME => {
				self.tag_for_next_bytes = BitStringAsn1::TAG;
				value.serialize(self)
			}
			BitStringAsn1Container::<()>::NAME => {
				self.encapsulated = true;
				value.serialize(self)
			}
			_ => value.serialize(self),
		}
	}
	
	fn serialize_newtype_variant<T: ?Sized + Serialize>(self, _name: &'static str,
		_variant_index: u32, _variant: &'static str, _value: &T) -> Result<Self::Ok>
	{
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
		Ok(Sequence::serialize_lazy(self))
	}
	//noinspection RsUnresolvedReference
	fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
		self.serialize_seq(Some(len))
	}
	//noinspection RsUnresolvedReference
	fn serialize_tuple_struct(self, _name: &'static str, len: usize)
		-> Result<Self::SerializeTupleStruct>
	{
		self.serialize_seq(Some(len))
	}
	
	fn serialize_tuple_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str, _len: usize) -> Result<Self::SerializeTupleVariant>
	{
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
		self.serialize_seq(Some(len))
	}
	
	fn serialize_struct_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str, _len: usize) -> Result<Self::SerializeStructVariant>
	{
		Err(SerdeAsn1DerError::UnsupportedType)
	}
}
impl<'a, 'se> serde::ser::SerializeTupleVariant for &'a mut Serializer<'se> {
	type Ok = usize;
	type Error = SerdeAsn1DerError;
	
	fn serialize_field<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<()> {
		unimplemented!("The implementation does not support tuple variants")
	}
	fn end(self) -> Result<Self::Ok> {
		unimplemented!("The implementation does not support tuple variants")
	}
}
impl<'a, 'se> serde::ser::SerializeMap for &'a mut Serializer<'se> {
	type Ok = usize;
	type Error = SerdeAsn1DerError;
	
	fn serialize_key<T: ?Sized + Serialize>(&mut self, _key: &T) -> Result<()> {
		unimplemented!("The implementation does not support maps")
	}
	fn serialize_value<T: ?Sized + Serialize>(&mut self, _value: &T) -> Result<()> {
		unimplemented!("The implementation does not support maps")
	}
	fn end(self) -> Result<Self::Ok> {
		unimplemented!("The implementation does not support maps")
	}
}
impl<'a, 'se> serde::ser::SerializeStructVariant for &'a mut Serializer<'se> {
	type Ok = usize;
	type Error = SerdeAsn1DerError;
	
	fn serialize_field<T: ?Sized + Serialize>(&mut self, _key: &'static str, _value: &T)
		-> Result<()>
	{
		unimplemented!("The implementation does not support struct variants")
	}
	fn end(self) -> Result<Self::Ok> {
		unimplemented!("The implementation does not support struct variants")
	}
}