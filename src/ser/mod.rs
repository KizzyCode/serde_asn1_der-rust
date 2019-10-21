mod boolean;
mod integer;
mod null;
mod sequence;
mod utf8_string;

#[cfg(feature = "more_types")]
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
	debug_log!("serialization using `to_bytes`");
	let mut serializer = Serializer::new_to_bytes(buf);
	value.serialize(&mut serializer)
}
/// Serializes `value` to `buf` and returns the amount of serialized bytes
pub fn to_byte_buf<T: ?Sized + Serialize>(value: &T, buf: &mut Vec<u8>) -> Result<usize> {
	debug_log!("serialization using `to_byte_buf`");
	let mut serializer = Serializer::new_to_byte_buf(buf);
	value.serialize(&mut serializer)
}
/// Serializes `value` to `writer` and returns the amount of serialized bytes
pub fn to_writer<T: ?Sized + Serialize>(value: &T, writer: impl Write) -> Result<usize> {
	debug_log!("serialization using `to_writer`");
	let mut serializer = Serializer::new_to_writer(writer);
	value.serialize(&mut serializer)
}


/// An ASN.1-DER serializer for `serde`
pub struct Serializer<'se> {
	writer: Box<dyn Write + 'se>,
	#[cfg(feature = "more_types")]
	tag_for_next_bytes: u8,
	#[cfg(feature = "more_types")]
	tag_for_next_seq: u8,
	#[cfg(feature = "more_types")]
	encapsulated: bool,
	#[cfg(feature = "more_types")]
	encapsulator_tag: u8,
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
	#[cfg(feature = "more_types")]
	pub fn new_to_writer(writer: impl Write + 'se) -> Self {
		Self {
			writer: Box::new(writer),
			tag_for_next_bytes: 0x04,
			tag_for_next_seq: 0x30,
			encapsulated: false,
			encapsulator_tag: BitStringAsn1Container::<()>::TAG,
		}
	}

	#[cfg(not(feature = "more_types"))]
	pub fn new_to_writer(writer: impl Write + 'se) -> Self {
		Self { writer: Box::new(writer) }
	}

	#[cfg(feature = "more_types")]
	fn __encapsulate(&mut self, tag: u8) {
		self.encapsulated = true;
		self.encapsulator_tag = tag;
	}

	#[cfg(feature = "more_types")]
	fn __write_encapsulator(&mut self, encapsulated_size: usize) -> Result<usize> {
		let mut written = 0;
		if self.encapsulated { // encapsulated
			written += self.writer.write_one(self.encapsulator_tag)?;
			if self.encapsulator_tag == BitStringAsn1Container::<()>::TAG {
				written += Length::serialize(encapsulated_size + 1, &mut self.writer)?;
				written += self.writer.write_one(0x00)?; // no unused bits
			} else {
				written += Length::serialize(encapsulated_size, &mut self.writer)?;
			}

			self.encapsulated = false; // reset encapsulation state
		}
		Ok(written)
	}

	#[cfg(not(feature = "more_types"))]
	#[inline]
	fn __write_encapsulator(&self, _: usize) -> Result<usize> {
		Ok(0)
	}

	#[cfg(feature = "more_types")]
	fn __serialize_bytes_with_tag(&mut self, bytes: &[u8]) -> Result<usize> {
		let mut written = self.__write_encapsulator(bytes.len() + Length::encoded_len(bytes.len()) + 1)?;

		// Write tag, length and data
		written += self.writer.write_one(self.tag_for_next_bytes)?;
		written += Length::serialize(bytes.len(), &mut self.writer)?;
		written += self.writer.write_exact(bytes)?;

		self.tag_for_next_bytes = 0x04; // reset to octet string

		Ok(written)
	}

	#[cfg(not(feature = "more_types"))]
	fn __serialize_bytes_with_tag(&mut self, bytes: &[u8]) -> Result<usize> {
		// Write tag, length and data
		let mut written = self.writer.write_one(0x04)?;
		written += Length::serialize(bytes.len(), &mut self.writer)?;
		written += self.writer.write_exact(bytes)?;
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
		debug_log!("serialize_bool: {}", v);
		Boolean::serialize(v, self)
	}
	
	fn serialize_i8(self, _v: i8) -> Result<Self::Ok> {
		debug_log!("serialize_i8: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_i16(self, _v: i16) -> Result<Self::Ok> {
		debug_log!("serialize_i16: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_i32(self, _v: i32) -> Result<Self::Ok> {
		debug_log!("serialize_i32: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_i64(self, _v: i64) -> Result<Self::Ok> {
		debug_log!("serialize_i64: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	//noinspection RsTraitImplementation
	fn serialize_i128(self, _v: i128) -> Result<Self::Ok> {
		debug_log!("serialize_i128: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_u8(self, v: u8) -> Result<Self::Ok> {
		debug_log!("serialize_u8: {}", v);
		self.serialize_u128(v as u128)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u16(self, v: u16) -> Result<Self::Ok> {
		debug_log!("serialize_u16: {}", v);
		self.serialize_u128(v as u128)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u32(self, v: u32) -> Result<Self::Ok> {
		debug_log!("serialize_u32: {}", v);
		self.serialize_u128(v as u128)
	}
	//noinspection RsUnresolvedReference
	fn serialize_u64(self, v: u64) -> Result<Self::Ok> {
		debug_log!("serialize_u64: {}", v);
		self.serialize_u128(v as u128)
	}
	//noinspection RsTraitImplementation
	fn serialize_u128(self, v: u128) -> Result<Self::Ok> {
		debug_log!("serialize_u128: {}", v);
		UnsignedInteger::serialize(v, self)
	}
	
	fn serialize_f32(self, _v: f32) -> Result<Self::Ok> {
		debug_log!("serialize_f32: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_f64(self, _v: f64) -> Result<Self::Ok> {
		debug_log!("serialize_f64: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_char(self, v: char) -> Result<Self::Ok> {
		debug_log!("serialize_char: {}", v);
		let mut buf = [0; 4];
		self.serialize_str(v.encode_utf8(&mut buf))
	}
	fn serialize_str(self, v: &str) -> Result<Self::Ok> {
		debug_log!("serialize_str: {}", v);
		Utf8String::serialize(v, self)
	}
	
	fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok> {
		debug_log!("serialize_bytes");
		self.__serialize_bytes_with_tag(v)
	}
	
	fn serialize_none(self) -> Result<Self::Ok> {
		debug_log!("serialize_none: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn serialize_some<T: ?Sized + Serialize>(self, _value: &T) -> Result<Self::Ok> {
		debug_log!("serialize_some: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_unit(self) -> Result<Self::Ok> {
		debug_log!("serialize_unit");
		Null::serialize(self)
	}
	//noinspection RsUnresolvedReference
	fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok> {
		debug_log!("serialize_unit_struct: {}", _name);
		Null::serialize(self)
	}
	
	fn serialize_unit_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str) -> Result<Self::Ok>
	{
		debug_log!("serialize_unit_variant: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}

	#[cfg(not(feature = "more_types"))]
	fn serialize_newtype_struct<T: ?Sized + Serialize>(self, _name: &'static str, value: &T)
		-> Result<Self::Ok>
	{
		debug_log!("serialize_newtype_struct: {}", _name);
		value.serialize(self)
	}

	#[cfg(feature = "more_types")]
	fn serialize_newtype_struct<T: ?Sized + Serialize>(mut self, name: &'static str, value: &T)
		-> Result<Self::Ok>
	{
		debug_log!("serialize_newtype_struct: {}", name);
		match name {
			ObjectIdentifierAsn1::NAME => {
				self.tag_for_next_bytes = ObjectIdentifierAsn1::TAG;
				value.serialize(self)
			}
			BitStringAsn1::NAME => {
				self.tag_for_next_bytes = BitStringAsn1::TAG;
				value.serialize(self)
			}
			IntegerAsn1::NAME => {
				self.tag_for_next_bytes = IntegerAsn1::TAG;
				value.serialize(self)
			}
			DateAsn1::NAME => {
				self.tag_for_next_bytes = DateAsn1::TAG;
				value.serialize(self)
			}
			Asn1SetOf::<()>::NAME => {
				self.tag_for_next_seq = Asn1SetOf::<()>::TAG;
				value.serialize(self)
			}
			Asn1SequenceOf::<()>::NAME => {
				self.tag_for_next_seq = Asn1SequenceOf::<()>::TAG;
				value.serialize(self)
			}
			BitStringAsn1Container::<()>::NAME => {
				self.__encapsulate(BitStringAsn1Container::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag0::<()>::NAME  => {
				self.__encapsulate(ApplicationTag0::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag1::<()>::NAME  => {
				self.__encapsulate(ApplicationTag1::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag2::<()>::NAME  => {
				self.__encapsulate(ApplicationTag2::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag3::<()>::NAME  => {
				self.__encapsulate(ApplicationTag3::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag4::<()>::NAME  => {
				self.__encapsulate(ApplicationTag4::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag5::<()>::NAME  => {
				self.__encapsulate(ApplicationTag5::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag6::<()>::NAME  => {
				self.__encapsulate(ApplicationTag6::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag7::<()>::NAME  => {
				self.__encapsulate(ApplicationTag7::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag8::<()>::NAME  => {
				self.__encapsulate(ApplicationTag8::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag9::<()>::NAME  => {
				self.__encapsulate(ApplicationTag9::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag10::<()>::NAME => {
				self.__encapsulate(ApplicationTag10::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag11::<()>::NAME => {
				self.__encapsulate(ApplicationTag11::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag12::<()>::NAME => {
				self.__encapsulate(ApplicationTag12::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag13::<()>::NAME => {
				self.__encapsulate(ApplicationTag13::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag14::<()>::NAME => {
				self.__encapsulate(ApplicationTag14::<()>::TAG);
				value.serialize(self)
			}
			ApplicationTag15::<()>::NAME => {
				self.__encapsulate(ApplicationTag15::<()>::TAG);
				value.serialize(self)
			}
			_ => value.serialize(self),
		}
	}
	
	fn serialize_newtype_variant<T: ?Sized + Serialize>(self, _name: &'static str,
		_variant_index: u32, _variant: &'static str, _value: &T) -> Result<Self::Ok>
	{
		debug_log!("serialize_newtype_variant: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}

	#[cfg(feature = "more_types")]
	fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
		debug_log!("serialize_seq");
		let mut tag = 0x30;
		std::mem::swap(&mut tag, &mut self.tag_for_next_seq);
		Ok(Sequence::serialize_lazy(self, tag))
	}
	#[cfg(not(feature = "more_types"))]
	fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq> {
		debug_log!("serialize_seq");
		Ok(Sequence::serialize_lazy(self, 0x30))
	}
	//noinspection RsUnresolvedReference
	fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple> {
		debug_log!("serialize_tuple: {}", len);
		self.serialize_seq(Some(len))
	}
	//noinspection RsUnresolvedReference
	fn serialize_tuple_struct(self, _name: &'static str, len: usize)
		-> Result<Self::SerializeTupleStruct>
	{
		debug_log!("serialize_tuple_struct: {}({})", _name, len);
		self.serialize_seq(Some(len))
	}
	
	fn serialize_tuple_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str, _len: usize) -> Result<Self::SerializeTupleVariant>
	{
		debug_log!("serialize_tuple_variant: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap> {
		debug_log!("serialize_map: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn serialize_struct(self, _name: &'static str, len: usize) -> Result<Self::SerializeStruct> {
		debug_log!("serialize_struct: {}", _name);
		self.serialize_seq(Some(len))
	}
	
	fn serialize_struct_variant(self, _name: &'static str, _variant_index: u32,
		_variant: &'static str, _len: usize) -> Result<Self::SerializeStructVariant>
	{
		debug_log!("serialize_struct_variant: UNSUPPORTED");
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