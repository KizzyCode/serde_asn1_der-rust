mod boolean;
mod integer;
mod null;
mod octet_string;
mod sequence;
mod utf8_string;

#[cfg(feature = "more_types")]
use crate::asn1_wrapper::*;
use crate::{
	Result, SerdeAsn1DerError,
	misc::{ ReadExt, PeekableReader, Length },
	de::{
		boolean::Boolean, integer::UnsignedInteger, null::Null, octet_string::OctetString,
		sequence::Sequence, utf8_string::Utf8String
	}
};
use serde::{ Deserialize, de::Visitor };
use std::io::{ Read, Cursor };


/// Deserializes `T` from `bytes`
pub fn from_bytes<'a, T: Deserialize<'a>>(bytes: &'a[u8]) -> Result<T> {
	let mut deserializer = Deserializer::new_from_bytes(bytes);
	T::deserialize(&mut deserializer)
}
/// Deserializes `T` from `reader`
pub fn from_reader<'a, T: Deserialize<'a>>(reader: impl Read + 'a) -> Result<T> {
	let mut deserializer = Deserializer::new_from_reader(reader);
	T::deserialize(&mut deserializer)
}


/// An ASN.1-DER deserializer for `serde`
pub struct Deserializer<'de> {
	reader: PeekableReader<Box<dyn Read + 'de>>,
	buf: Vec<u8>,
	#[cfg(feature = "more_types")]
	encapsulated: bool,
}
impl<'de> Deserializer<'de> {
	/// Creates a new deserializer over `bytes`
	pub fn new_from_bytes(bytes: &'de[u8]) -> Self {
		Self::new_from_reader(Cursor::new(bytes))
	}
	/// Creates a new deserializer for `reader`
	#[cfg(feature = "more_types")]
	pub fn new_from_reader(reader: impl Read + 'de) -> Self {
		Self {
			reader: PeekableReader::new(Box::new(reader)),
			buf: Vec::new(),
			encapsulated: false
		}
	}

	#[cfg(not(feature = "more_types"))]
	pub fn new_from_reader(reader: impl Read + 'de) -> Self {
		Self {
			reader: PeekableReader::new(Box::new(reader)),
			buf: Vec::new(),
		}
	}
	
	/// Reads tag and length of the next DER object
	fn next_tag_len(&mut self) -> Result<(u8, usize)> {
		// Read type and length
		let tag = self.reader.read_one()?;
		let len = Length::deserialized(&mut self.reader)?;
		Ok((tag, len))
	}
	/// Reads the next DER object into `self.buf` and returns the tag
	fn next_object(&mut self) -> Result<u8> {
		#[cfg(feature = "more_types")]
		self.decapsulate()?;

		// Read type
		let tag = self.reader.read_one()?;
		
		// Deserialize length and read data
		let len = Length::deserialized(&mut self.reader)?;
		self.buf.resize(len, 0);
		self.reader.read_exact(&mut self.buf)?;
		
		Ok(tag)
	}

	#[cfg(feature = "more_types")]
	fn decapsulate(&mut self) -> Result<()> {
		if self.encapsulated {
			// discard bit string header bytes
			self.reader.read_one()?; // tag
			self.reader.read_one()?; // len
			self.reader.read_one()?; // unused bits count
			self.encapsulated = false;
		}
		Ok(())
	}
}
impl<'de, 'a> serde::de::Deserializer<'de> for &'a mut Deserializer<'de> {
	type Error = SerdeAsn1DerError;
	
	//noinspection RsUnresolvedReference
	fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		match self.reader.peek_one()? {
			Boolean::TAG => self.deserialize_bool(visitor),
			UnsignedInteger::TAG => self.deserialize_u128(visitor),
			Null::TAG => self.deserialize_unit(visitor),
			OctetString::TAG => self.deserialize_byte_buf(visitor),
			Sequence::TAG => self.deserialize_seq(visitor),
			Utf8String::TAG => self.deserialize_string(visitor),
			#[cfg(feature = "more_types")]
			ObjectIdentifierAsn1::TAG => self.deserialize_bytes(visitor),
			#[cfg(feature = "more_types")]
			BitStringAsn1::TAG => self.deserialize_byte_buf(visitor),
			_ => Err(SerdeAsn1DerError::InvalidData),
		}
	}
	
	fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != Boolean::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		visitor.visit_bool(Boolean::deserialize(&self.buf)?)
	}
	
	fn deserialize_i8<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn deserialize_i16<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn deserialize_i32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn deserialize_i64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	//noinspection RsTraitImplementation
	fn deserialize_i128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != UnsignedInteger::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		visitor.visit_u8(UnsignedInteger::deserialize(&self.buf)?)
	}
	fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != UnsignedInteger::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		visitor.visit_u16(UnsignedInteger::deserialize(&self.buf)?)
	}
	fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != UnsignedInteger::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		visitor.visit_u32(UnsignedInteger::deserialize(&self.buf)?)
	}
	fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != UnsignedInteger::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		visitor.visit_u64(UnsignedInteger::deserialize(&self.buf)?)
	}
	//noinspection RsTraitImplementation
	fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != UnsignedInteger::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		visitor.visit_u128(UnsignedInteger::deserialize(&self.buf)?)
	}
	
	fn deserialize_f32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn deserialize_f64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != Utf8String::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		let s = Utf8String::deserialize(&self.buf)?;
		
		let c = s.chars().next().ok_or(SerdeAsn1DerError::UnsupportedValue)?;
		visitor.visit_char(c)
	}
	fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != Utf8String::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		visitor.visit_str(Utf8String::deserialize(&self.buf)?)
	}
	fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != Utf8String::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		visitor.visit_string(Utf8String::deserialize(&self.buf)?.to_string())
	}
	
	fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		match self.next_object()? {
			OctetString::TAG => visitor.visit_bytes(OctetString::deserialize(&self.buf)?),
			#[cfg(feature = "more_types")]
			ObjectIdentifierAsn1::TAG => visitor.visit_bytes(&self.buf),
			#[cfg(feature = "more_types")]
			BitStringAsn1::TAG => visitor.visit_bytes(&self.buf),
			#[cfg(feature = "more_types")]
			IntegerAsn1::TAG => visitor.visit_bytes(&self.buf),
			_ => Err(SerdeAsn1DerError::InvalidData),
		}
	}
	fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		match self.next_object()? {
			OctetString::TAG => visitor.visit_byte_buf(OctetString::deserialize(&self.buf)?.to_vec()),
			#[cfg(feature = "more_types")]
			BitStringAsn1::TAG => visitor.visit_byte_buf(self.buf.to_vec()),
			_ => Err(SerdeAsn1DerError::InvalidData),
		}
	}
	
	fn deserialize_option<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		if self.next_object()? != Null::TAG { Err(SerdeAsn1DerError::InvalidData)? }
		Null::deserialize(&self.buf)?;
		visitor.visit_unit()
	}
	//noinspection RsUnresolvedReference
	fn deserialize_unit_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V)
		-> Result<V::Value>
	{
		self.deserialize_unit(visitor)
	}
	
	//noinspection RsUnresolvedReference
	// As is done here, serializers are encouraged to treat newtype structs as
	// insignificant wrappers around the data they contain. That means not
	// parsing anything other than the contained value.
	#[cfg(feature = "more_types")]
	fn deserialize_newtype_struct<V: Visitor<'de>>(self, name: &'static str, visitor: V)
		-> Result<V::Value>
	{
		match name {
			BitStringAsn1Container::<()>::NAME => {
				self.encapsulated = true;
				visitor.visit_newtype_struct(self)
			}
			_ => visitor.visit_newtype_struct(self),
		}
	}

	#[cfg(not(feature = "more_types"))]
	fn deserialize_newtype_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V)
		-> Result<V::Value>
	{
		visitor.visit_newtype_struct(self)
	}
	
	fn deserialize_seq<V: Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
		#[cfg(feature = "more_types")]
		self.decapsulate()?;

		// Read tag and length
		let (tag, len) = self.next_tag_len()?;
		match tag {
			Sequence::TAG => visitor.visit_seq(Sequence::deserialize_lazy(&mut self, len)),
			_ => {
				Err(SerdeAsn1DerError::InvalidData)
			},
		}
	}
	//noinspection RsUnresolvedReference
	fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
		self.deserialize_seq(visitor)
	}
	//noinspection RsUnresolvedReference
	fn deserialize_tuple_struct<V: Visitor<'de>>(self, _name: &'static str, _len: usize, visitor: V)
		-> Result<V::Value>
	{
		self.deserialize_seq(visitor)
	}
	
	fn deserialize_map<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn deserialize_struct<V: Visitor<'de>>(self, _name: &'static str,
		_fields: &'static [&'static str], visitor: V) -> Result<V::Value>
	{
		self.deserialize_seq(visitor)
	}
	
	fn deserialize_enum<V: Visitor<'de>>(self, _name: &'static str,
		_variants: &'static [&'static str], _visitor: V) -> Result<V::Value>
	{
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn deserialize_identifier<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	// Like `deserialize_any` but indicates to the `Deserializer` that it makes
	// no difference which `Visitor` method is called because the data is
	// ignored.
	//
	// Some deserializers are able to implement this more efficiently than
	// `deserialize_any`, for example by rapidly skipping over matched
	// delimiters without paying close attention to the data in between.
	//
	// Some formats are not able to implement this at all. Formats that can
	// implement `deserialize_any` and `deserialize_ignored_any` are known as
	// self-describing.
	fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		// Skip tag
		self.reader.peek_one()?;
		
		// Read len and copy payload into `self.buf`
		let len = Length::deserialized(&mut self.reader)?;
		self.buf.resize(len, 0);
		self.reader.read_exact(&mut self.buf)?;
		
		visitor.visit_unit()
	}
}