mod boolean;
mod integer;
mod null;
mod octet_string;
mod sequence;
mod utf8_string;

#[cfg(feature = "extra_types")]
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
	debug_log!("deserialization using `from_bytes`");
	let mut deserializer = Deserializer::new_from_bytes(bytes);
	T::deserialize(&mut deserializer)
}
/// Deserializes `T` from `reader`
pub fn from_reader<'a, T: Deserialize<'a>>(reader: impl Read + 'a) -> Result<T> {
	debug_log!("deserialization using `from_reader`");
	let mut deserializer = Deserializer::new_from_reader(reader);
	T::deserialize(&mut deserializer)
}


/// An ASN.1-DER deserializer for `serde`
pub struct Deserializer<'de> {
	reader: PeekableReader<Box<dyn Read + 'de>>,
	buf: Vec<u8>,
	#[cfg(feature = "extra_types")]
	encapsulated: bool,
	#[cfg(feature = "extra_types")]
	encapsulator_tag: u8,
}

impl<'de> Deserializer<'de> {
	/// Creates a new deserializer over `bytes`
	pub fn new_from_bytes(bytes: &'de[u8]) -> Self {
		Self::new_from_reader(Cursor::new(bytes))
	}
	/// Creates a new deserializer for `reader`
	#[cfg(feature = "extra_types")]
	pub fn new_from_reader(reader: impl Read + 'de) -> Self {
		Self {
			reader: PeekableReader::new(Box::new(reader)),
			buf: Vec::new(),
			encapsulated: false,
			encapsulator_tag: BitStringAsn1Container::<()>::TAG,
		}
	}

	#[cfg(not(feature = "extra_types"))]
	pub fn new_from_reader(reader: impl Read + 'de) -> Self {
		Self {
			reader: PeekableReader::new(Box::new(reader)),
			buf: Vec::new(),
		}
	}
	
	/// Reads tag and length of the next DER object
	fn __next_tag_len(&mut self) -> Result<(u8, usize)> {
		// Read type and length
		let tag = self.reader.read_one()?;
		let len = Length::deserialized(&mut self.reader)?;
		Ok((tag, len))
	}

	/// Reads the next DER object into `self.buf` and returns the tag
	fn __next_object(&mut self) -> Result<u8> {
		#[cfg(feature = "extra_types")]
		self.__decapsulate()?;

		// Read type
		let tag = self.reader.read_one()?;
		
		// Deserialize length and read data
		let len = Length::deserialized(&mut self.reader)?;
		self.buf.resize(len, 0);
		self.reader.read_exact(&mut self.buf)?;
		
		Ok(tag)
	}

	/// Peek next DER object tag (ignoring encapsulator)
	#[cfg(feature = "extra_types")]
	fn __peek_object(&mut self) -> Result<u8> {
		if self.encapsulated {
			let peeked = self.reader.peek_buffer()?;

			if peeked.len() < 1 {
				debug_log!("peek_object: TRUNCATED DATA (couldn't read encapsulator tag or length)");
				return Err(SerdeAsn1DerError::TruncatedData);
			}

			// check tag
			if peeked.buffer()[0] != self.encapsulator_tag {
				debug_log!("peek_object: INVALID (encapsulator tag doesn't match)");
				self.encapsulated = false;
				return Err(SerdeAsn1DerError::InvalidData);
			}

			let length = {
				let len = Length::deserialized(&mut Cursor::new(&peeked.buffer()[1..]))?;
				Length::encoded_len(len)
			};

			let object_tag_index = if self.encapsulator_tag == BitStringAsn1Container::<()>::TAG {
				length + 2
			} else {
				length + 1
			};

			if peeked.len() < object_tag_index {
				debug_log!("peek_object: TRUNCATED DATA (couldn't read object tag)");
				return Err(SerdeAsn1DerError::TruncatedData);
			}

			Ok(peeked.buffer()[object_tag_index])
		} else {
			Ok(self.reader.peek_one()?)
		}
	}

	#[cfg(not(feature = "extra_types"))]
	fn __peek_object(&mut self) -> Result<u8> {
		Ok(self.reader.peek_one()?)
	}

	#[cfg(feature = "extra_types")]
	fn __encapsulate(&mut self, tag: u8) {
		debug_log!("> encapsulator ({})", tag);
		self.encapsulated = true;
		self.encapsulator_tag = tag;
	}

	#[cfg(feature = "extra_types")]
	fn __decapsulate(&mut self) -> Result<()> {
		if self.encapsulated {
			self.encapsulated = false;

			// tag
			if self.reader.peek_one()? == self.encapsulator_tag {
				self.reader.read_one()?; // discard it
			} else {
				debug_log!("decapsulate: INVALID (encapsulator tag doesn't match)");
				return Err(SerdeAsn1DerError::InvalidData);
			}

			Length::deserialized(&mut self.reader)?; // len

			if self.encapsulator_tag == BitStringAsn1Container::<()>::TAG {
				self.reader.read_one()?; // unused bits count
			}
		}
		Ok(())
	}
}
impl<'de, 'a> serde::de::Deserializer<'de> for &'a mut Deserializer<'de> {
	type Error = SerdeAsn1DerError;
	
	//noinspection RsUnresolvedReference
	#[cfg(not(feature = "extra_types"))]
	fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_any");
		match self.__peek_object()? {
			Boolean::TAG => self.deserialize_bool(visitor),
			UnsignedInteger::TAG => self.deserialize_u128(visitor),
			Null::TAG => self.deserialize_unit(visitor),
			OctetString::TAG => self.deserialize_byte_buf(visitor),
			Sequence::TAG => self.deserialize_seq(visitor),
			Utf8String::TAG => self.deserialize_string(visitor),
			_ => {
				debug_log!("deserialize_any: INVALID");
				Err(SerdeAsn1DerError::InvalidData)
			},
		}
	}
	#[cfg(feature = "extra_types")]
	fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_any");
		match self.__peek_object()? {
			Boolean::TAG => self.deserialize_bool(visitor),
			UnsignedInteger::TAG => self.deserialize_u128(visitor), // FIXME: doesn't work for big integer as it
			Null::TAG => self.deserialize_unit(visitor),
			OctetString::TAG => self.deserialize_byte_buf(visitor),
			Sequence::TAG => self.deserialize_seq(visitor),
			Utf8String::TAG => self.deserialize_string(visitor),
			ObjectIdentifierAsn1::TAG => self.deserialize_bytes(visitor),
			BitStringAsn1::TAG => self.deserialize_byte_buf(visitor),
			DateAsn1::TAG => self.deserialize_bytes(visitor),
			ApplicationTag0::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag0::<()>::NAME, visitor),
			ApplicationTag1::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag1::<()>::NAME, visitor),
			ApplicationTag2::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag2::<()>::NAME, visitor),
			ApplicationTag3::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag3::<()>::NAME, visitor),
			ApplicationTag4::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag4::<()>::NAME, visitor),
			ApplicationTag5::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag5::<()>::NAME, visitor),
			ApplicationTag6::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag6::<()>::NAME, visitor),
			ApplicationTag7::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag7::<()>::NAME, visitor),
			ApplicationTag8::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag8::<()>::NAME, visitor),
			ApplicationTag9::<()>::TAG  => self.deserialize_newtype_struct(ApplicationTag9::<()>::NAME, visitor),
			ApplicationTag10::<()>::TAG => self.deserialize_newtype_struct(ApplicationTag10::<()>::NAME, visitor),
			ApplicationTag11::<()>::TAG => self.deserialize_newtype_struct(ApplicationTag11::<()>::NAME, visitor),
			ApplicationTag12::<()>::TAG => self.deserialize_newtype_struct(ApplicationTag12::<()>::NAME, visitor),
			ApplicationTag13::<()>::TAG => self.deserialize_newtype_struct(ApplicationTag13::<()>::NAME, visitor),
			ApplicationTag14::<()>::TAG => self.deserialize_newtype_struct(ApplicationTag14::<()>::NAME, visitor),
			ApplicationTag15::<()>::TAG => self.deserialize_newtype_struct(ApplicationTag15::<()>::NAME, visitor),
			_ => {
				debug_log!("deserialize_any: INVALID");
				Err(SerdeAsn1DerError::InvalidData)
			},
		}
	}
	
	fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_bool");
		if self.__peek_object()? != Boolean::TAG {
			debug_log!("deserialize_bool: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_bool(Boolean::deserialize(&self.buf)?)
	}
	
	fn deserialize_i8<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_i8: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn deserialize_i16<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_i16: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn deserialize_i32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_i32: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn deserialize_i64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_i64: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	//noinspection RsTraitImplementation
	fn deserialize_i128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_i128: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn deserialize_u8<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_u8");
		if self.__peek_object()? != UnsignedInteger::TAG {
			debug_log!("deserialize_u8: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_u8(UnsignedInteger::deserialize(&self.buf)?)
	}
	fn deserialize_u16<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_u16");
		if self.__peek_object()? != UnsignedInteger::TAG {
			debug_log!("deserialize_u16: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_u16(UnsignedInteger::deserialize(&self.buf)?)
	}
	fn deserialize_u32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_u32");
		if self.__peek_object()? != UnsignedInteger::TAG {
			debug_log!("deserialize_u32: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_u32(UnsignedInteger::deserialize(&self.buf)?)
	}
	fn deserialize_u64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_u64");
		if self.__peek_object()? != UnsignedInteger::TAG {
			debug_log!("deserialize_u64: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_u64(UnsignedInteger::deserialize(&self.buf)?)
	}
	//noinspection RsTraitImplementation
	fn deserialize_u128<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_u128");
		if self.__peek_object()? != UnsignedInteger::TAG {
			debug_log!("deserialize_u128: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_u128(UnsignedInteger::deserialize(&self.buf)?)
	}
	
	fn deserialize_f32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_f32: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	fn deserialize_f64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_f64: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn deserialize_char<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_char");
		if self.__peek_object()? != Utf8String::TAG {
			return Err(SerdeAsn1DerError::InvalidData)
		}
		self.__next_object()?;
		let s = Utf8String::deserialize(&self.buf)?;
		
		let c = s.chars().next().ok_or(SerdeAsn1DerError::UnsupportedValue)?;
		visitor.visit_char(c)
	}
	fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_str");
		if self.__peek_object()? != Utf8String::TAG {
			debug_log!("deserialize_str: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_str(Utf8String::deserialize(&self.buf)?)
	}
	fn deserialize_string<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_string");
		if self.__peek_object()? != Utf8String::TAG {
			debug_log!("deserialize_string: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_string(Utf8String::deserialize(&self.buf)?.to_string())
	}

	#[cfg(feature = "extra_types")]
	fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_bytes");
		match self.__peek_object()? {
			OctetString::TAG => {
				self.__next_object()?;
				return visitor.visit_bytes(OctetString::deserialize(&self.buf)?);
			},
			ObjectIdentifierAsn1::TAG => {},
			BitStringAsn1::TAG => {},
			IntegerAsn1::TAG => {},
			DateAsn1::TAG => {},
			_ => {
				debug_log!("deserialize_bytes: INVALID");
				return Err(SerdeAsn1DerError::InvalidData);
			},
		}

		self.__next_object()?;
		visitor.visit_bytes(&self.buf)
	}
	#[cfg(not(feature = "extra_types"))]
	fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_bytes");
		if self.__peek_object()? != OctetString::TAG {
			debug_log!("deserialize_bytes: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_bytes(OctetString::deserialize(&self.buf)?)
	}
	#[cfg(feature = "extra_types")]
	fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_byte_buf");
		match self.__peek_object()? {
			OctetString::TAG => {
				self.__next_object()?;
				return visitor.visit_byte_buf(OctetString::deserialize(&self.buf)?.to_vec());
			},
			BitStringAsn1::TAG => {},
			_ => {
				debug_log!("deserialize_byte_buf: INVALID");
				return Err(SerdeAsn1DerError::InvalidData);
			},
		}

		self.__next_object()?;
		visitor.visit_byte_buf(self.buf.to_vec())
	}
	#[cfg(not(feature = "extra_types"))]
	fn deserialize_byte_buf<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_byte_buf");
		if self.__peek_object()? != OctetString::TAG {
			debug_log!("deserialize_byte_buf: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		visitor.visit_byte_buf(OctetString::deserialize(&self.buf)?.to_vec())
	}
	
	fn deserialize_option<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_option: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_unit");
		if self.__peek_object()? != Null::TAG {
			debug_log!("deserialize_unit: INVALID");
			return Err(SerdeAsn1DerError::InvalidData);
		}
		self.__next_object()?;
		Null::deserialize(&self.buf)?;
		visitor.visit_unit()
	}
	//noinspection RsUnresolvedReference
	fn deserialize_unit_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V)
		-> Result<V::Value>
	{
		debug_log!("deserialize_unit_struct");
		self.deserialize_unit(visitor)
	}
	
	//noinspection RsUnresolvedReference
	// As is done here, serializers are encouraged to treat newtype structs as
	// insignificant wrappers around the data they contain. That means not
	// parsing anything other than the contained value.
	#[cfg(feature = "extra_types")]
	fn deserialize_newtype_struct<V: Visitor<'de>>(self, name: &'static str, visitor: V)
		-> Result<V::Value>
	{
		debug_log!("deserialize_newtype_struct: {}", name);
		match name {
			BitStringAsn1Container::<()>::NAME => self.__encapsulate(BitStringAsn1Container::<()>::TAG),
			ApplicationTag0::<()>::NAME  => self.__encapsulate(ApplicationTag0::<()>::TAG),
			ApplicationTag1::<()>::NAME  => self.__encapsulate(ApplicationTag1::<()>::TAG),
			ApplicationTag2::<()>::NAME  => self.__encapsulate(ApplicationTag2::<()>::TAG),
			ApplicationTag3::<()>::NAME  => self.__encapsulate(ApplicationTag3::<()>::TAG),
			ApplicationTag4::<()>::NAME  => self.__encapsulate(ApplicationTag4::<()>::TAG),
			ApplicationTag5::<()>::NAME  => self.__encapsulate(ApplicationTag5::<()>::TAG),
			ApplicationTag6::<()>::NAME  => self.__encapsulate(ApplicationTag6::<()>::TAG),
			ApplicationTag7::<()>::NAME  => self.__encapsulate(ApplicationTag7::<()>::TAG),
			ApplicationTag8::<()>::NAME  => self.__encapsulate(ApplicationTag8::<()>::TAG),
			ApplicationTag9::<()>::NAME  => self.__encapsulate(ApplicationTag9::<()>::TAG),
			ApplicationTag10::<()>::NAME => self.__encapsulate(ApplicationTag10::<()>::TAG),
			ApplicationTag11::<()>::NAME => self.__encapsulate(ApplicationTag11::<()>::TAG),
			ApplicationTag12::<()>::NAME => self.__encapsulate(ApplicationTag12::<()>::TAG),
			ApplicationTag13::<()>::NAME => self.__encapsulate(ApplicationTag13::<()>::TAG),
			ApplicationTag14::<()>::NAME => self.__encapsulate(ApplicationTag14::<()>::TAG),
			ApplicationTag15::<()>::NAME => self.__encapsulate(ApplicationTag15::<()>::TAG),
			_ => {},
		}

		visitor.visit_newtype_struct(self)
	}

	#[cfg(not(feature = "extra_types"))]
	fn deserialize_newtype_struct<V: Visitor<'de>>(self, _name: &'static str, visitor: V)
		-> Result<V::Value>
	{
		debug_log!("deserialize_newtype_struct: {}", _name);
		visitor.visit_newtype_struct(self)
	}
	
	fn deserialize_seq<V: Visitor<'de>>(mut self, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_seq");

		#[cfg(feature = "extra_types")]
		self.__decapsulate()?;

		// Read tag and length
		let (tag, len) = self.__next_tag_len()?;
		debug_log!("len: {}", len);
		match tag {
			Sequence::TAG => {},
			#[cfg(feature = "extra_types")]
			Asn1SetOf::<()>::TAG =>	{},
			_ => {
				debug_log!("deserialize_seq: INVALID");
				return Err(SerdeAsn1DerError::InvalidData);
			},
		}

		visitor.visit_seq(Sequence::deserialize_lazy(&mut self, len))
	}
	//noinspection RsUnresolvedReference
	fn deserialize_tuple<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_tuple: {}", _len);
		self.deserialize_seq(visitor)
	}
	//noinspection RsUnresolvedReference
	fn deserialize_tuple_struct<V: Visitor<'de>>(self, _name: &'static str, _len: usize, visitor: V)
		-> Result<V::Value>
	{
		debug_log!("deserialize_tuple_struct: {}({})", _name, _len);
		self.deserialize_seq(visitor)
	}
	
	fn deserialize_map<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_map: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	//noinspection RsUnresolvedReference
	fn deserialize_struct<V: Visitor<'de>>(self, _name: &'static str,
		_fields: &'static [&'static str], visitor: V) -> Result<V::Value>
	{
		debug_log!("deserialize_struct: {}", _name);
		self.deserialize_seq(visitor)
	}
	
	fn deserialize_enum<V: Visitor<'de>>(self, _name: &'static str,
		_variants: &'static [&'static str], _visitor: V) -> Result<V::Value>
	{
		debug_log!("deserialize_enum: UNSUPPORTED");
		Err(SerdeAsn1DerError::UnsupportedType)
	}
	
	fn deserialize_identifier<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value> {
		debug_log!("deserialize_identifier: UNSUPPORTED");
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
		debug_log!("deserialize_ignored_any");

		// Skip tag
		self.reader.read_one()?;
		
		// Read len and copy payload into `self.buf`
		let len = Length::deserialized(&mut self.reader)?;
		self.buf.resize(len, 0);
		self.reader.read_exact(&mut self.buf)?;
		
		visitor.visit_unit()
	}
}