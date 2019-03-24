use crate::{
	Result,
	misc::{ WriteExt, Length }
};
use std::io::Write;


/// A trait that allows you to map all unsigned integers to a `u128`
pub trait UInt: Sized + Copy {
	/// Converts `self` into a `u128`
	fn into_u128(self) -> u128;
}
macro_rules! impl_uint {
	($type:ident) => {
		impl UInt for $type {
			fn into_u128(self) -> u128 {
				self as u128
			}
		}
	};
	($($type:ident),+) => ($( impl_uint!($type); )+)
}
impl_uint!(usize, u128, u64, u32, u16, u8);


/// A serializer for unsigned integers
pub struct UnsignedInteger;
impl UnsignedInteger {
	/// Serializes `value` into `writer`
	pub fn serialize<T: UInt>(value: T, mut writer: impl Write) -> Result<usize> {
		// Convert the value and compute the amount of bytes to skip
		let value = value.into_u128();
		let skip = match value.leading_zeros() as usize {
			n if n % 8 == 0 => n / 8,
			n => (n / 8) + 1
		};
		
		// Write tag and length
		let mut written = writer.write_one(0x02)?;
		written += Length::serialize(17 - skip, &mut writer)?;
		
		// Serialize the value and write the bytes
		let mut bytes = [0; 17];
		bytes[1..].copy_from_slice(&value.to_be_bytes());
		written += writer.write_exact(&bytes[skip..])?;
		
		Ok(written)
	}
}