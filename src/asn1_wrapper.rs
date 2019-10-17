use crate::bit_string::BitString;
use oid::ObjectIdentifier;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

/// Generate a thin ASN1 wrapper type with associated tag
/// and name for serialization and deserialization purpose.
macro_rules! asn1_wrapper {
    (struct $wrapper_ty:ident ( $wrapped_ty:ident ), $tag:literal) => {
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        pub struct $wrapper_ty(pub $wrapped_ty);

        impl $wrapper_ty {
            pub const TAG: u8 = $tag;
            pub(crate) const NAME: &'static str = stringify!($wrapper_ty);
        }

        impl From<$wrapped_ty> for $wrapper_ty {
            fn from(wrapped: $wrapped_ty) -> $wrapper_ty {
                Self(wrapped)
            }
        }

        impl Into<$wrapped_ty> for $wrapper_ty {
            fn into(self) -> $wrapped_ty {
                self.0
            }
        }

        impl Deref for $wrapper_ty {
            type Target = $wrapped_ty;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $wrapper_ty {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
    };
}

asn1_wrapper! { struct BitStringAsn1(BitString),               0x03 }
asn1_wrapper! { struct ObjectIdentifierAsn1(ObjectIdentifier), 0x06 }

/// A BitString encapsulating things.
/// Useful to perform a full serialization / deserialization in one pass
/// instead of using `BitStringAsn1` manually.
///
/// Examples
/// ```
/// use serde_asn1_der::asn1_wrapper::BitStringAsn1Container;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize, Debug, PartialEq)]
/// struct MyType {
///     a: u32,
///     b: u16,
///     c: u16,
/// }
///
/// type MyTypeEncapsulated = BitStringAsn1Container<MyType>;
///
/// let encapsulated: MyTypeEncapsulated = MyType {
///     a: 83910,
///     b: 3839,
///     c: 4023,
/// }.into();
///
/// let buffer = [
///     0x03, 0x0f, 0x00, // bit string part
///     0x30, 0x0d, // sequence
///     0x02, 0x03, 0x01, 0x47, 0xc6, // integer a
///     0x02, 0x02, 0x0e, 0xff, // integer b
///     0x02, 0x02, 0x0f, 0xb7, // integer c
/// ];
///
/// let encoded = serde_asn1_der::to_vec(&encapsulated).expect("couldn't serialize");
/// assert_eq!(
///     encoded,
///     buffer,
/// );
///
/// let decoded: MyTypeEncapsulated = serde_asn1_der::from_bytes(&buffer).expect("couldn't deserialize");
/// assert_eq!(
///     decoded,
///     encapsulated,
/// );
/// ```
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct BitStringAsn1Container<Encapsulated>(Encapsulated);

impl<Encapsulated> BitStringAsn1Container<Encapsulated> {
    pub const TAG: u8 = 0x03;
    pub(crate) const NAME: &'static str = "BitStringAsn1Container";
}

impl<Encapsulated> From<Encapsulated> for BitStringAsn1Container<Encapsulated> {
    fn from(wrapped: Encapsulated) -> Self {
        Self(wrapped)
    }
}

impl<Encapsulated> Deref for BitStringAsn1Container<Encapsulated> {
    type Target = Encapsulated;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<Encapsulated> DerefMut for BitStringAsn1Container<Encapsulated> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;

    #[test]
    fn oid() {
        let oid_buffer = [0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A];
        let oid = ObjectIdentifierAsn1::from(ObjectIdentifier::try_from("1.3.14.3.2.26").unwrap());

        let parsed_oid: ObjectIdentifierAsn1 =
            crate::from_bytes(&oid_buffer).expect("deserialization failed");
        assert_eq!(parsed_oid, oid);

        let encoded_oid = crate::to_vec(&oid).expect("serialization failed");
        assert_eq!(encoded_oid, oid_buffer);
    }

    #[test]
    fn bit_string() {
        #[rustfmt::skip]
        let bit_string_buffer = [
            0x03, // tag
            0x81, 0x81, // length
            0x00, // unused bits
            0x47, 0xeb, 0x99, 0x5a, 0xdf, 0x9e, 0x70, 0x0d, 0xfb, 0xa7, 0x31, 0x32, 0xc1, 0x5f, 0x5c, 0x24,
            0xc2, 0xe0, 0xbf, 0xc6, 0x24, 0xaf, 0x15, 0x66, 0x0e, 0xb8, 0x6a, 0x2e, 0xab, 0x2b, 0xc4, 0x97,
            0x1f, 0xe3, 0xcb, 0xdc, 0x63, 0xa5, 0x25, 0xec, 0xc7, 0xb4, 0x28, 0x61, 0x66, 0x36, 0xa1, 0x31,
            0x1b, 0xbf, 0xdd, 0xd0, 0xfc, 0xbf, 0x17, 0x94, 0x90, 0x1d, 0xe5, 0x5e, 0xc7, 0x11, 0x5e, 0xc9,
            0x55, 0x9f, 0xeb, 0xa3, 0x3e, 0x14, 0xc7, 0x99, 0xa6, 0xcb, 0xba, 0xa1, 0x46, 0x0f, 0x39, 0xd4,
            0x44, 0xc4, 0xc8, 0x4b, 0x76, 0x0e, 0x20, 0x5d, 0x6d, 0xa9, 0x34, 0x9e, 0xd4, 0xd5, 0x87, 0x42,
            0xeb, 0x24, 0x26, 0x51, 0x14, 0x90, 0xb4, 0x0f, 0x06, 0x5e, 0x52, 0x88, 0x32, 0x7a, 0x95, 0x20,
            0xa0, 0xfd, 0xf7, 0xe5, 0x7d, 0x60, 0xdd, 0x72, 0x68, 0x9b, 0xf5, 0x7b, 0x05, 0x8f, 0x6d, 0x1e,
        ];
        let bit_string = BitStringAsn1::from(BitString::with_bytes(&bit_string_buffer[4..]));

        let parsed_bit_string: BitStringAsn1 =
            crate::from_bytes(&bit_string_buffer).expect("deserialization failed");
        assert_eq!(parsed_bit_string, bit_string);

        let encoded_bit_string = crate::to_vec(&bit_string).expect("serialization failed");
        assert_eq!(encoded_bit_string, bit_string_buffer.to_vec());
    }

    #[test]
    fn encapsulated_types() {
        {
            let buffer = [0x03, 0x5, 0x00, 0x02, 0x03, 0x3c, 0x1c, 0x37];
            let encapsulated: BitStringAsn1Container<u64> = u64::from(3939383u64).into();

            let encoded = crate::to_vec(&encapsulated).expect("encapsulated vec serialization failed");
            assert_eq!(encoded, buffer);

            let decoded: BitStringAsn1Container<u64> = crate::from_bytes(&buffer).expect("encapsulated vec deserialization failed");
            assert_eq!(decoded, encapsulated);
        }

        {
            let buffer = [
                0x03, 0x10, 0x00, 0x0c, 0x0e, 0x55, 0x54, 0x46,
                0x2d, 0x38, 0xe6, 0x96, 0x87, 0xe5, 0xad, 0x97,
                0xe5, 0x88, 0x97
            ];
            let encapsulated: BitStringAsn1Container<String> = String::from("UTF-8文字列").into();

            let encoded = crate::to_vec(&encapsulated).expect("encapsulated utf8 string serialization failed");
            assert_eq!(encoded, buffer);

            let decoded: BitStringAsn1Container<String> = crate::from_bytes(&buffer).expect("encapsulated utf8 string deserialization failed");
            assert_eq!(decoded, encapsulated);
        }
    }
}
