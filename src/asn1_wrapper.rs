use crate::bit_string::BitString;
use chrono::{Datelike, Timelike};
use num_bigint::{BigInt, Sign};
use oid::ObjectIdentifier;
use serde::{de, ser, Deserialize, Serialize};
use std::{
    fmt,
    ops::{Deref, DerefMut},
};

/// Generate a thin ASN1 wrapper type with associated tag
/// and name for serialization and deserialization purpose.
macro_rules! asn1_wrapper {
    (struct $wrapper_ty:ident ( $wrapped_ty:ident ), $tag:literal) => {
        /// Wrapper type
        #[derive(Debug, PartialEq)]
        pub struct $wrapper_ty(pub $wrapped_ty);

        impls! { $wrapper_ty ( $wrapped_ty ), $tag }
    };
    (auto struct $wrapper_ty:ident ( $wrapped_ty:ident ), $tag:literal) => {
        /// Wrapper type
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        pub struct $wrapper_ty(pub $wrapped_ty);

        impls! { $wrapper_ty ( $wrapped_ty ), $tag }
    };
    (application tag struct $wrapper_ty:ident < $generic:ident >, $tag:literal) => {
        /// Wrapper type
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        pub struct $wrapper_ty<$generic>(pub $generic);

        impls! { $wrapper_ty < $generic >, $tag }
    };
    (auto collection struct $wrapper_ty:ident < T >, $tag:literal) => {
        /// Asn1 wrapper around a collection of elements of the same type.
        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        pub struct $wrapper_ty<T>(
            #[serde(
                serialize_with = "serialize_vec",
                deserialize_with = "deserialize_vec",
                bound(serialize = "T: Serialize", deserialize = "T: Deserialize<'de>")
            )]
            pub Vec<T>,
        );

        impls! { $wrapper_ty ( Vec < T > ), $tag }
    };
}

macro_rules! impls {
    ($wrapper_ty:ident ( $wrapped_ty:ident ), $tag:literal) => {
        impl $wrapper_ty {
            pub const TAG: u8 = $tag;
            pub(crate) const NAME: &'static str = stringify!($wrapper_ty);
        }

        impl From<$wrapped_ty> for $wrapper_ty {
            fn from(wrapped: $wrapped_ty) -> Self {
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

        impl PartialEq<$wrapped_ty> for $wrapper_ty {
            fn eq(&self, other: &$wrapped_ty) -> bool {
                self.0.eq(other)
            }
        }
    };
    ($wrapper_ty:ident < $generic:ident >, $tag:literal) => {
        impl<$generic> $wrapper_ty<$generic> {
            pub const TAG: u8 = $tag;
            pub const NAME: &'static str = stringify!($wrapper_ty);
        }

        impl<$generic> From<$generic> for $wrapper_ty<$generic> {
            fn from(wrapped: $generic) -> Self {
                Self(wrapped)
            }
        }

        //-- Into cannot be defined to convert into a generic type (E0119) --

        impl<$generic> Deref for $wrapper_ty<$generic> {
            type Target = $generic;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<$generic> DerefMut for $wrapper_ty<$generic> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<$generic> PartialEq<$generic> for $wrapper_ty<$generic>
        where
            $generic: PartialEq,
        {
            fn eq(&self, other: &$generic) -> bool {
                self.0.eq(other)
            }
        }
    };
    ($wrapper_ty:ident ( $wrapped_ty:ident < $generic:ident > ), $tag:literal) => {
        impl<$generic> $wrapper_ty<$generic> {
            pub const TAG: u8 = $tag;
            pub(crate) const NAME: &'static str = stringify!($wrapper_ty);
        }

        impl<$generic> From<$wrapped_ty<$generic>> for $wrapper_ty<$generic> {
            fn from(wrapped: $wrapped_ty<$generic>) -> Self {
                Self(wrapped)
            }
        }

        impl<$generic> Into<$wrapped_ty<$generic>> for $wrapper_ty<$generic> {
            fn into(self) -> $wrapped_ty<$generic> {
                self.0
            }
        }

        impl<$generic> Deref for $wrapper_ty<$generic> {
            type Target = $wrapped_ty<$generic>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl<$generic> DerefMut for $wrapper_ty<$generic> {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl<$generic> PartialEq<$wrapped_ty<$generic>> for $wrapper_ty<$generic>
        where
            $generic: PartialEq,
        {
            fn eq(&self, other: &$wrapped_ty<$generic>) -> bool {
                self.0.eq(other)
            }
        }
    };
}

macro_rules! define_application_tag {
    ( $name:ident => $tag:literal ) => {
        asn1_wrapper! { application tag struct $name<T>, $tag }
    };
    ( $( $name:ident => $tag:literal , )+ ) => {
        $( define_application_tag! { $name => $tag } )+
    };
}

asn1_wrapper! { auto struct BitStringAsn1(BitString),               0x03 }
asn1_wrapper! { auto struct ObjectIdentifierAsn1(ObjectIdentifier), 0x06 }

asn1_wrapper! { auto collection struct Asn1SequenceOf<T>, 0x30 }
asn1_wrapper! { auto collection struct Asn1SetOf<T>,      0x31 }

define_application_tag! {
    ApplicationTag0  => 0xA0,
    ApplicationTag1  => 0xA1,
    ApplicationTag2  => 0xA2,
    ApplicationTag3  => 0xA3,
    ApplicationTag4  => 0xA4,
    ApplicationTag5  => 0xA5,
    ApplicationTag6  => 0xA6,
    ApplicationTag7  => 0xA7,
    ApplicationTag8  => 0xA8,
    ApplicationTag9  => 0xA9,
    ApplicationTag10 => 0xAA,
    ApplicationTag11 => 0xAB,
    ApplicationTag12 => 0xAC,
    ApplicationTag13 => 0xAD,
    ApplicationTag14 => 0xAE,
    ApplicationTag15 => 0xAF,
}

fn serialize_vec<S, T>(
    set: &[T],
    serializer: S,
) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
where
    S: ser::Serializer,
    T: Serialize,
{
    use serde::ser::SerializeSeq;

    let mut seq = serializer.serialize_seq(Some(set.len()))?;
    for e in set {
        seq.serialize_element(e)?;
    }
    seq.end()
}

fn deserialize_vec<'de, D, T>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: de::Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct Visitor<T>(std::marker::PhantomData<T>);

    impl<'de, T> de::Visitor<'de> for Visitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid sequence of T")
        }

        fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            let mut vec = Vec::new();
            while let Some(e) = seq.next_element()? {
                vec.push(e);
            }
            Ok(vec)
        }
    }

    deserializer.deserialize_seq(Visitor(std::marker::PhantomData))
}

/// A BigInt wrapper for Asn1 encoding.
///
/// Simply use primitive integer types if you don't need big integer.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct IntegerAsn1(
    #[serde(
        serialize_with = "serialize_big_int",
        deserialize_with = "deserialize_big_int"
    )]
    pub BigInt,
);

impls! { IntegerAsn1(BigInt), 0x02 }

fn serialize_big_int<S>(
    big_int: &BigInt,
    serializer: S,
) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
where
    S: ser::Serializer,
{
    serializer.serialize_bytes(&big_int.to_signed_bytes_be())
}

fn deserialize_big_int<'de, D>(deserializer: D) -> Result<BigInt, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = BigInt;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid buffer representing a bit string")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            if v.len() > 1 {
                if v[0] == 0x00 {
                    Ok(BigInt::from_bytes_be(Sign::Plus, &v[1..]))
                } else if v[0] & 0x80 != 0 {
                    Ok(BigInt::from_bytes_be(Sign::Minus, v))
                } else {
                    Ok(BigInt::from_bytes_be(Sign::Plus, v))
                }
            } else {
                Ok(BigInt::from(v[0] as i8))
            }
        }
    }

    deserializer.deserialize_bytes(Visitor)
}

/// A timestamp date wrapper for Asn1 encoding.
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct DateAsn1(
    #[serde(
        serialize_with = "serialize_date_timestamp",
        deserialize_with = "deserialize_date_timestamp"
    )]
    pub i64,
);

impls! { DateAsn1(i64), 0x17 }

fn serialize_date_timestamp<S>(
    timestamp: &i64,
    serializer: S,
) -> Result<<S as ser::Serializer>::Ok, <S as ser::Serializer>::Error>
where
    S: ser::Serializer,
{
    use chrono::naive::NaiveDateTime;

    let date = NaiveDateTime::from_timestamp(*timestamp, 0);
    let year = if date.year() >= 2000 {
        date.year() - 2000
    } else {
        date.year() - 1900
    };

    let mut encoded = [
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A,
    ];
    encoded[0] |= (year / 10) as u8;
    encoded[1] |= (year % 10) as u8;
    encoded[2] |= (date.month() / 10) as u8;
    encoded[3] |= (date.month() % 10) as u8;
    encoded[4] |= (date.day() / 10) as u8;
    encoded[5] |= (date.day() % 10) as u8;
    encoded[6] |= (date.hour() / 10) as u8;
    encoded[7] |= (date.hour() % 10) as u8;
    encoded[8] |= (date.minute() / 10) as u8;
    encoded[9] |= (date.minute() % 10) as u8;
    encoded[10] |= (date.second() / 10) as u8;
    encoded[11] |= (date.second() % 10) as u8;

    serializer.serialize_bytes(&encoded)
}

fn deserialize_date_timestamp<'de, D>(deserializer: D) -> Result<i64, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = i64;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            formatter.write_str("a valid buffer representing an Asn1 UTCDate")
        }

        fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
        where
            E: de::Error,
        {
            use chrono::naive::NaiveDate;

            if v.len() != 13 {
                return Err(E::invalid_value(
                    de::Unexpected::Other("unsupported date format"),
                    &"a valid buffer representing an Asn1 UTCDate (exactly 13 bytes required)",
                ));
            }

            let yyyy = {
                let yy = i32::from(v[0] & 0x0F) * 10 + i32::from(v[1] & 0x0F);
                if yy >= 50 {
                    1900 + yy
                } else {
                    2000 + yy
                }
            };
            let month = u32::from(v[2] & 0x0F) * 10 + u32::from(v[3] & 0x0F);
            let day = u32::from(v[4] & 0x0F) * 10 + u32::from(v[5] & 0x0F);
            let hour = u32::from(v[6] & 0x0F) * 10 + u32::from(v[7] & 0x0F);
            let minute = u32::from(v[8] & 0x0F) * 10 + u32::from(v[9] & 0x0F);
            let second = u32::from(v[10] & 0x0F) * 10 + u32::from(v[11] & 0x0F);
            let dt = NaiveDate::from_ymd(yyyy, month, day).and_hms(hour, minute, second);

            Ok(dt.timestamp())
        }
    }

    deserializer.deserialize_bytes(Visitor)
}

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
///     0x03, 0x10, 0x00, // bit string part
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
pub struct BitStringAsn1Container<Encapsulated>(pub Encapsulated);

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

impl<Encapsulated> PartialEq<Encapsulated> for BitStringAsn1Container<Encapsulated>
where
    Encapsulated: PartialEq,
{
    fn eq(&self, other: &Encapsulated) -> bool {
        self.0.eq(other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use num_bigint::ToBigInt;
    use pretty_assertions::assert_eq;
    use std::{borrow::Cow, convert::TryFrom};

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
            let buffer = [0x03, 0x6, 0x00, 0x02, 0x03, 0x3c, 0x1c, 0x37];
            let encapsulated: BitStringAsn1Container<u64> = u64::from(3939383u64).into();

            let encoded =
                crate::to_vec(&encapsulated).expect("encapsulated vec serialization failed");
            assert_eq!(encoded, buffer);

            let decoded: BitStringAsn1Container<u64> =
                crate::from_bytes(&buffer).expect("encapsulated vec deserialization failed");
            assert_eq!(decoded, encapsulated);
        }

        {
            let buffer = [
                0x03, 0x11, 0x00, 0x0c, 0x0e, 0x55, 0x54, 0x46, 0x2d, 0x38, 0xe6, 0x96, 0x87, 0xe5,
                0xad, 0x97, 0xe5, 0x88, 0x97,
            ];
            let encapsulated: BitStringAsn1Container<String> = String::from("UTF-8文字列").into();

            let encoded = crate::to_vec(&encapsulated)
                .expect("encapsulated utf8 string serialization failed");
            assert_eq!(encoded, buffer);

            let decoded: BitStringAsn1Container<String> = crate::from_bytes(&buffer)
                .expect("encapsulated utf8 string deserialization failed");
            assert_eq!(decoded, encapsulated);
        }
    }

    #[test]
    fn big_integer() {
        #[rustfmt::skip]
        let big_integer_buffer = [
            0x02, // tag
            0x81, 0x81, // length
            0x00, // + sign
            0x8f, 0xe2, 0x41, 0x2a, 0x08, 0xe8, 0x51, 0xa8, 0x8c, 0xb3, 0xe8, 0x53, 0xe7, 0xd5, 0x49, 0x50,
            0xb3, 0x27, 0x8a, 0x2b, 0xcb, 0xea, 0xb5, 0x42, 0x73, 0xea, 0x02, 0x57, 0xcc, 0x65, 0x33, 0xee,
            0x88, 0x20, 0x61, 0xa1, 0x17, 0x56, 0xc1, 0x24, 0x18, 0xe3, 0xa8, 0x08, 0xd3, 0xbe, 0xd9, 0x31,
            0xf3, 0x37, 0x0b, 0x94, 0xb8, 0xcc, 0x43, 0x08, 0x0b, 0x70, 0x24, 0xf7, 0x9c, 0xb1, 0x8d, 0x5d,
            0xd6, 0x6d, 0x82, 0xd0, 0x54, 0x09, 0x84, 0xf8, 0x9f, 0x97, 0x01, 0x75, 0x05, 0x9c, 0x89, 0xd4,
            0xd5, 0xc9, 0x1e, 0xc9, 0x13, 0xd7, 0x2a, 0x6b, 0x30, 0x91, 0x19, 0xd6, 0xd4, 0x42, 0xe0, 0xc4,
            0x9d, 0x7c, 0x92, 0x71, 0xe1, 0xb2, 0x2f, 0x5c, 0x8d, 0xee, 0xf0, 0xf1, 0x17, 0x1e, 0xd2, 0x5f,
            0x31, 0x5b, 0xb1, 0x9c, 0xbc, 0x20, 0x55, 0xbf, 0x3a, 0x37, 0x42, 0x45, 0x75, 0xdc, 0x90, 0x65,
        ];
        let big_integer =
            IntegerAsn1::from(BigInt::from_bytes_be(Sign::Plus, &big_integer_buffer[4..]));

        let parsed_big_integer: IntegerAsn1 =
            crate::from_bytes(&big_integer_buffer).expect("deserialization failed");
        assert_eq!(parsed_big_integer, big_integer);

        let encoded_big_integer = crate::to_vec(&big_integer).expect("serialization failed");
        assert_eq!(encoded_big_integer, big_integer_buffer.to_vec());
    }

    #[test]
    fn small_integer() {
        let buffer = [0x02, 0x01, 0x03];
        let big_integer = IntegerAsn1::from(3.to_bigint().unwrap());

        let parsed_big_integer: IntegerAsn1 =
            crate::from_bytes(&buffer).expect("deserialization failed");
        assert_eq!(parsed_big_integer, big_integer);

        let encoded_big_integer = crate::to_vec(&big_integer).expect("serialization failed");
        assert_eq!(encoded_big_integer, buffer);
    }

    #[test]
    fn small_integer_negative() {
        let buffer = [0x02, 0x01, 0xF9];
        let big_integer = IntegerAsn1::from(-7.to_bigint().unwrap());

        let parsed_big_integer: IntegerAsn1 =
            crate::from_bytes(&buffer).expect("deserialization failed");
        assert_eq!(parsed_big_integer, big_integer);

        let encoded_big_integer = crate::to_vec(&big_integer).expect("serialization failed");
        assert_eq!(encoded_big_integer, buffer);
    }

    #[test]
    fn date() {
        use chrono::naive::NaiveDate;

        let buffer = [
            0x17, 0x0D, 0x31, 0x39, 0x31, 0x30, 0x31, 0x37, 0x31, 0x37, 0x34, 0x31, 0x32, 0x38,
            0x5A,
        ];
        let timestamp = DateAsn1(
            NaiveDate::from_ymd(2019, 10, 17)
                .and_hms(17, 41, 28)
                .timestamp(),
        );

        let parsed: DateAsn1 = crate::from_bytes(&buffer).expect("deserialization failed");
        assert_eq!(parsed, timestamp);

        let encoded = crate::to_vec(&timestamp).expect("serialization failed");
        assert_eq!(encoded, buffer.to_vec());
    }

    #[test]
    fn set_of() {
        #[derive(Debug, Serialize, Deserialize, Ord, PartialOrd, PartialEq, Eq)]
        struct Elem<'a> {
            #[serde(borrow)]
            first_name: Cow<'a, str>,
            #[serde(borrow)]
            last_name: Cow<'a, str>,
        }

        let set_of_elems = Asn1SetOf(vec![
            Elem {
                first_name: "名前".into(),
                last_name: "苗字".into(),
            },
            Elem {
                first_name: "和夫".into(),
                last_name: "田中".into(),
            },
        ]);

        #[rustfmt::skip]
        let buffer = [
            0x31, 0x24,
                0x30, 0x10,
                    0x0C, 0x06, 0xE5, 0x90, 0x8D, 0xE5, 0x89, 0x8D,
                    0x0C, 0x06, 0xE8, 0x8B, 0x97, 0xE5, 0xAD, 0x97,
                0x30, 0x10,
                    0x0C, 0x06, 0xE5, 0x92, 0x8C, 0xE5, 0xA4, 0xAB,
                    0x0C, 0x06, 0xE7, 0x94, 0xB0, 0xE4, 0xB8, 0xAD,
        ];

        let parsed: Asn1SetOf<Elem> = crate::from_bytes(&buffer).expect("deserialization failed");
        assert_eq!(parsed, set_of_elems);

        let encoded = crate::to_vec(&set_of_elems).expect("serialization failed");
        assert_eq!(encoded, buffer.to_vec());
    }

    #[test]
    fn sequence_of() {
        #[derive(Debug, Serialize, Deserialize, Ord, PartialOrd, PartialEq, Eq)]
        struct Elem<'a> {
            #[serde(borrow)]
            first_name: Cow<'a, str>,
            #[serde(borrow)]
            last_name: Cow<'a, str>,
        }

        let set_of_elems = Asn1SequenceOf(vec![
            Elem {
                first_name: "名前".into(),
                last_name: "苗字".into(),
            },
            Elem {
                first_name: "和夫".into(),
                last_name: "田中".into(),
            },
        ]);

        #[rustfmt::skip]
        let buffer = [
            0x30, 0x24,
                0x30, 0x10,
                    0x0C, 0x06, 0xE5, 0x90, 0x8D, 0xE5, 0x89, 0x8D,
                    0x0C, 0x06, 0xE8, 0x8B, 0x97, 0xE5, 0xAD, 0x97,
                0x30, 0x10,
                    0x0C, 0x06, 0xE5, 0x92, 0x8C, 0xE5, 0xA4, 0xAB,
                    0x0C, 0x06, 0xE7, 0x94, 0xB0, 0xE4, 0xB8, 0xAD,
        ];

        let parsed: Asn1SequenceOf<Elem> =
            crate::from_bytes(&buffer).expect("deserialization failed");
        assert_eq!(parsed, set_of_elems);

        let encoded = crate::to_vec(&set_of_elems).expect("serialization failed");
        assert_eq!(encoded, buffer.to_vec());
    }

    #[test]
    fn application_tag0() {
        let buffer = [0xA0, 0x03, 0x02, 0x01, 0xF9];
        let application_tag = ApplicationTag0(IntegerAsn1::from(-7.to_bigint().unwrap()));

        let parsed_application_tag: ApplicationTag0<IntegerAsn1> =
            crate::from_bytes(&buffer).expect("deserialization failed");
        assert_eq!(parsed_application_tag, application_tag);

        let encoded_application_tag =
            crate::to_vec(&application_tag).expect("serialization failed");
        assert_eq!(encoded_application_tag, buffer);
    }
}
