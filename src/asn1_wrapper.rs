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

asn1_wrapper! { struct ObjectIdentifierAsn1(ObjectIdentifier), 0x06 }

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
        assert_eq!(oid, parsed_oid);

        let encoded_oid = crate::to_vec(&oid).expect("serialization failed");
        assert_eq!(oid_buffer.to_vec(), encoded_oid);
    }
}
