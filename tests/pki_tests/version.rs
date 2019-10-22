use serde::{de, ser, Deserialize, Serialize};
use serde_asn1_der::asn1_wrapper::ApplicationTag0;
use std::fmt;

#[derive(Debug, PartialEq, Clone, Copy)]
#[repr(u8)]
pub enum Version {
    V1 = 0x00,
    V2 = 0x01,
    V3 = 0x02,
}

impl Version {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x00 => Some(Self::V1),
            0x01 => Some(Self::V2),
            0x02 => Some(Self::V3),
            _ => None,
        }
    }
}

impl Serialize for Version {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_u8(*self as u8)
    }
}

impl<'de> Deserialize<'de> for Version {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> de::Visitor<'de> for Visitor {
            type Value = Version;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "nothing or a valid version number")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Version::from_u8(v).ok_or_else(|| {
                    E::invalid_value(
                        de::Unexpected::Other("unsupported version number"),
                        &"a valid integer representing a supported version number",
                    )
                })
            }
        }

        deserializer.deserialize_u8(Visitor)
    }
}

const VERSION_DEFAULT: Version = Version::V1;
pub fn version_is_default(version: &ApplicationTag0<Version>) -> bool {
    version == &ApplicationTag0(VERSION_DEFAULT)
}
pub fn deserialize_optional_version<'de, D>(d: D) -> Result<ApplicationTag0<Version>, D::Error>
where
    D: de::Deserializer<'de>,
{
    struct Visitor;

    impl<'de> de::Visitor<'de> for Visitor {
        type Value = ApplicationTag0<Version>;

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "a valid ASN.1 version behind application tag 0")
        }

        fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            Version::deserialize(deserializer).map(ApplicationTag0)
        }
    }

    match d.deserialize_newtype_struct(ApplicationTag0::<Version>::NAME, Visitor) {
        Err(_) => Ok(ApplicationTag0(VERSION_DEFAULT)),
        result => result,
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq)]
struct OptionalVersionTestStruct {
    #[serde(
        deserialize_with = "deserialize_optional_version",
        skip_serializing_if = "version_is_default"
    )]
    version: ApplicationTag0<Version>,
    other_non_optional_integer: u8,
}

#[test]
fn optional_version() {
    let buffer_with_version: [u8; 10] =
        [0x30, 0x08, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x6E];

    let non_default = OptionalVersionTestStruct {
        version: ApplicationTag0(Version::V3),
        other_non_optional_integer: 0x6E,
    };

    check!(non_default: OptionalVersionTestStruct in buffer_with_version);

    let buffer_without_version: [u8; 5] = [0x30, 0x03, 0x02, 0x01, 0x6E];

    let default = OptionalVersionTestStruct {
        version: ApplicationTag0(VERSION_DEFAULT),
        other_non_optional_integer: 0x6E,
    };

    check!(default: OptionalVersionTestStruct in buffer_without_version);
}
