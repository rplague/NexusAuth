//! sidecar 二进制字段编解码：写 `bstr`，读 `bstr` 或整数数组。
//!
//! 与 NexusNet 0.7.0 的 `src/bytes_serde.rs` 保持一致。

use std::fmt;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::ser::Serializer;

/// 以 CBOR `bstr` 写出的字节串。
struct ByteStr<'a>(&'a [u8]);

impl serde::Serialize for ByteStr<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.0)
    }
}

/// 读 `bstr` 或整数数组。
struct BytesOrSeqVisitor;

impl<'de> Visitor<'de> for BytesOrSeqVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a CBOR byte string or an array of bytes")
    }

    fn visit_bytes<E: de::Error>(self, value: &[u8]) -> Result<Self::Value, E> {
        Ok(value.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, value: Vec<u8>) -> Result<Self::Value, E> {
        Ok(value)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0));
        while let Some(byte) = seq.next_element::<u8>()? {
            out.push(byte);
        }
        Ok(out)
    }
}

/// 读 `null` / `bstr` / 整数数组。
struct OptBytesOrSeqVisitor;

impl<'de> Visitor<'de> for OptBytesOrSeqVisitor {
    type Value = Option<Vec<u8>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an optional CBOR byte string or an array of bytes")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_any(BytesOrSeqVisitor).map(Some)
    }
}

/// `bstr` 写、`bstr`/数组读。
pub mod bytes_or_seq {
    use super::*;

    #[allow(clippy::ptr_arg)]
    pub fn serialize<S: Serializer>(value: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(value)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        deserializer.deserialize_any(BytesOrSeqVisitor)
    }
}

/// 可选版本：`bstr` 写、`bstr`/数组读。
pub mod bytes_or_seq_opt {
    use super::*;

    #[allow(clippy::ptr_arg, clippy::ref_option)]
    pub fn serialize<S: Serializer>(
        value: &Option<Vec<u8>>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match value {
            Some(bytes) => serializer.serialize_some(&ByteStr(bytes.as_slice())),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Vec<u8>>, D::Error> {
        deserializer.deserialize_option(OptBytesOrSeqVisitor)
    }
}
