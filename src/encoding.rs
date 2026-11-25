//! Canonical binary encoding: the only source of bytes to hash or sign.
//! Integers are big-endian; variable-length data carries a u32 length prefix.

pub const TAG_CERTIFICATE: &str = "CertChain/v1/CERTIFICADO";
pub const TAG_EMISSION: &str = "CertChain/v1/EMISION";
pub const TAG_REVOCATION: &str = "CertChain/v1/REVOCACION";
pub const TAG_TRANSACTION: &str = "CertChain/v1/TRANSACCION";
pub const TAG_GENESIS: &str = "CertChain/v1/GENESIS";
pub const TAG_BLOCK_HASH: &str = "CertChain/v1/BLOQUE";
pub const TAG_BLOCK_SIGNATURE: &str = "CertChain/v1/FIRMA_BLOQUE";

pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Starts an encoding bound to a domain tag.
    pub fn new(tag: &str) -> Self {
        Self { buf: Vec::new() }.bytes(tag.as_bytes())
    }

    pub fn u8(mut self, value: u8) -> Self {
        self.buf.push(value);
        self
    }

    pub fn u32(mut self, value: u32) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    pub fn u64(mut self, value: u64) -> Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Fixed-size data, without a length prefix.
    pub fn fixed<const N: usize>(mut self, value: &[u8; N]) -> Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Variable-length data, with a length prefix. Panics above `u32::MAX` bytes.
    pub fn bytes(self, value: &[u8]) -> Self {
        let len = u32::try_from(value.len()).expect("data longer than u32::MAX bytes");
        let mut encoder = self.u32(len);
        encoder.buf.extend_from_slice(value);
        encoder
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_TAG: &str = "00000000";

    fn hex_of(encoder: Encoder) -> String {
        hex::encode(encoder.finish())
    }

    #[test]
    fn tag_vector() {
        assert_eq!(hex_of(Encoder::new("AB")), "000000024142");
    }

    #[test]
    fn integers_are_big_endian() {
        let encoder = Encoder::new("")
            .u8(0x01)
            .u32(0x0203_0405)
            .u64(0x0607_0809_0a0b_0c0d);
        assert_eq!(
            hex_of(encoder),
            format!("{EMPTY_TAG}0102030405060708090a0b0c0d")
        );
    }

    #[test]
    fn fixed_has_no_prefix() {
        let encoder = Encoder::new("").fixed(&[0xaa, 0xbb, 0xcc]);
        assert_eq!(hex_of(encoder), format!("{EMPTY_TAG}aabbcc"));
    }

    #[test]
    fn bytes_have_length_prefix() {
        let encoder = Encoder::new("").bytes(b"").bytes(b"abc");
        assert_eq!(
            hex_of(encoder),
            format!("{EMPTY_TAG}0000000000000003616263")
        );
    }

    #[test]
    fn length_counts_utf8_bytes() {
        let encoder = Encoder::new("").bytes("Ñ".as_bytes());
        assert_eq!(hex_of(encoder), format!("{EMPTY_TAG}00000002c391"));
    }

    #[test]
    fn full_vector() {
        let encoder = Encoder::new(TAG_GENESIS)
            .u64(1)
            .u32(1)
            .bytes(b"U")
            .fixed(&[0x11; 4]);
        let expected = concat!(
            "00000014",
            "43657274436861696e2f76312f47454e45534953",
            "0000000000000001",
            "00000001",
            "0000000155",
            "11111111",
        );
        assert_eq!(hex_of(encoder), expected);
    }

    #[test]
    fn field_boundaries_matter() {
        let left = Encoder::new("T").bytes(b"ab").bytes(b"c").finish();
        let right = Encoder::new("T").bytes(b"a").bytes(b"bc").finish();
        assert_ne!(left, right);
    }

    #[test]
    fn tags_are_distinct() {
        let tags = [
            TAG_CERTIFICATE,
            TAG_EMISSION,
            TAG_REVOCATION,
            TAG_TRANSACTION,
            TAG_GENESIS,
            TAG_BLOCK_HASH,
            TAG_BLOCK_SIGNATURE,
        ];
        let unique: std::collections::HashSet<_> = tags.iter().collect();
        assert_eq!(unique.len(), tags.len());
    }
}
