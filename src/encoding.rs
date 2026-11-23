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
        todo!()
    }

    pub fn u8(self, value: u8) -> Self {
        todo!()
    }

    pub fn u32(self, value: u32) -> Self {
        todo!()
    }

    pub fn u64(self, value: u64) -> Self {
        todo!()
    }

    /// Fixed-size data, without a length prefix.
    pub fn fixed<const N: usize>(self, value: &[u8; N]) -> Self {
        todo!()
    }

    /// Variable-length data, with a length prefix.
    pub fn bytes(self, value: &[u8]) -> Self {
        todo!()
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }
}
