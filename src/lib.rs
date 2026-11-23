//! CertChain: verifiable academic certificates on a simple blockchain.

// Scaffold only: remove once every `todo!()` is implemented.
#![allow(unused_variables)]

pub mod crypto;
pub mod encoding;
pub mod error;
pub mod types;

pub use error::{Error, Result};
