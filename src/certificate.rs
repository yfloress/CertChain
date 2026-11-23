use serde::{Deserialize, Serialize};

use crate::Result;
use crate::types::{Digest, Salt};

/// Off-chain document; only its hash goes into the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub id: String,
    #[serde(rename = "estudiante")]
    pub student: String,
    #[serde(rename = "carrera")]
    pub program: String,
    /// Unix seconds, UTC.
    #[serde(rename = "fecha")]
    pub date: u64,
    #[serde(rename = "detalle")]
    pub courses: Vec<Course>,
    pub salt: Salt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Course {
    #[serde(rename = "ramo")]
    pub name: String,
    /// Tenths: 50 means 5.0.
    #[serde(rename = "nota")]
    pub grade: u8,
}

impl Certificate {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        todo!()
    }

    pub fn hash(&self) -> Digest {
        todo!()
    }

    /// Checks grade range and required fields.
    pub fn validate(&self) -> Result<()> {
        todo!()
    }
}

pub fn generate_salt() -> Result<Salt> {
    todo!()
}
