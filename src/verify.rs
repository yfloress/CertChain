use crate::certificate::Certificate;
use crate::chain::ValidatedChain;
use crate::proof::InclusionProof;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Authentic { issuer: String, timestamp: u64 },
    Revoked { reason: String, timestamp: u64 },
    NotFound,
    UnauthorizedIssuer,
    InvalidSignature,
    InvalidProof,
}

pub fn verify_certificate(
    chain: &ValidatedChain,
    certificate: &Certificate,
    proof: Option<&InclusionProof>,
) -> Outcome {
    todo!()
}
