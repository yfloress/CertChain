use std::process::ExitCode;

use certchain::chain::{Authority, Chain, Genesis};
use certchain::storage::Storage;
use certchain::types::PublicKey;
use certchain::{Error, Result};
use ed25519_dalek::VerifyingKey;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Emisor autorizado, como NOMBRE=CLAVE_PUBLICA_HEX (repetible)
    #[arg(long = "emisor", required = true)]
    pub issuers: Vec<String>,
    /// Validador autorizado, como NOMBRE=CLAVE_PUBLICA_HEX (repetible)
    #[arg(long = "validador", required = true)]
    pub validators: Vec<String>,
}

pub fn run(args: Args, storage: &Storage) -> Result<ExitCode> {
    // Leftover pending transactions would leak into the new chain.
    for path in [storage.chain_path(), storage.pending_path()] {
        if path.exists() {
            return Err(invalid(format!("ya existe {}", path.display())));
        }
    }
    let timestamp = u64::try_from(chrono::Utc::now().timestamp())
        .map_err(|_| invalid("el reloj del sistema es anterior a 1970"))?;
    let genesis = Genesis {
        timestamp,
        issuers: parse_authorities(&args.issuers)?,
        validators: parse_authorities(&args.validators)?,
    };
    let hash = genesis.hash();
    storage.save_chain(&Chain::new(genesis))?;
    println!("Cadena creada en {}", storage.chain_path().display());
    println!("Hash de génesis: {hash}");
    println!("Publica este hash: quien verifique lo usará con --genesis.");
    Ok(ExitCode::SUCCESS)
}

fn parse_authorities(values: &[String]) -> Result<Vec<Authority>> {
    let mut authorities: Vec<Authority> = Vec::new();
    for value in values {
        let authority = parse_authority(value)?;
        if authorities
            .iter()
            .any(|a| a.name == authority.name || a.public_key == authority.public_key)
        {
            return Err(invalid(format!("nombre o clave repetidos en '{value}'")));
        }
        authorities.push(authority);
    }
    Ok(authorities)
}

fn parse_authority(value: &str) -> Result<Authority> {
    let (name, key) = value
        .rsplit_once('=')
        .ok_or_else(|| invalid(format!("'{value}' no tiene la forma NOMBRE=CLAVE")))?;
    let name = name.trim();
    if name.is_empty() {
        return Err(invalid(format!("falta el nombre en '{value}'")));
    }
    let public_key = PublicKey::try_from(key.trim().to_owned())
        .map_err(|_| invalid(format!("la clave de '{name}' no son 32 bytes en hex")))?;
    // Weak keys can never produce an accepted signature.
    match VerifyingKey::from_bytes(&public_key.0) {
        Ok(key) if !key.is_weak() => Ok(Authority {
            name: name.to_owned(),
            public_key,
        }),
        _ => Err(invalid(format!(
            "la clave de '{name}' no es una clave Ed25519 válida"
        ))),
    }
}

fn invalid(message: impl Into<String>) -> Error {
    Error::Invalid(message.into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use certchain::crypto::KeyPair;
    use tempfile::TempDir;

    fn entry(name: &str, seed: u8) -> String {
        let key = KeyPair::from_secret_bytes(&[seed; 32]).public_key();
        format!("{name}={key}")
    }

    fn args() -> Args {
        Args {
            issuers: vec![entry("Universidad", 1), entry("Instituto", 2)],
            validators: vec![entry("Universidad", 1)],
        }
    }

    #[test]
    fn creates_a_valid_chain() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new(dir.path().join("datos"));
        run(args(), &storage).unwrap();
        let chain = storage.load_chain().unwrap();
        let names: Vec<_> = chain.genesis.issuers.iter().map(|a| &a.name).collect();
        assert_eq!(names, ["Universidad", "Instituto"]);
        assert_eq!(chain.genesis.validators.len(), 1);
        assert!(chain.genesis.timestamp > 0);
        assert!(chain.validate().is_ok());
    }

    #[test]
    fn never_overwrites_a_chain() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new(dir.path());
        run(args(), &storage).unwrap();
        let before = storage.load_chain().unwrap();
        assert!(run(args(), &storage).is_err());
        assert_eq!(storage.load_chain().unwrap(), before);
    }

    #[test]
    fn rejects_leftover_pending() {
        let dir = TempDir::new().unwrap();
        let storage = Storage::new(dir.path());
        storage.save_pending(&[]).unwrap();
        assert!(run(args(), &storage).is_err());
        assert!(!storage.chain_path().exists());
    }

    #[test]
    fn name_may_contain_equals() {
        assert_eq!(parse_authority(&entry("A=B", 1)).unwrap().name, "A=B");
    }

    #[test]
    fn rejects_bad_authorities() {
        let weak = format!("U=01{}", "00".repeat(31));
        let not_a_point = format!("U=02{}", "00".repeat(31));
        for value in ["U", "U=", "U=abcd", &entry(" ", 1), &weak, &not_a_point] {
            assert!(parse_authority(value).is_err(), "accepted {value}");
        }
    }

    #[test]
    fn rejects_duplicates() {
        for second in [entry("A", 2), entry("B", 1)] {
            assert!(parse_authorities(&[entry("A", 1), second]).is_err());
        }
    }
}
