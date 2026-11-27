use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use certchain::certificate::Certificate;
use certchain::storage::{Storage, load_key};
use certchain::transaction::Transaction;
use certchain::{Error, Result};

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub cert: PathBuf,
    #[arg(long = "clave")]
    pub key: PathBuf,
}

pub fn run(args: Args, storage: &Storage) -> Result<ExitCode> {
    let cert = load_certificate(&args.cert)?;
    let key = load_key(&args.key)?;
    let tx = Transaction::emission(&key, cert.hash(), now());
    submit(storage, tx, "Emisión")
}

pub fn load_certificate(path: &Path) -> Result<Certificate> {
    let cert: Certificate = serde_json::from_slice(&std::fs::read(path)?)?;
    cert.validate()?;
    Ok(cert)
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Checks `tx` against the validated chain and leaves it pending.
/// Exit 1 when the chain or the transaction is rejected.
pub fn submit(storage: &Storage, tx: Transaction, label: &str) -> Result<ExitCode> {
    if !storage.chain_path().exists() {
        return Err(Error::Invalid(format!(
            "no existe {}; crea la cadena con init",
            storage.chain_path().display()
        )));
    }
    let chain = match storage.load_chain()?.validate() {
        Ok(chain) => chain,
        Err(report) => {
            eprintln!("Cadena inválida:");
            for block in report.blocks.iter().filter(|b| !b.errors.is_empty()) {
                eprintln!("  bloque {}: {:?}", block.height, block.errors);
            }
            return Ok(ExitCode::from(1));
        }
    };
    let mut pending = storage.load_pending()?;
    if let Err(error) = chain.check_transaction(&pending, &tx) {
        let reason = match error {
            Error::Unauthorized => "la clave no está autorizada para esta operación".into(),
            Error::Duplicate => "ya existe una transacción igual para este certificado".into(),
            Error::InvalidSignature => "firma inválida".into(),
            // ponytail: matches chain.rs messages; replace with typed errors if more appear.
            Error::Invalid(reason) => match reason.as_str() {
                "revocation without emission" => "el certificado no ha sido emitido".into(),
                "revoker is not the original issuer" => {
                    "solo el emisor original puede revocar".into()
                }
                _ => reason,
            },
            other => return Err(other),
        };
        eprintln!("Rechazado: {reason}");
        return Ok(ExitCode::from(1));
    }
    let cert_hash = *tx.cert_hash();
    pending.push(tx);
    storage.save_pending(&pending)?;
    println!("{label} pendiente del certificado {cert_hash}");
    println!("Para incluirla en la cadena, ejecuta sellar-bloque.");
    Ok(ExitCode::SUCCESS)
}
