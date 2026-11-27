use std::path::PathBuf;
use std::process::ExitCode;

use certchain::storage::{Storage, load_key};
use certchain::transaction::Transaction;
use certchain::{Error, Result};

use super::emitir::{load_certificate, now, submit};

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub cert: PathBuf,
    #[arg(long = "clave")]
    pub key: PathBuf,
    #[arg(long = "motivo")]
    pub reason: String,
}

pub fn run(args: Args, storage: &Storage) -> Result<ExitCode> {
    let reason = args.reason.trim();
    if reason.is_empty() {
        return Err(Error::Invalid("el motivo no puede estar vacío".into()));
    }
    let cert = load_certificate(&args.cert)?;
    let key = load_key(&args.key)?;
    let tx = Transaction::revocation(&key, cert.hash(), now(), reason.to_string());
    submit(storage, tx, "Revocación")
}
