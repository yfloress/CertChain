use std::path::PathBuf;
use std::process::ExitCode;

use certchain::Result;
use certchain::storage::Storage;

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
    todo!()
}
