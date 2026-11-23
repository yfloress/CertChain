use std::path::PathBuf;
use std::process::ExitCode;

use certchain::Result;
use certchain::storage::Storage;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub cert: PathBuf,
    #[arg(long = "prueba")]
    pub proof: Option<PathBuf>,
    /// Hash de génesis esperado, en hexadecimal
    #[arg(long)]
    pub genesis: Option<String>,
}

pub fn run(args: Args, storage: &Storage) -> Result<ExitCode> {
    todo!()
}
