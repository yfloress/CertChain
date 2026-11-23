use std::path::PathBuf;
use std::process::ExitCode;

use certchain::Result;
use certchain::storage::Storage;

#[derive(Debug, clap::Args)]
pub struct Args {
    #[arg(long)]
    pub cert: PathBuf,
    #[arg(long = "salida", default_value = "prueba.json")]
    pub output: PathBuf,
}

pub fn run(args: Args, storage: &Storage) -> Result<ExitCode> {
    todo!()
}
