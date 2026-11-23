use std::process::ExitCode;

use certchain::Result;
use certchain::storage::Storage;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Nombre del archivo de clave, sin extensión
    #[arg(long = "nombre")]
    pub name: String,
}

pub fn run(args: Args, storage: &Storage) -> Result<ExitCode> {
    todo!()
}
