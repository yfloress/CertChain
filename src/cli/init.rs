use std::process::ExitCode;

use certchain::Result;
use certchain::storage::Storage;

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
    todo!()
}
