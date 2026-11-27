use std::path::PathBuf;
use std::process::ExitCode;

use certchain::crypto::KeyPair;
use certchain::storage::{Storage, save_key};
use certchain::{Error, Result};

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Nombre del archivo de clave, sin extensión
    #[arg(long = "nombre")]
    pub name: String,
}

pub fn run(args: Args, _storage: &Storage) -> Result<ExitCode> {
    let valid = !args.name.is_empty()
        && args
            .name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_');
    if !valid {
        return Err(Error::Invalid(
            "el nombre solo puede tener letras, números, '-' y '_'".into(),
        ));
    }
    let path = PathBuf::from(format!("{}.key", args.name));
    let key = KeyPair::generate()?;
    save_key(&path, &key)?;
    println!(
        "Clave privada guardada en {} (no la compartas)",
        path.display()
    );
    println!("Clave pública: {}", key.public_key());
    Ok(ExitCode::SUCCESS)
}
