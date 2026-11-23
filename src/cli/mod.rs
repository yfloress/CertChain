mod emitir;
mod exportar_prueba;
mod init;
mod keygen;
mod revocar;
mod sellar_bloque;
mod validar_cadena;
mod verificar;

use std::path::PathBuf;
use std::process::ExitCode;

use certchain::Result;
use certchain::storage::Storage;
use clap::{Parser, Subcommand};

/// Certificados académicos verificables con blockchain
#[derive(Debug, Parser)]
#[command(name = "certchain", version)]
pub struct Cli {
    /// Carpeta con los datos de la cadena
    #[arg(long = "datos", global = true, default_value = "datos")]
    data_dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Crea una cadena nueva con sus emisores y validadores
    Init(init::Args),
    /// Genera un par de claves Ed25519
    Keygen(keygen::Args),
    /// Firma la emisión de un certificado y la deja pendiente
    Emitir(emitir::Args),
    /// Firma la revocación de un certificado y la deja pendiente
    Revocar(revocar::Args),
    /// Sella las transacciones pendientes en un bloque
    SellarBloque(sellar_bloque::Args),
    /// Exporta la prueba de inclusión de un certificado
    ExportarPrueba(exportar_prueba::Args),
    /// Verifica un certificado
    Verificar(verificar::Args),
    /// Valida la cadena completa
    ValidarCadena(validar_cadena::Args),
}

impl Cli {
    pub fn run(self) -> Result<ExitCode> {
        let storage = Storage::new(self.data_dir);
        match self.command {
            Command::Init(args) => init::run(args, &storage),
            Command::Keygen(args) => keygen::run(args, &storage),
            Command::Emitir(args) => emitir::run(args, &storage),
            Command::Revocar(args) => revocar::run(args, &storage),
            Command::SellarBloque(args) => sellar_bloque::run(args, &storage),
            Command::ExportarPrueba(args) => exportar_prueba::run(args, &storage),
            Command::Verificar(args) => verificar::run(args, &storage),
            Command::ValidarCadena(args) => validar_cadena::run(args, &storage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }
}
