use std::process::ExitCode;

use certchain::Result;
use certchain::chain::{BlockError, ValidationReport};
use certchain::storage::Storage;

#[derive(Debug, clap::Args)]
pub struct Args {}

pub fn run(_args: Args, storage: &Storage) -> Result<ExitCode> {
    let chain = storage.load_chain()?;
    let report = chain.report();
    println!("Hash de génesis: {}", chain.genesis.hash());
    print!("{}", render(&report));
    Ok(if report.is_valid() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

fn render(report: &ValidationReport) -> String {
    let mut lines = Vec::new();
    for block in &report.blocks {
        if block.errors.is_empty() {
            lines.push(format!("Bloque {}: correcto", block.height));
        } else {
            lines.push(format!("Bloque {}: con errores", block.height));
            lines.extend(block.errors.iter().map(|e| format!("  - {}", describe(e))));
        }
    }
    let total = report.blocks.len();
    let bad = report
        .blocks
        .iter()
        .filter(|b| !b.errors.is_empty())
        .count();
    lines.push(if bad == 0 {
        format!("Cadena válida (bloques: {total})")
    } else {
        format!("Cadena inválida (bloques con errores: {bad} de {total})")
    });
    lines.join("\n") + "\n"
}

/// Transactions are numbered from 1.
fn describe(error: &BlockError) -> String {
    let tx = |index: &usize, text: &str| format!("transacción {}: {text}", index + 1);
    match error {
        BlockError::WrongHeight => "la altura no es la esperada".into(),
        BlockError::PrevHashMismatch => "el hash anterior no coincide".into(),
        BlockError::MerkleRootMismatch => "la raíz de Merkle no coincide".into(),
        BlockError::TxCountMismatch => "la cantidad de transacciones no coincide".into(),
        BlockError::EmptyBlock => "el bloque está vacío".into(),
        BlockError::UnauthorizedValidator => "el validador no está autorizado".into(),
        BlockError::InvalidBlockSignature => "la firma del bloque es inválida".into(),
        BlockError::InvalidTimestamp => "la fecha es anterior a la del bloque previo".into(),
        BlockError::UnauthorizedIssuer { tx_index } => tx(tx_index, "emisor no autorizado"),
        BlockError::InvalidTxSignature { tx_index } => tx(tx_index, "firma inválida"),
        BlockError::DuplicateTx { tx_index } => tx(tx_index, "repetida"),
        BlockError::RevocationWithoutEmission { tx_index } => {
            tx(tx_index, "revoca un certificado que no fue emitido")
        }
        BlockError::RevokerIsNotIssuer { tx_index } => {
            tx(tx_index, "quien revoca no es el emisor original")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use certchain::chain::BlockReport;

    fn report(blocks: Vec<Vec<BlockError>>) -> ValidationReport {
        ValidationReport {
            blocks: (1..)
                .zip(blocks)
                .map(|(height, errors)| BlockReport { height, errors })
                .collect(),
        }
    }

    #[test]
    fn renders_valid_chains() {
        assert_eq!(render(&report(vec![])), "Cadena válida (bloques: 0)\n");
        assert_eq!(
            render(&report(vec![vec![]])),
            "Bloque 1: correcto\nCadena válida (bloques: 1)\n"
        );
    }

    #[test]
    fn renders_every_error_of_every_block() {
        let text = render(&report(vec![
            vec![
                BlockError::MerkleRootMismatch,
                BlockError::InvalidTxSignature { tx_index: 0 },
            ],
            vec![],
            vec![BlockError::PrevHashMismatch],
        ]));
        assert_eq!(
            text,
            "Bloque 1: con errores\n\
             \x20 - la raíz de Merkle no coincide\n\
             \x20 - transacción 1: firma inválida\n\
             Bloque 2: correcto\n\
             Bloque 3: con errores\n\
             \x20 - el hash anterior no coincide\n\
             Cadena inválida (bloques con errores: 2 de 3)\n"
        );
    }
}
