use std::process::ExitCode;

use certchain::Result;
use certchain::storage::Storage;

#[derive(Debug, clap::Args)]
pub struct Args {}

pub fn run(args: Args, storage: &Storage) -> Result<ExitCode> {
    todo!()
}
