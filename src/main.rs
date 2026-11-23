// Scaffold only: remove once every `todo!()` is implemented.
#![allow(unused_variables, dead_code)]

mod cli;

use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
    match cli::Cli::parse().run() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("Error: {error}");
            ExitCode::from(2)
        }
    }
}
