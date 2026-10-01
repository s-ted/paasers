//! Command line interface (subcommands are added in later phases).
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "paasers", version, about = "PaaS edge gateway & ingress proxy")]
pub struct Cli {}

pub fn main() -> std::process::ExitCode {
    let _cli = Cli::parse();
    std::process::ExitCode::SUCCESS
}
