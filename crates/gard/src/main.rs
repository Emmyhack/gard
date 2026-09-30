use clap::Parser;
use gard::cli::Cli;
use gard::commands;
use std::process;

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    // Initialize logging
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    let command = cli.command.clone();
    let result = match commands::execute_command(command, &cli).await {
        Ok(exit_code) => exit_code,
        Err(e) => {
            if !cli.quiet {
                eprintln!("Error: {}", e);
                eprintln!("Remediation: {}", e.remediation());
            }
            e.exit_code()
        },
    };

    process::exit(result);
}
