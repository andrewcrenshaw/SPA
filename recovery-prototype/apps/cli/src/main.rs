//! `recovery` — SPA Tier-0 recovery lifecycle CLI.

mod commands;
mod persistence;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "recovery", about = "SPA Tier-0 recovery lifecycle demo")]
struct Cli {
    /// Override the share storage root (default: ~/.spa-recovery).
    /// Also read from SPA_RECOVERY_HOME env var.
    #[arg(long, env = "SPA_RECOVERY_HOME")]
    home: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate shares and record the identity-anchor receipt.
    Onboard {
        #[arg(long)]
        user: String,
    },
    /// Sign a message with the device + cloud shares and verify immediately.
    Sign {
        #[arg(long)]
        user: String,
        #[arg(long)]
        message: String,
    },
    /// Simulate device loss (removes device share, records receipt).
    LoseDevice {
        #[arg(long)]
        user: String,
    },
    /// Present cloud + recovery_code factors and start the 48-hour cooldown.
    Recover {
        #[arg(long)]
        user: String,
    },
    /// Advance the injected test clock by SECS seconds and tick the state machine.
    /// Requires SPA_TEST_CLOCK=1 — refused in production.
    CooldownAdvance {
        #[arg(long)]
        user: String,
        #[arg(long)]
        secs: u64,
    },
    /// Print and verify the full receipt chain.
    Audit {
        #[arg(long)]
        user: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let base = cli.home.unwrap_or_else(|| {
        dirs::home_dir()
            .expect("cannot determine home directory")
            .join(".spa-recovery")
    });

    let result = match cli.command {
        Command::Onboard { user } => commands::onboard(&base, &user),
        Command::Sign { user, message } => commands::sign(&base, &user, &message),
        Command::LoseDevice { user } => commands::lose_device(&base, &user),
        Command::Recover { user } => commands::recover(&base, &user),
        Command::CooldownAdvance { user, secs } => {
            if std::env::var("SPA_TEST_CLOCK").as_deref() != Ok("1") {
                eprintln!("error: cooldown-advance requires SPA_TEST_CLOCK=1");
                std::process::exit(1);
            }
            commands::cooldown_advance(&base, &user, secs)
        }
        Command::Audit { user } => commands::audit(&base, &user),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
