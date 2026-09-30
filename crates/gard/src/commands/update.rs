//! Update command - check for new releases
//!
//! Queries GitHub releases for the latest version and compares against
//! the running binary. Binary self-replacement ships in v0.2; until then
//! this command reports availability and prints install instructions.

use crate::cli::UpdateCommand;
use crate::error::{GardError, Result};

const RELEASES_API: &str = "https://api.github.com/repos/nextlevelbuilder/gard/releases/latest";

pub async fn execute(cmd: UpdateCommand) -> Result<i32> {
    if cmd.channel != "stable" {
        println!(
            "Channel '{}' has no releases yet; only 'stable' is published.",
            cmd.channel
        );
        return Ok(2);
    }

    println!("Current version: {}", crate::VERSION);

    let latest = match fetch_latest_version().await {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Could not check for updates: {}", e);
            return Ok(1);
        },
    };

    println!("Latest release:  {}", latest);

    let up_to_date = latest.trim_start_matches('v') == crate::VERSION;
    if up_to_date && !cmd.force {
        println!("Already up to date.");
        return Ok(2);
    }

    if cmd.check || cmd.dry_run {
        println!("Update available: {} -> {}", crate::VERSION, latest);
        println!("Run 'gard update' to see install instructions.");
        return Ok(0);
    }

    // Binary self-replacement with signature verification lands in v0.2.
    println!("\nAutomatic self-update is not available in this version.");
    println!("Install the new release manually:");
    println!(
        "  https://github.com/nextlevelbuilder/gard/releases/tag/{}",
        latest
    );
    println!("Verify the .sha256 checksum before replacing the binary.");
    Ok(0)
}

async fn fetch_latest_version() -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent(format!("gard/{}", crate::VERSION))
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| GardError::NetworkError {
            endpoint: RELEASES_API.to_string(),
            reason: e.to_string(),
        })?;

    let response = client
        .get(RELEASES_API)
        .send()
        .await
        .map_err(|e| GardError::NetworkError {
            endpoint: RELEASES_API.to_string(),
            reason: e.to_string(),
        })?;

    if !response.status().is_success() {
        return Err(GardError::NetworkError {
            endpoint: RELEASES_API.to_string(),
            reason: format!("HTTP {}", response.status()),
        });
    }

    let body: serde_json::Value = response.json().await.map_err(|e| GardError::NetworkError {
        endpoint: RELEASES_API.to_string(),
        reason: e.to_string(),
    })?;

    body.get("tag_name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| GardError::NetworkError {
            endpoint: RELEASES_API.to_string(),
            reason: "Release response missing tag_name".to_string(),
        })
}
