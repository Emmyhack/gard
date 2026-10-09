//! Fleet command - team-wide compliance over a shared directory
//!
//! Members submit signed scan reports into a shared directory (a synced
//! folder or a git repository); `fleet status` verifies every report's
//! signature, matches signing keys against the team roster, and shows
//! who is green, who is failing, whose report has gone stale, whose
//! suppressions are about to expire, and which findings are new since
//! the member's previous submission.

use crate::cli::FleetSubcommand;
use crate::config;
use crate::error::{GardError, Result};
use crate::report::{verify_report, ReportSigner};
use crate::types::{Policy, Report};
use colored::Colorize;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_MAX_AGE_HOURS: u64 = 24;

/// Suppressions expiring within this many days are called out
const SUPPRESSION_WARN_DAYS: i64 = 7;

/// Subdirectory holding each member's previous submission for diffing
const HISTORY_DIR: &str = "history";

pub async fn execute(subcommand: FleetSubcommand) -> Result<i32> {
    let policy = config::load_policy(None)?;
    match subcommand {
        FleetSubcommand::Submit { dir, url, token } => submit(&policy, dir, url, token).await,
        FleetSubcommand::Status {
            dir,
            max_age_hours,
            json,
        } => status(&policy, dir, max_age_hours, json),
        FleetSubcommand::Dashboard {
            dir,
            max_age_hours,
            output,
        } => dashboard(&policy, dir, max_age_hours, output),
        FleetSubcommand::Serve {
            dir,
            port,
            bind,
            token,
            max_age_hours,
        } => {
            serve(
                &policy,
                ServeOptions {
                    dir,
                    port,
                    bind,
                    token,
                    max_age_hours,
                },
            )
            .await
        },
    }
}

async fn submit(
    policy: &Policy,
    dir: Option<String>,
    url: Option<String>,
    token: Option<String>,
) -> Result<i32> {
    let mut report = super::scan::run_scan(policy, &HashSet::new(), &HashSet::new())?;
    let signer = ReportSigner::new()?;
    signer.sign_report(&mut report)?;

    if let Some(url) = url {
        return submit_remote(&report, &url, token.as_deref()).await;
    }

    let fleet_dir = resolve_fleet_dir(policy, dir)?;
    fs::create_dir_all(&fleet_dir)?;
    // Key the file by roster identity when this machine's key is registered,
    // matching the server, so a hostname change does not duplicate a member
    let own_key = signer.public_key_hex();
    let roster_name = policy
        .team
        .signers
        .iter()
        .find(|s| s.public_key.eq_ignore_ascii_case(&own_key))
        .map(|s| s.name.clone());
    let file_name = store_report(&fleet_dir, &report, roster_name.as_deref())?;

    // Keep a previously generated dashboard current with every submission
    let dashboard_path = fleet_dir.join("index.html");
    if dashboard_path.exists() {
        let max_age = policy.fleet.max_age_hours.unwrap_or(DEFAULT_MAX_AGE_HOURS) as i64;
        let members = collect_members(policy, &fleet_dir, max_age)?;
        fs::write(&dashboard_path, render_dashboard(&members, max_age))?;
        println!("Dashboard refreshed: {}", dashboard_path.display());
    }

    let status = if report.summary.preflight_passing {
        "PASS".green().bold()
    } else {
        "FAIL".red().bold()
    };
    println!(
        "Submitted {} ({} findings, preflight {}) to {}",
        file_name,
        report.summary.total_findings,
        status,
        fleet_dir.display()
    );
    if fleet_dir.join(".git").exists() {
        println!("Fleet directory is a git repository — remember to commit and push.");
    }

    Ok(if report.summary.preflight_passing {
        0
    } else {
        1
    })
}

/// Write a report into the fleet directory, rotating the member's
/// previous submission into history/ so status can diff against it.
/// Returns the stored file name.
fn store_report(fleet_dir: &Path, report: &Report, owner: Option<&str>) -> Result<String> {
    let legacy_name = format!(
        "{}@{}.json",
        sanitize(&report.metadata.username),
        sanitize(&report.metadata.hostname)
    );
    // Rostered members are keyed by their roster name, which is bound to
    // their signing key, so no member can overwrite another's report by
    // forging the username/hostname fields of a report they signed
    let file_name = match owner {
        Some(name) => format!("{}.json", sanitize(name)),
        None => legacy_name.clone(),
    };
    let path = fleet_dir.join(&file_name);
    let history_dir = fleet_dir.join(HISTORY_DIR);

    // A member newly added to the roster keeps their diff baseline: the
    // legacy user@host file becomes their previous submission
    if owner.is_some() && !path.exists() {
        let legacy = fleet_dir.join(&legacy_name);
        if legacy.exists() {
            fs::create_dir_all(&history_dir)?;
            fs::rename(&legacy, history_dir.join(&file_name))?;
        }
    }

    if path.exists() {
        fs::create_dir_all(&history_dir)?;
        fs::rename(&path, history_dir.join(&file_name))?;
    }

    fs::write(&path, serde_json::to_string_pretty(report)?)?;
    Ok(file_name)
}

/// POST the signed report to a fleet server
async fn submit_remote(report: &Report, url: &str, token: Option<&str>) -> Result<i32> {
    let endpoint = format!("{}/api/submit", url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .map_err(|e| GardError::NetworkError {
            endpoint: endpoint.clone(),
            reason: e.to_string(),
        })?;

    let mut request = client.post(&endpoint).json(report);
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }

    let response = request.send().await.map_err(|e| GardError::NetworkError {
        endpoint: endpoint.clone(),
        reason: e.to_string(),
    })?;

    let status_code = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_default();

    if status_code.is_success() {
        println!(
            "Submitted to {} ({} findings, preflight {})",
            endpoint,
            report.summary.total_findings,
            if report.summary.preflight_passing {
                "PASS".green().bold()
            } else {
                "FAIL".red().bold()
            }
        );
        Ok(if report.summary.preflight_passing {
            0
        } else {
            1
        })
    } else {
        Err(GardError::NetworkError {
            endpoint,
            reason: format!(
                "HTTP {}: {}",
                status_code,
                body.get("error")
                    .and_then(|e| e.as_str())
                    .unwrap_or("submission rejected")
            ),
        })
    }
}

/// A suppression as shown in the fleet view
#[derive(serde::Serialize)]
struct SuppressionStatus {
    check_id: String,
    reason: String,
    expires: String,
    days_left: i64,
    expiring_soon: bool,
}

/// Per-check aggregate for a member, feeding the dashboard heatmap
#[derive(serde::Serialize)]
struct CheckCell {
    id: String,
    severity: String,
    count: usize,
}

/// One member's row in the fleet view
#[derive(serde::Serialize)]
struct MemberStatus {
    file: String,
    member: String,
    hostname: String,
    signature_valid: bool,
    trusted: Option<String>,
    age_hours: i64,
    stale: bool,
    critical: usize,
    high: usize,
    total_findings: usize,
    preflight_passing: bool,
    suppressions: Vec<SuppressionStatus>,
    new_check_ids: Vec<String>,
    resolved_check_ids: Vec<String>,
    checks: Vec<CheckCell>,
}

fn status(
    policy: &Policy,
    dir: Option<String>,
    max_age_hours: Option<u64>,
    json: bool,
) -> Result<i32> {
    let fleet_dir = resolve_fleet_dir(policy, dir)?;
    if !fleet_dir.exists() {
        return Err(GardError::ConfigurationError {
            path: fleet_dir.to_string_lossy().to_string(),
            reason: "Fleet directory does not exist".to_string(),
        });
    }

    let max_age = max_age_hours
        .or(policy.fleet.max_age_hours)
        .unwrap_or(DEFAULT_MAX_AGE_HOURS) as i64;

    let members = collect_members(policy, &fleet_dir, max_age)?;

    if members.is_empty() {
        println!(
            "No fleet reports found in {}. Members submit with 'gard fleet submit'.",
            fleet_dir.display()
        );
        return Ok(1);
    }

    let all_green = members
        .iter()
        .all(|m| m.signature_valid && m.preflight_passing && !m.stale);

    if json {
        let payload = serde_json::json!({
            "fleet_dir": fleet_dir.to_string_lossy(),
            "max_age_hours": max_age,
            "all_green": all_green,
            "members": members,
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        print_table(&members, max_age);
        if all_green {
            println!(
                "\n{}",
                "FLEET GREEN — all members passing and fresh."
                    .green()
                    .bold()
            );
        } else {
            println!(
                "\n{}",
                "FLEET NOT GREEN — review the rows above.".red().bold()
            );
        }
    }

    Ok(if all_green { 0 } else { 1 })
}

/// Read and evaluate every member report in the fleet directory
fn collect_members(policy: &Policy, fleet_dir: &Path, max_age: i64) -> Result<Vec<MemberStatus>> {
    let mut members = Vec::new();
    let mut entries: Vec<PathBuf> = fs::read_dir(fleet_dir)?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().map(|e| e == "json").unwrap_or(false))
        .collect();
    entries.sort();

    for path in entries {
        let Ok(content) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(report) = serde_json::from_str::<Report>(&content) else {
            tracing::warn!(file = %path.display(), "Skipping unparseable fleet report");
            continue;
        };
        let previous = load_previous(fleet_dir, &path);
        members.push(evaluate_member(
            &path,
            &report,
            previous.as_ref(),
            policy,
            max_age,
        ));
    }

    Ok(members)
}

fn dashboard(
    policy: &Policy,
    dir: Option<String>,
    max_age_hours: Option<u64>,
    output: Option<String>,
) -> Result<i32> {
    let fleet_dir = resolve_fleet_dir(policy, dir)?;
    if !fleet_dir.exists() {
        return Err(GardError::ConfigurationError {
            path: fleet_dir.to_string_lossy().to_string(),
            reason: "Fleet directory does not exist".to_string(),
        });
    }

    let max_age = max_age_hours
        .or(policy.fleet.max_age_hours)
        .unwrap_or(DEFAULT_MAX_AGE_HOURS) as i64;

    let members = collect_members(policy, &fleet_dir, max_age)?;
    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| fleet_dir.join("index.html"));
    fs::write(&output_path, render_dashboard(&members, max_age))?;

    println!(
        "Dashboard written to {} ({} member report(s)).",
        output_path.display(),
        members.len()
    );
    println!(
        "Open it locally, or serve the fleet directory (e.g. GitHub Pages) to give the team a URL."
    );
    if fleet_dir.join(".git").exists() {
        println!("Fleet directory is a git repository — remember to commit and push.");
    }

    Ok(0)
}

/// Maximum accepted submission body (a signed report)
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Concurrent connections served before new ones are refused
const MAX_CONNECTIONS: usize = 256;

/// Budget for reading a request and writing its response
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Serve the dashboard, live status API, and submission API. Fleet state
/// is recomputed from the directory on every API request, so the page
/// stays current without regeneration.
/// Options for the fleet server
struct ServeOptions {
    dir: Option<String>,
    port: u16,
    bind: String,
    token: Option<String>,
    max_age_hours: Option<u64>,
}

async fn serve(policy: &Policy, options: ServeOptions) -> Result<i32> {
    use tokio::io::AsyncWriteExt;

    let ServeOptions {
        dir,
        port,
        bind,
        token,
        max_age_hours,
    } = options;
    let bind = bind.as_str();

    let fleet_dir = resolve_fleet_dir(policy, dir)?;
    fs::create_dir_all(&fleet_dir)?;

    let localhost = bind == "127.0.0.1" || bind == "localhost" || bind == "::1";
    if !localhost && token.is_none() {
        return Err(GardError::ConfigurationError {
            path: bind.to_string(),
            reason: "Binding beyond localhost requires --token so the fleet is not \
                     exposed unauthenticated. Put TLS in front (reverse proxy) for \
                     anything reachable from the internet."
                .to_string(),
        });
    }

    let max_age = max_age_hours
        .or(policy.fleet.max_age_hours)
        .unwrap_or(DEFAULT_MAX_AGE_HOURS) as i64;

    let listener = tokio::net::TcpListener::bind((bind, port))
        .await
        .map_err(|e| GardError::NetworkError {
            endpoint: format!("{}:{}", bind, port),
            reason: e.to_string(),
        })?;

    println!("Fleet dashboard: http://{}:{}/", bind, port);
    println!("Live status API: http://{}:{}/api/status", bind, port);
    println!(
        "Submissions:     gard fleet submit --url http://{}:{}{}",
        bind,
        port,
        if token.is_some() {
            " --token <TOKEN>"
        } else {
            ""
        }
    );
    if token.is_some() {
        println!("API access requires the bearer token; the dashboard will prompt for it.");
    }
    println!("Watching {} — Ctrl-C to stop.", fleet_dir.display());

    let token = std::sync::Arc::new(token);
    let limiter = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));

    loop {
        let (mut stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    tracing::warn!(error = %e, "accept failed");
                    continue;
                },
            },
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down fleet server.");
                return Ok(0);
            }
        };

        // Over capacity: refuse rather than queue without bound
        let Ok(permit) = limiter.clone().try_acquire_owned() else {
            tracing::warn!(peer = %peer, "connection refused: at capacity");
            drop(stream);
            continue;
        };
        let fleet_dir = fleet_dir.clone();
        let token = token.clone();

        tokio::spawn(async move {
            let _permit = permit;
            let request =
                match tokio::time::timeout(REQUEST_TIMEOUT, read_request(&mut stream)).await {
                    Ok(Some(request)) => request,
                    Ok(None) => return,
                    Err(_) => {
                        tracing::warn!(peer = %peer, "request timed out");
                        return;
                    },
                };

            // Policy reloaded per request so roster/config edits apply live
            let policy = config::load_policy(None).unwrap_or_default();
            let max_age = policy
                .fleet
                .max_age_hours
                .map(|h| h as i64)
                .unwrap_or(max_age);
            let mut response = respond(&request, &policy, &fleet_dir, max_age, token.as_deref());
            if request.method == "HEAD" {
                if let Some(end) = response.find("\r\n\r\n") {
                    response.truncate(end + 4);
                }
            }
            let status = response.split_whitespace().nth(1).unwrap_or("?");
            tracing::info!(peer = %peer, method = %request.method, path = %request.path, status = %status, "request");

            let _ = tokio::time::timeout(REQUEST_TIMEOUT, async {
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            })
            .await;
        });
    }
}

/// A minimally parsed HTTP request
struct HttpRequest {
    method: String,
    path: String,
    bearer_token: Option<String>,
    body: String,
}

/// Read and parse one HTTP request (headers plus Content-Length body)
async fn read_request(stream: &mut tokio::net::TcpStream) -> Option<HttpRequest> {
    use tokio::io::AsyncReadExt;

    let mut data = Vec::new();
    let mut buf = [0u8; 8192];

    // Read until end of headers
    let header_end = loop {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&buf[..n]);
        if let Some(pos) = find_subslice(&data, b"\r\n\r\n") {
            break pos + 4;
        }
        if data.len() > 64 * 1024 {
            return None;
        }
    };

    let headers = String::from_utf8_lossy(&data[..header_end]).to_string();
    let mut lines = headers.lines();
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_uppercase();
    let path = parts.next()?.to_string();

    let mut bearer_token = None;
    let mut content_length = 0usize;
    for line in lines {
        let lower = line.to_lowercase();
        if let Some(value) = lower.strip_prefix("authorization:") {
            if let Some(tok) = value.trim().strip_prefix("bearer ") {
                // Recover original-case token from the raw line
                let raw = line[line.len() - tok.len()..].trim().to_string();
                bearer_token = Some(raw);
            }
        } else if let Some(value) = lower.strip_prefix("content-length:") {
            content_length = value.trim().parse().unwrap_or(0);
        }
    }

    if content_length > MAX_BODY_BYTES {
        return None;
    }

    // Read the remainder of the body
    while data.len() < header_end + content_length {
        let n = stream.read(&mut buf).await.ok()?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);
    }
    let body = String::from_utf8_lossy(&data[header_end..]).to_string();

    Some(HttpRequest {
        method,
        path,
        bearer_token,
        body,
    })
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Constant-time-ish token comparison to avoid trivially timeable equality
fn token_matches(provided: Option<&str>, expected: &str) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    provided.len() == expected.len()
        && provided
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

/// Route an HTTP request to a full HTTP/1.1 response
fn respond(
    request: &HttpRequest,
    policy: &Policy,
    fleet_dir: &Path,
    max_age: i64,
    token: Option<&str>,
) -> String {
    let authorized = match token {
        Some(expected) => token_matches(request.bearer_token.as_deref(), expected),
        None => true,
    };
    let unauthorized = || {
        http_response(
            "401 Unauthorized",
            "application/json",
            &serde_json::json!({ "error": "missing or invalid bearer token" }).to_string(),
        )
    };

    // HEAD is answered like GET; the caller strips the body
    let method = if request.method == "HEAD" {
        "GET"
    } else {
        request.method.as_str()
    };

    match (method, request.path.as_str()) {
        // The page itself is a data-free shell; all data is behind the API
        ("GET", "/") | ("GET", "/index.html") => {
            let html = include_str!("fleet_dashboard.html")
                .replace("__GARD_DATA__", "null")
                // Live mode polls the API; a full page reload is unnecessary
                .replace("<meta http-equiv=\"refresh\" content=\"300\">\n", "");
            http_response("200 OK", "text/html; charset=utf-8", &html)
        },
        // Liveness for load balancers and uptime monitors; carries no data
        ("GET", "/healthz") => http_response("200 OK", "application/json", r#"{"status":"ok"}"#),
        ("GET", "/api/status") => {
            if !authorized {
                return unauthorized();
            }
            match collect_members(policy, fleet_dir, max_age) {
                Ok(members) => {
                    let all_green = !members.is_empty()
                        && members
                            .iter()
                            .all(|m| m.signature_valid && m.preflight_passing && !m.stale);
                    let payload = serde_json::json!({
                        "generated_at": chrono::Utc::now(),
                        "max_age_hours": max_age,
                        "all_green": all_green,
                        "members": members,
                    });
                    http_response(
                        "200 OK",
                        "application/json",
                        &serde_json::to_string(&payload).unwrap_or_else(|_| "{}".to_string()),
                    )
                },
                Err(e) => http_response(
                    "500 Internal Server Error",
                    "application/json",
                    &serde_json::json!({ "error": e.to_string() }).to_string(),
                ),
            }
        },
        ("POST", "/api/submit") => {
            if !authorized {
                return unauthorized();
            }
            handle_submission(&request.body, policy, fleet_dir)
        },
        _ => http_response("404 Not Found", "text/plain; charset=utf-8", "not found"),
    }
}

/// Accept a submitted report: parse, verify its Ed25519 signature, and
/// (when a team roster exists) require the signing key to be registered.
fn handle_submission(body: &str, policy: &Policy, fleet_dir: &Path) -> String {
    let reject = |status: &str, reason: &str| {
        http_response(
            status,
            "application/json",
            &serde_json::json!({ "error": reason }).to_string(),
        )
    };

    let Ok(report) = serde_json::from_str::<Report>(body) else {
        return reject("400 Bad Request", "body is not a valid gard report");
    };

    if !verify_report(&report).unwrap_or(false) {
        return reject("403 Forbidden", "report signature is missing or invalid");
    }

    let mut roster_name: Option<String> = None;
    if !policy.team.signers.is_empty() {
        roster_name = report.metadata.public_key.as_ref().and_then(|pk| {
            let pk_hex = pk.strip_prefix("ed25519 ").unwrap_or(pk);
            policy
                .team
                .signers
                .iter()
                .find(|s| s.public_key.eq_ignore_ascii_case(pk_hex))
                .map(|s| s.name.clone())
        });
        if roster_name.is_none() {
            return reject(
                "403 Forbidden",
                "signing key is not on the team roster; register it with 'gard team add'",
            );
        }
    }

    match store_report(fleet_dir, &report, roster_name.as_deref()) {
        Ok(file_name) => http_response(
            "200 OK",
            "application/json",
            &serde_json::json!({ "stored": file_name }).to_string(),
        ),
        Err(e) => reject("500 Internal Server Error", &e.to_string()),
    }
}

fn http_response(status: &str, content_type: &str, body: &str) -> String {
    let mut out = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\n",
        status,
        content_type,
        body.len()
    );
    out.push_str("Cache-Control: no-store\r\n");
    out.push_str("X-Content-Type-Options: nosniff\r\n");
    out.push_str("X-Frame-Options: DENY\r\n");
    out.push_str("Referrer-Policy: no-referrer\r\n");
    out.push_str("Connection: close\r\n");
    if content_type.starts_with("text/html") {
        // The dashboard is a single inline page: scripts and styles are
        // inline, fonts come from Google Fonts, data only from this origin
        out.push_str(
            "Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; \
             style-src 'unsafe-inline' https://fonts.googleapis.com; \
             font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; \
             base-uri 'none'; form-action 'self'; frame-ancestors 'none'\r\n",
        );
    }
    out.push_str("\r\n");
    out.push_str(body);
    out
}

/// Render the fleet view into the self-contained HTML template
fn render_dashboard(members: &[MemberStatus], max_age: i64) -> String {
    let all_green = !members.is_empty()
        && members
            .iter()
            .all(|m| m.signature_valid && m.preflight_passing && !m.stale);

    let payload = serde_json::json!({
        "generated_at": chrono::Utc::now(),
        "max_age_hours": max_age,
        "all_green": all_green,
        "members": members,
    });
    let json = serde_json::to_string(&payload)
        .unwrap_or_else(|_| "{}".to_string())
        // Prevent a value containing "</script>" from closing the tag
        .replace("</", "<\\/");

    include_str!("fleet_dashboard.html").replace("__GARD_DATA__", &json)
}

fn load_previous(fleet_dir: &Path, current: &Path) -> Option<Report> {
    let file_name = current.file_name()?;
    let previous_path = fleet_dir.join(HISTORY_DIR).join(file_name);
    let content = fs::read_to_string(previous_path).ok()?;
    serde_json::from_str(&content).ok()
}

fn evaluate_member(
    path: &Path,
    report: &Report,
    previous: Option<&Report>,
    policy: &Policy,
    max_age: i64,
) -> MemberStatus {
    let signature_valid = verify_report(report).unwrap_or(false);

    let trusted = report.metadata.public_key.as_ref().and_then(|pk| {
        let pk_hex = pk.strip_prefix("ed25519 ").unwrap_or(pk);
        policy
            .team
            .signers
            .iter()
            .find(|s| s.public_key.eq_ignore_ascii_case(pk_hex))
            .map(|s| s.name.clone())
    });

    let age_hours = (chrono::Utc::now() - report.metadata.timestamp).num_hours();
    let today = chrono::Utc::now().date_naive();

    let suppressions = report
        .metadata
        .active_suppressions
        .iter()
        .map(|s| {
            let days_left = chrono::NaiveDate::parse_from_str(&s.expires, "%Y-%m-%d")
                .map(|d| (d - today).num_days())
                .unwrap_or(0);
            SuppressionStatus {
                check_id: s.check_id.clone(),
                reason: s.reason.clone(),
                expires: s.expires.clone(),
                days_left,
                expiring_soon: days_left <= SUPPRESSION_WARN_DAYS,
            }
        })
        .collect();

    let (new_check_ids, resolved_check_ids) = match previous {
        Some(prev) => diff_check_ids(report, prev),
        None => (Vec::new(), Vec::new()),
    };

    // Worst severity and count per check, for the findings matrix
    let mut by_check: std::collections::BTreeMap<String, (crate::types::Severity, usize)> =
        std::collections::BTreeMap::new();
    for finding in &report.findings {
        let entry = by_check
            .entry(finding.check_id.clone())
            .or_insert((finding.severity, 0));
        entry.0 = entry.0.max(finding.severity);
        entry.1 += 1;
    }
    let checks = by_check
        .into_iter()
        .map(|(id, (severity, count))| CheckCell {
            id,
            severity: severity.to_string(),
            count,
        })
        .collect();

    MemberStatus {
        file: path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default(),
        member: trusted
            .clone()
            .unwrap_or_else(|| report.metadata.username.clone()),
        hostname: report.metadata.hostname.clone(),
        signature_valid,
        trusted,
        age_hours,
        stale: age_hours > max_age,
        critical: report.summary.critical,
        high: report.summary.high,
        total_findings: report.summary.total_findings,
        preflight_passing: report.summary.preflight_passing,
        suppressions,
        new_check_ids,
        resolved_check_ids,
        checks,
    }
}

/// Check ids that appeared in, or disappeared from, the current report
/// relative to the previous one
fn diff_check_ids(current: &Report, previous: &Report) -> (Vec<String>, Vec<String>) {
    let current_ids: HashSet<&str> = current
        .findings
        .iter()
        .map(|f| f.check_id.as_str())
        .collect();
    let previous_ids: HashSet<&str> = previous
        .findings
        .iter()
        .map(|f| f.check_id.as_str())
        .collect();

    let mut new_ids: Vec<String> = current_ids
        .difference(&previous_ids)
        .map(|s| s.to_string())
        .collect();
    let mut resolved: Vec<String> = previous_ids
        .difference(&current_ids)
        .map(|s| s.to_string())
        .collect();
    new_ids.sort();
    resolved.sort();
    (new_ids, resolved)
}

fn print_table(members: &[MemberStatus], max_age: i64) {
    println!(
        "{:<16} {:<14} {:<6} {:<8} {:<5} {:<5} {:<9} STATUS",
        "MEMBER", "HOST", "AGE", "SIG", "CRIT", "HIGH", "TRUSTED"
    );
    for m in members {
        let status = if !m.signature_valid {
            "BAD SIG".red().bold()
        } else if m.stale {
            "STALE".yellow().bold()
        } else if !m.preflight_passing {
            "FAIL".red().bold()
        } else {
            "PASS".green().bold()
        };
        println!(
            "{:<16} {:<14} {:<6} {:<8} {:<5} {:<5} {:<9} {}",
            m.member,
            m.hostname,
            format!("{}h", m.age_hours),
            if m.signature_valid {
                "valid"
            } else {
                "INVALID"
            },
            m.critical,
            m.high,
            m.trusted.as_deref().unwrap_or("-"),
            status
        );

        for s in &m.suppressions {
            if s.days_left < 0 {
                continue;
            }
            let line = format!(
                "suppression '{}' expires in {} day(s) ({})",
                s.check_id, s.days_left, s.reason
            );
            if s.expiring_soon {
                println!("  {} {}", "!".yellow().bold(), line.yellow());
            } else {
                println!("  - {}", line);
            }
        }
        if !m.new_check_ids.is_empty() {
            println!(
                "  {} new since previous report: {}",
                "!".red().bold(),
                m.new_check_ids.join(", ").red()
            );
        }
        if !m.resolved_check_ids.is_empty() {
            println!(
                "  {} resolved since previous report: {}",
                "+".green(),
                m.resolved_check_ids.join(", ")
            );
        }
    }
    println!("\nStale threshold: {}h", max_age);
}

fn resolve_fleet_dir(policy: &Policy, dir: Option<String>) -> Result<PathBuf> {
    dir.or_else(|| policy.fleet.dir.clone())
        .map(PathBuf::from)
        .ok_or_else(|| GardError::ConfigurationError {
            path: "policy.toml".to_string(),
            reason: "No fleet directory given. Pass --dir or set [fleet] dir in policy."
                .to_string(),
        })
}

fn sanitize(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{current_platform, Finding, ReportMetadata, ReportSummary, Severity};

    fn report_with_checks(check_ids: &[&str]) -> Report {
        let findings: Vec<Finding> = check_ids
            .iter()
            .map(|id| Finding {
                id: format!("f_{}", id),
                check_id: id.to_string(),
                check_name: id.to_string(),
                severity: Severity::High,
                platform: current_platform(),
                description: "x".to_string(),
                remediation: "y".to_string(),
                blocking: true,
                timestamp: chrono::Utc::now(),
                details: serde_json::json!({}),
            })
            .collect();
        Report {
            metadata: ReportMetadata {
                version: "1.0".to_string(),
                gard_version: "0.1.0".to_string(),
                timestamp: chrono::Utc::now(),
                hostname: "h".to_string(),
                username: "u".to_string(),
                platform: current_platform(),
                platform_version: "v".to_string(),
                scan_duration_ms: 1,
                active_suppressions: Vec::new(),
                signed: false,
                signature: None,
                public_key: None,
            },
            summary: ReportSummary::from_findings(&findings),
            findings,
        }
    }

    #[test]
    fn test_diff_detects_new_and_resolved() {
        let previous = report_with_checks(&["ssh-key-hygiene"]);
        let current = report_with_checks(&["ssh-key-hygiene", "open-ports-remote-access"]);
        let (new_ids, resolved) = diff_check_ids(&current, &previous);
        assert_eq!(new_ids, vec!["open-ports-remote-access".to_string()]);
        assert!(resolved.is_empty());

        let (new_ids, resolved) = diff_check_ids(&previous, &current);
        assert!(new_ids.is_empty());
        assert_eq!(resolved, vec!["open-ports-remote-access".to_string()]);
    }

    #[test]
    fn test_render_dashboard_embeds_data() {
        let report = report_with_checks(&["ssh-key-hygiene"]);
        let member = evaluate_member(
            Path::new("/tmp/u@h.json"),
            &report,
            None,
            &crate::types::Policy::default(),
            24,
        );
        let html = render_dashboard(&[member], 24);
        assert!(html.contains("ssh-key-hygiene") || html.contains("\"member\""));
        assert!(html.contains("Gard Fleet"));
        assert!(!html.contains("__GARD_DATA__"));
    }

    fn get(path: &str, token: Option<&str>) -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            path: path.to_string(),
            bearer_token: token.map(String::from),
            body: String::new(),
        }
    }

    #[test]
    fn test_respond_routes() {
        let policy = crate::types::Policy::default();
        let dir = std::env::temp_dir();

        let page = respond(&get("/", None), &policy, &dir, 24, None);
        assert!(page.starts_with("HTTP/1.1 200 OK"));
        assert!(page.contains("Gard Fleet"));
        assert!(page.contains("let DATA = null;"));
        assert!(!page.contains("http-equiv=\"refresh\""));

        let api = respond(&get("/api/status", None), &policy, &dir, 24, None);
        assert!(api.starts_with("HTTP/1.1 200 OK"));
        assert!(api.contains("\"members\""));

        let missing = respond(&get("/nope", None), &policy, &dir, 24, None);
        assert!(missing.starts_with("HTTP/1.1 404"));
    }

    #[test]
    fn test_api_requires_token_when_configured() {
        let policy = crate::types::Policy::default();
        let dir = std::env::temp_dir();

        let denied = respond(&get("/api/status", None), &policy, &dir, 24, Some("s3cret"));
        assert!(denied.starts_with("HTTP/1.1 401"));

        let wrong = respond(
            &get("/api/status", Some("nope")),
            &policy,
            &dir,
            24,
            Some("s3cret"),
        );
        assert!(wrong.starts_with("HTTP/1.1 401"));

        let ok = respond(
            &get("/api/status", Some("s3cret")),
            &policy,
            &dir,
            24,
            Some("s3cret"),
        );
        assert!(ok.starts_with("HTTP/1.1 200"));

        // The dashboard shell itself stays reachable; it holds no data
        let page = respond(&get("/", None), &policy, &dir, 24, Some("s3cret"));
        assert!(page.starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn test_token_matches() {
        assert!(token_matches(Some("abc"), "abc"));
        assert!(!token_matches(Some("abd"), "abc"));
        assert!(!token_matches(Some("ab"), "abc"));
        assert!(!token_matches(None, "abc"));
    }

    #[test]
    fn test_submission_rejects_unsigned_and_tampered() {
        let policy = crate::types::Policy::default();
        let dir = std::env::temp_dir();

        let garbage = handle_submission("not json", &policy, &dir);
        assert!(garbage.starts_with("HTTP/1.1 400"));

        // Unsigned report is refused
        let report = report_with_checks(&[]);
        let body = serde_json::to_string(&report).unwrap();
        let unsigned = handle_submission(&body, &policy, &dir);
        assert!(unsigned.starts_with("HTTP/1.1 403"));
    }

    #[test]
    fn test_submission_roster_enforcement() {
        use ed25519_dalek::SigningKey;
        let mut rng = rand::thread_rng();
        let seed: [u8; 32] = rand::Rng::gen(&mut rng);
        let signer = crate::report::ReportSigner::from_signing_key(SigningKey::from_bytes(&seed));

        let mut report = report_with_checks(&[]);
        signer.sign_report(&mut report).unwrap();
        let body = serde_json::to_string(&report).unwrap();

        let dir = std::env::temp_dir().join("gard-fleet-test");
        std::fs::create_dir_all(&dir).unwrap();

        // Roster configured, key not on it -> refused
        let mut policy = crate::types::Policy::default();
        policy.team.signers.push(crate::types::TeamSigner {
            name: "someone-else".to_string(),
            public_key: "ab".repeat(32),
        });
        let refused = handle_submission(&body, &policy, &dir);
        assert!(refused.starts_with("HTTP/1.1 403"));

        // Key registered -> accepted and stored
        policy.team.signers[0].public_key = signer.public_key_hex();
        let accepted = handle_submission(&body, &policy, &dir);
        assert!(accepted.starts_with("HTTP/1.1 200"), "{}", accepted);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_http_response_content_length() {
        let r = http_response("200 OK", "text/plain", "abc");
        assert!(r.contains("Content-Length: 3"));
        assert!(r.ends_with("abc"));
    }

    #[test]
    fn test_store_report_keys_rostered_members_by_name() {
        let dir = std::env::temp_dir().join(format!("gard-store-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let report = report_with_checks(&[]);

        assert_eq!(store_report(&dir, &report, None).unwrap(), "u@h.json");
        // Promotion to the roster migrates the legacy file into history
        assert_eq!(
            store_report(&dir, &report, Some("alice")).unwrap(),
            "alice.json"
        );
        assert!(dir.join("alice.json").exists());
        assert!(!dir.join("u@h.json").exists());
        assert!(dir.join(HISTORY_DIR).join("alice.json").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_healthz_is_public() {
        let policy = crate::types::Policy::default();
        let dir = std::env::temp_dir();
        let r = respond(&get("/healthz", None), &policy, &dir, 24, Some("s3cret"));
        assert!(r.starts_with("HTTP/1.1 200"));
        assert!(r.contains("X-Content-Type-Options: nosniff"));
    }

    #[test]
    fn test_head_routes_like_get() {
        let policy = crate::types::Policy::default();
        let dir = std::env::temp_dir();
        let mut req = get("/healthz", None);
        req.method = "HEAD".to_string();
        assert!(respond(&req, &policy, &dir, 24, None).starts_with("HTTP/1.1 200"));
    }

    #[test]
    fn test_html_response_carries_csp() {
        let policy = crate::types::Policy::default();
        let dir = std::env::temp_dir();
        let r = respond(&get("/", None), &policy, &dir, 24, None);
        assert!(r.contains("Content-Security-Policy:"));
        assert!(r.contains("frame-ancestors 'none'"));
    }

    #[test]
    fn test_diff_no_changes() {
        let a = report_with_checks(&["ssh-key-hygiene"]);
        let b = report_with_checks(&["ssh-key-hygiene"]);
        let (new_ids, resolved) = diff_check_ids(&a, &b);
        assert!(new_ids.is_empty());
        assert!(resolved.is_empty());
    }
}
