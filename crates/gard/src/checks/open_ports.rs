//! Open remote access port detection
//!
//! Probes localhost for listening remote-access services (SSH, VNC, RDP,
//! and common remote-desktop agents). A signing machine should expose no
//! inbound remote control surface.

use crate::checks::{build_finding, CheckModule};
use crate::error::Result;
use crate::types::{Finding, Platform, Severity};
use serde_json::json;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

pub struct OpenPortsCheck;

/// (port, service, blocking) — services that grant remote control block preflight
const REMOTE_ACCESS_PORTS: &[(u16, &str, bool)] = &[
    (22, "SSH", true),
    (3389, "RDP", true),
    (5900, "VNC / macOS Screen Sharing", true),
    (5901, "VNC (display :1)", true),
    (5938, "TeamViewer", true),
    (3283, "Apple Remote Desktop", true),
    (23, "Telnet", true),
];

impl CheckModule for OpenPortsCheck {
    fn id(&self) -> &str {
        "open-ports-remote-access"
    }

    fn name(&self) -> &str {
        "Open Remote Access Port Detection"
    }

    fn description(&self) -> &str {
        "Probes the local machine for listening remote-access services such as SSH, \
        VNC, RDP, and remote desktop agents that expose the machine to remote control."
    }

    fn severity(&self) -> Severity {
        Severity::High
    }

    fn blocking_in_preflight(&self) -> bool {
        true
    }

    fn platforms(&self) -> &[Platform] {
        &[Platform::MacOS, Platform::Linux, Platform::Windows]
    }

    fn remediation(&self) -> &str {
        "Disable remote access services on signing machines (Sharing preferences on \
        macOS, sshd/xrdp/vnc services on Linux). If SSH is operationally required, \
        restrict it to key-only auth from a trusted network and document the exception \
        as a policy suppression."
    }

    fn run(&self) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        for &(port, service, blocking) in REMOTE_ACCESS_PORTS {
            if probe_local_port(port) {
                let mut finding = build_finding(
                    self,
                    format!(
                        "Remote access service listening on port {}: {}",
                        port, service
                    ),
                    json!({
                        "port": port,
                        "service": service,
                        "address": "127.0.0.1"
                    }),
                );
                finding.blocking = blocking;
                findings.push(finding);
            }
        }

        Ok(findings)
    }
}

/// A completed TCP connect to localhost means something is listening
fn probe_local_port(port: u16) -> bool {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_check_metadata() {
        let check = OpenPortsCheck;
        assert_eq!(check.id(), "open-ports-remote-access");
        assert!(check.blocking_in_preflight());
    }

    #[test]
    fn test_probe_detects_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
        let port = listener.local_addr().expect("local addr").port();
        assert!(probe_local_port(port));
    }

    #[test]
    fn test_probe_closed_port() {
        // Bind then drop to get a port that was free moments ago
        let port = {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
            listener.local_addr().expect("local addr").port()
        };
        assert!(!probe_local_port(port));
    }
}
