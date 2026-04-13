// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! pktexec: client CLI for the pktexec shell server.
//!
//! Connects to pktexecd over a SOCK_SEQPACKET Unix socket, sends an
//! ExecRequest with the caller's stdio fds via SCM_RIGHTS, and waits
//! for the exit code. See DESIGN.md §5.2.

use std::io::IoSlice;
use std::os::fd::AsFd;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, ensure};
use tokio::signal::unix::{SignalKind, signal};
use tokio_seqpacket::UnixSeqpacket;
use tokio_seqpacket::ancillary::AncillaryMessageWriter;

const SOCK_ENV: &str = "PKTEXEC_SOCK";
const MAX_MSG_SIZE: usize = 65536;

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            eprintln!("pktexec: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn parse_args() -> Result<(PathBuf, Vec<String>)> {
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut sock = std::env::var(SOCK_ENV).ok();

    // Handle --sock option (overrides PKTEXEC_SOCK).
    if args.first().is_some_and(|s| s == "--sock") {
        ensure!(args.len() >= 2, "--sock requires a value");
        sock = Some(args[1].clone());
        args.drain(..2);
    }

    // Skip optional --.
    if args.first().is_some_and(|s| s == "--") {
        args.remove(0);
    }

    let sock = sock
        .context("no socket path: pass --sock PATH or set PKTEXEC_SOCK")?;
    ensure!(!args.is_empty(), "no command specified");
    Ok((PathBuf::from(sock), args))
}

async fn run() -> Result<u8> {
    let (sock_path, argv) = parse_args()?;

    let conn = UnixSeqpacket::connect(&sock_path)
        .await
        .with_context(|| format!("connect to {:?}", sock_path))?;

    // Send ExecRequest + our stdio fds via SCM_RIGHTS.
    let working_dir = std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let req = wire::ClientMessage::ExecRequest { argv, working_dir };
    let req_bytes = wire::encode(&req)?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();

    let mut ancillary_buf = [0u8; 128];
    let mut ancillary = AncillaryMessageWriter::new(&mut ancillary_buf);
    ancillary
        .add_fds(&[stdin.as_fd(), stdout.as_fd(), stderr.as_fd()])
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    conn.send_vectored_with_ancillary(
        &[IoSlice::new(&req_bytes)],
        &mut ancillary,
    )
    .await
    .context("send ExecRequest")?;

    // Once send() returns, the kernel holds its own references to the three
    // fds (SCM_RIGHTS), so the daemon receives them even after we close ours.
    // Close ours now so downstream pipe readers see EOF when the host command
    // finishes, not when this client exits.
    drop(stdin);
    drop(stdout);
    drop(stderr);
    close_stdio();

    // Signal forwarding + wait for Exit.
    let mut buf = vec![0u8; MAX_MSG_SIZE];
    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    let mut sigquit = signal(SignalKind::quit())?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                send_signal(&conn, libc::SIGTERM).await;
            }
            _ = sigint.recv() => {
                send_signal(&conn, libc::SIGINT).await;
            }
            _ = sigquit.recv() => {
                send_signal(&conn, libc::SIGQUIT).await;
            }
            result = conn.recv(&mut buf) => {
                match result {
                    Ok(0) | Err(_) => return Ok(1),
                    Ok(n) => {
                        let msg: wire::ServerMessage = wire::decode(&buf[..n])
                            .context("decode server message")?;
                        let wire::ServerMessage::Exit { code } = msg;
                        return Ok(code.clamp(0, 255) as u8);
                    }
                }
            }
        }
    }
}

async fn send_signal(conn: &UnixSeqpacket, signo: i32) {
    let msg = wire::ClientMessage::TermSignal { signo };
    if let Ok(bytes) = wire::encode(&msg) {
        let _ = conn.send(&bytes).await;
    }
}

fn close_stdio() {
    // Reopen stdin/stdout/stderr to /dev/null so the host process holds
    // the only copies of the original fds. Using OwnedFd::from_raw_fd
    // would also require unsafe; redirecting to /dev/null is safe and
    // prevents "bad fd" errors if anything tries to write to stderr later.
    use std::fs::OpenOptions;
    if let Ok(devnull) = OpenOptions::new().read(true).write(true).open("/dev/null") {
        use std::os::fd::AsRawFd;
        let dn = devnull.as_raw_fd();
        // dup2 is safe via nix.
        let _ = nix::unistd::dup2(dn, 0);
        let _ = nix::unistd::dup2(dn, 1);
        let _ = nix::unistd::dup2(dn, 2);
    }
}
