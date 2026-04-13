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

//! pktexecd: host-side shell server for pktexec.
//!
//! Listens on a SOCK_SEQPACKET Unix socket, receives command execution
//! requests with file descriptors via SCM_RIGHTS, and runs each command in
//! the environment this daemon was launched in. Commands inherit the daemon's
//! environment, so launching it from an already-set-up shell (e.g. after
//! `lunch` or inside `cros_sdk`) lets clients run commands in that same
//! environment without repeating the setup. See DESIGN.md §5.1.
//!
//! This is not a security boundary: every received command is run as-is.

use std::io::IoSliceMut;
use std::os::fd::OwnedFd;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::{Context, Result, bail, ensure};
use clap::Parser;
use nix::sys::stat::{Mode, umask};
use tokio::signal::unix::{SignalKind, signal};
use tokio_seqpacket::ancillary::OwnedAncillaryMessage;
use tokio_seqpacket::{UnixSeqpacket, UnixSeqpacketListener};

/// Host-side shell server for pktexec.
#[derive(Parser)]
#[command(name = "pktexecd")]
struct Args {
    /// Path for the listening Unix socket.
    #[arg(long)]
    sock: PathBuf,
}

const MAX_MSG_SIZE: usize = 65536;
const ANCILLARY_BUF_SIZE: usize = 128;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Remove stale socket if present.
    let _ = std::fs::remove_file(&args.sock);

    // Create the socket as mode 0600 so only the owning user can connect.
    // Setting umask before bind closes the window in which the socket would
    // otherwise be world-connectable (a post-bind chmod leaves that window
    // open); the explicit set_permissions below is a belt-and-suspenders
    // guarantee in case the platform ignores umask for AF_UNIX.
    let prev_umask = umask(Mode::from_bits_truncate(0o177));
    let bind_result = UnixSeqpacketListener::bind(&args.sock);
    umask(prev_umask);
    let mut listener =
        bind_result.with_context(|| format!("bind {:?}", args.sock))?;
    std::fs::set_permissions(&args.sock, std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {:?}", args.sock))?;
    eprintln!("pktexecd: listening on {:?}", args.sock);

    // Graceful shutdown on SIGTERM.
    let mut sigterm = signal(SignalKind::terminate())?;

    loop {
        tokio::select! {
            result = listener.accept() => {
                let conn = result.context("accept")?;
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(conn).await {
                        eprintln!("pktexecd: connection error: {e:#}");
                    }
                });
            }
            _ = sigterm.recv() => {
                eprintln!("pktexecd: shutting down");
                break;
            }
        }
    }

    let _ = std::fs::remove_file(&args.sock);
    Ok(())
}

async fn handle_connection(conn: UnixSeqpacket) -> Result<()> {
    // Receive ExecRequest + 3 stdio fds via SCM_RIGHTS.
    let mut buf = vec![0u8; MAX_MSG_SIZE];
    let mut ancillary_buf = [0u8; ANCILLARY_BUF_SIZE];
    let (n, ancillary) = conn
        .recv_vectored_with_ancillary(
            &mut [IoSliceMut::new(&mut buf)],
            &mut ancillary_buf,
        )
        .await
        .context("recv ExecRequest")?;

    // Extract file descriptors from ancillary data.
    let mut fds: Vec<OwnedFd> = Vec::new();
    for msg in ancillary.into_messages() {
        if let OwnedAncillaryMessage::FileDescriptors(file_descriptors) = msg {
            fds.extend(file_descriptors);
        }
    }
    ensure!(fds.len() == 3, "expected 3 fds, got {}", fds.len());

    let msg: wire::ClientMessage =
        wire::decode(&buf[..n]).context("decode ExecRequest")?;

    let (argv, working_dir) = match msg {
        wire::ClientMessage::ExecRequest { argv, working_dir } => (argv, working_dir),
        _ => bail!("expected ExecRequest, got {msg:?}"),
    };
    ensure!(!argv.is_empty(), "empty argv");

    let stdin_fd = fds.remove(0);
    let stdout_fd = fds.remove(0);
    let stderr_fd = fds.remove(0);

    // Spawn the command with the client's stdio attached. The command inherits
    // this daemon's environment — the whole point of the shell server.
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::from(stdin_fd))
        .stdout(Stdio::from(stdout_fd))
        .stderr(Stdio::from(stderr_fd))
        .kill_on_drop(true);
    if !working_dir.is_empty() {
        cmd.current_dir(&working_dir);
    }

    // New process group so signals and cleanup target the whole command tree
    // (pipelines, background jobs) rather than just the immediate child.
    unsafe {
        cmd.pre_exec(|| {
            // setpgid(0, 0) cannot fail meaningfully for a freshly forked
            // child; a separate ns-helper binary (DESIGN §5.3) would let us
            // drop this last unsafe block, but is out of scope here.
            libc::setpgid(0, 0);
            Ok(())
        });
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) => {
            // Command could not be started (e.g. not found). The client has
            // already closed its stdio, so report via the protocol, not stderr.
            let _ = conn
                .send(&wire::encode(&wire::ServerMessage::Exit { code: 127 })?)
                .await;
            return Err(e).with_context(|| format!("spawn {:?}", argv[0]));
        }
    };
    let pid = child.id().unwrap_or(0) as i32;

    // Event loop: forward signals and wait for the command to exit.
    loop {
        tokio::select! {
            result = conn.recv(&mut buf) => {
                match result {
                    Ok(0) | Err(_) => {
                        // Client disconnected — kill the process group.
                        kill_pg(pid, libc::SIGKILL);
                        let _ = child.wait().await;
                        return Ok(());
                    }
                    Ok(n) => {
                        if let Ok(wire::ClientMessage::TermSignal { signo }) =
                            wire::decode(&buf[..n])
                        {
                            kill_pg(pid, signo);
                        }
                    }
                }
            }
            result = child.wait() => {
                let status = result.context("wait")?;
                // Kill any lingering background processes in the group so they
                // release their inherited copies of the passed fds.
                kill_pg(pid, libc::SIGKILL);
                let code = exit_code(&status);
                let _ = conn
                    .send(&wire::encode(&wire::ServerMessage::Exit { code })?)
                    .await;
                return Ok(());
            }
        }
    }
}

fn kill_pg(pid: i32, sig: i32) {
    if pid > 0 {
        let _ = nix::sys::signal::killpg(
            nix::unistd::Pid::from_raw(pid),
            nix::sys::signal::Signal::try_from(sig).ok(),
        );
    }
}

/// Extract exit code from a process status. For signal deaths, return
/// 128 + signal number (standard shell convention).
fn exit_code(status: &std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    if let Some(code) = status.code() {
        code
    } else if let Some(sig) = status.signal() {
        128 + sig
    } else {
        1
    }
}
