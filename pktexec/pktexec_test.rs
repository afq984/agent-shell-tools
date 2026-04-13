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

use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use googletest::prelude::*;

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn resolve_bin(env_var: &str) -> PathBuf {
    let rootpath =
        std::env::var(env_var).unwrap_or_else(|_| panic!("{env_var} must be set"));
    match std::env::var("RUNFILES_DIR") {
        Ok(dir) => PathBuf::from(dir).join("_main").join(rootpath),
        Err(_) => PathBuf::from(rootpath),
    }
}

fn pktexecd_bin() -> PathBuf {
    resolve_bin("PKTEXECD_BIN")
}
fn pktexec_bin() -> PathBuf {
    resolve_bin("PKTEXEC_BIN")
}

fn sock_path(test_name: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "pktexec-test-{test_name}-{}.sock",
        std::process::id()
    ))
}

struct Daemon {
    child: std::process::Child,
    sock: PathBuf,
}

impl Daemon {
    fn start(test_name: &str) -> Self {
        Self::start_with_env(test_name, &[])
    }

    fn start_with_env(test_name: &str, envs: &[(&str, &str)]) -> Self {
        let sock = sock_path(test_name);
        let _ = std::fs::remove_file(&sock);
        let mut cmd = Command::new(pktexecd_bin());
        cmd.arg("--sock").arg(&sock).stderr(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }
        // New process group so we can kill the whole tree.
        unsafe {
            cmd.pre_exec(|| {
                libc::setpgid(0, 0);
                Ok(())
            });
        }
        let child = cmd.spawn().expect("failed to spawn pktexecd");

        // Wait for the socket to appear.
        for _ in 0..100 {
            if sock.exists() {
                return Daemon { child, sock };
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("pktexecd did not create socket within 5s");
    }

    fn pktexec(&self, args: &[&str]) -> std::process::Output {
        Command::new(pktexec_bin())
            .env("PKTEXEC_SOCK", &self.sock)
            .args(args)
            .output()
            .expect("failed to spawn pktexec")
    }

    fn pktexec_with_stdin(&self, args: &[&str], input: &[u8]) -> std::process::Output {
        let mut child = Command::new(pktexec_bin())
            .env("PKTEXEC_SOCK", &self.sock)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn pktexec");
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(input)
            .expect("write stdin");
        child.wait_with_output().expect("wait_with_output")
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        // Kill the process group.
        unsafe { libc::kill(-(self.child.id() as i32), libc::SIGTERM) };
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.sock);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[googletest::test]
fn echo_stdout() {
    let d = Daemon::start("echo_stdout");
    let out = d.pktexec(&["echo", "hello world"]);
    expect_that!(out.status.code(), some(eq(0)));
    expect_that!(
        String::from_utf8_lossy(&out.stdout).trim(),
        eq("hello world")
    );
}

#[googletest::test]
fn exit_code_preserved() {
    let d = Daemon::start("exit_code");
    let out = d.pktexec(&["sh", "-c", "exit 42"]);
    expect_that!(out.status.code(), some(eq(42)));
}

#[googletest::test]
fn signal_exit_code() {
    let d = Daemon::start("signal_exit");
    let out = d.pktexec(&["sh", "-c", "kill -INT $$"]);
    expect_that!(out.status.code(), some(eq(130)));
}

#[googletest::test]
fn command_not_found() {
    let d = Daemon::start("cmd_not_found");
    let out = d.pktexec(&["does-not-exist-cmd"]);
    expect_that!(out.status.code(), some(eq(127)));
}

#[googletest::test]
fn pipe_stdin() {
    let d = Daemon::start("pipe_stdin");
    let out = d.pktexec_with_stdin(&["cat"], b"hello from stdin");
    expect_that!(out.status.code(), some(eq(0)));
    expect_that!(
        String::from_utf8_lossy(&out.stdout).as_ref(),
        eq("hello from stdin")
    );
}

#[googletest::test]
fn pipe_stdout_composition() {
    let d = Daemon::start("pipe_stdout");
    // pktexec echo hello | tr a-z A-Z — but we run it via sh -c.
    let out = Command::new("sh")
        .arg("-c")
        .arg(format!(
            "{} echo hello | tr a-z A-Z",
            pktexec_bin().display()
        ))
        .env("PKTEXEC_SOCK", &d.sock)
        .output()
        .expect("sh -c failed");
    expect_that!(out.status.code(), some(eq(0)));
    expect_that!(
        String::from_utf8_lossy(&out.stdout).trim(),
        eq("HELLO")
    );
}

#[googletest::test]
fn inherits_daemon_env() {
    // The defining property of the shell server: commands run in the
    // environment the daemon was launched in.
    let d = Daemon::start_with_env(
        "inherits_env",
        &[("PKTEXEC_TEST_VAR", "from-daemon")],
    );
    let out = d.pktexec(&["sh", "-c", "printf %s \"$PKTEXEC_TEST_VAR\""]);
    expect_that!(out.status.code(), some(eq(0)));
    expect_that!(
        String::from_utf8_lossy(&out.stdout).as_ref(),
        eq("from-daemon")
    );
}

#[googletest::test]
fn forwards_term_signal() {
    // SIGTERM to the client is forwarded to the host command's process group.
    let d = Daemon::start("forward_term");
    let mut child = Command::new(pktexec_bin())
        .env("PKTEXEC_SOCK", &d.sock)
        .args(["sh", "-c", "trap 'exit 7' TERM; while :; do sleep 1; done"])
        .spawn()
        .expect("failed to spawn pktexec");
    // Give the command time to install its trap before signalling.
    std::thread::sleep(std::time::Duration::from_millis(300));
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let status = child.wait().expect("wait pktexec");
    expect_that!(status.code(), some(eq(7)));
}

#[googletest::test]
fn concurrent_commands() {
    let d = Daemon::start("concurrent");
    // Spawn two commands simultaneously.
    let c1 = Command::new(pktexec_bin())
        .env("PKTEXEC_SOCK", &d.sock)
        .args(["echo", "one"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let c2 = Command::new(pktexec_bin())
        .env("PKTEXEC_SOCK", &d.sock)
        .args(["echo", "two"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let o1 = c1.wait_with_output().unwrap();
    let o2 = c2.wait_with_output().unwrap();
    expect_that!(o1.status.code(), some(eq(0)));
    expect_that!(o2.status.code(), some(eq(0)));
    expect_that!(String::from_utf8_lossy(&o1.stdout).trim(), eq("one"));
    expect_that!(String::from_utf8_lossy(&o2.stdout).trim(), eq("two"));
}
