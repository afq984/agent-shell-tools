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

package main_test

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bazelbuild/rules_go/go/runfiles"
)

func binPath(t *testing.T) string {
	t.Helper()
	rloc := os.Getenv("EGRESSD_BIN")
	if rloc == "" {
		t.Fatal("EGRESSD_BIN not set")
	}
	r, err := runfiles.New()
	if err != nil {
		t.Fatalf("runfiles: %v", err)
	}
	p, err := r.Rlocation(rloc)
	if err != nil {
		t.Fatalf("rlocation(%q): %v", rloc, err)
	}
	return p
}

// startDaemon launches egressd with the given allowlist and returns its
// socket path. The daemon is stopped on cleanup.
func startDaemon(t *testing.T, allow ...string) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "egress.sock")
	args := []string{"--sock", sock}
	for _, a := range allow {
		args = append(args, "--allow", a)
	}
	cmd := exec.Command(binPath(t), args...)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start egressd: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Signal(syscall.SIGTERM)
		cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		if c, err := net.Dial("unix", sock); err == nil {
			c.Close()
			return sock
		}
		if time.Now().After(deadline) {
			t.Fatal("egressd did not start listening")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// dial connects to the proxy socket.
func dial(t *testing.T, sock string) net.Conn {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// roundtrip sends a raw request head on c and reads one response.
func roundtrip(t *testing.T, c net.Conn, r *bufio.Reader, head string) (*http.Response, string) {
	t.Helper()
	if _, err := io.WriteString(c, head); err != nil {
		t.Fatalf("write: %v", err)
	}
	resp, err := http.ReadResponse(r, nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, string(body)
}

// echoServer accepts one connection and echoes it back until EOF.
func echoServer(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { lis.Close() })
	go func() {
		c, err := lis.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		io.Copy(c, c)
	}()
	return lis.Addr().String()
}

// unusedAddr returns a loopback address nothing listens on.
func unusedAddr(t *testing.T) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	return lis.Addr().String()
}

func TestForwardsAllowedPlainHTTP(t *testing.T) {
	gotCh := make(chan *http.Request, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCh <- r
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	addr := upstream.Listener.Addr().String()
	sock := startDaemon(t, addr)

	c := dial(t, sock)
	resp, body := roundtrip(t, c, bufio.NewReader(c), fmt.Sprintf(
		"GET http://%s/hello?x=1 HTTP/1.1\r\nHost: %s\r\n"+
			"Proxy-Connection: keep-alive\r\nProxy-Authorization: Basic eDp5\r\n\r\n", addr, addr))
	if resp.StatusCode != http.StatusOK || body != "ok" {
		t.Fatalf("got %d %q, want 200 \"ok\"", resp.StatusCode, body)
	}
	got := <-gotCh
	if got.RequestURI != "/hello?x=1" {
		t.Errorf("upstream RequestURI = %q, want origin form /hello?x=1", got.RequestURI)
	}
	for _, h := range []string{"Proxy-Connection", "Proxy-Authorization", "X-Forwarded-For"} {
		if v := got.Header.Get(h); v != "" {
			t.Errorf("upstream saw %s: %q", h, v)
		}
	}
}

func TestDeniesPlainHTTPToUnlistedDestination(t *testing.T) {
	denied := unusedAddr(t)
	sock := startDaemon(t, unusedAddr(t))

	c := dial(t, sock)
	resp, body := roundtrip(t, c, bufio.NewReader(c),
		fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", denied, denied))
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, denied) {
		t.Fatalf("got %d %q, want 403 naming %s", resp.StatusCode, body, denied)
	}
}

// Every request on a kept-alive connection is checked on its own.
func TestChecksEachRequestOnAConnection(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()
	allowed := upstream.Listener.Addr().String()
	denied := unusedAddr(t)
	sock := startDaemon(t, allowed)

	c := dial(t, sock)
	r := bufio.NewReader(c)
	for _, tc := range []struct {
		addr string
		want int
	}{
		{allowed, http.StatusOK},
		{denied, http.StatusForbidden},
		{allowed, http.StatusOK},
	} {
		resp, _ := roundtrip(t, c, r,
			fmt.Sprintf("GET http://%s/ HTTP/1.1\r\nHost: %s\r\n\r\n", tc.addr, tc.addr))
		if resp.StatusCode != tc.want {
			t.Errorf("GET %s: got %d, want %d", tc.addr, resp.StatusCode, tc.want)
		}
	}
}

func TestTunnelsAllowedConnect(t *testing.T) {
	addr := echoServer(t)
	sock := startDaemon(t, addr)

	c := dial(t, sock)
	// Bytes sent right behind the request head must reach the tunnel too.
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\nping", addr, addr); err != nil {
		t.Fatal(err)
	}
	c.(*net.UnixConn).CloseWrite()
	out, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if want := "HTTP/1.1 200 Connection established\r\n\r\nping"; string(out) != want {
		t.Fatalf("got %q, want %q", out, want)
	}
}

func TestDeniesConnectToUnlistedDestination(t *testing.T) {
	sock := startDaemon(t, "example.com:443")
	c := dial(t, sock)
	resp, _ := roundtrip(t, c, bufio.NewReader(c),
		"CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\n\r\n")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("got %d, want 403", resp.StatusCode)
	}
}

func TestAllowlistHostIsCaseInsensitive(t *testing.T) {
	addr := echoServer(t)
	_, port, _ := net.SplitHostPort(addr)
	sock := startDaemon(t, "LOCALHOST:"+port)

	c := dial(t, sock)
	fmt.Fprintf(c, "CONNECT localhost:%s HTTP/1.1\r\nHost: localhost:%s\r\n\r\n", port, port)
	// Only the status line: a tunnel's 200 has no body length, so reading
	// a response body would wait for the tunnel to close.
	status, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(status, "HTTP/1.1 200 ") {
		t.Fatalf("got %q, %v; want 200", status, err)
	}
}

func TestRejectsOriginFormRequest(t *testing.T) {
	sock := startDaemon(t)
	c := dial(t, sock)
	resp, _ := roundtrip(t, c, bufio.NewReader(c), "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("got %d, want 400", resp.StatusCode)
	}
}

func TestRemovesSocketOnShutdown(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "egress.sock")
	cmd := exec.Command(binPath(t), "--sock", sock)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket still present after SIGTERM: %v", err)
	}
}
