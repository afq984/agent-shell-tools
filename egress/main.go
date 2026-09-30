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

// Binary egressd is an allowlisting HTTP proxy on a Unix socket.
//
// The sandbox runs in a network namespace with only a loopback interface,
// so this socket, bind-mounted into the jail, is its only way out. Clients
// reach it through the sandbox's in-jail relay as an ordinary HTTP proxy
// (HTTP_PROXY=http://127.0.0.1:3128).
//
// Two request forms are served, both gated by an exact host:port allowlist
// on the destination the client names:
//
//   - CONNECT host:port opens an opaque tunnel (HTTPS and anything else).
//     Only the destination is checked; the tunneled bytes are not inspected.
//   - METHOD http://host:port/path forwards a plain-HTTP request. Each
//     request on a connection is checked on its own.
//
// The proxy resolves hostnames itself, so the sandbox needs no DNS.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// allowFlag collects repeated --allow values.
type allowFlag []string

func (a *allowFlag) String() string     { return strings.Join(*a, ",") }
func (a *allowFlag) Set(v string) error { *a = append(*a, v); return nil }

func main() {
	log.SetPrefix("egressd: ")
	log.SetFlags(0)

	sock := flag.String("sock", "", "Unix socket path to listen on (required)")
	var allowArgs allowFlag
	flag.Var(&allowArgs, "allow",
		"destination the sandbox may reach, as host:port (repeatable); "+
			"matched exactly against the requested host and port, host case-insensitive")
	flag.Parse()

	if *sock == "" {
		log.Fatal("--sock is required")
	}
	allow := make(map[string]bool)
	for _, a := range allowArgs {
		key, err := destKey(a, "")
		if err != nil {
			log.Fatalf("--allow %q: %v", a, err)
		}
		allow[key] = true
	}

	lis, err := listen(*sock)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s, allowing %v", *sock, allowArgs)

	srv := &http.Server{
		Handler:           newProxy(allow),
		ReadHeaderTimeout: 30 * time.Second,
		ErrorLog:          log.Default(),
	}

	// Remove the socket on the way out, so a restart finds no leftover.
	go func() {
		sigCh := make(chan os.Signal, 1)
		signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
		sig := <-sigCh
		log.Printf("%v: shutting down", sig)
		srv.Close()
	}()

	err = srv.Serve(lis)
	os.Remove(*sock)
	if !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

// listen binds the Unix socket as mode 0600, replacing only a stale one.
func listen(sock string) (net.Listener, error) {
	// A live socket belongs to another daemon. Only a refused connection on
	// a path that really is a socket proves a leftover that is safe to
	// replace; connect(2) reports ECONNREFUSED for a regular file as well.
	if c, err := net.Dial("unix", sock); err == nil {
		c.Close()
		return nil, fmt.Errorf("%s is in use by another daemon", sock)
	} else if errors.Is(err, syscall.ECONNREFUSED) {
		fi, err := os.Lstat(sock)
		if err != nil {
			return nil, err
		}
		if fi.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket; refusing to replace it", sock)
		}
		if err := os.Remove(sock); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	} else if !errors.Is(err, syscall.ENOENT) {
		return nil, fmt.Errorf("probe %s: %w", sock, err)
	}

	// The jailed user maps to our uid; nobody else may connect. Setting the
	// umask before bind leaves no window in which the socket is open wider.
	old := syscall.Umask(0o177)
	lis, err := net.Listen("unix", sock)
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		lis.Close()
		return nil, err
	}
	return lis, nil
}

// destKey returns the canonical host:port form of an authority used for
// allowlist lookups: lower-case host, brackets around IPv6, decimal port.
// defaultPort applies when the authority has no port; "" requires one.
func destKey(authority, defaultPort string) (string, error) {
	host, port, err := net.SplitHostPort(authority)
	var addrErr *net.AddrError
	if errors.As(err, &addrErr) && addrErr.Err == "missing port in address" && defaultPort != "" {
		host, port, err = strings.TrimSuffix(strings.TrimPrefix(authority, "["), "]"), defaultPort, nil
	}
	if err != nil {
		return "", err
	}
	if host == "" {
		return "", errors.New("empty host")
	}
	if strings.ContainsAny(host, "/@?# ") {
		return "", fmt.Errorf("invalid host %q", host)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return "", fmt.Errorf("invalid port %q", port)
	}
	return net.JoinHostPort(strings.ToLower(host), strconv.FormatUint(n, 10)), nil
}

type proxy struct {
	allow   map[string]bool
	dialer  net.Dialer
	forward *httputil.ReverseProxy
}

func newProxy(allow map[string]bool) *proxy {
	p := &proxy{allow: allow, dialer: net.Dialer{Timeout: 30 * time.Second}}
	p.forward = &httputil.ReverseProxy{
		// The request already carries the absolute URL that was checked.
		// Rewrite (unlike Director) also strips any X-Forwarded-* headers.
		Rewrite: func(pr *httputil.ProxyRequest) {},
		Transport: &http.Transport{
			// Never chain through the host's own proxy settings.
			Proxy:               nil,
			DialContext:         p.dialer.DialContext,
			MaxIdleConnsPerHost: 4,
			IdleConnTimeout:     90 * time.Second,
		},
		// Flush every write: model APIs stream their responses.
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("forward %s: %v", r.URL.Host, err)
			http.Error(w, fmt.Sprintf("egressd: %v", err), http.StatusBadGateway)
		},
	}
	return p
}

func (p *proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var key string
	var err error
	switch {
	case r.Method == http.MethodConnect:
		key, err = destKey(r.Host, "")
	case r.URL.IsAbs() && r.URL.Scheme == "http":
		key, err = destKey(r.URL.Host, "80")
	default:
		err = fmt.Errorf("expected an absolute http:// URI or CONNECT, got %q", r.RequestURI)
	}
	if err != nil {
		http.Error(w, fmt.Sprintf("egressd: %v", err), http.StatusBadRequest)
		return
	}
	if !p.allow[key] {
		log.Printf("deny %s", key)
		http.Error(w, fmt.Sprintf("egressd: destination not allowed: %s", key), http.StatusForbidden)
		return
	}
	log.Printf("allow %s", key)

	if r.Method == http.MethodConnect {
		p.tunnel(w, r, key)
	} else {
		p.forward.ServeHTTP(w, r)
	}
}

// tunnel connects to key and splices the hijacked client connection to it.
func (p *proxy) tunnel(w http.ResponseWriter, r *http.Request, key string) {
	// Not r.Context(): the server cancels it when the client half-closes,
	// which a client may do right after sending its first tunneled bytes.
	upstream, err := p.dialer.Dial("tcp", key)
	if err != nil {
		log.Printf("connect %s: %v", key, err)
		http.Error(w, fmt.Sprintf("egressd: cannot connect to %s: %v", key, err), http.StatusBadGateway)
		return
	}
	client, buf, err := http.NewResponseController(w).Hijack()
	if err != nil {
		upstream.Close()
		http.Error(w, "egressd: cannot hijack connection", http.StatusInternalServerError)
		return
	}
	if _, err := client.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n")); err != nil {
		client.Close()
		upstream.Close()
		return
	}
	splice(client, buf.Reader, upstream)
}

// splice copies bytes both ways until each side has sent EOF, propagating
// each EOF as a write shutdown so half-closed streams keep working. Errors
// are not reported: either peer hanging up mid-stream is how a tunnel ends
// when, say, the jailed client exits. clientR holds any bytes the client
// sent past the request head, followed by the rest of its stream.
func splice(client net.Conn, clientR *bufio.Reader, upstream net.Conn) {
	defer client.Close()
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		io.Copy(upstream, clientR)
		closeWrite(upstream)
	}()
	if _, err := io.Copy(client, upstream); err != nil {
		// A broken client will never read again: tear the upstream down so
		// the other direction's copy unblocks instead of waiting forever.
		upstream.Close()
	}
	closeWrite(client)
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
}
