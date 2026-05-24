package hw1_tests

import (
	"crypto/sha256"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/proxy"
)

// ============================================================================
// Handshake / Auth Tests (Raw TCP)
// ============================================================================

// Test 1: TestNoAuthHandshake verifies that the proxy accepts no-auth method.
// Raw TCP: sends [0x05, 0x01, 0x00], expects [0x05, 0x00].
func TestNoAuthHandshake(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port) // No auth env vars

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	require.NoError(t, err, "failed to connect to proxy")
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Client greeting: VER=5, NMETHODS=1, METHODS=[NO_AUTH]
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err, "failed to write greeting")

	// Read server response: VER, METHOD
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err, "failed to read response")

	assert.Equal(t, byte(0x05), buf[0], "version must be 5")
	assert.Equal(t, byte(0x00), buf[1], "method must be no-auth (0x00)")
}

// Test 2: TestUsernamePasswordAuth verifies full username/password authentication.
// Raw TCP: full auth flow with valid credentials. Sub-negotiation version must be 0x01.
func TestUsernamePasswordAuth(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port, "PROXY_USER=testuser", "PROXY_PASS=testpass")

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	require.NoError(t, err, "failed to connect to proxy")
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Client greeting: VER=5, NMETHODS=1, METHODS=[USERNAME_PASSWORD]
	_, err = conn.Write([]byte{0x05, 0x01, 0x02})
	require.NoError(t, err, "failed to write greeting")

	// Read method selection response
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err, "failed to read method selection")

	assert.Equal(t, byte(0x05), buf[0], "version must be 5")
	assert.Equal(t, byte(0x02), buf[1], "method must be username/password (0x02)")

	// Send username/password sub-negotiation (VER=0x01, not 0x05!)
	user := []byte("testuser")
	pass := []byte("testpass")
	authReq := []byte{0x01, byte(len(user))}
	authReq = append(authReq, user...)
	authReq = append(authReq, byte(len(pass)))
	authReq = append(authReq, pass...)

	_, err = conn.Write(authReq)
	require.NoError(t, err, "failed to write auth request")

	// Read auth response: VER=0x01, STATUS
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err, "failed to read auth response")

	assert.Equal(t, byte(0x01), authResp[0], "auth sub-negotiation version must be 0x01")
	assert.Equal(t, byte(0x00), authResp[1], "auth status must be success (0x00)")
}

// Test 3: TestInvalidAuthRejection verifies that wrong credentials are rejected.
// Raw TCP: auth with wrong password returns non-zero status.
func TestInvalidAuthRejection(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port, "PROXY_USER=testuser", "PROXY_PASS=testpass")

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	require.NoError(t, err, "failed to connect to proxy")
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Client greeting
	_, err = conn.Write([]byte{0x05, 0x01, 0x02})
	require.NoError(t, err)

	// Read method selection
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, byte(0x02), buf[1], "server should select username/password")

	// Send wrong credentials
	user := []byte("testuser")
	pass := []byte("WRONGPASS")
	authReq := []byte{0x01, byte(len(user))}
	authReq = append(authReq, user...)
	authReq = append(authReq, byte(len(pass)))
	authReq = append(authReq, pass...)

	_, err = conn.Write(authReq)
	require.NoError(t, err)

	// Read auth response
	authResp := make([]byte, 2)
	_, err = io.ReadFull(conn, authResp)
	require.NoError(t, err)

	assert.Equal(t, byte(0x01), authResp[0], "auth version must be 0x01")
	assert.NotEqual(t, byte(0x00), authResp[1], "auth status must be non-zero (failure)")
}

// Test 4: TestUnsupportedMethod verifies that offering only unsupported methods
// results in 0xFF rejection.
// Raw TCP: sends [0x05, 0x01, 0x03] (CHAP only), expects [0x05, 0xFF].
func TestUnsupportedMethod(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port) // No auth

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	require.NoError(t, err, "failed to connect to proxy")
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Client greeting: VER=5, NMETHODS=1, METHODS=[CHAP (0x03)]
	_, err = conn.Write([]byte{0x05, 0x01, 0x03})
	require.NoError(t, err)

	// Read response
	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)

	assert.Equal(t, byte(0x05), buf[0], "version must be 5")
	assert.Equal(t, byte(0xFF), buf[1], "method must be 0xFF (no acceptable methods)")
}

// ============================================================================
// Proxy Functional Tests (SOCKS5 Client Library)
// ============================================================================

// Test 5: TestIPv4Connect verifies CONNECT to an IPv4 address.
// Uses proxy.SOCKS5 dialer to connect to a test server via 127.0.0.1.
func TestIPv4Connect(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port)

	// Start test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ipv4-ok"))
	}))
	t.Cleanup(func() { ts.Close() })

	// Create SOCKS5 dialer (no auth)
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, proxy.Direct)
	require.NoError(t, err, "failed to create SOCKS5 dialer")

	// Get test server address as IP:port (not localhost)
	tsAddr := ts.Listener.Addr().(*net.TCPAddr)
	target := fmt.Sprintf("127.0.0.1:%d", tsAddr.Port)

	// Dial through proxy to test server
	conn, err := dialer.Dial("tcp", target)
	require.NoError(t, err, "failed to dial through proxy")
	defer conn.Close()

	// Send HTTP request
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\nConnection: close\r\n\r\n", tsAddr.Port)
	require.NoError(t, err)

	// Read response
	body, err := io.ReadAll(conn)
	require.NoError(t, err)

	assert.Contains(t, string(body), "ipv4-ok", "response body should contain expected content")
}

// Test 6: TestDomainConnect verifies CONNECT to a domain name (localhost).
// Validates that the proxy resolves domain names correctly.
func TestDomainConnect(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port)

	// Start test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("domain-ok"))
	}))
	t.Cleanup(func() { ts.Close() })

	// Create SOCKS5 dialer (no auth)
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, proxy.Direct)
	require.NoError(t, err, "failed to create SOCKS5 dialer")

	// Use "localhost" as domain name (proxy must resolve it)
	tsAddr := ts.Listener.Addr().(*net.TCPAddr)
	target := fmt.Sprintf("localhost:%d", tsAddr.Port)

	// Dial through proxy
	conn, err := dialer.Dial("tcp", target)
	require.NoError(t, err, "failed to dial through proxy via domain")
	defer conn.Close()

	// Send HTTP request
	_, err = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: localhost:%d\r\nConnection: close\r\n\r\n", tsAddr.Port)
	require.NoError(t, err)

	// Read response
	body, err := io.ReadAll(conn)
	require.NoError(t, err)

	assert.Contains(t, string(body), "domain-ok", "response body should contain expected content")
}

// Test 7: TestHTTPThroughProxy verifies a full HTTP GET through the SOCKS5 proxy.
// Uses http.Client with custom transport wrapping the SOCKS5 dialer.
func TestHTTPThroughProxy(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port)

	// Start test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("hello from test server"))
	}))
	t.Cleanup(func() { ts.Close() })

	// Create SOCKS5 dialer (no auth)
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, proxy.Direct)
	require.NoError(t, err, "failed to create SOCKS5 dialer")

	// Create HTTP client with SOCKS5 transport
	transport := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Make HTTP request through proxy
	resp, err := client.Get(ts.URL)
	require.NoError(t, err, "HTTP request through proxy failed")
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	assert.Equal(t, http.StatusOK, resp.StatusCode, "expected 200 OK")
	assert.Equal(t, "hello from test server", string(body), "response body mismatch")
}

// Test 8: TestInvalidTarget verifies that CONNECT to an unreachable target returns
// an error reply (REP != 0x00).
// Raw TCP: complete no-auth handshake, then send CONNECT to port 1 (closed).
func TestInvalidTarget(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	require.NoError(t, err, "failed to connect to proxy")
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// No-auth handshake
	_, err = conn.Write([]byte{0x05, 0x01, 0x00})
	require.NoError(t, err)

	buf := make([]byte, 2)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, byte(0x00), buf[1], "expected no-auth accepted")

	// Send CONNECT request to 127.0.0.1:1 (almost certainly closed)
	connectReq := []byte{
		0x05, 0x01, 0x00, 0x01, // VER, CMD=CONNECT, RSV, ATYP=IPv4
		0x7f, 0x00, 0x00, 0x01, // 127.0.0.1
		0x00, 0x01, // port 1
	}
	_, err = conn.Write(connectReq)
	require.NoError(t, err)

	// Read CONNECT reply (10 bytes for IPv4 reply)
	reply := make([]byte, 10)
	_, err = io.ReadFull(conn, reply)
	require.NoError(t, err, "failed to read connect reply")

	assert.Equal(t, byte(0x05), reply[0], "version must be 5")
	assert.NotEqual(t, byte(0x00), reply[1], "REP must be non-zero (error) for unreachable target")
}

// ============================================================================
// Edge Case Tests
// ============================================================================

// Test 9: TestConcurrentConnections verifies that 10 simultaneous HTTP requests
// through the proxy all succeed.
func TestConcurrentConnections(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port)

	// Start test HTTP server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("concurrent-ok"))
	}))
	t.Cleanup(func() { ts.Close() })

	// Create SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, proxy.Direct)
	require.NoError(t, err)

	transport := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	// Launch 10 concurrent requests
	const numRequests = 10
	var wg sync.WaitGroup
	errors := make(chan error, numRequests)
	results := make(chan string, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			resp, err := client.Get(ts.URL)
			if err != nil {
				errors <- fmt.Errorf("request %d failed: %w", idx, err)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				errors <- fmt.Errorf("request %d body read failed: %w", idx, err)
				return
			}

			results <- string(body)
		}(i)
	}

	wg.Wait()
	close(errors)
	close(results)

	// Check for errors
	for err := range errors {
		t.Error(err)
	}

	// Count successful results
	count := 0
	for result := range results {
		assert.Equal(t, "concurrent-ok", result)
		count++
	}

	assert.Equal(t, numRequests, count, "all %d requests should succeed", numRequests)
}

// Test 10: TestLargePayloadRelay verifies that 1MB of data is relayed correctly
// through the proxy without corruption.
func TestLargePayloadRelay(t *testing.T) {
	port := getFreePort(t)
	setupProxy(t, port)

	// Generate 1MB of deterministic random data
	const payloadSize = 1024 * 1024 // 1MB
	rng := rand.New(rand.NewSource(42))
	payload := make([]byte, payloadSize)
	rng.Read(payload)
	expectedHash := sha256.Sum256(payload)

	// Start test HTTP server that returns the 1MB payload
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write(payload)
	}))
	t.Cleanup(func() { ts.Close() })

	// Create SOCKS5 dialer
	dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", port), nil, proxy.Direct)
	require.NoError(t, err)

	transport := &http.Transport{
		Dial: dialer.Dial,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Make request through proxy
	resp, err := client.Get(ts.URL)
	require.NoError(t, err, "HTTP request for large payload failed")
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "failed to read large payload response")

	assert.Equal(t, payloadSize, len(body), "payload size mismatch")

	actualHash := sha256.Sum256(body)
	assert.Equal(t, expectedHash, actualHash, "payload integrity check failed (SHA-256 mismatch)")
}
