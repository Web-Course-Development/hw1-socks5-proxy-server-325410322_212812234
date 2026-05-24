package hw1_tests

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// setupProxy builds and launches the proxy binary on the given port.
// If envVars are provided, they are set as KEY=VALUE pairs on the process.
// Returns the exec.Cmd. The process is killed on test cleanup.
func setupProxy(t *testing.T, port int, envVars ...string) *exec.Cmd {
	t.Helper()

	// Build the student binary from the parent directory
	buildCmd := exec.Command("go", "build", "-o", "proxy-binary", ".")
	buildCmd.Dir = ".."
	out, err := buildCmd.CombinedOutput()
	require.NoError(t, err, "build failed: %s", string(out))

	// Launch the binary. Path is resolved AFTER chdir to cmd.Dir, so use
	// "./proxy-binary" (binary lives at repo root where the build wrote it).
	cmd := exec.Command("./proxy-binary", "-port", strconv.Itoa(port))
	cmd.Dir = ".."
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Set environment variables (inherit current env + add specified ones)
	cmd.Env = append(os.Environ(), envVars...)

	require.NoError(t, cmd.Start(), "failed to start proxy binary")

	// Register cleanup to kill the process and remove the binary
	t.Cleanup(func() {
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		os.Remove("../proxy-binary")
	})

	// Wait for the proxy to be ready
	waitForPort(t, port, 5*time.Second)

	return cmd
}

// waitForPort retries connecting to localhost:port until success or timeout.
func waitForPort(t *testing.T, port int, timeout time.Duration) {
	t.Helper()

	deadline := time.Now().Add(timeout)
	addr := fmt.Sprintf("127.0.0.1:%d", port)

	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("port %d not ready within %s", port, timeout)
}

// getFreePort returns an available TCP port by listening on :0 and releasing.
func getFreePort(t *testing.T) int {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to get free port")
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}
