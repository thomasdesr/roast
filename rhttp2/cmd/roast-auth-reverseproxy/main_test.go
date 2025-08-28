package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/thomasdesr/roast/internal/testutils"
	"github.com/thomasdesr/roast/rhttp2"
)

func TestReverseProxyE2E(t *testing.T) {
	cfg := testutils.AWSConfigIfHasCredentials(t)
	localRole, err := testutils.GetLocalRole(context.Background(), sts.NewFromConfig(cfg))
	if err != nil {
		t.Fatalf("failed to get local role: %v", err)
	}
	localRoleARN := localRole.ARN()

	// Create a client with the role ARN
	client, err := rhttp2.Client([]arn.ARN{localRoleARN})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	testCases := []struct {
		name        string
		setupTarget func(t *testing.T) (*url.URL, func())
		wantStatus  int
	}{
		{
			name:        "HTTP target",
			setupTarget: newHTTPTestServer,
			wantStatus:  http.StatusOK,
		},
		{
			name:        "Unix socket target",
			setupTarget: newUnixTestServer,
			wantStatus:  http.StatusOK,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Setup downstream target server (what the proxy will be proxying to)
			targetURL, cleanup := tc.setupTarget(t)
			t.Cleanup(cleanup)

			// Setup the auth proxy
			proxy, proxyURL := setupProxy(t, targetURL, []arn.ARN{localRoleARN})
			t.Cleanup(func() { proxy.Server.Server.Shutdown(context.Background()) })

			// Make our test request
			resp, err := client.Get(proxyURL.String() + "/test")
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}

			t.Log("resp", resp.StatusCode, resp.ContentLength, string(body))

			if resp.StatusCode != tc.wantStatus {
				t.Errorf("expected status %d, got %d", tc.wantStatus, resp.StatusCode)
			}
		})
	}
}

// setupProxy creates and starts our roast auth proxy
func setupProxy(t *testing.T, targetURL *url.URL, allowedRoles []arn.ARN) (*rhttp2.ReverseProxy, *url.URL) {
	// Create proxy configuration
	cfg := &config{
		targetURL:    targetURL,
		allowedRoles: allowedRoles,
		bindAddr:     "localhost:0", // Use port 0 for testing
	}

	// Start the proxy server
	listener, err := net.Listen("tcp", cfg.bindAddr)
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	// Create the proxy
	proxy, err := createReverseProxy(cfg)
	if err != nil {
		t.Fatalf("failed to create reverse proxy: %v", err)
	}
	t.Cleanup(func() { proxy.Server.Server.Shutdown(context.Background()) })

	// Start the proxy in a goroutine
	go proxy.Serve(listener)

	// Create proxy URL
	addr := listener.Addr().String()
	proxyURL, err := url.Parse("https://" + addr)
	if err != nil {
		t.Fatalf("failed to parse proxy URL: %v", err)
	}

	return proxy, proxyURL
}

// newHTTPTestServer creates an test server that listens on a local tcp socket.
// This is one of two forms of test servers that the roast proxy can connect to,
// specifically the HTTP form that listens on a TCP port.
func newHTTPTestServer(t *testing.T) (*url.URL, func()) {
	return newTestServer(t, func() (net.Listener, *url.URL) {
		listener, err := net.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatalf("failed to create listener: %v", err)
		}

		u, err := url.Parse("http://" + listener.Addr().String())
		if err != nil {
			t.Fatalf("failed to parse server URL: %v", err)
		}

		return listener, u
	})
}

// newUnixTestServer creates a test server that listens on a Unix socket.
// This is one of two forms of test servers that the roast proxy can connect to,
// specifically the Unix socket form that listens on a local filesystem socket.
func newUnixTestServer(t *testing.T) (*url.URL, func()) {
	// Sadly need to hard code /tmp, because otherwise a solid chunk
	// of the time on macos this is exceeding the max path length
	// for a unix socket. Come back and fix this if we're ever
	// supporting windows.
	tmpDir, err := os.MkdirTemp("/tmp", "unix-socket-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	socketPath := filepath.Join(tmpDir, "target.sock")

	return newTestServer(t, func() (net.Listener, *url.URL) {
		// Create the listener
		listener, err := net.Listen("unix", socketPath)
		if err != nil {
			t.Fatalf("failed to create Unix socket: %v", err)
		}

		u, err := url.Parse("http+unix://" + socketPath)
		if err != nil {
			t.Fatalf("failed to parse Unix socket URL: %v", err)
		}

		return listener, u
	})
}

// newTestServer creates the protected http listening server that the roast
// proxy will be protecting and proxying to.
//
// It verifies headers and parses peer metadata from the request to ensure we
// roasted the connection correctly.
func newTestServer(t *testing.T, createListener func() (net.Listener, *url.URL)) (*url.URL, func()) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := rhttp2.ParsePeerMetadataFromRequest(r)
		if err != nil {
			t.Errorf("failed to parse peer metadata: %v", err)
			http.Error(w, "missing peer metadata", http.StatusTeapot)
			return
		}

		t.Log("request from peer received", peer.Role)
		fmt.Fprintf(w, "peer: %+v", peer)
	})

	// Create the listener and get its URL
	listener, serverURL := createListener()

	// Create and start the server
	srv := httptest.NewUnstartedServer(handler)
	srv.Listener = listener
	srv.Start()

	return serverURL, func() {
		srv.Close()
		listener.Close()
	}
}
