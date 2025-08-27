package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/elazarl/goproxy"
	"github.com/thomasdesr/roast/rhttp2"
)

var (
	socketPath   = flag.String("socket", getEnvWithDefault("ROAST_SOCKET", os.ExpandEnv("$HOME/.roast/proxy.sock")), "Unix socket path to listen on")
	allowedRoles = flag.String("roles", getEnvWithDefault("ROAST_PEER_ROLES", ""), "Comma-separated list of allowed peer roles")
)

// getEnvWithDefault returns the value of the environment variable if set, otherwise returns the default value
func getEnvWithDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// config holds the parsed configuration for the forward proxy
type config struct {
	socketPath   string
	allowedRoles []arn.ARN
}

// parseFlags parses command line flags and returns a config struct
func parseFlags() (*config, error) {
	flag.Parse()

	// Parse allowed roles
	var roles []arn.ARN
	if *allowedRoles != "" {
		for _, roleStr := range strings.Split(*allowedRoles, ",") {
			roleStr = strings.TrimSpace(roleStr)
			role, err := arn.Parse(roleStr)
			if err != nil {
				return nil, fmt.Errorf("invalid role ARN %q: %v", roleStr, err)
			}
			roles = append(roles, role)
		}
	}

	// Ensure socket path is absolute
	if !filepath.IsAbs(*socketPath) {
		abs, err := filepath.Abs(*socketPath)
		if err != nil {
			return nil, fmt.Errorf("failed to get absolute path for %q: %v", *socketPath, err)
		}
		*socketPath = abs
	}

	return &config{
		socketPath:   *socketPath,
		allowedRoles: roles,
	}, nil
}

func main() {
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("Failed to parse flags: %v", err)
	}

	// Use Roast for outbound connections
	tr, err := rhttp2.Transport(cfg.allowedRoles)
	if err != nil {
		log.Fatalf("Failed to create transport: %v", err)
	}

	// Create the forward proxy server
	proxy := goproxy.NewProxyHttpServer()
	proxy.Verbose = true

	// Regardless of what the URL passed to us said, going forward it'll be over
	// HTTPS (which is what roast is doing and also what `http2.Transport` requires`)
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		req.URL.Scheme = "https"
		return req, nil
	})

	// For normal HTTP PROXY requests, use the roast-ified RoundTripper
	proxy.OnRequest().DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
		ctx.RoundTripper = goproxy.RoundTripperFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Response, error) {
			return tr.RoundTrip(req)
		})

		return req, nil
	})

	// For HTTP PROXY CONNECT requests, ensure we use the Roast dialer for that
	// connection
	proxy.ConnectDialWithReq = func(req *http.Request, network, addr string) (net.Conn, error) {
		return tr.DialTLSContext(req.Context(), network, addr, nil)
	}

	// Remove existing socket if it exists
	if err := os.RemoveAll(cfg.socketPath); err != nil {
		log.Fatalf("Failed to remove existing socket: %v", err)
	}

	// Create the directory for the socket if it doesn't exist
	socketDir := filepath.Dir(cfg.socketPath)
	if err := os.MkdirAll(socketDir, 0700); err != nil {
		log.Fatalf("Failed to create socket directory: %v", err)
	}

	// Start listening on the Unix socket
	listener, err := net.Listen("unix", cfg.socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.socketPath, err)
	}

	log.Printf("Starting forward proxy on %s", cfg.socketPath)

	// Start serving
	server := &http.Server{
		Handler: handleRawRequests(proxy),
	}

	if err := server.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// handleRawRequests recognizes requests that aren't speaking HTTP_PROXY
// protocol (e.g. someone is using a Dialer to talk to us) and uses the ambient
// info to figure out where the request should be going to, then modifies the
// request to be HTTP_PROXY protocol friendly and feeds it into the proxy.
func handleRawRequests(proxy *goproxy.ProxyHttpServer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// In HTTP PROXY protocol, the r.RequestURI line (and thus r.URL) will
		// be a full URL and not just a path. So use this logic to detect if the
		// request isa raw or HTTP PROXY request
		if !r.URL.IsAbs() {
			// If its a raw request, then use the Host header to figure out
			// where to forward the request to.
			if r.Host == "" {
				http.Error(w, "Host header is required for non-http_proxy requests", http.StatusBadRequest)
				return
			}

			// This is a normal HTTP request, not an HTTP_PROXY protocol
			// request, fix it to be
			r.URL.Host = r.Host
		}

		proxy.ServeHTTP(w, r)
	})
}
