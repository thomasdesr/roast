package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/rhttp2"
)

func main() {
	cfg, err := parseFlags()
	if err != nil {
		log.Fatalf("Failed to parse flags: %v", err)
	}

	// Create the reverse proxy
	proxy, err := createReverseProxy(cfg)
	if err != nil {
		log.Fatalf("Failed to create reverse proxy: %v", err)
	}

	// Start listening
	listener, err := net.Listen("tcp", cfg.bindAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", cfg.bindAddr, err)
	}

	log.Printf("Starting reverse proxy on %s, forwarding to %s for roles %s", cfg.bindAddr, cfg.targetURL, cfg.allowedRoles)

	if err := proxy.Serve(listener); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}

// createReverseProxy creates a reverse proxy configured for the target scheme.
// It handles setting up the appropriate transport and request handling based on
// whether we're proxying to an HTTP endpoint or a Unix socket.
func createReverseProxy(cfg *config) (*rhttp2.ReverseProxy, error) {
	switch cfg.targetURL.Scheme {
	case "http", "https":
		return httpTargetProxy(cfg.targetURL, cfg.allowedRoles)
	case "unix", "http+unix":
		return unixTargetProxy(cfg.targetURL, cfg.allowedRoles)
	default:
		return nil, fmt.Errorf("unsupported scheme %q", cfg.targetURL.Scheme)
	}
}

// httpTargetProxy creates and configures a proxy for HTTP/HTTPS targets
func httpTargetProxy(targetURL *url.URL, allowedRoles []arn.ARN) (*rhttp2.ReverseProxy, error) {
	proxy, err := rhttp2.NewReverseProxy(targetURL, allowedRoles)
	if err != nil {
		return nil, fmt.Errorf("failed to create reverse proxy: %v", err)
	}

	// Create a transport that handles TCP connections
	proxy.ReverseProxy.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// We don't use any of the arguments to net.Dial, because we know
			// where we're going, and we don't want the reverse proxy's choices
			// to affect that.
			return net.Dial("tcp", targetURL.Host)
		},
	}

	return proxy, nil
}

// unixTargetProxy creates and configures a proxy for Unix socket targets
func unixTargetProxy(targetURL *url.URL, allowedRoles []arn.ARN) (*rhttp2.ReverseProxy, error) {
	// Create a new URL that httputil.ReverseProxy will accept for speaking
	// "http" over a Unix socket
	httpURL := &url.URL{
		Scheme: "http",
		Host:   targetURL.EscapedPath(),
	}

	// Create the base reverse proxy with the HTTP URL
	proxy, err := rhttp2.NewReverseProxy(httpURL, allowedRoles)
	if err != nil {
		return nil, fmt.Errorf("failed to create reverse proxy: %v", err)
	}

	// Create a transport that handles Unix socket connections
	proxy.ReverseProxy.Transport = &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			// We don't use any of the arguments to net.Dial, because we know
			// where we're going, and we don't want the reverse proxy's choices
			// to affect that.
			return net.Dial("unix", targetURL.Path)
		},
	}

	return proxy, nil
}
