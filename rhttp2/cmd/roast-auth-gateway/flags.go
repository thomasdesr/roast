package main

import (
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/internal/errorutil"
)

var (
	bindAddr     = flag.String("bind", getEnvWithDefault("ROAST_BIND", ":8443"), "Address to bind the reverse proxy to")
	targetAddr   = flag.String("target", getEnvWithDefault("ROAST_TARGET", "http://localhost:8080"), "Target address to forward traffic to (http:// or http+unix://)")
	allowedRoles = flag.String("roles", getEnvWithDefault("ROAST_PEER_ROLES", ""), "Comma-separated list of allowed peer roles")
)

// getEnvWithDefault returns the value of the environment variable if set, otherwise returns the default value
func getEnvWithDefault(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// config holds the parsed configuration for the reverse proxy
type config struct {
	bindAddr     string
	targetURL    *url.URL
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
				return nil, errorutil.Wrapf(err, "invalid role ARN %q", roleStr)
			}
			roles = append(roles, role)
		}
	}

	// Parse target URL
	targetURL, err := url.Parse(*targetAddr)
	if err != nil {
		return nil, errorutil.Wrapf(err, "invalid target URL %q", *targetAddr)
	}

	// Validate scheme and path
	switch targetURL.Scheme {
	case "http", "https":
		// HTTP/HTTPS URLs are fine as is
	case "unix", "http+unix":
		// For Unix sockets, validate the path
		if targetURL.Path == "" {
			return nil, fmt.Errorf("unix socket path cannot be empty")
		}

		// Ensure path is absolute
		if !filepath.IsAbs(targetURL.Path) {
			abs, err := filepath.Abs(targetURL.Path)
			if err != nil {
				return nil, errorutil.Wrapf(err, "failed to get absolute path for %q", targetURL.Path)
			}
			targetURL.Path = abs
		}
		// Check if socket exists and is accessible
		if _, err := os.Stat(targetURL.Path); err != nil {
			return nil, errorutil.Wrapf(err, "unix socket path %q is not accessible", targetURL.Path)
		}
	default:
		return nil, fmt.Errorf("unsupported target scheme %q, must be http://, https://, or unix://", targetURL.Scheme)
	}

	return &config{
		bindAddr:     *bindAddr,
		targetURL:    targetURL,
		allowedRoles: roles,
	}, nil
}
