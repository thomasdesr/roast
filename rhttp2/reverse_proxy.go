package rhttp2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast"
	"github.com/thomasdesr/roast/internal/errorutil"
)

// ReverseProxy represents a Roast-terminating HTTP reverse proxy server that
// forwards requests to a target URL while preserving and passing through peer
// metadata information.
//
// The proxy, like any Roast server, will only allow clients that have completed
// a Roast handshake and have a role that matches one of the allowed roles.
type ReverseProxy struct {
	*Server

	// ReverseProxy is the underlying httputil.ReverseProxy that handles the actual
	// request forwarding and peer metadata extraction.
	ReverseProxy *httputil.ReverseProxy

	// Handler is a convenient re-export of the inner http.Server's Handler to
	// allow wrapping if needed. It is intentionally a pointer to an interface
	// so that you can mutate the very nested field.
	Handler *http.Handler
}

// NewReverseProxy creates a new reverse proxy that forwards requests to the
// target URL while passing through peer information as HTTP headers.
//
// The proxy like any roast server will only allow requests from peers with
// roles matching the provided allowedRoles list.
func NewReverseProxy(target *url.URL, allowedRoles []arn.ARN) (*ReverseProxy, error) {
	proxy := ReverseProxyHandler(target)

	// Create the base server w/ our ReverseProxyHandler
	srv := &Server{
		Server: &http.Server{
			Handler: proxy,
		},

		AllowedRoles: allowedRoles,
	}

	return &ReverseProxy{
		Server:       srv,
		ReverseProxy: proxy,
	}, nil
}

// ReverseProxyHandler creates a new httputil.ReverseProxy configured to
// extracts peer information from the request context and adds it as HTTP
// headers in the forwarded request.
func ReverseProxyHandler(target *url.URL) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// Get peer information from context
			peer := roast.PeerMetadataFromContext(r.In.Context())

			// Add peer information as headers
			setRoastHTTPPeerMetadataHeaders(r.Out, peer)

			// Set the URL to the target URL
			r.SetURL(target)
			// But preserve the original hostname
			r.Out.Host = r.In.Host
		},
	}
}

// roastHTTPPeerMetadataIdentityHeader is the HTTP header key used to store peer
// metadata information in forwarded requests.
const (
	roastHTTPPeerMetadataIdentityHeader = "X-Roast-Peer-Identity"
	roastHTTPPeerRoleARNHeader          = "X-Roast-Peer-Role-ARN"
	roastHTTPPeerAWSAccountIDHeader     = "X-Roast-Peer-AWS-Account-ID"
)

// ParsePeerMetadataFromRequest extracts peer metadata information from an HTTP
// request. It looks for the X-Roast-Peer-Identity header and attempts to
// unmarshal its JSON contents into a PeerMetadata struct.
//
// Returns an error if the header is missing or if the JSON cannot be
// unmarshaled.
func ParsePeerMetadataFromRequest(r *http.Request) (roast.PeerMetadata, error) {
	peerMetadata := roast.PeerMetadata{}

	peerMetadataJSON := r.Header.Get(roastHTTPPeerMetadataIdentityHeader)
	if peerMetadataJSON == "" {
		return roast.PeerMetadata{}, fmt.Errorf("missing peer metadata header")
	}

	if err := json.Unmarshal([]byte(peerMetadataJSON), &peerMetadata); err != nil {
		return roast.PeerMetadata{}, errorutil.Wrap(err, "failed to unmarshal peer metadata")
	}

	return peerMetadata, nil
}

// setRoastHTTPPeerMetadataHeaders adds peer metadata information to the HTTP
// request headers. It marshals the peer metadata to JSON and sets it in the
// X-Roast-Peer-Identity header.
//
// Panics if the peer metadata cannot be marshaled to JSON, as this indicates a
// serious internal error that should not occur with valid peer metadata.
func setRoastHTTPPeerMetadataHeaders(r *http.Request, peerMetadata *roast.PeerMetadata) {
	peerMetadataJSON, err := json.Marshal(peerMetadata)
	if err != nil {
		// We use Panic here because if we can't marshal our own data, something
		// is very wrong, and because this will be being called by the Rewrite
		// function of the httputil.ReverseProxy, which doesn't have a good way
		// to report errors
		panic(err)
	}

	r.Header.Set(roastHTTPPeerMetadataIdentityHeader, string(peerMetadataJSON))
	r.Header.Set(roastHTTPPeerRoleARNHeader, peerMetadata.Role.String())
	r.Header.Set(roastHTTPPeerAWSAccountIDHeader, peerMetadata.AccountID)
}
