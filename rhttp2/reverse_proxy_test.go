package rhttp2

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast"
)

func TestReverseProxyHasHeaders(t *testing.T) {
	roleARN, err := arn.Parse("arn:aws:iam::123456789012:role/test-role")
	if err != nil {
		t.Fatalf("failed to parse role ARN: %v", err)
	}
	// Add peer metadata to the request context
	ctx := roast.AttachPeerMetadataToContext(context.Background(), &roast.Conn{
		Peer: &roast.PeerMetadata{
			Role:      roleARN,
			AccountID: roleARN.AccountID,
		},
	})

	// Create a test request
	req := httptest.NewRequestWithContext(ctx, "GET", "/test", nil)

	// Create a test server that will receive a forwarded request
	receivedHeaders := make(chan http.Header, 1)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders <- r.Header
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	// Parse the test server URL
	targetURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("failed to parse test server URL: %v", err)
	}

	// Serve the request through the proxy
	ReverseProxyHandler(targetURL).ServeHTTP(httptest.NewRecorder(), req)

	// Get the headers that were received by the test server
	headers := <-receivedHeaders

	// Verify the headers were correctly forwarded
	if got := headers.Get(roastHTTPPeerRoleARNHeader); got != roleARN.String() {
		t.Errorf("expected role ARN header %q, got %q", roleARN.String(), got)
	}
	if got := headers.Get(roastHTTPPeerAWSAccountIDHeader); got != roleARN.AccountID {
		t.Errorf("expected account ID header %q, got %q", roleARN.AccountID, got)
	}

	// Verify the peer metadata JSON header exists and can be parsed
	peerMetadata, err := ParsePeerMetadataFromRequest(&http.Request{Header: headers})
	if err != nil {
		t.Fatalf("failed to parse peer metadata: %v", err)
	}
	if peerMetadata.Role != roleARN {
		t.Errorf("expected role %v, got %v", roleARN, peerMetadata.Role)
	}
	if peerMetadata.AccountID != roleARN.AccountID {
		t.Errorf("expected account ID %q, got %q", roleARN.AccountID, peerMetadata.AccountID)
	}
}
