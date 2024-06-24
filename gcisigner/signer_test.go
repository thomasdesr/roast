package gcisigner_test

import (
	"context"
	"encoding/xml"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/thomasdesr/aws-role-mtls/gcisigner"
	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/awsapi"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	srv := httptest.NewTLSServer(&gciServer{tb: t, responses: []awsapi.GetCallerIdentityResponse{
		{
			GetCallerIdentityResult: awsapi.GetCallerIdentityResult{
				Arn:     "arn:aws:sts::1234567890:assumed-role/RoleName/roleSession",
				UserId:  "AROAEXAMPLE",
				Account: "1234567890",
			},
		},
	}})
	defer srv.Close()

	signer, err := gcisigner.NewSigner("us-west-2", credentials.NewStaticCredentialsProvider("AKIA", "SK", "TK"))
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Hello World!")
	signedMessage, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}

	verifier := gcisigner.NewVerifier(func(*awsapi.GetCallerIdentityResult) (bool, error) {
		return true, nil
	}, httptestServerTransport(srv))

	verifiedMessage, err := verifier.Verify(context.Background(), (*gcisigner.UnverifiedMessage)(signedMessage))
	if err != nil {
		t.Fatal(err)
	}

	if string(verifiedMessage.Payload) != string(payload) {
		t.Errorf("expected payload %q, got %q", payload, verifiedMessage.Payload)
	}
}

type gciServer struct {
	tb        testing.TB
	responses []awsapi.GetCallerIdentityResponse
}

func (gci *gciServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	gci.tb.Helper()

	resp := gci.responses[0]
	gci.responses = gci.responses[1:]

	if err := xml.NewEncoder(w).Encode(&resp); err != nil {
		gci.tb.Fatal("xml encode failed", err)
	}
}

func httptestServerTransport(srv *httptest.Server) *http.Transport {
	lAddr := srv.Listener.Addr()

	tr := srv.Client().Transport.(*http.Transport)

	// Force any conntions from this client to talk to the server
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		// Force connections to our test server
		return net.Dial(lAddr.Network(), lAddr.String())
	}

	if tr.TLSClientConfig != nil {
		// If we've got a TLS config, make sure we're verifying against our local name
		tr.TLSClientConfig.ServerName, _, _ = net.SplitHostPort(lAddr.String())
	}

	return tr
}
