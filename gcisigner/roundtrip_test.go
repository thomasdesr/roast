package gcisigner_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/gcisigner/source_verifiers"
	"github.com/thomasdesr/roast/internal/testutils"
)

func TestLiveRoundTrip(t *testing.T) {
	cfg := testutils.AWSConfigIfHasCredentials(t)

	localRole, err := testutils.GetLocalRole(context.Background(), sts.NewFromConfig(cfg))
	if err != nil {
		t.Fatalf("failed to get local role: %v", err)
	}

	signer, err := gcisigner.NewSigner(cfg.Region, cfg.Credentials)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("Hello World!")
	signedMessage, err := signer.Sign(context.Background(), payload)
	if err != nil {
		t.Fatal(err)
	}

	debugPrintSignedMessage(t, signedMessage)

	verifier := gcisigner.NewVerifier(source_verifiers.MatchesRoles([]arn.ARN{localRole}), nil)

	verifiedMessage, err := verifier.Verify(context.Background(), (*gcisigner.UnverifiedMessage)(signedMessage))
	if err != nil {
		t.Fatal(err)
	}

	if string(verifiedMessage.Payload) != string(payload) {
		t.Errorf("expected payload %q, got %q", payload, verifiedMessage.Payload)
	}

	t.Log("Success!")
}

func debugPrintSignedMessage(t testing.TB, signedMessage *gcisigner.SignedMessage) {
	t.Helper()

	body, err := json.Marshal(signedMessage)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Signed message: %s", body)
}
