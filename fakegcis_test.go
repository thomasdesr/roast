package roast_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	roast "github.com/thomasdesr/roast"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/gcisigner/awsapi"
	"github.com/thomasdesr/roast/internal/testutils"
	"golang.org/x/crypto/blake2b"
)

func localValidListenerAndDialer(t testing.TB) (*roast.Listener, *roast.Dialer) {
	clientRole := arn.ARN{
		Partition: "aws",
		Service:   "sts",
		Region:    "",
		AccountID: "1234567890",
		Resource:  "assumed-role/ClientRole",
	}
	serverRole := arn.ARN{
		Partition: "aws",
		Service:   "sts",
		Region:    "",
		AccountID: "1234567890",
		Resource:  "assumed-role/ServerRole",
	}

	gcisKey := make([]byte, 32)
	rand.Read(gcisKey)

	listener, dialCtx := testutils.ListenerDialer(t)

	// Create our server
	serverGCIS := &fakeGCIS{
		key: gcisKey,
		callerIdentity: awsapi.GetCallerIdentityResult{
			Arn: clientRole.String(),
		},
	}

	tlsListener, err := roast.NewListener(listener, []arn.ARN{clientRole})
	if err != nil {
		t.Fatal(err)
	}
	tlsListener.Signer, tlsListener.Verifier = serverGCIS, serverGCIS

	// Create our client
	clientGCIS := &fakeGCIS{
		key: gcisKey,
		callerIdentity: awsapi.GetCallerIdentityResult{
			Arn: serverRole.String(),
		},
	}

	tlsDialer, err := roast.NewDialer([]arn.ARN{serverRole})
	if err != nil {
		t.Fatal(err)
	}
	tlsDialer.Signer, tlsDialer.Verifier = clientGCIS, clientGCIS
	tlsDialer.Dialer = dialCtx

	return tlsListener, tlsDialer
}

type fakeGCIS struct {
	key            []byte
	callerIdentity awsapi.GetCallerIdentityResult
}

func (f *fakeGCIS) Sign(ctx context.Context, payload []byte) (*gcisigner.SignedMessage, error) {
	// We're doing this keyed MAC, just to ensure we don't cross-wire GCIS
	// instances
	kmac, _ := blake2b.New256(f.key)
	kmac.Write(payload)

	return &gcisigner.SignedMessage{
		Body:             payload,
		AmzAuthorization: hex.EncodeToString(kmac.Sum(nil)),
		Region:           awsapi.Region_US_WEST_2,
	}, nil
}

func (f *fakeGCIS) Verify(ctx context.Context, msg *gcisigner.UnverifiedMessage) (*gcisigner.VerifiedMessage, error) {
	kmac, _ := blake2b.New256(f.key)
	kmac.Write(msg.Body)

	kmacSig := hex.EncodeToString(kmac.Sum(nil))

	if kmacSig != msg.AmzAuthorization {
		return nil, fmt.Errorf("invalid sig: %q != %q", kmacSig, msg.AmzAuthorization)
	}

	return &gcisigner.VerifiedMessage{
		Payload:        msg.Body,
		CallerIdentity: f.callerIdentity,
		Raw:            (*gcisigner.SignedMessage)(msg),
	}, nil
}
