package roast_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	roast "github.com/thomasdesr/roast"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/gcisigner/awsapi"
	"github.com/thomasdesr/roast/internal/errorutil"
	"github.com/thomasdesr/roast/internal/testutils"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/sync/errgroup"
)

func TestRoundTrip(t *testing.T) {
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

	// And send the hello world through!
	runRoundTrip(context.Background(), t, tlsListener, tlsDialer)
	t.Log("success")
}

func TestRoundTripWithRealCredentials(t *testing.T) {
	ctx := context.Background()
	if !testutils.HasAWSCredentials(ctx) {
		t.Skip("no AWS credentials, skipping")
	}

	config, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		t.Fatal(err)
	}

	localARN, err := testutils.GetLocalRole(ctx, sts.NewFromConfig(config))
	if err != nil {
		t.Fatal(err)
	}

	listener, dialCtx := testutils.ListenerDialer(t)

	// Construct our tls listener and dialer
	tlsDialer, err := roast.NewDialer([]arn.ARN{localARN})
	if err != nil {
		t.Fatal(err)
	}
	tlsDialer.Dialer = dialCtx

	tlsListener, err := roast.NewListener(listener, []arn.ARN{localARN})
	if err != nil {
		t.Fatal(err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	runRoundTrip(ctxWithTimeout, t, tlsListener, tlsDialer)
}

func runRoundTrip(ctx context.Context, t *testing.T, listener *roast.Listener, dialer *roast.Dialer) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error { // Server side
		c, err := listener.Accept()
		if err != nil {
			return errorutil.Wrap(err, "accept failed")
		}
		defer c.Close()

		// Server copies any data it recieves back to the client
		if _, err := io.Copy(c, c); err != nil && err != io.EOF {
			return errorutil.Wrap(err, "copy failed")
		}

		return nil
	})

	g.Go(func() error { // Client side
		c, err := dialer.DialContext(ctx, listener.Addr().Network(), listener.Addr().String())
		if err != nil {
			return errorutil.Wrap(err, "dial failed")
		}
		defer c.Close()

		go func() {
			<-ctx.Done()
			c.Close()
		}()

		if err := testConnRoundTrip(t, c); err != nil {
			errorutil.Wrap(err, "client: round trip failed")
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
}

func testConnRoundTrip(t *testing.T, conn net.Conn) error {
	var g errgroup.Group

	messageToRoundTrip := []byte("hello world")

	// Write some data into the pipe
	g.Go(func() error {
		if _, err := conn.Write(messageToRoundTrip); err != nil {
			return errorutil.Wrap(err, "write failed")
		}
		return nil
	})

	// Ensure the data is comes back out the other end
	g.Go(func() error {
		hello := make([]byte, 1024)
		n, err := conn.Read(hello)
		if err != nil {
			return errorutil.Wrap(err, "read failed")
		}

		hello = hello[:n]
		if !bytes.Equal(hello, messageToRoundTrip) {
			return fmt.Errorf("read: unexpected message: %q", hello)
		}

		t.Log("read success:", string(hello))

		return nil
	})

	return g.Wait()
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
