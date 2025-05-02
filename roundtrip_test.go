package roast_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	roast "github.com/thomasdesr/roast"
	"github.com/thomasdesr/roast/internal/errorutil"
	"github.com/thomasdesr/roast/internal/testutils"
	"golang.org/x/sync/errgroup"
)

func TestRoundTripWithRealCredentials(t *testing.T) {
	ctx := context.Background()

	config := testutils.AWSConfigIfHasCredentials(t)

	localARN, err := testutils.GetLocalRole(ctx, sts.NewFromConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Using local ARN: %v", localARN)

	listener, dialCtx := testutils.ListenerDialer(t)

	// Construct our tls listener and dialer
	tlsDialer, err := roast.NewDialer([]arn.ARN{localARN.ARN()})
	if err != nil {
		t.Fatal(err)
	}
	tlsDialer.Dialer = dialCtx

	tlsListener, err := roast.NewListener(listener, []arn.ARN{localARN.ARN()})
	if err != nil {
		t.Fatal(err)
	}

	ctxWithTimeout, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	// And send the hello world through!
	runRoundTrip(ctxWithTimeout, t, tlsListener, tlsDialer.DialContext)
	t.Log("success")
}

func TestRoundTrip(t *testing.T) {
	l, d := localValidListenerAndDialer(t)

	// And send the hello world through!
	runRoundTrip(context.Background(), t, l, d.DialContext)
	t.Log("success")
}

func runRoundTrip(ctx context.Context, t *testing.T, listener net.Listener, dialCtx func(context.Context, string, string) (net.Conn, error)) {
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
		c, err := dialCtx(ctx, listener.Addr().Network(), listener.Addr().String())
		if err != nil {
			return errorutil.Wrap(err, "dial failed")
		}
		defer c.Close()

		messageToRoundTrip := []byte("hello world")

		// Write some data into the conn so it'll get echo'd back to us
		g.Go(func() error {
			if _, err := c.Write(messageToRoundTrip); err != nil {
				return errorutil.Wrap(err, "write failed")
			}
			return nil
		})

		// Ensure the data is comes back
		hello := make([]byte, 1024)
		n, err := c.Read(hello)
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

	if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
