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
	ctx = testutils.WithHTTPTrace(t, ctx)

	config := testutils.AWSConfigIfHasCredentials(t)

	localARN, err := testutils.GetLocalRole(ctx, sts.NewFromConfig(config))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("Using local ARN: %v", localARN)

	rawListener, rawDialer := testutils.ListenerDialer(t)

	// Construct our tls listener and dialer
	rd, err := roast.NewDialer([]arn.ARN{localARN.ARN()})
	if err != nil {
		t.Fatal(err)
	}
	rd.Dialer = rawDialer

	t.Log("Dialer:", rd)

	rl, err := roast.NewListener(rawListener, []arn.ARN{localARN.ARN()})
	if err != nil {
		t.Fatal(err)
	}

	t.Log("Listener:", rl)

	// And send the hello world through!
	runRoundTrip(ctx, t, rl, rd.DialContext)
	t.Log("success")
}

func TestRoundTrip(t *testing.T) {
	l, d := localValidListenerAndDialer(t)

	// And send the hello world through!
	runRoundTrip(context.Background(), t, l, d.DialContext)
	t.Log("success")
}

func runRoundTrip(ctx context.Context, t *testing.T, listener net.Listener, dialCtx func(context.Context, string, string) (net.Conn, error)) {
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	var g errgroup.Group

	g.Go(func() error { // Server side
		t.Log("Server Side: Waiting for connection")
		c, err := listener.Accept()
		if err != nil {
			return errorutil.Wrap(err, "accept failed")
		}
		defer c.Close()
		// defer context.AfterFunc(ctx, func() { t.Log("Context canceled, closing server side of the connection", c.Close()) })

		// Server copies any data it receives back to the client
		t.Log("Server side: copying data")
		if _, err := io.Copy(c, c); err != nil && err != io.EOF {
			return errorutil.Wrap(err, "copy failed")
		}

		t.Log("Server side: copy complete, exiting cleanly")

		return nil
	})

	g.Go(func() error { // Client side
		t.Log("Client Side: Opening connection")
		c, err := dialCtx(ctx, listener.Addr().Network(), listener.Addr().String())
		if err != nil {
			return errorutil.Wrap(err, "dial failed")
		}
		defer c.Close()
		// defer context.AfterFunc(ctx, func() { t.Log("Context canceled, closing client side of connection", c.Close()) })

		messageToRoundTrip := []byte("hello world")

		// Write some data into the conn so it'll get echo'd back to us
		g.Go(func() error {
			t.Log("Client Side: Writing data")
			if _, err := c.Write(messageToRoundTrip); err != nil {
				return errorutil.Wrap(err, "write failed")
			}
			t.Log("Client Side: Writing complete")
			return nil
		})

		// Ensure the data is comes back
		t.Log("Client Side: Reading data")
		hello := make([]byte, 1024)
		n, err := io.ReadAtLeast(c, hello, len(messageToRoundTrip))
		if err != nil {
			return errorutil.Wrap(err, "read failed")
		}

		hello = hello[:n]
		if !bytes.Equal(hello, messageToRoundTrip) {
			return fmt.Errorf("read: unexpected message: %q", hello)
		}

		t.Log("Client Side: Read success:", string(hello))

		// Note this close is pretty load bearing, the server isn't ever gonna give up as long as the client is connected
		t.Log("Client Side: Read complete, closing client side of connection to trigger server side close")
		if err := c.Close(); err != nil {
			t.Logf("Failed to close client side connection: %v", err)
		}

		t.Log("Client Side: roundtrip complete, exitingly cleanly")

		return nil
	})

	if err := g.Wait(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}
