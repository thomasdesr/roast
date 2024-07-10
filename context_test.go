package roast_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	roast "github.com/thomasdesr/roast"
	"golang.org/x/sync/errgroup"
)

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func TestContext(t *testing.T) {
	conn := &roast.Conn{
		Peer: &roast.PeerMetadata{
			Role: must(arn.Parse("arn:aws:sts::1234567890:assumed-role/ClientRole")),
		},
	}

	ctx := roast.AttachPeerMetadataToContext(context.Background(), conn)

	peer := roast.PeerMetadataFromContext(ctx)
	if peer == nil {
		t.Fatal("expected peer metadata")
	}

	if peer.Role.Resource != "assumed-role/ClientRole" {
		t.Fatalf("unexpected role: %v", peer.Role)
	}
}

func TestContextOnPair(t *testing.T) {
	l, d := localValidListenerAndDialer(t)

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		defer conn.Close()

		// Ensure the handshake has completed (server handshake is async before a read/write)
		if err := conn.(*roast.Conn).HandshakeContext(ctx); err != nil {
			t.Error(err)
		}

		ctx := roast.AttachPeerMetadataToContext(ctx, conn)
		peer := roast.PeerMetadataFromContext(ctx)
		if peer == nil {
			return fmt.Errorf("expected peer metadata after Accept & Attach")
		}

		return nil
	})

	g.Go(func() error {
		conn, err := d.DialContext(ctx, l.Addr().Network(), l.Addr().String())
		if err != nil {
			t.Error(err)
		}
		defer conn.Close()

		ctx := roast.AttachPeerMetadataToContext(ctx, conn)
		peer := roast.PeerMetadataFromContext(ctx)
		if peer == nil {
			t.Error("expected peer metadata after Dial & Attach")
		}

		return nil
	})

	if err := g.Wait(); err != nil {
		t.Error(err)
	}
}
