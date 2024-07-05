package roast_test

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	roast "github.com/thomasdesr/roast"
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
