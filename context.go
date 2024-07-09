package roast

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

type PeerMetadata struct {
	AccountID string
	Role      arn.ARN
}

type (
	peerConnContextKey struct{}
)

var (
	peerConnContextKeyInstance = peerConnContextKey{}
)

func AttachPeerMetadataToContext(ctx context.Context, c net.Conn) context.Context {
	rConn := maybeGetRoastConn(c)

	if rConn == nil {
		return ctx
	}

	return context.WithValue(ctx, peerConnContextKeyInstance, rConn)
}

func maybeGetRoastConn(conn net.Conn) *Conn {
	switch c := conn.(type) {
	case *Conn:
		return c
	case *tls.Conn:
		rConn, _ := c.NetConn().(*Conn)
		return rConn
	}

	return nil
}

func PeerMetadataFromContext(ctx context.Context) *PeerMetadata {
	rConn, ok := ctx.Value(peerConnContextKeyInstance).(*Conn)
	if !ok {
		return nil
	}

	return rConn.Peer
}
