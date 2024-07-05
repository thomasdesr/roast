package roast

import (
	"context"
	"crypto/tls"
	"net"
)

type (
	peerMetadataContextKey struct{}
)

var (
	peerMetadataKeyInstance = peerMetadataContextKey{}
)

func AttachPeerMetadataToContext(ctx context.Context, c net.Conn) context.Context {
	rConn := maybeGetRoastConn(c)

	if rConn == nil {
		return ctx
	}

	return context.WithValue(ctx, peerMetadataKeyInstance, rConn.Peer)
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
	rConn, ok := ctx.Value(peerMetadataKeyInstance).(*PeerMetadata)
	if !ok {
		return nil
	}

	return rConn
}
