package roast

import (
	"context"
	"crypto/tls"
	"net"
	"sync"
)

type Conn struct {
	net.Conn

	Peer *PeerMetadata

	handshake     sync.Once
	handshakeFunc func(ctx context.Context, c net.Conn) (*tls.Conn, *PeerMetadata, error)
	handshakeErr  error
}

func (c *Conn) HandshakeContext(ctx context.Context) error {
	c.handshake.Do(func() {
		// Swap out our "Conn" for a TLS conn
		conn, peer, err := c.handshakeFunc(ctx, c.Conn)
		if err != nil {
			c.handshakeErr = err
			return
		}
		c.Conn, c.Peer = conn, peer
	})

	return c.handshakeErr
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}

	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.HandshakeContext(context.Background()); err != nil {
		return 0, err
	}

	return c.Conn.Write(b)
}
