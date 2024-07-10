package roast

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/internal/errorutil"
)

type Listener struct {
	net.Listener

	Signer   gcisigner.Signer
	Verifier gcisigner.Verifier
}

func NewListener(l net.Listener, allowedClientRoles []arn.ARN) (*Listener, error) {
	config, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	signer, err := gcisigner.NewSigner(config.Region, config.Credentials)
	if err != nil {
		return nil, errorutil.Wrap(err, "failed to create signer")
	}

	verifier := gcisigner.NewVerifier(assumedRoleInRoles(allowedClientRoles), nil)

	return &Listener{
		Listener: l,

		Signer:   signer,
		Verifier: verifier,
	}, nil
}

func (l *Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	c := &Conn{
		Conn:          conn,
		handshakeFunc: l.UpgradeServerConn,
	}

	// Proactively trigger a handshake, and ignore any errors (they'll be
	// returned on any read/write).
	go c.HandshakeContext(context.Background())

	return c, nil
}

func (l *Listener) UpgradeServerConn(ctx context.Context, c net.Conn) (*tls.Conn, *PeerMetadata, error) {
	tlsConf, peerMetadata, err := serverHandshake(ctx, c, l.Signer, l.Verifier)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to complete a roast handshake")
	}

	tlsConn := tls.Server(c, tlsConf)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to complete a tls handshake")
	}

	return tlsConn, peerMetadata, nil
}
