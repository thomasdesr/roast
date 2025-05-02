package roast

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/gcisigner/source_verifiers"
	"github.com/thomasdesr/roast/internal/errorutil"
)

type Dialer struct {
	Dialer func(ctx context.Context, network, address string) (net.Conn, error)

	Signer   gcisigner.Signer
	Verifier gcisigner.Verifier
}

func NewDialer(allowedServerRoles []arn.ARN, opts ...Option[Dialer]) (*Dialer, error) {
	d := &Dialer{
		Dialer: (&net.Dialer{}).DialContext,
	}

	for _, opt := range opts {
		if err := opt(d); err != nil {
			return nil, errorutil.Wrap(err, "failed to apply dialer option")
		}
	}

	// Fallback to defaults if not set
	if d.Signer == nil {
		config, err := config.LoadDefaultConfig(context.Background())
		if err != nil {
			return nil, errorutil.Wrap(err, "failed to load default AWS config")
		}

		if err := WithAWSConfig[Dialer](&config)(d); err != nil {
			return nil, errorutil.Wrap(err, "failed to create signer from default config")
		}
	}

	if d.Verifier == nil {
		serverRoles, err := parseRolesToSources(allowedServerRoles)
		if err != nil {
			return nil, errorutil.Wrap(err, "failed to parse server roles")
		}

		d.Verifier = gcisigner.NewVerifier(source_verifiers.MatchesAny(serverRoles), nil)
	}

	return d, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer(ctx, network, address)
	if err != nil {
		return nil, err
	}

	c := &Conn{
		Conn:          conn,
		handshakeFunc: d.UpgradeClientConn,
	}

	// Proactively try to trigger a handshake. This is a Dial so ensure this
	// happens before we give the connection back to the caller.
	if err := c.HandshakeContext(ctx); err != nil {
		return nil, errorutil.Wrap(err, "failed to complete a roast handshake")
	}

	return c, nil
}

func (d *Dialer) UpgradeClientConn(ctx context.Context, c net.Conn) (*tls.Conn, *PeerMetadata, error) {
	tlsConf, peerMetadata, err := clientHandshake(ctx, c, d.Signer, d.Verifier)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to complete a roast handshake")
	}

	tlsConn := tls.Client(c, tlsConf)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to complete a tls handshake")
	}

	return tlsConn, peerMetadata, nil
}
