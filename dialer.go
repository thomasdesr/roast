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

type Dialer struct {
	Dialer func(ctx context.Context, network, address string) (net.Conn, error)

	Signer   gcisigner.Signer
	Verifier gcisigner.Verifier
}

func NewDialer(allowedServerRoles []arn.ARN) (*Dialer, error) {
	config, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		return nil, err
	}

	signer, err := gcisigner.NewSigner(config.Region, config.Credentials)
	if err != nil {
		return nil, errorutil.Wrap(err, "failed to create signer")
	}

	verifier := gcisigner.NewVerifier(assumedRoleInRoles(allowedServerRoles), nil)

	return &Dialer{
		Dialer: (&net.Dialer{}).DialContext,

		Signer:   signer,
		Verifier: verifier,
	}, nil
}

func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.Dialer(ctx, network, address)
	if err != nil {
		return nil, err
	}

	return d.UpgradeClientConn(ctx, conn)
}

func (d *Dialer) UpgradeClientConn(ctx context.Context, c net.Conn) (*tls.Conn, error) {
	tlsConf, err := clientHandshake(ctx, c, d.Signer, d.Verifier)
	if err != nil {
		return nil, errorutil.Wrap(err, "failed to complete a handshake")
	}

	tlsConn := tls.Client(c, tlsConf)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, errorutil.Wrap(err, "failed to complete a handshake")
	}

	return tlsConn, nil
}
