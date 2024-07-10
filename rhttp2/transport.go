package rhttp2

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast"
	"github.com/thomasdesr/roast/internal/errorutil"
	"golang.org/x/net/http2"
)

func Transport(allowedRoles []arn.ARN) (*http2.Transport, error) {
	d, err := roast.NewDialer(allowedRoles)
	if err != nil {
		return nil, errorutil.Wrap(err, "failed to create dialer")
	}

	return &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, _ *tls.Config) (net.Conn, error) {
			return d.DialContext(ctx, network, addr)
		},
	}, nil
}
