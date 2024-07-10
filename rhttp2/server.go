package rhttp2

import (
	"context"
	"net"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast"
	"golang.org/x/net/http2"
)

type Server struct {
	Server *http.Server

	AllowedRoles []arn.ARN
}

func (s *Server) Serve(l net.Listener) error {
	rl, err := roast.NewListener(l, s.AllowedRoles)
	if err != nil {
		return err
	}

	h2srv := &http2.Server{}
	for {
		conn, err := rl.Accept()
		if err != nil {
			return err
		}

		go h2srv.ServeConn(conn, &http2.ServeConnOpts{
			Context:    roast.AttachPeerMetadataToContext(context.Background(), conn),
			BaseConfig: s.Server,
		})
	}
}
