package roast

import (
	"net"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

type Conn struct {
	net.Conn

	Peer *PeerMetadata
}

type PeerMetadata struct {
	AccountID string
	Role      arn.ARN
}
