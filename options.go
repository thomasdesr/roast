package roast

import (
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/internal/errorutil"
)

type Option[T any] func(opt *T) error

// WithAWSConfig sets the AWS config to be used for signing requests
func WithAWSConfig[T Dialer | Listener](config *aws.Config) Option[T] {
	return func(opt *T) error {
		signer, err := gcisigner.NewSigner(config.Region, config.Credentials)
		if err != nil {
			return errorutil.Wrap(err, "failed to create signer from config")
		}

		// Set the Signer
		switch v := any(opt).(type) {
		case *Dialer:
			v.Signer = signer
		case *Listener:
			v.Signer = signer
		default:
			panic("unsupported type, generics have failed somehow?")
		}
		return nil
	}
}

// WithHandshakeTimeout sets the maximum amount of time for the handshake to
// complete before closing the connection.
//
// Note: This timeout only applies during the handshake phase. For connection
// behavior before the handshake, configure the underlying net.Listener or
// net.Dialer. For behavior after the handshake, set the appropriate deadline on
// the returned roast.Conn.
func WithHandshakeTimeout[T Dialer | Listener](timeout time.Duration) Option[T] {
	return func(opt *T) error {
		// Set the handshake timeout
		switch v := any(opt).(type) {
		case *Dialer:
			v.handshakeTimeout = timeout
		case *Listener:
			v.handshakeTimeout = timeout
		default:
			panic("unsupported type, generics have failed somehow?")
		}
		return nil
	}
}
