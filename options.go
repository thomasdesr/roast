package roast

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/internal/errorutil"
)

type Option[T any] func(opt *T) error

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
