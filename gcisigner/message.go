package gcisigner

import (
	"github.com/thomasdesr/roast/gcisigner/awsapi"
)

type SignedMessage struct {
	Body []byte
	Mask []byte

	Region            awsapi.Region
	AmzAuthorization  string
	XAmzSecurityToken string
	XAmzDate          string
}

// Same as a SignedMessage, but since we're on the read side, we want to make it
// clear to readers we don't trust its contents yet
type UnverifiedMessage SignedMessage

type VerifiedMessage struct {
	Payload        []byte
	CallerIdentity awsapi.GetCallerIdentityResult

	// The original message that was verified
	Raw *SignedMessage
}
