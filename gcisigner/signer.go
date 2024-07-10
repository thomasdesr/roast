package gcisigner

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/thomasdesr/roast/gcisigner/awsapi"
	"github.com/thomasdesr/roast/gcisigner/internal/masker"
	"github.com/thomasdesr/roast/internal/errorutil"
)

type Signer interface {
	Sign(ctx context.Context, payload []byte) (*SignedMessage, error)
}

// SigV4Signer is a `Signer` that uses the provided `aws.CredentialsProvider` to
// construct a GetCallerIdentity requests using SigV4. `Sign` returns a message
// that can be send to a `Verifier` for verification.
type SigV4Signer struct {
	region awsapi.Region

	creds       aws.CredentialsProvider
	sigV4Signer *v4.Signer

	nowFunc func() time.Time
}

var _ Signer = &SigV4Signer{}

func NewSigner(regionName string, creds aws.CredentialsProvider) (*SigV4Signer, error) {
	region := awsapi.Region(regionName)
	if !region.IsValid() { // Ensure we get handed a vaild region
		return nil, fmt.Errorf("invalid region: %q", regionName)
	}

	return &SigV4Signer{
		region:      region,
		creds:       creds,
		sigV4Signer: v4.NewSigner(),
		nowFunc:     time.Now,
	}, nil
}

// Sign takes a payload and returns a `SignedMessage` that can be sent to a
// another client and probably validated by a `Verifier`.
func (s *SigV4Signer) Sign(ctx context.Context, payload []byte) (*SignedMessage, error) {
	// Retrieve the credentials we'll use to Sign this request
	creds, err := s.creds.Retrieve(ctx)
	if err != nil {
		return nil, errorutil.Wrap(err, "getting credentials")
	}

	// Construct the GetCallerIdentity request we need to sign
	req, err := http.NewRequest(
		"POST",
		strings.Replace(awsapi.RegionalGetCallerIdentityURLTemplate, "{region}", s.region.String(), 1),
		bytes.NewBuffer(payload),
	)
	if err != nil {
		return nil, errorutil.Wrap(err, "creating request")
	}

	// Hash the payload per SigV4 spec
	hashedPayload := sha256.Sum256(payload)

	// AWS Sigv4 Sign the request
	signedReq := req.Clone(ctx)
	err = s.sigV4Signer.SignHTTP(ctx,
		creds,
		signedReq,
		hex.EncodeToString(hashedPayload[:]),
		"sts",
		s.region.String(),
		s.nowFunc(),
	)
	if err != nil {
		return nil, errorutil.Wrap(err, "sigv4 signing")
	}

	mask := make([]byte, 32)
	rand.Read(mask)

	// Construct our "SignedMessage" we can safely hand to clients
	return &SignedMessage{
		Region:            s.region,
		Body:              masker.Mask(mask, payload),
		Mask:              mask,
		AmzAuthorization:  signedReq.Header.Get("Authorization"),
		XAmzDate:          signedReq.Header.Get("X-Amz-Date"),
		XAmzSecurityToken: signedReq.Header.Get("X-Amz-Security-Token"),
	}, nil
}
