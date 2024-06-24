package gcisigner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/awsapi"
	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/errorutil"
	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/masker"
)

type SigV4Signer struct {
	region awsapi.Region

	creds       aws.CredentialsProvider
	sigV4Signer *v4.Signer

	nowFunc func() time.Time
}

var _ Signer = &SigV4Signer{}

func NewSigner(regionName string, creds aws.CredentialsProvider) (*SigV4Signer, error) {
	region := awsapi.ToRegion(regionName)
	if !region.IsValid() {
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
	presignedURL, _, err := s.sigV4Signer.PresignHTTP(ctx,
		creds,
		req,
		hex.EncodeToString(hashedPayload[:]),
		"sts",
		s.region.String(),
		s.nowFunc(),
	)
	if err != nil {
		return nil, errorutil.Wrap(err, "sigv4 signing")
	}

	// Start to extract the fields we need to hand to the client
	parsedPresignedURI, err := url.Parse(presignedURL)
	if err != nil {
		return nil, errorutil.Wrap(err, "parsing url")
	}

	// Extract the signature from the presigned URL so we can use it for masking
	// the provided payload.
	sig := parsedPresignedURI.Query().Get("X-Amz-Signature")
	sigB, err := hex.DecodeString(sig)
	if err != nil {
		return nil, errorutil.Wrap(err, "decoding signature")
	}

	// Construct our "SignedMessage" we can safely hand to clients
	return &SignedMessage{
		Region:            s.region,
		Body:              masker.Mask(sigB, payload),
		XAmzCredential:    parsedPresignedURI.Query().Get("X-Amz-Credential"),
		XAmzDate:          parsedPresignedURI.Query().Get("X-Amz-Date"),
		XAmzSecurityToken: parsedPresignedURI.Query().Get("X-Amz-Security-Token"),
		XAmzSignature:     sig,
	}, nil
}
