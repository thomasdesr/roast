package gcisigner

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/thomasdesr/aws-role-mtls/gcisigner/awsapi"
	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/masker"
	"github.com/thomasdesr/aws-role-mtls/internal/errorutil"
)

type Verifier interface {
	Verify(ctx context.Context, msg *UnverifiedMessage) (*VerifiedMessage, error)
}

// SigV4Verifier is a Verifier that uses SigV4 signed GetCallerIdentity requests
// (usually constructed by a `Signer`) to verify the contents of the message and
// confirms that the source meets the requirements of the `IsValidSource`.
type SigV4Verifier struct {
	raw unconstrainedSigV4Verifier

	IsValidSource SourceVerifier
}

var _ Verifier = &SigV4Verifier{}

// SourceVerifier is a function that is called when a SigV4Verifier is
// attempting to determine if a client should be allowed to connect. You can
// rely on its argument never being null.
type SourceVerifier func(*awsapi.GetCallerIdentityResult) (bool, error)

func NewVerifier(validSources SourceVerifier, tr http.RoundTripper) *SigV4Verifier {
	// We should never get a redirect, so we can safely ignore them
	nonRedirectingClient := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}}

	return &SigV4Verifier{
		raw: unconstrainedSigV4Verifier{c: nonRedirectingClient},

		IsValidSource: validSources,
	}
}

func (v *SigV4Verifier) Verify(ctx context.Context, msg *UnverifiedMessage) (*VerifiedMessage, error) {
	sigVerifiedPayload, gcir, err := v.raw.VerifyPayload(ctx, msg)
	if err != nil {
		return nil, errorutil.Wrap(err, "failed to verify unconstrained")
	} else if gcir == nil {
		panic("gcir should never be nil if there wasn't an error")
	}

	if ok, err := v.IsValidSource(gcir); err != nil {
		return nil, errorutil.Wrap(err, "failed to verify source")
	} else if !ok {
		return nil, fmt.Errorf("msg came from an invalid source: %v", gcir)
	}

	return &VerifiedMessage{
		Payload:        sigVerifiedPayload,
		CallerIdentity: *gcir,

		Raw: (*SignedMessage)(msg),
	}, nil
}

type unconstrainedSigV4Verifier struct {
	c *http.Client
}

func (v *unconstrainedSigV4Verifier) VerifyPayload(ctx context.Context, msg *UnverifiedMessage) ([]byte, *awsapi.GetCallerIdentityResult, error) {
	canonReq, unverifiedPayload /* cannot be trusted until we complete verification */, err := canonicalRequestFrom(ctx, msg)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to create canonical request")
	}

	// Send the request to STS to verify the signature
	resp, err := v.c.Do(canonReq)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	// This should fail if the signature doesn't match
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("failed to verify request: %s", resp.Status)
	}

	// Extract the info about the caller from the response
	var gcir awsapi.GetCallerIdentityResponse
	if err := xml.NewDecoder(resp.Body).Decode(&gcir); err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to unmarshal response")
	}

	return unverifiedPayload, &gcir.GetCallerIdentityResult, nil
}

func canonicalRequestFrom(ctx context.Context, msg *UnverifiedMessage) (*http.Request, []byte, error) {
	if !msg.Region.IsValid() {
		return nil, nil, fmt.Errorf("invalid region: %q", msg.Region)
	}

	// Construct sts:GetCallerIdentity URL for verification
	uri, _ := url.Parse(strings.Replace(awsapi.RegionalGetCallerIdentityURLTemplate, "{region}", msg.Region.String(), 1))

	// Unmask our data
	unmaskedPayload, err := masker.Unmask(msg.Mask, msg.Body)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to unmask")
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		uri.String(),
		bytes.NewBuffer(unmaskedPayload),
	)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to create request")
	}

	{
		req.Header.Add("Authorization", msg.AmzAuthorization)
		req.Header.Add("X-Amz-Date", msg.XAmzDate)
		req.Header.Add("X-Amz-Security-Token", msg.XAmzSecurityToken)

		// Verify our request has given us vaguely correct values
		for k, v := range req.Header {
			if v[0] == "" {
				return nil, nil, fmt.Errorf("invalid message field: %q: %v", k, v[0])
			}
		}
	}

	return req, unmaskedPayload, nil
}
