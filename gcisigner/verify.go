package gcisigner

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/awsapi"
	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/errorutil"
	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/masker"
)

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

	// Start to construct a URL for our Call to STS for verification
	var stsPresignedURL *url.URL
	{
		uri, _ := url.Parse(strings.Replace(awsapi.RegionalGetCallerIdentityURLTemplate, "{region}", msg.Region.String(), 1))

		q := uri.Query()
		q.Add("X-Amz-Algorithm", "AWS4-HMAC-SHA256")
		q.Add("X-Amz-SignedHeaders", "content-length;host")
		q.Add("X-Amz-Credential", msg.XAmzCredential)
		q.Add("X-Amz-Date", msg.XAmzDate)
		q.Add("X-Amz-Security-Token", msg.XAmzSecurityToken)
		q.Add("X-Amz-Signature", msg.XAmzSignature)

		// Verify our request has given us vaguely correct values
		for k, v := range q {
			if v[0] == "" {
				return nil, nil, fmt.Errorf("invalid message field: %q: %v", k, v[1])
			}
		}

		uri.RawQuery = q.Encode()

		// Store our fully reconstructed URI
		stsPresignedURL = uri
	}

	// Decode the signature from the message so we can unmask the message
	sigB, err := hex.DecodeString(msg.XAmzSignature)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to decode signature")
	}

	unmaskedPayload, err := masker.Unmask(sigB, msg.Body)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to unmask")
	}

	req, err := http.NewRequestWithContext(
		ctx,
		"POST",
		stsPresignedURL.String(),
		bytes.NewBuffer(unmaskedPayload),
	)
	if err != nil {
		return nil, nil, errorutil.Wrap(err, "failed to create request")
	}

	return req, unmaskedPayload, nil
}
