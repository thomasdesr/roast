package gcisigner_test

import (
	"bytes"
	"context"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/gcisigner/awsapi"
	"github.com/thomasdesr/roast/gcisigner/internal/masker"
	"github.com/thomasdesr/roast/gcisigner/source_verifiers"
)

func TestVerifyAWSRequestBad(t *testing.T) {
	v := &gcisigner.SigV4Verifier{}

	for i, tc := range []gcisigner.UnverifiedMessage{
		{},
		{AmzAuthorization: ""},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			resp, err := v.Verify(context.Background(), &tc)
			if err == nil {
				t.Fatal("Expected error")
			}

			if resp != nil {
				t.Fatalf("Expected nil verify response, got %v", resp)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	srv := httptest.NewTLSServer(&gciServer{tb: t, responses: []awsapi.GetCallerIdentityResponse{
		{
			GetCallerIdentityResult: awsapi.GetCallerIdentityResult{
				Arn:     "arn:aws:sts::1234567890:assumed-role/RoleName/roleSession",
				UserId:  "AROAEXAMPLE",
				Account: "1234567890",
			},
		},
	}})
	defer srv.Close()

	v := gcisigner.NewVerifier(
		source_verifiers.VerifyFunc(func(*awsapi.GetCallerIdentityResult) (bool, error) {
			// Any source is good for this call
			return true, nil
		}),
		httptestServerTransport(srv),
	)

	payload := []byte("hello world")
	mask := bytes.Repeat([]byte("mask"), 8)

	resp, err := v.Verify(context.Background(), &gcisigner.UnverifiedMessage{
		Region:            "us-east-1",
		Body:              masker.Mask(mask, payload),
		Mask:              mask,
		AmzAuthorization:  "AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/sts/aws4_request,SignedHeaders=host;user-agent;x-amz-date,Signature=sig",
		XAmzSecurityToken: "token",
		XAmzDate:          "date",
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp == nil {
		t.Fatal("Expected response")
	}

	if !bytes.Equal(payload, resp.Payload) {
		t.Fatalf("Expected payload %s, got %s", payload, resp.Payload)
	}
}

func TestVerifyBadSource(t *testing.T) {
	srv := httptest.NewTLSServer(&gciServer{tb: t, responses: []awsapi.GetCallerIdentityResponse{
		{
			GetCallerIdentityResult: awsapi.GetCallerIdentityResult{
				Arn:     "arn:aws:sts::1234567890:assumed-role/RoleName/roleSession",
				UserId:  "AROAEXAMPLE",
				Account: "1234567890",
			},
		},
	}})
	defer srv.Close()

	v := gcisigner.NewVerifier(
		source_verifiers.VerifyFunc(func(*awsapi.GetCallerIdentityResult) (bool, error) {
			// Any source is bad
			return false, nil
		}),
		httptestServerTransport(srv),
	)

	payload := []byte("hello world")
	mask := bytes.Repeat([]byte("mask"), 8)

	resp, err := v.Verify(context.Background(), &gcisigner.UnverifiedMessage{
		Region:            "us-east-1",
		Body:              masker.Mask(mask, payload),
		Mask:              mask,
		AmzAuthorization:  "AWS4-HMAC-SHA256 Credential=AKIAI44QH8DHBEXAMPLE/20160126/us-east-1/sts/aws4_request,SignedHeaders=host;user-agent;x-amz-date,Signature=sig",
		XAmzSecurityToken: "token",
		XAmzDate:          "date",
	})
	if err == nil {
		t.Fatal("Verification should've failed", err)
	}
	if resp != nil {
		t.Fatalf("Expected nil response, got %v", resp)
	}
}
