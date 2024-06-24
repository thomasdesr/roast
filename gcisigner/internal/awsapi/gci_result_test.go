package awsapi_test

import (
	"encoding/xml"
	"testing"

	"github.com/thomasdesr/aws-role-mtls/gcisigner/internal/awsapi"
)

const realResp = `
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::1234567890:assumed-role/RoleName/roleSession</Arn>
    <UserId>AROAEXAMPLE</UserId>
    <Account>1234567890</Account>
  </GetCallerIdentityResult>
  <ResponseMetadata>
    <RequestId>bc2b1bf3-cc93-43bd-a16c-604c592e523e</RequestId>
  </ResponseMetadata>
</GetCallerIdentityResponse>
`

func TestGetCallerIdentityXML(t *testing.T) {
	resp := &awsapi.GetCallerIdentityResponse{}
	if err := xml.Unmarshal([]byte(realResp), resp); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if resp.GetCallerIdentityResult.Account != "1234567890" {
		t.Errorf("expected account 1234567890, got %s", resp.GetCallerIdentityResult.Account)
	}

	if resp.GetCallerIdentityResult.UserId != "AROAEXAMPLE" {
		t.Errorf("expected user id AROAEXAMPLE, got %s", resp.GetCallerIdentityResult.UserId)
	}

	if resp.GetCallerIdentityResult.Arn != "arn:aws:sts::1234567890:assumed-role/RoleName/roleSession" {
		t.Errorf("received incorrect ARN %s", resp.GetCallerIdentityResult.Arn)
	}
}
