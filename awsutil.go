package roast

import (
	"fmt"
	"slices"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/gcisigner"
	"github.com/thomasdesr/roast/gcisigner/awsapi"
	"github.com/thomasdesr/roast/internal/errorutil"
)

func assumedRoleInRoles(allowedPeerRoles []arn.ARN) gcisigner.SourceVerifier {
	return func(gcir *awsapi.GetCallerIdentityResult) (bool, error) {
		assumedRoleARN, err := arn.Parse(gcir.Arn)
		if err != nil {
			return false, errorutil.Wrapf(err, "failed to parse assumed role ARN: %q", gcir.Arn)
		}

		peerRoleARN, err := assumedRoleToRole(assumedRoleARN)
		if err != nil {
			return false, errorutil.Wrap(err, "failed to convert assumed role to role")
		}

		return slices.Contains(allowedPeerRoles, peerRoleARN), nil
	}
}

func assumedRoleToRole(assumedARN arn.ARN) (arn.ARN, error) {
	if assumedARN.Service != "sts" || !strings.HasPrefix(assumedARN.Resource, "assumed-role/") {
		return arn.ARN{}, fmt.Errorf("provided arn (%q) is not an assumed role arn", assumedARN.String())
	}

	parsedResource := strings.SplitN(assumedARN.Resource, "/", 3)
	if len(parsedResource) < 2 {
		return arn.ARN{}, fmt.Errorf("invalid assumed role arn")
	}
	roleName := parsedResource[1]

	return arn.ARN{
		Partition: assumedARN.Partition,
		Region:    assumedARN.Region,
		AccountID: assumedARN.AccountID,
		Service:   "iam",
		Resource:  fmt.Sprintf("role/%s", roleName),
	}, nil
}
