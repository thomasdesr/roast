package testutils

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/thomasdesr/roast/gcisigner/source_verifiers/sources"
	"github.com/thomasdesr/roast/internal/errorutil"
)

func GetLocalRole(ctx context.Context, sts *sts.Client) (sources.Role, error) {
	result, err := sts.GetCallerIdentity(ctx, nil)
	if err != nil {
		return sources.Role{}, errorutil.Wrap(err, "failed to get caller identity")
	}

	arn, err := arn.Parse(*result.Arn)
	if err != nil {
		return sources.Role{}, errorutil.Wrap(err, "failed to parse caller identity arn")
	}

	assumedRole, err := sources.FromARN[sources.AssumedRole](arn)
	if err != nil {
		return sources.Role{}, errorutil.Wrap(err, "failed to parse caller identity arn")
	}

	sessionIssuer, err := assumedRole.SessionIssuer()
	if err != nil {
		return sources.Role{}, errorutil.Wrap(err, "failed to get parent role")
	}

	return sessionIssuer, nil
}
