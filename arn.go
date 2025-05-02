package roast

import (
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/gcisigner/source_verifiers/sources"
	"github.com/thomasdesr/roast/internal/errorutil"
)

func parseRolesToSources(maybeRoles []arn.ARN) ([]sources.Role, error) {
	srcs := make([]sources.Role, 0, len(maybeRoles))

	for _, arn := range maybeRoles {
		role, err := sources.FromARN[sources.Role](arn)
		if err != nil {
			return nil, errorutil.Wrap(err, "failed to create server role from ARN")
		}

		srcs = append(srcs, role)
	}

	return srcs, nil
}
