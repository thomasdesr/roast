package sources

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/internal/errorutil"
)

var (
	// ErrInvalidARN indicates the provided string isn't a valid ARN
	ErrInvalidARN = errors.New("invalid ARN format")

	// ErrInvalidRoleARN indicates the provided ARN is not a valid IAM role ARN
	ErrInvalidRoleARN = errors.New("invalid IAM role ARN")

	// ErrInvalidAssumedRoleARN indicates the provided ARN is not a valid STS assumed role ARN
	ErrInvalidAssumedRoleARN = errors.New("invalid STS assumed role ARN")
)

// validNamePattern adheres to AWS IAM naming rules
var validNamePattern = regexp.MustCompile(`^[\w+=,.@-]+$`)

// FromARN converts an arn.ARN into either a Role or AssumedRole
// Returns an error if the ARN is invalid
func FromARN[T Role | AssumedRole](arn arn.ARN) (T, error) {
	var result T

	// Create the appropriate type based on the generic type parameter
	switch any(result).(type) {
	case Role:
		role, err := roleFromARN(arn)
		if err != nil {
			return result, errorutil.Wrapf(err, "failed to parse %q as role ARN", arn)
		}
		return any(role).(T), nil
	case AssumedRole:
		assumedRole, err := assumedRoleFromARN(arn)
		if err != nil {
			return result, errorutil.Wrapf(err, "failed to parse %q as assumed role ARN", arn)
		}
		return any(assumedRole).(T), nil
	default:
		panic(fmt.Sprintf("unsupported type %T", result))
	}
}
