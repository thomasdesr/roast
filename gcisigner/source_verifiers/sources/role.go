package sources

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/internal/errorutil"
)

// Role represents an IAM role ARN
type Role struct {
	arn arn.ARN
}

// roleFromARN parses an ARN string into a Role
func roleFromARN(a arn.ARN) (Role, error) {
	// Check service and resource prefix
	if a.Service != "iam" {
		return Role{}, errorutil.Wrapf(ErrInvalidRoleARN, "service must be 'iam', got %q", a.Service)
	}

	// Check resource has role/ prefix
	parts := strings.SplitN(a.Resource, "/", 2)
	if len(parts) != 2 || parts[0] != "role" {
		return Role{}, errorutil.Wrapf(ErrInvalidRoleARN, "resource must start with 'role/', got %q", a.Resource)
	}

	// Check role name is valid
	if !validNamePattern.MatchString(parts[1]) {
		return Role{}, errorutil.Wrapf(ErrInvalidRoleARN, "role name must match pattern %q, got %q",
			validNamePattern.String(), parts[1])
	}

	return Role{arn: a}, nil
}

// ARN returns the ARN of the role, it exists because we don't want to allow people to construct a Role
// without using the blessed paths.
func (r Role) ARN() arn.ARN {
	return r.arn
}

// RoleName returns the name of the role without the path
func (r Role) RoleName() string {
	parts := strings.Split(r.arn.Resource, "/")
	if len(parts) < 2 {
		return ""
	}
	return parts[len(parts)-1]
}
