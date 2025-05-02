package sources

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/internal/errorutil"
)

// AssumedRole represents an STS assumed role ARN
type AssumedRole struct {
	arn arn.ARN
}

// assumedRoleFromARN parses an ARN string into an AssumedRole
func assumedRoleFromARN(a arn.ARN) (AssumedRole, error) {
	// Check service
	if a.Service != "sts" {
		return AssumedRole{}, errorutil.Wrapf(ErrInvalidAssumedRoleARN, "service must be 'sts', got %q", a.Service)
	}

	// Check assumed-role prefix and validate structure
	if !strings.HasPrefix(a.Resource, "assumed-role/") {
		return AssumedRole{}, errorutil.Wrapf(ErrInvalidAssumedRoleARN, "resource must start with 'assumed-role/', got %q", a.Resource)
	}

	// Extract role name and session name
	parts := strings.Split(a.Resource, "/")
	if len(parts) < 3 {
		return AssumedRole{}, errorutil.Wrapf(ErrInvalidAssumedRoleARN, "resource must have format 'assumed-role/role-name/session-name'")
	}

	// Validate role name and session name
	roleName := parts[1]
	sessionName := parts[2]

	if !validNamePattern.MatchString(roleName) {
		return AssumedRole{}, errorutil.Wrapf(ErrInvalidAssumedRoleARN, "role name must match pattern %q, got %q",
			validNamePattern.String(), roleName)
	}

	if !validNamePattern.MatchString(sessionName) {
		return AssumedRole{}, errorutil.Wrapf(ErrInvalidAssumedRoleARN, "session name must match pattern %q, got %q",
			validNamePattern.String(), sessionName)
	}

	return AssumedRole{arn: a}, nil
}

// ARN returns the ARN of the assumed role, it exists because we don't want to allow people to construct an AssumedRole
// without using the blessed paths.
func (a AssumedRole) ARN() arn.ARN {
	return a.arn
}

// RoleName returns the name of the assumed role without the path
func (a AssumedRole) RoleName() string {
	parts := strings.Split(a.arn.Resource, "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[1]
}

// SessionName returns the session name of the assumed role
func (a AssumedRole) SessionName() string {
	parts := strings.Split(a.arn.Resource, "/")
	if len(parts) < 3 {
		return ""
	}
	return parts[2]
}

// SessionIssuer returns the IAM role that minted the assumed role
func (a AssumedRole) SessionIssuer() (Role, error) {
	roleName := a.RoleName()
	if roleName == "" {
		return Role{}, ErrInvalidAssumedRoleARN
	}

	parentARN := arn.ARN{
		Partition: a.arn.Partition,
		Service:   "iam",
		Region:    a.arn.Region,
		AccountID: a.arn.AccountID,
		Resource:  fmt.Sprintf("role/%s", roleName),
	}

	// Validate the constructed role ARN
	parent, err := roleFromARN(parentARN)
	if err != nil {
		return Role{}, errorutil.Wrapf(err, "failed to create parent role")
	}

	return parent, nil
}
