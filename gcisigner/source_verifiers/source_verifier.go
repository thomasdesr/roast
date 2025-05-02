package source_verifiers

import (
	"slices"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/thomasdesr/roast/gcisigner/awsapi"
	"github.com/thomasdesr/roast/gcisigner/source_verifiers/sources"
	"github.com/thomasdesr/roast/internal/errorutil"
)

// SourceVerifier is a function that is called when a SigV4Verifier is
// attempting to determine if a client should be allowed to connect. You can
// rely on its argument never being null.
type Verifier interface {
	Verify(*awsapi.GetCallerIdentityResult) (bool, error)
}

type VerifyFunc func(*awsapi.GetCallerIdentityResult) (bool, error)

var _ Verifier = VerifyFunc(nil)

func (v VerifyFunc) Verify(gcir *awsapi.GetCallerIdentityResult) (bool, error) {
	return v(gcir)
}

// MatchesIAMRoles is a SourceVerifier that checks if the caller's ARN is in
// the list of allowed peer roles. The passed in set of Roles should be aws IAM
// role ARNs
func MatchesAny(allowedRoles []sources.Role) Verifier {
	return VerifyFunc(func(gcir *awsapi.GetCallerIdentityResult) (bool, error) {
		// Parse the caller's ARN string into an arn.ARN
		callerARN, err := arn.Parse(gcir.Arn)
		if err != nil {
			return false, errorutil.Wrap(err, "failed to parse caller ARN")
		}

		assumedRole, err := sources.FromARN[sources.AssumedRole](callerARN)
		if err != nil {
			return false, errorutil.Wrap(err, "caller isn't an AssumedRole")
		}

		// Get the parent role from the assumed role
		parentRole, err := assumedRole.ParentRole()
		if err != nil {
			return false, errorutil.Wrap(err, "failed to get parent role from assumed role")
		}

		return slices.Contains(allowedRoles, parentRole), nil
	})
}
