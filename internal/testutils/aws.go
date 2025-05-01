package testutils

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

func AWSConfigIfHasCredentials(tb testing.TB) aws.Config {
	tb.Helper()

	ctx := context.Background()

	config, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		tb.Fatalf("loading default config: %v", err)
	}

	if _, err := config.Credentials.Retrieve(ctx); err != nil {
		tb.Skipf("didn't find any credentials to use, skipping: %v", err)
	}

	return config
}

func GetLocalRole(ctx context.Context, sts *sts.Client) (arn.ARN, error) {
	result, err := sts.GetCallerIdentity(ctx, nil)
	if err != nil {
		return arn.ARN{}, fmt.Errorf("failed to get caller identity: %w", err)
	}

	localRoleArn, err := arn.Parse(*result.Arn)
	if err != nil {
		return arn.ARN{}, fmt.Errorf("failed to parse caller identity arn: %w", err)
	}

	if localRoleArn.Service != "sts" || !strings.HasPrefix(localRoleArn.Resource, "assumed-role/") {
		return arn.ARN{}, fmt.Errorf("provided arn (%q) is not an assumed role arn", localRoleArn.String())
	}

	// Hacky way to convert assumed-role to role
	localRoleArn.Service = "iam"
	localRoleArn.Resource = "role/" + strings.SplitN(localRoleArn.Resource, "/", 3)[1]
	return localRoleArn, nil
}
