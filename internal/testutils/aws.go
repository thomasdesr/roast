package testutils

import (
	"context"
	"flag"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/thomasdesr/roast/gcisigner/source_verifiers/sources"
	"github.com/thomasdesr/roast/internal/errorutil"
)

var (
	shouldRunAWSIntegrationTests = flag.Bool("run-aws", false, "run aws tests that require credentials")
	awsIntegrationTestTimeout    = flag.Duration("aws-integration-test-timeout", time.Second*5, "timeout for aws integration tests")
)

func AWSConfigIfHasCredentials(tb testing.TB) aws.Config {
	tb.Helper()

	if !*shouldRunAWSIntegrationTests {
		tb.Skip("skipping aws tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *awsIntegrationTestTimeout)
	defer cancel()

	config, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		tb.Fatalf("loading default config: %v", err)
	}

	if _, err := config.Credentials.Retrieve(ctx); err != nil {
		tb.Fatalf("didn't find any credentials to use, skipping: %v", err)
	}

	return config
}

func GetLocalRole(ctx context.Context, sts *sts.Client) (sources.Role, error) {
	result, err := sts.GetCallerIdentity(ctx, nil)
	if err != nil {
		return sources.Role{}, errorutil.Wrap(err, "failed to get caller identity")
	}

	arn, err := arn.Parse(*result.Arn)
	if err != nil {
		return sources.Role{}, errorutil.Wrap(err, "failed to parse caller identity arn")
	}

	role, err := sources.FromARN[sources.Role](arn)
	if err != nil {
		return sources.Role{}, errorutil.Wrap(err, "failed to parse caller identity arn")
	}

	return role, nil
}
