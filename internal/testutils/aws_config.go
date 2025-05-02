//go:build runaws
// +build runaws

package testutils

import (
	"context"
	"flag"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
)

var awsIntegrationTestConfigTimeout = flag.Duration("aws-integration-test-config-timeout", 5*time.Minute, "timeout for AWS integration tests")

func AWSConfigIfHasCredentials(tb testing.TB) aws.Config {
	tb.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), *awsIntegrationTestConfigTimeout)
	defer cancel()

	config, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		tb.Fatalf("loading default config: %v", err)
	}

	if _, err := config.Credentials.Retrieve(ctx); err != nil {
		tb.Fatalf("didn't find any credentials to use: %v", err)
	}

	return config
}
