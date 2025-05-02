//go:build !runaws
// +build !runaws

package testutils

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
)

func AWSConfigIfHasCredentials(tb testing.TB) aws.Config {
	tb.Helper()
	tb.Skip("skipping aws tests - use -tags=runaws to enable")
	return aws.Config{}
}
