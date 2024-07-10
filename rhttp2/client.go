package rhttp2

import (
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
)

func Client(allowedRoles []arn.ARN) (*http.Client, error) {
	tr, err := Transport(allowedRoles)
	if err != nil {
		return nil, err
	}

	return &http.Client{
		Transport: tr,
	}, nil
}
