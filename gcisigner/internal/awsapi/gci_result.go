package awsapi

import "encoding/xml"

// GetCallerIdentityResult
// https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
type GetCallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserId  string `xml:"UserId"`
	Account string `xml:"Account"`
}

// GetCallerIdentityResponse is the raw, outer XML response from the GetCallerIdentity API call.
type GetCallerIdentityResponse struct {
	XMLName                 xml.Name                `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetCallerIdentityResponse"`
	GetCallerIdentityResult GetCallerIdentityResult `xml:"GetCallerIdentityResult"`
	ResponseMetadata        ResponseMetadata        `xml:"ResponseMetadata"`
}

type ResponseMetadata any
