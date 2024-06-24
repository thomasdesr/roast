package awsapi

import "encoding/xml"

// TODO: Switch to using JSON for this struct, since that's apaprently possible!

// GetCallerIdentityResponse is the raw, outer XML response from the GetCallerIdentity API call.
type GetCallerIdentityResponse struct {
	XMLName                 xml.Name                `xml:"https://sts.amazonaws.com/doc/2011-06-15/ GetCallerIdentityResponse"`
	GetCallerIdentityResult GetCallerIdentityResult `xml:"GetCallerIdentityResult"`
	ResponseMetadata        ResponseMetadata        `xml:"ResponseMetadata"`
}

// GetCallerIdentityResult
// https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html
type GetCallerIdentityResult struct {
	Arn     string `xml:"Arn"`
	UserId  string `xml:"UserId"`
	Account string `xml:"Account"`
}

type ResponseMetadata any
