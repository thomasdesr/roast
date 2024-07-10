package awsapi

import (
	"encoding/json"
	"fmt"
)

type Region string

const (
	Region_US_EAST_1      Region = "us-east-1"
	Region_US_EAST_2      Region = "us-east-2"
	Region_US_WEST_1      Region = "us-west-1"
	Region_US_WEST_2      Region = "us-west-2"
	Region_EU_WEST_1      Region = "eu-west-1"
	Region_EU_CENTRAL_1   Region = "eu-central-1"
	Region_EU_NORTH_1     Region = "eu-north-1"
	Region_AP_SOUTHEAST_1 Region = "ap-southeast-1"
	Region_AP_SOUTHEAST_2 Region = "ap-southeast-2"
	Region_AP_NORTHEAST_1 Region = "ap-northeast-1"
	Region_AP_NORTHEAST_2 Region = "ap-northeast-2"
	Region_AP_SOUTH_1     Region = "ap-south-1"
	Region_SA_EAST_1      Region = "sa-east-1"
	Region_CA_CENTRAL_1   Region = "ca-central-1"
	Region_ME_SOUTH_1     Region = "me-south-1"
	Region_AF_SOUTH_1     Region = "af-south-1"
	Region_EU_WEST_2      Region = "eu-west-2"
	Region_EU_SOUTH_1     Region = "eu-south-1"
	Region_AP_EAST_1      Region = "ap-east-1"
	Region_EU_WEST_3      Region = "eu-west-3"
	Region_EU_NORTHEAST_1 Region = "eu-northeast-1"
	Region_AP_NORTHEAST_3 Region = "ap-northeast-3"
)

func (r Region) MarshalJSON() ([]byte, error) {
	if !r.IsValid() {
		return nil, fmt.Errorf("invalid region: %q", string(r))
	}
	return json.Marshal(string(r))
}

func (r *Region) UnmarshalJSON(b []byte) error {
	rs := (*string)(r)
	if err := json.Unmarshal(b, rs); err != nil {
		return err
	}

	if !r.IsValid() {
		return fmt.Errorf("invalid region: %q", *r)
	}

	return nil
}

func (r Region) String() string {
	return string(r)
}

func (r Region) IsValid() bool {
	switch r {
	case Region_US_EAST_1,
		Region_US_EAST_2,
		Region_US_WEST_1,
		Region_US_WEST_2,
		Region_EU_WEST_1,
		Region_EU_CENTRAL_1,
		Region_EU_NORTH_1,
		Region_AP_SOUTHEAST_1,
		Region_AP_SOUTHEAST_2,
		Region_AP_NORTHEAST_1,
		Region_AP_NORTHEAST_2,
		Region_AP_SOUTH_1,
		Region_SA_EAST_1,
		Region_CA_CENTRAL_1,
		Region_ME_SOUTH_1,
		Region_AF_SOUTH_1,
		Region_EU_WEST_2,
		Region_EU_SOUTH_1,
		Region_AP_EAST_1,
		Region_EU_WEST_3,
		Region_EU_NORTHEAST_1,
		Region_AP_NORTHEAST_3:
		return true
	}
	return false
}
