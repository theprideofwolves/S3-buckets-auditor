package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// An explicit expected-result matrix, not an accuracy estimate for live AWS.
func TestConfigurationTruthMatrix(t *testing.T) {
	for _, policy := range []string{"public", "not-public", "no-policy"} {
		for mask := 0; mask < 16; mask++ {
			t.Run(fmt.Sprintf("%s/flags-%02d", policy, mask), func(t *testing.T) {
				api := flagAPI{fakeAPI: fakeAPI{public: policy == "public"}, flags: &types.PublicAccessBlockConfiguration{
					BlockPublicAcls: aws.Bool(mask&1 != 0), IgnorePublicAcls: aws.Bool(mask&2 != 0), BlockPublicPolicy: aws.Bool(mask&4 != 0), RestrictPublicBuckets: aws.Bool(mask&8 != 0),
				}}
				if policy == "no-policy" {
					api.fakeAPI.policyErr = &smithy.GenericAPIError{Code: "NoSuchBucketPolicy"}
				}
				report := inspect(context.Background(), api, "synthetic-matrix-bucket")
				want := "Block configuration incomplete"
				if policy == "public" {
					want = "Public policy detected"
				} else if mask == 15 {
					want = "Checked controls enabled"
				}
				got, _ := report.Status()
				if got != want || !completeObservation(report) {
					t.Fatalf("want %s; got %+v", want, report)
				}
			})
		}
	}
}
