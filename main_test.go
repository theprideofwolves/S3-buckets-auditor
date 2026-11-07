package main

import (
	"bytes"
	"context"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"strings"
	"testing"
	"time"
)

type fakeAPI struct {
	policyErr, blockErr error
	public, incomplete  bool
}

func (f fakeAPI) GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	return &s3.GetBucketPolicyStatusOutput{PolicyStatus: &types.PolicyStatus{IsPublic: aws.Bool(f.public)}}, f.policyErr
}
func (f fakeAPI) GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{BlockPublicAcls: aws.Bool(!f.incomplete), BlockPublicPolicy: aws.Bool(true), IgnorePublicAcls: aws.Bool(true), RestrictPublicBuckets: aws.Bool(true)}}, f.blockErr
}
func TestClassification(t *testing.T) {
	denied := &smithy.GenericAPIError{Code: "AccessDenied", Message: "denied"}
	missing := &smithy.GenericAPIError{Code: "NoSuchPublicAccessBlockConfiguration"}
	for _, tc := range []struct {
		name string
		api  fakeAPI
		want string
	}{
		{"enabled", fakeAPI{}, "Checked controls enabled"}, {"public", fakeAPI{public: true}, "Public policy detected"}, {"disabled", fakeAPI{incomplete: true}, "Block configuration incomplete"}, {"missing", fakeAPI{blockErr: missing}, "Block configuration incomplete"}, {"denied-policy", fakeAPI{policyErr: denied}, "Unknown / incomplete"}, {"denied-block", fakeAPI{blockErr: denied}, "Unknown / incomplete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := inspect(context.Background(), tc.api, "demo")
			s, _ := r.Status()
			if s != tc.want {
				t.Fatalf("%s != %s", s, tc.want)
			}
		})
	}
}
func TestConcurrentAuditAndReport(t *testing.T) {
	r := audit(context.Background(), fakeAPI{}, []string{"z", "a", "m"}, 2)
	if len(r) != 3 || r[0].Name != "a" {
		t.Fatalf("results: %+v", r)
	}
	r[0].Errors = []string{"AccessDenied"}
	var out, errs bytes.Buffer
	if err := writeReports(&out, &errs, r, time.Unix(0, 0)); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Unknown / incomplete") || !strings.Contains(errs.String(), "AccessDenied") {
		t.Fatal("lost error evidence")
	}
}
