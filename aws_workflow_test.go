package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Exercise the real SDK credential/configuration/serialization path without
// contacting AWS or reading the developer's credentials.
func fakeAWSEnvironment(t *testing.T, endpoint string) {
	t.Helper()
	empty := filepath.Join(t.TempDir(), "empty-config")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{
		"AWS_ACCESS_KEY_ID": "synthetic-test-access-key", "AWS_SECRET_ACCESS_KEY": "synthetic-test-secret",
		"AWS_SESSION_TOKEN": "", "AWS_PROFILE": "", "AWS_DEFAULT_PROFILE": "",
		"AWS_CONFIG_FILE": empty, "AWS_SHARED_CREDENTIALS_FILE": empty,
		"AWS_EC2_METADATA_DISABLED": "true", "AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "false",
		"AWS_ENDPOINT_URL_STS": endpoint, "AWS_ENDPOINT_URL_S3": endpoint,
		"AWS_MAX_ATTEMPTS": "1",
	} {
		t.Setenv(key, value)
	}
}

func TestAWSIdentityAndPaginatedAssessment(t *testing.T) {
	var mu sync.Mutex
	var calls []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		mu.Unlock()
		w.Header().Set("Content-Type", "application/xml")
		if r.Method == "POST" {
			if err := r.ParseForm(); err != nil || r.PostForm.Get("Action") != "GetCallerIdentity" {
				t.Error("unexpected identity action", r.PostForm, err)
			}
			fmt.Fprint(w, `<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Account>123456789012</Account><Arn>arn:aws:iam::123456789012:user/synthetic</Arn><UserId>synthetic</UserId></GetCallerIdentityResult><ResponseMetadata><RequestId>test</RequestId></ResponseMetadata></GetCallerIdentityResponse>`)
			return
		}
		if r.Method != "GET" {
			t.Error("non-read S3 request", r.Method)
			w.WriteHeader(405)
			return
		}
		switch {
		case r.URL.Path == "/" && r.URL.Query().Get("continuation-token") == "":
			fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>risk-bucket</Name></Bucket></Buckets><ContinuationToken>next-page</ContinuationToken></ListAllMyBucketsResult>`)
		case r.URL.Path == "/" && r.URL.Query().Get("continuation-token") == "next-page":
			fmt.Fprint(w, `<ListAllMyBucketsResult><Buckets><Bucket><Name>clean-bucket</Name></Bucket><Bucket><Name>denied-bucket</Name></Bucket></Buckets></ListAllMyBucketsResult>`)
		case r.URL.Query().Has("policyStatus") && strings.Contains(r.URL.Path, "denied-bucket"):
			w.WriteHeader(403)
			fmt.Fprint(w, `<Error><Code>AccessDenied</Code><Message>synthetic denied inspection</Message></Error>`)
		case r.URL.Query().Has("policyStatus"):
			fmt.Fprintf(w, `<PolicyStatus><IsPublic>%t</IsPublic></PolicyStatus>`, strings.Contains(r.URL.Path, "risk-bucket"))
		case r.URL.Query().Has("publicAccessBlock"):
			fmt.Fprint(w, `<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>`)
		default:
			t.Error("unexpected AWS request", r.URL.String())
			w.WriteHeader(400)
		}
	}))
	defer srv.Close()
	fakeAWSEnvironment(t, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	message, err := checkAWSIdentity(ctx, map[string]string{"region": "us-east-1"})
	if err != nil || !strings.Contains(message, "123456789012") || !strings.Contains(message, "Bucket permissions are not verified") {
		t.Fatal(message, err)
	}
	mu.Lock()
	identityCalls := len(calls)
	mu.Unlock()
	if identityCalls != 1 {
		t.Fatal("setup performed more than identity lookup", identityCalls)
	}
	scan, err := collect(ctx, "", "us-east-1", "")
	if err != nil || scan.Demo || scan.Scope != "123456789012 / us-east-1" || len(scan.Reports) != 3 {
		t.Fatal(scan, err)
	}
	if scan.Reports[0].Name != "clean-bucket" || scan.Reports[0].PublicPolicy || scan.Reports[0].IncompleteBlock || len(scan.Reports[0].Errors) != 0 {
		t.Fatal(scan.Reports)
	}
	if scan.Reports[1].Name != "denied-bucket" || len(scan.Reports[1].Errors) == 0 || scan.Reports[1].PolicyState != "unknown" {
		t.Fatal(scan.Reports)
	}
	if scan.Reports[2].Name != "risk-bucket" || !scan.Reports[2].PublicPolicy || len(scan.Reports[2].Errors) != 0 {
		t.Fatal(scan.Reports)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 10 {
		t.Fatal("expected two identity, two discovery and six bucket reads", calls)
	}
}

func TestInvalidTargetsFailBeforeAWSCalls(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(500) }))
	defer srv.Close()
	fakeAWSEnvironment(t, srv.URL)
	if _, err := collect(context.Background(), "", "us-east-1", "INVALID-BUCKET"); err == nil {
		t.Fatal("invalid targets accepted")
	}
	if calls != 0 {
		t.Fatal("invalid input made AWS calls", calls)
	}
}
