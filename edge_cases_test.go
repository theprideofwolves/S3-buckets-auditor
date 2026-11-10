package main

import (
	"context"
	"fmt"
	"github.com/aws/smithy-go"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBucketInputSyntax(t *testing.T) {
	for _, name := range []string{"-bucket", "bucket-", ".bucket", "bucket.", "two..dots", "127.0.0.1", "bucket_name", "bücket"} {
		if _, err := namesFrom(name); err == nil {
			t.Errorf("accepted invalid bucket %q", name)
		}
	}
	for _, name := range []string{"abc", "123", "my.bucket", "bucket-123", strings.Repeat("a", 63)} {
		if _, err := namesFrom(name); err != nil {
			t.Errorf("rejected valid syntax %q: %v", name, err)
		}
	}
}

func TestInvalidHistoryCannotBecomeEmptyWorkspace(t *testing.T) {
	for i, body := range []string{"null", "{}", `{"unrelated":true}`, `{"Scans":[],"Tickets":{},"extra":"allowed"}`} {
		path := filepath.Join(t.TempDir(), "history.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadApp(path)
		if i < 3 && err == nil {
			t.Errorf("invalid history accepted: %s", body)
		}
		if i == 3 && err != nil {
			t.Errorf("forward-compatible field rejected: %v", err)
		}
		after, _ := os.ReadFile(path)
		if string(after) != body {
			t.Fatal("load overwrote history")
		}
	}
}

func TestJiraLinkRejectsUnusableEvidence(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"empty", "", 200}, {"malformed", "{broken", 200}, {"missing-key", "{}", 200},
		{"different-key", `{"key":"SEC-999"}`, 200}, {"html", "<html>login</html>", 200},
		{"not-found", `{"key":"SEC-123"}`, 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.status); fmt.Fprint(w, tc.body) }))
			defer srv.Close()
			a := testApp(t)
			a.client = srv.Client()
			a.state.Scans = []Scan{{ID: "test", Scope: "123456789012 / us-east-1", Reports: []BucketReport{demoReport("test-bucket", true, false)}}}
			out := request(a, "POST", "/?token="+a.token, url.Values{"action": {"link"}, "id": {"test"}, "bucket": {"test-bucket"}, "url": {srv.URL}, "key": {"SEC-123"}})
			if strings.Contains(out.Body.String(), "Existing Jira issue linked") || len(a.state.Tickets) != 0 {
				t.Fatal("invalid link was saved", a.state.Tickets)
			}
		})
	}
}

func TestMissingPolicyIsNotUnknown(t *testing.T) {
	report := inspect(context.Background(), fakeAPI{policyErr: &smithy.GenericAPIError{Code: "NoSuchBucketPolicy"}}, "test-bucket")
	if len(report.Errors) != 0 || report.PolicyState != "no bucket policy" || report.PublicPolicy {
		t.Fatal(report)
	}
}

func TestUnrecordedControlsCannotSendJiraEvidence(t *testing.T) {
	calls := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(201) }))
	defer srv.Close()
	unknown := demoReport("test-bucket", true, false)
	unknown.Controls = &BucketControls{}
	missingFlag := demoReport("test-bucket", true, true)
	missingFlag.Controls.RestrictPublicBuckets = nil
	legacyUnknown := BucketReport{Name: "test-bucket", PublicPolicy: true}
	for _, report := range []BucketReport{unknown, missingFlag, legacyUnknown} {
		for _, linked := range []bool{false, true} {
			a := testApp(t)
			a.client = srv.Client()
			a.state.Scans = []Scan{{ID: "test", Scope: "123456789012 / us-east-1", Reports: []BucketReport{report}}}
			if linked {
				a.state.Tickets[srv.URL+"|123456789012 / us-east-1|test-bucket"] = Ticket{Key: "SEC-1", State: "linked"}
			}
			out := request(a, "POST", "/?token="+a.token, url.Values{"action": {"ticket"}, "id": {"test"}, "bucket": {"test-bucket"}, "url": {srv.URL}, "project": {"SEC"}, "kind": {"Task"}})
			if !strings.Contains(out.Body.String(), "Inspection incomplete") {
				t.Fatal("unrecorded controls allowed evidence")
			}
		}
	}
	if calls != 0 {
		t.Fatal("unrecorded controls contacted Jira", calls)
	}
}
