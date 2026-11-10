package main

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The old two-scan assertions now exercise the same replay as the UI.
func compare(now Scan, old *Scan) map[string]string {
	scans := []Scan{}
	if old != nil {
		copy := *old
		copy.ID = "prior"
		scans = append(scans, copy)
	}
	now.ID = "current"
	scans = append(scans, now)
	record, _ := verification(scans, now.ID)
	out := map[string]string{}
	for _, b := range record.Buckets {
		out[b.Name] = b.Assessment
	}
	return out
}

func workflowScans() []Scan {
	scans := verificationDemo()
	at := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for i := range scans {
		scans[i].ID = string(rune('a' + i))
		scans[i].At = at.Add(time.Duration(i) * time.Hour)
	}
	return scans
}

func mustVerification(t *testing.T, scans []Scan, id string) VerificationRecord {
	t.Helper()
	record, err := verification(scans, id)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestConcernSurvivesDeniedAndMissingThenVerified(t *testing.T) {
	scans := workflowScans()
	for _, stage := range []int{1, 2} {
		record := mustVerification(t, scans, scans[stage].ID)
		bucket := record.Buckets[0]
		if bucket.OpenConcerns != 2 {
			t.Fatal("concerns disappeared through a gap", bucket)
		}
		for _, i := range []int{0, 1, 4} {
			c := bucket.Controls[i]
			if len(c.Episodes) != 1 || c.Episodes[0].VerifiedClear != nil || c.LastKnown.ScanID != "a" || c.Episodes[0].AgeSeconds != int64(stage*3600) {
				t.Fatal(c)
			}
		}
	}
	record := mustVerification(t, scans, "d")
	bucket := record.Buckets[0]
	if bucket.Assessment != "Verified clear for checked controls" || bucket.OpenConcerns != 0 {
		t.Fatal(bucket)
	}
	policy := bucket.Controls[0]
	if policy.Change != "public → not public" || policy.ComparedWith.ScanID != "a" || policy.Episodes[0].VerifiedClear.ScanID != "d" {
		t.Fatal(policy)
	}
	states := []string{}
	for _, event := range policy.Timeline {
		states = append(states, event.State)
	}
	if !reflect.DeepEqual(states, []string{"concern", "unknown", "not_assessed", "clear"}) {
		t.Fatal(states)
	}
	if bucket.Controls[4].Change != "disabled → enabled" {
		t.Fatal(bucket.Controls[4])
	}
}

func TestRecurrenceStartsAnotherEpisode(t *testing.T) {
	scans := workflowScans()
	again := scans[0]
	again.ID = "e"
	again.At = scans[3].At.Add(time.Hour)
	scans = append(scans, again)
	bucket := mustVerification(t, scans, "e").Buckets[0]
	if bucket.Assessment != "New concern" || len(bucket.Controls[0].Episodes) != 2 || bucket.Controls[0].Episodes[1].FirstObserved.ScanID != "e" || bucket.Controls[0].Episodes[0].AgeSeconds != 10800 {
		t.Fatal(bucket)
	}
}

func TestPartialSuccessOnlyClearsObservedControl(t *testing.T) {
	scans := workflowScans()[:2]
	partial := demoReport("demo-verification-bucket", false, false)
	partial.BlockState = "unknown"
	partial.Controls = &BucketControls{PolicyPublic: boolValue(false)}
	partial.Errors = []string{"block unavailable"}
	scans[1].Reports = []BucketReport{partial}
	bucket := mustVerification(t, scans, "b").Buckets[0]
	if bucket.OpenConcerns != 1 || bucket.Assessment != "Unknown — reassessment incomplete" || bucket.Controls[0].Episodes[0].VerifiedClear == nil || bucket.Controls[1].Episodes[0].VerifiedClear != nil {
		t.Fatal(bucket)
	}
	partial = demoReport("demo-verification-bucket", false, false)
	partial.PolicyState = "unknown"
	partial.Controls.PolicyPublic = nil
	partial.Errors = []string{"policy unavailable"}
	scans[1].Reports = []BucketReport{partial}
	bucket = mustVerification(t, scans, "b").Buckets[0]
	if bucket.OpenConcerns != 1 || bucket.Controls[0].Episodes[0].VerifiedClear != nil || bucket.Controls[1].Episodes[0].VerifiedClear == nil {
		t.Fatal(bucket)
	}
}

func TestVerificationScopeAndAsOfIsolation(t *testing.T) {
	scans := workflowScans()
	before := mustVerification(t, scans, "b")
	other := scans[3]
	other.ID = "other"
	other.Scope = "another-account / another-region"
	syntheticCollision := scans[3]
	syntheticCollision.ID = "live"
	syntheticCollision.Demo = false
	mixed := append([]Scan{scans[0], other, syntheticCollision}, scans[1:]...)
	if got := mustVerification(t, mixed, "b"); !reflect.DeepEqual(got, before) {
		t.Fatal("another scope or future observation changed export")
	}
	if _, err := verification(scans, "missing"); err == nil {
		t.Fatal("missing selection accepted")
	}
	// Saved order wins over wall-clock skew; negative ages never leak.
	scans[1].At = scans[0].At.Add(-time.Hour)
	if age := mustVerification(t, scans, "b").Buckets[0].Controls[0].Episodes[0].AgeSeconds; age != 0 {
		t.Fatal(age)
	}
}

func TestLegacyDetailsAreNotInvented(t *testing.T) {
	scans := workflowScans()[:2]
	scans[0].Reports[0].Controls = nil // Legacy incomplete-block summary: no individual flag history.
	scans[1].Reports = []BucketReport{demoReport("demo-verification-bucket", false, false)}
	first := mustVerification(t, scans, "a").Buckets[0]
	if first.OpenConcerns != 2 || first.Controls[4].Current.Value != nil || len(first.Controls[4].Episodes) != 0 {
		t.Fatal(first)
	}
	final := mustVerification(t, scans, "b").Buckets[0]
	if final.Assessment != "Verified clear for checked controls" || final.Controls[4].ComparedWith != nil || final.Controls[4].Change != "First successful observation" {
		t.Fatal(final)
	}
	// An explicitly unknown new observation cannot fall back to friendly strings.
	r := demoReport("bucket", false, false)
	r.Controls = &BucketControls{}
	if completeObservation(r) {
		t.Fatal("explicit unknown became a pass")
	}
}

func TestMissingConfigurationPreservesFlagUncertainty(t *testing.T) {
	scans := workflowScans()[:2]
	absent := demoReport("demo-verification-bucket", false, false)
	absent.BlockState = "configuration absent"
	absent.IncompleteBlock = true
	absent.Controls = &BucketControls{PolicyPublic: boolValue(false), BlockConfigurationPresent: boolValue(false)}
	scans[1].Reports = []BucketReport{absent}
	bucket := mustVerification(t, scans, "b").Buckets[0]
	if bucket.OpenConcerns != 1 || bucket.Controls[4].Current.State != "unknown" || bucket.Controls[4].Episodes[0].VerifiedClear != nil {
		t.Fatal(bucket)
	}
}

func TestVerificationExportRestartAndBatchRollback(t *testing.T) {
	a := testApp(t)
	a.state.Scans = workflowScans()
	if err := a.save(); err != nil {
		t.Fatal(err)
	}
	get := func(app *App, id string) []byte {
		w := request(app, "GET", "/verification?token="+app.token+"&id="+id, nil)
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		return w.Body.Bytes()
	}
	before := get(a, "b")
	var evidence VerificationRecord
	if err := json.Unmarshal(before, &evidence); err != nil || evidence.Version != 1 || evidence.Buckets[0].OpenConcerns != 2 {
		t.Fatal(err, evidence)
	}
	reloaded, err := loadApp(a.file)
	if err != nil {
		t.Fatal(err)
	}
	reloaded.host = a.host
	if string(get(reloaded, "b")) != string(before) {
		t.Fatal("restart rewrote historical verification")
	}
	if request(a, "POST", "/verification?token="+a.token, nil).Code != 405 || request(a, "GET", "/verification?id=b", nil).Code != 403 || request(a, "GET", "/verification?token="+a.token+"&id=missing", nil).Code != 404 {
		t.Fatal("export boundaries")
	}
	a.initGuide()
	savedFile := a.file
	original, _ := os.ReadFile(savedFile)
	a.file = filepath.Join(filepath.Dir(a.file), "blocked")
	if err := os.Mkdir(a.file, 0700); err != nil {
		t.Fatal(err)
	}
	out := request(a, "POST", "/?token="+a.token, url.Values{"action": {"demo-verification"}})
	if !strings.Contains(out.Body.String(), "Could not save scan") || len(a.state.Scans) != 4 {
		t.Fatal("batch rollback failed")
	}
	after, _ := os.ReadFile(savedFile)
	if string(after) != string(original) {
		t.Fatal("earlier history changed")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(a.file), "onboarding.json")); !os.IsNotExist(err) {
		t.Fatal("failed batch completed guide")
	}
}

func TestReplayDoesNotMutateObservationsAndLinksAreSeparate(t *testing.T) {
	a := testApp(t)
	a.state.Scans = workflowScans()
	before, _ := json.Marshal(a.state.Scans)
	a.state.Tickets["https://jira.example|SYNTHETIC VERIFICATION DEMO|demo-verification-bucket"] = Ticket{Key: "SEC-0", State: "linked"}
	record, err := a.verificationRecord("b")
	if err != nil {
		t.Fatal(err)
	}
	if len(record.CurrentTicketLinks) != 0 {
		t.Fatal("synthetic export included Jira mappings")
	}
	untouched, _ := json.Marshal(a.state.Scans)
	if string(untouched) != string(before) {
		t.Fatal("synthetic replay mutated observations")
	}
	for i := range a.state.Scans {
		a.state.Scans[i].Demo = false
		a.state.Scans[i].Scope = "123456789012 / us-east-1"
	}
	a.state.Tickets = map[string]Ticket{
		"https://jira.example|123456789012 / us-east-1|demo-verification-bucket": {Key: "SEC-7", State: "linked"},
		"https://jira.example|999999999999 / us-east-1|demo-verification-bucket": {Key: "SEC-8", State: "linked"},
	}
	liveBefore, _ := json.Marshal(a.state.Scans)
	record, err = a.verificationRecord("b")
	if err != nil {
		t.Fatal(err)
	}
	if len(record.CurrentTicketLinks) != 1 || record.CurrentTicketLinks[0].Key != "SEC-7" {
		t.Fatal(record.CurrentTicketLinks)
	}
	after, _ := json.Marshal(a.state.Scans)
	if string(after) != string(liveBefore) {
		t.Fatal("replay mutated observations")
	}
	text := verificationSummary(record, "demo-verification-bucket")
	if !strings.Contains(text, "unresolved aggregate checks: 2") || !strings.Contains(text, "scan a") || strings.Contains(text, "AccessDenied") {
		t.Fatal(text)
	}
}

func TestMalformedHistoryIDsRejected(t *testing.T) {
	for _, ids := range [][]string{{""}, {"duplicate", "duplicate"}} {
		a := testApp(t)
		for _, id := range ids {
			scan := demoScan()
			scan.ID = id
			a.state.Scans = append(a.state.Scans, scan)
		}
		if err := a.save(); err != nil {
			t.Fatal(err)
		}
		if _, err := loadApp(a.file); err == nil {
			t.Fatal("ambiguous history accepted", ids)
		}
	}
}
