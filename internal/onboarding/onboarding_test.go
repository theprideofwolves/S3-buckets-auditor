package onboarding

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func req(h http.Handler, method, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := httptest.NewRecorder()
	h.ServeHTTP(out, r)
	return out
}
func TestFirstRunChoiceAndPersistence(t *testing.T) {
	dir := t.TempDir()
	w := New(Config{Name: "Example", Token: "private", Dir: dir, Expected: "one synthetic result", DemoFields: map[string]string{"action": "demo"}})
	calls := 0
	h := w.Wrap(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) { calls++; io.WriteString(out, "workspace") }))
	out := req(h, "GET", "/?token=private", nil)
	if out.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("form-compatible referrer policy missing")
	}
	if out.Code != 200 || !strings.Contains(out.Body.String(), "Try the guided demo") || calls != 0 {
		t.Fatal(out.Body.String(), calls)
	}
	out = req(h, "POST", "/onboarding/start?token=private", url.Values{"mode": {"own"}})
	if out.Code != 303 {
		t.Fatal(out.Code)
	}
	out = req(h, "GET", "/?token=private", nil)
	if out.Body.String() != "workspace" {
		t.Fatal(out.Body.String())
	}
	if _, e := os.Stat(filepath.Join(dir, "onboarding.json")); !os.IsNotExist(e) {
		t.Fatal("choice falsely marked successful")
	}
	w.Complete()
	next := New(w.c)
	if !next.done || !next.started {
		t.Fatal("completion not remembered")
	}
	out = req(h, "GET", "/welcome?token=private", nil)
	if !strings.Contains(out.Body.String(), "Already have results?") {
		t.Fatal("guide not restartable")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "onboarding.json"))
	var state map[string]any
	if json.Unmarshal(b, &state) != nil || len(state) != 2 {
		t.Fatal(string(b))
	}
}
func TestSetupChecksAreNonDestructiveAndPrefill(t *testing.T) {
	calls := 0
	checks := 0
	w := New(Config{Name: "Example", Token: "t", Folder: true, Fields: []Field{{Name: "path", Label: "Folder"}}, Check: func(ctx context.Context, v map[string]string) (string, error) {
		checks++
		if v["path"] != "<script>" {
			t.Fatal(v)
		}
		return "Readable, not scanned", nil
	}, Picker: func(context.Context) (string, error) { return "/chosen/folder", nil }})
	h := w.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	out := req(h, "POST", "/setup/check?token=t", url.Values{"check": {"input"}, "path": {"<script>"}})
	if out.Code != 200 || !strings.Contains(out.Body.String(), "Readable, not scanned") || strings.Contains(out.Body.String(), "value=\"<script>") || calls != 0 || checks != 1 {
		t.Fatal(out.Body.String())
	}
	req(h, "POST", "/setup/check?token=t", url.Values{"check": {"browse"}})
	if w.Value("path") != "/chosen/folder" || calls != 0 {
		t.Fatal("picker ran task")
	}
}
func TestRequestAndSampleBoundaries(t *testing.T) {
	w := New(Config{Token: "t", Host: "localhost", Samples: []Sample{{"example.txt", "synthetic"}}})
	h := w.Wrap(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) { out.WriteHeader(204) }))
	for _, tc := range []struct {
		method, path string
		code         int
	}{{"GET", "/", 403}, {"DELETE", "/?token=t", 405}, {"GET", "/onboarding/start?token=t", 405}, {"GET", "/setup/check?token=t", 405}, {"POST", "/welcome?token=t", 405}, {"GET", "/onboarding/sample?token=t&name=../../secret", 404}} {
		if got := req(h, tc.method, tc.path, nil).Code; got != tc.code {
			t.Fatalf("%s %s: %d", tc.method, tc.path, got)
		}
	}
	out := req(h, "GET", "/onboarding/sample?token=t&name=example.txt", nil)
	if out.Body.String() != "synthetic" || !strings.Contains(out.Header().Get("Content-Disposition"), "example.txt") {
		t.Fatal(out)
	}
	if req(h, "POST", "/onboarding/start?token=t", url.Values{"mode": {"wrong"}}).Code != 400 {
		t.Fatal("bad choice")
	}
	if req(h, "POST", "/setup/check?token=t", url.Values{"check": {"unknown"}}).Code != 400 {
		t.Fatal("bad check")
	}
	if req(h, "POST", "/setup/check?token=t", url.Values{"path": {strings.Repeat("x", 40<<10)}}).Code != 400 {
		t.Fatal("oversized request accepted")
	}
	r := httptest.NewRequest("POST", "http://localhost/setup/check?token=t", nil)
	r.Header.Set("Origin", "https://evil.test")
	out = httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 403 {
		t.Fatal("origin")
	}
	r = httptest.NewRequest("POST", "http://localhost/setup/check?token=t", nil)
	r.Header.Set("Origin", "null")
	out = httptest.NewRecorder()
	h.ServeHTTP(out, r)
	if out.Code != 403 {
		t.Fatal("opaque origin allowed")
	}
}
func TestJiraReadOnlyAndNoCredentialRetention(t *testing.T) {
	for _, tc := range []struct {
		status  int
		body    string
		success bool
	}{{200, `{"accountId":"test-account"}`, true}, {200, `{}`, false}, {401, `{}`, false}, {403, `{}`, false}, {429, `{}`, false}, {503, `{}`, false}, {302, `{}`, false}} {
		t.Run(string(rune(tc.status)), func(t *testing.T) {
			calls := 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "GET" || r.URL.Path != "/rest/api/3/myself" {
					t.Error("destructive or wrong request")
				}
				if user, password, ok := r.BasicAuth(); !ok || user != "analyst@example.test" || password != "sensitive-only-for-test" {
					t.Error("authentication")
				}
				out.Header().Set("Location", "https://never-follow.invalid")
				out.WriteHeader(tc.status)
				io.WriteString(out, tc.body)
			}))
			defer srv.Close()
			dir := t.TempDir()
			w := New(Config{Token: "t", Dir: dir, Jira: true, Client: srv.Client(), Fields: []Field{{Name: "path", Default: "/selected"}}})
			h := w.Wrap(http.NotFoundHandler())
			out := req(h, "POST", "/setup/check?token=t", url.Values{"check": {"jira"}, "jira": {srv.URL}, "email": {"analyst@example.test"}, "secret": {"sensitive-only-for-test"}})
			if out.Code != 200 || calls != 1 {
				t.Fatal(out.Code, calls)
			}
			if strings.Contains(out.Body.String(), "Jira sign-in works") != tc.success {
				t.Fatal(out.Body.String())
			}
			if strings.Contains(out.Body.String(), "sensitive-only-for-test") || strings.Contains(out.Body.String(), "analyst@example.test") {
				t.Fatal("credential echoed")
			}
			if w.Value("secret") != "" || w.Value("email") != "" || w.done || w.Value("path") != "/selected" {
				t.Fatal("credential or completion retained")
			}
			files, _ := os.ReadDir(dir)
			if len(files) != 0 {
				t.Fatal("check persisted data")
			}
		})
	}
}
func TestFolderAndPreferenceFailures(t *testing.T) {
	dir := t.TempDir()
	if _, e := CheckFolder(context.Background(), map[string]string{"path": dir}); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{"relative", filepath.Join(dir, "missing")} {
		if _, e := CheckFolder(context.Background(), map[string]string{"path": p}); e == nil {
			t.Fatal(p)
		}
	}
	p := filepath.Join(dir, "file.txt")
	os.WriteFile(p, []byte("not a directory"), 0600)
	if _, e := CheckFolder(context.Background(), map[string]string{"path": p}); e == nil {
		t.Fatal("file accepted as folder")
	}
	os.WriteFile(filepath.Join(dir, "onboarding.json"), []byte("corrupt"), 0600)
	w := New(Config{Dir: dir})
	if w.done || w.started {
		t.Fatal("corrupt preference trusted")
	}
	w.c.Dir = filepath.Join(dir, "missing")
	w.Complete()
	if w.warning == "" {
		t.Fatal("preference write error hidden")
	}
}
