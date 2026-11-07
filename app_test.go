package main

import (
	"context"
	"errors"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCompareSafety(t *testing.T) {
	old := Scan{Scope: "account-a", Reports: []BucketReport{{Name: "risk", PublicPolicy: true}, {Name: "missing", PublicPolicy: true}}}
	for _, tc := range []struct {
		name string
		r    BucketReport
		want string
	}{
		{"persistent", BucketReport{Name: "risk", PublicPolicy: true}, "Persistent concern"},
		{"resolved", BucketReport{Name: "risk"}, "Verified clear for checked controls"},
		{"denied", BucketReport{Name: "risk", Errors: []string{"denied"}}, "Unknown — reassessment incomplete"},
		{"new", BucketReport{Name: "new", IncompleteBlock: true}, "New concern"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := compare(Scan{Scope: old.Scope, Reports: []BucketReport{tc.r}}, &old)
			if got[tc.r.Name] != tc.want || got["missing"] != "Not assessed in this scan" {
				t.Fatal(got)
			}
		})
	}
	if got := compare(Scan{Scope: "other", Reports: []BucketReport{{Name: "risk", PublicPolicy: true}}}, &old); got["risk"] != "New concern" {
		t.Fatal(got)
	}
}
func TestNamesAndKeyValidation(t *testing.T) {
	for _, s := range []string{"a", "UPPER-bucket", "abc/def", "abc def", "abc:443", strings.Repeat("a", 64)} {
		if _, e := namesFrom(s); e == nil {
			t.Errorf("accepted %q", s)
		}
	}
	v, e := namesFrom("abc,abc\nxyz\r\n")
	if e != nil || len(v) != 2 || v[0] != "abc" {
		t.Fatal(v, e)
	}
	for _, s := range []string{"SEC-1/../../x", "SEC-", "-123", "sec-1", "SEC-a"} {
		if validKey(s) {
			t.Fatal(s)
		}
	}
	if !validKey("SEC-123") {
		t.Fatal("key")
	}
}
func TestStorage(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nested", "history.json")
	a, e := loadApp(p)
	if e != nil {
		t.Fatal(e)
	}
	a.state.Scans = append(a.state.Scans, demoScan())
	if e = a.save(); e != nil {
		t.Fatal(e)
	}
	b, e := loadApp(p)
	if e != nil || len(b.state.Scans) != 1 {
		t.Fatal(e)
	}
	if e = b.save(); e != nil {
		t.Fatal("replace existing history", e)
	}
	os.WriteFile(p, []byte("broken"), 0600)
	if _, e = loadApp(p); e == nil {
		t.Fatal("corrupt history accepted")
	}
}
func testApp(t *testing.T) *App {
	t.Helper()
	a, e := loadApp(filepath.Join(t.TempDir(), "history.json"))
	if e != nil {
		t.Fatal(e)
	}
	a.host = "127.0.0.1:1234"
	return a
}
func request(a *App, method, path string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://"+a.host+path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	a.handler(w, r)
	return w
}
func TestLocalBoundariesAndDemo(t *testing.T) {
	a := testApp(t)
	if request(a, "GET", "/", nil).Code != 403 {
		t.Fatal("token")
	}
	p := "/?token=" + a.token
	if request(a, "PUT", p, nil).Code != 405 {
		t.Fatal("method")
	}
	r := httptest.NewRequest("GET", "http://evil.test"+p, nil)
	w := httptest.NewRecorder()
	a.handler(w, r)
	if w.Code != 403 {
		t.Fatal("host")
	}
	r = httptest.NewRequest("POST", "http://"+a.host+p, strings.NewReader("action=demo"))
	r.Header.Set("Origin", "https://evil.test")
	w = httptest.NewRecorder()
	a.handler(w, r)
	if w.Code != 403 {
		t.Fatal("origin")
	}
	w = request(a, "POST", p, url.Values{"action": {"demo"}})
	if w.Code != 200 || !strings.Contains(w.Body.String(), "SYNTHETIC") || len(a.state.Scans) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	s := a.state.Scans[0]
	w = request(a, "GET", "/export?token="+a.token+"&id="+s.ID, nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), s.ID) {
		t.Fatal(w.Code)
	}
	w = request(a, "POST", p, url.Values{"action": {"ticket"}, "id": {s.ID}})
	if !strings.Contains(w.Body.String(), "synthetic data cannot") {
		t.Fatal(w.Body.String())
	}
}
func TestOversizedAndEscaping(t *testing.T) {
	a := testApp(t)
	a.state.Scans = []Scan{{ID: "test", Reports: []BucketReport{{Name: "<script>alert(1)</script>"}}}}
	w := request(a, "GET", "/?token="+a.token, nil)
	if strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("XSS")
	}
	w = request(a, "POST", "/?token="+a.token, url.Values{"action": {strings.Repeat("x", 70<<10)}})
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
}
func TestJiraURL(t *testing.T) {
	for _, s := range []string{"http://jira.test", "https://user:pass@jira.test", "https://jira.test/path", "https://jira.test?x=1", "https://jira.test#x"} {
		if _, e := jiraBase(s); e == nil {
			t.Fatal(s)
		}
	}
	if _, e := jiraBase("https://team.atlassian.net/"); e != nil {
		t.Fatal(e)
	}
}
func TestJiraCreateDedupAndUncertain(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   string
	}{{"created", 201, `{"key":"SEC-123"}`, "linked"}, {"denied", 403, `{"error":"secret must not be shown"}`, "rejected"}, {"throttled", 429, `{}`, "uncertain"}, {"server", 503, `{}`, "uncertain"}, {"invalid response", 201, `{}`, "uncertain"}} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if u, p, ok := r.BasicAuth(); !ok || u != "analyst@test.com" || p != "private-token" {
					t.Error("auth")
				}
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			a := testApp(t)
			a.client = server.Client()
			a.state.Scans = []Scan{{ID: "live", Scope: "123 / us-east-1", At: time.Now(), Reports: []BucketReport{{Name: "bucket", PublicPolicy: true}}}}
			f := url.Values{"action": {"ticket"}, "id": {"live"}, "bucket": {"bucket"}, "url": {server.URL}, "email": {"analyst@test.com"}, "secret": {"private-token"}, "project": {"SEC"}, "kind": {"Task"}}
			r := httptest.NewRequest("POST", "/", strings.NewReader(f.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.ParseForm()
			a.action(r)
			key := server.URL + "|123 / us-east-1|bucket"
			if a.state.Tickets[key].State != tc.want {
				t.Fatal(a.state.Tickets)
			}
			if tc.want == "uncertain" {
				a.action(r)
				if calls != 1 {
					t.Fatal("blind duplicate create")
				}
			} else {
				a.action(r)
				if calls != 2 {
					t.Fatal("expected comment")
				}
			}
			data, _ := os.ReadFile(a.file)
			if strings.Contains(string(data), "private-token") {
				t.Fatal("secret persisted")
			}
		})
	}
}

type emptyAPI struct {
	fakeAPI
	partial bool
}

func (f emptyAPI) GetBucketPolicyStatus(context.Context, *s3.GetBucketPolicyStatusInput, ...func(*s3.Options)) (*s3.GetBucketPolicyStatusOutput, error) {
	return nil, nil
}
func (f emptyAPI) GetPublicAccessBlock(context.Context, *s3.GetPublicAccessBlockInput, ...func(*s3.Options)) (*s3.GetPublicAccessBlockOutput, error) {
	if f.partial {
		return &s3.GetPublicAccessBlockOutput{PublicAccessBlockConfiguration: &types.PublicAccessBlockConfiguration{}}, nil
	}
	return nil, nil
}
func TestEmptyAndCancellation(t *testing.T) {
	for _, f := range []emptyAPI{{}, {partial: true}} {
		r := inspect(context.Background(), f, "bucket")
		if len(r.Errors) != 2 {
			t.Fatal(r)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := audit(ctx, fakeAPI{}, []string{"abc", "abc", "def"}, 100)
	if len(r) != 2 {
		t.Fatal(r)
	}
	for _, v := range r {
		if len(v.Errors) == 0 {
			t.Fatal("cancel looked clean")
		}
	}
	if len(audit(ctx, fakeAPI{}, nil, 0)) != 0 {
		t.Fatal("empty")
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }
func TestReportWriteFailure(t *testing.T) {
	if e := writeReports(failWriter{}, io.Discard, nil, time.Now()); e == nil {
		t.Fatal("lost error")
	}
	if e := writeReports(io.Discard, failWriter{}, []BucketReport{{Name: "bucket", Errors: []string{"denied"}}}, time.Now()); e == nil {
		t.Fatal("lost log error")
	}
}
func TestJiraLostResponseAndRedirect(t *testing.T) {
	for _, mode := range []string{"disconnect", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if mode == "disconnect" {
					h := w.(http.Hijacker)
					c, _, _ := h.Hijack()
					c.Close()
					return
				}
				w.Header().Set("Location", "https://should-not-follow.invalid/")
				w.WriteHeader(302)
			}))
			defer server.Close()
			a := testApp(t)
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			a.client = client
			if _, e := a.jira(context.Background(), server.URL, "e", "token", "POST", "/rest/api/3/issue", map[string]string{}); e == nil {
				t.Fatal("expected uncertain outcome")
			}
			if calls != 1 {
				t.Fatal(calls)
			}
		})
	}
}
func TestPersistenceFailureDoesNotSend(t *testing.T) {
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(201)
		io.WriteString(w, `{"key":"SEC-1"}`)
	}))
	defer server.Close()
	a := testApp(t)
	a.client = server.Client()
	a.file = filepath.Join(t.TempDir(), "directory")
	os.Mkdir(a.file, 0700)
	a.state.Scans = []Scan{{ID: "live", Scope: "123 / region", Reports: []BucketReport{{Name: "bucket", PublicPolicy: true}}}}
	f := url.Values{"action": {"ticket"}, "id": {"live"}, "bucket": {"bucket"}, "url": {server.URL}, "project": {"SEC"}, "kind": {"Task"}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	message := a.action(r)
	if calls != 0 || !strings.Contains(message, "no request sent") {
		t.Fatal(calls, message)
	}
}
func TestVerifiedLinkAndCommentPath(t *testing.T) {
	paths := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		w.WriteHeader(200)
		io.WriteString(w, `{}`)
	}))
	defer server.Close()
	a := testApp(t)
	a.client = server.Client()
	a.state.Scans = []Scan{{ID: "live", Scope: "account / region", Reports: []BucketReport{{Name: "bucket"}}}}
	f := url.Values{"action": {"link"}, "id": {"live"}, "bucket": {"bucket"}, "url": {server.URL}, "key": {"SEC-123"}}
	r := httptest.NewRequest("POST", "/", strings.NewReader(f.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ParseForm()
	a.action(r)
	r.Form.Set("action", "ticket")
	a.action(r)
	if len(paths) != 2 || paths[0] != "GET /rest/api/3/issue/SEC-123" || paths[1] != "POST /rest/api/3/issue/SEC-123/comment" {
		t.Fatal(paths)
	}
}
