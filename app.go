package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

type Scan struct {
	ID, Scope string
	At        time.Time
	Demo      bool
	Reports   []BucketReport
}
type Ticket struct{ Key, State string }
type History struct {
	Scans   []Scan
	Tickets map[string]Ticket
}
type App struct {
	mu                sync.Mutex
	file, token, host string
	state             History
	client            *http.Client
}

func randomID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func loadApp(file string) (*App, error) {
	a := &App{file: file, token: randomID(), client: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	a.state.Tickets = map[string]Ticket{}
	b, e := os.ReadFile(file)
	if errors.Is(e, os.ErrNotExist) {
		return a, nil
	}
	if e != nil {
		return nil, e
	}
	if e = json.Unmarshal(b, &a.state); e != nil {
		return nil, fmt.Errorf("history cannot be read; restore a backup rather than overwriting it: %w", e)
	}
	if a.state.Tickets == nil {
		a.state.Tickets = map[string]Ticket{}
	}
	return a, nil
}
func (a *App) save() error {
	if e := os.MkdirAll(filepath.Dir(a.file), 0700); e != nil {
		return e
	}
	b, e := json.MarshalIndent(a.state, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(a.file), "history-*.tmp")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(name, a.file)
}
func concern(r BucketReport) bool { return r.PublicPolicy || r.IncompleteBlock }
func compare(now Scan, old *Scan) map[string]string {
	out := map[string]string{}
	prior := map[string]BucketReport{}
	if old != nil && old.Scope == now.Scope {
		for _, r := range old.Reports {
			prior[r.Name] = r
		}
	}
	for _, r := range now.Reports {
		p, ok := prior[r.Name]
		s := "Checked controls enabled"
		switch {
		case len(r.Errors) > 0:
			s = "Unknown â€” reassessment incomplete"
		case concern(r) && (!ok):
			s = "New concern"
		case concern(r) && concern(p):
			s = "Persistent concern"
		case concern(r):
			s = "New concern"
		case ok && concern(p):
			s = "Verified clear for checked controls"
		}
		out[r.Name] = s
		delete(prior, r.Name)
	}
	for name := range prior {
		out[name] = "Not assessed in this scan"
	}
	return out
}
func namesFrom(s string) ([]string, error) {
	set := map[string]bool{}
	for _, n := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if len(n) < 3 || len(n) > 63 || strings.ContainsAny(n, " /\\:\t") {
			return nil, fmt.Errorf("invalid bucket name %q", n)
		}
		for _, c := range n {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
				return nil, fmt.Errorf("invalid bucket name %q", n)
			}
		}
		set[n] = true
	}
	if len(set) > 1000 {
		return nil, errors.New("select at most 1000 buckets per scan")
	}
	out := []string{}
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}
func collect(ctx context.Context, profile, region, targets string) (Scan, error) {
	scan := Scan{ID: randomID(), At: time.Now().UTC()}
	names, e := namesFrom(targets)
	if e != nil {
		return scan, e
	}
	opts := []func(*config.LoadOptions) error{config.WithRegion(region)}
	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}
	cfg, e := config.LoadDefaultConfig(ctx, opts...)
	if e != nil {
		return scan, errors.New("AWS configuration failed; check the selected profile and SSO session")
	}
	id, e := sts.NewFromConfig(cfg).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if e != nil || id.Account == nil {
		return scan, errors.New("AWS identity check failed; sign in to your profile and check connectivity")
	}
	scan.Scope = *id.Account + " / " + region
	client := s3.NewFromConfig(cfg)
	if len(names) == 0 {
		pager := s3.NewListBucketsPaginator(client, &s3.ListBucketsInput{})
		for pager.HasMorePages() {
			page, e := pager.NextPage(ctx)
			if e != nil {
				return scan, errors.New("bucket discovery failed; check ListBuckets permissions or specify bucket names")
			}
			for _, b := range page.Buckets {
				if b.Name != nil {
					names = append(names, *b.Name)
				}
			}
			if len(names) > 1000 {
				return scan, errors.New("discovery exceeds 1000 buckets; specify a smaller scope")
			}
		}
	}
	// Wrong-region responses remain explicit inspection errors, never clean results.
	scan.Reports = audit(ctx, client, names, 8)
	if ctx.Err() != nil {
		return scan, errors.New("scan timed out or was cancelled; no complete scan was saved")
	}
	return scan, nil
}
func demoScan() Scan {
	return Scan{ID: randomID(), Scope: "SYNTHETIC DEMO", Demo: true, At: time.Now().UTC(), Reports: []BucketReport{{Name: "demo-public-policy", PublicPolicy: true}, {Name: "demo-incomplete-block", IncompleteBlock: true}, {Name: "demo-checked-controls"}, {Name: "demo-access-denied", Errors: []string{"policy: AccessDenied (synthetic)"}}}}
}
func ticketID(scope, bucket string) string { return scope + "|" + bucket }
func jiraBase(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return "", errors.New("Jira URL must be an HTTPS origin, e.g. https://team.atlassian.net")
	}
	return strings.TrimSuffix(raw, "/"), nil
}

type jiraHTTPError struct{ Status int }

func (e *jiraHTTPError) Error() string {
	return fmt.Sprintf("Jira returned HTTP %d; check credentials, permissions, required fields, and rate limits", e.Status)
}
func (a *App) jira(ctx context.Context, base, email, secret, method, path string, body any) (string, error) {
	b, e := json.Marshal(body)
	if e != nil {
		return "", e
	}
	req, e := http.NewRequestWithContext(ctx, method, base+path, strings.NewReader(string(b)))
	if e != nil {
		return "", e
	}
	req.SetBasicAuth(email, secret)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, e := a.client.Do(req)
	if e != nil {
		return "", errors.New("Jira connection failed; outcome may be uncertain")
	}
	defer resp.Body.Close()
	data, e := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if e != nil {
		return "", errors.New("Jira response incomplete; reconcile before retry")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", &jiraHTTPError{Status: resp.StatusCode}
	}
	if method == "POST" && strings.HasSuffix(path, "/issue") {
		var v struct{ Key string }
		if json.Unmarshal(data, &v) != nil || !validKey(v.Key) {
			return "", errors.New("Jira returned no issue key; reconcile before retry")
		}
		return v.Key, nil
	}
	return "", nil
}
func adf(text string) any {
	return map[string]any{"type": "doc", "version": 1, "content": []any{map[string]any{"type": "paragraph", "content": []any{map[string]string{"type": "text", "text": text}}}}}
}
func (a *App) handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	if r.Host != a.host {
		http.Error(w, "Invalid host", 403)
		return
	}
	if r.URL.Query().Get("token") != a.token {
		http.Error(w, "Open the application using its launcher URL", 403)
		return
	}
	if r.Method != "GET" && r.Method != "POST" {
		http.Error(w, "Method not allowed", 405)
		return
	}
	if r.Method == "POST" {
		if o := r.Header.Get("Origin"); o != "" && o != "http://"+a.host {
			http.Error(w, "Invalid origin", 403)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if e := r.ParseForm(); e != nil {
			http.Error(w, "Invalid or oversized request", 400)
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path == "/export" {
		if r.Method != "GET" {
			http.Error(w, "GET required", 405)
			return
		}
		for _, s := range a.state.Scans {
			if s.ID == r.URL.Query().Get("id") {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Disposition", "attachment; filename=scan-"+s.ID+".json")
				json.NewEncoder(w).Encode(s)
				return
			}
		}
		http.NotFound(w, r)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	message := ""
	if r.Method == "POST" {
		message = a.action(r)
	}
	var selected *Scan
	id := r.URL.Query().Get("scan")
	for i := len(a.state.Scans) - 1; i >= 0; i-- {
		if id == "" || a.state.Scans[i].ID == id {
			selected = &a.state.Scans[i]
			break
		}
	}
	delta := map[string]string{}
	if selected != nil {
		var old *Scan
		for i := range a.state.Scans {
			v := &a.state.Scans[i]
			if v.ID == selected.ID {
				break
			}
			if v.Scope == selected.Scope {
				old = v
			}
		}
		delta = compare(*selected, old)
	}
	data := struct {
		Token, Message string
		Selected       *Scan
		Scans          []Scan
		Delta          map[string]string
		Tickets        map[string]Ticket
	}{a.token, message, selected, a.state.Scans, delta, a.state.Tickets}
	if e := page.Execute(w, data); e != nil {
		return
	}
}
func (a *App) action(r *http.Request) string {
	switch r.FormValue("action") {
	case "demo", "scan":
		var s Scan
		var e error
		if r.FormValue("action") == "demo" {
			s = demoScan()
		} else {
			region := strings.TrimSpace(r.FormValue("region"))
			if region == "" {
				return "Choose the AWS region first."
			}
			ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
			defer cancel()
			s, e = collect(ctx, strings.TrimSpace(r.FormValue("profile")), region, r.FormValue("targets"))
			if e != nil {
				return e.Error()
			}
		}
		a.state.Scans = append(a.state.Scans, s)
		if e = a.save(); e != nil {
			a.state.Scans = a.state.Scans[:len(a.state.Scans)-1]
			return "Could not save scan; check disk space and data directory permissions."
		}
		return "Scan saved. Review individual observations and coverage before creating a ticket."
	case "ticket", "link":
		var selected *Scan
		for i := range a.state.Scans {
			if a.state.Scans[i].ID == r.FormValue("id") {
				selected = &a.state.Scans[i]
			}
		}
		if selected == nil || selected.Demo {
			return "Choose a live scan; synthetic data cannot create real Jira issues."
		}
		var report *BucketReport
		for i := range selected.Reports {
			if selected.Reports[i].Name == r.FormValue("bucket") {
				report = &selected.Reports[i]
			}
		}
		if report == nil {
			return "Bucket not found."
		}
		base, e := jiraBase(r.FormValue("url"))
		if e != nil {
			return e.Error()
		}
		keyID := base + "|" + ticketID(selected.Scope, report.Name)
		previous := a.state.Tickets[keyID]
		if r.FormValue("action") == "link" {
			key := strings.TrimSpace(r.FormValue("key"))
			if !validKey(key) {
				return "Enter a Jira key such as SEC-123."
			}
			if _, e = a.jira(r.Context(), base, r.FormValue("email"), r.FormValue("secret"), "GET", "/rest/api/3/issue/"+key, nil); e != nil {
				return e.Error()
			}
			a.state.Tickets[keyID] = Ticket{Key: key, State: "linked"}
			if e = a.save(); e != nil {
				a.state.Tickets[keyID] = previous
				return "Could not save link."
			}
			return "Existing Jira issue linked; updates will use this issue."
		}
		if previous.State == "pending" || previous.State == "uncertain" {
			return "A previous create may have succeeded. Find the issue in Jira using the correlation ID below, then link its key before retrying."
		}
		if len(report.Errors) > 0 {
			return "Inspection incomplete: rescan successfully before sending verification or findings."
		}
		status, _ := report.Status()
		description := fmt.Sprintf("S3 configuration review\nAccount/region: %s\nBucket: %s\nObserved: %s\nPublic policy: %t; incomplete block: %t\nScan: %s at %s\nCorrelation: %s\nScope: bucket policy status and bucket-level Public Access Block only. Not proof of effective anonymous access. A clear rescan verifies only these checks; analyst review is required. No automatic ticket closure.", selected.Scope, report.Name, status, report.PublicPolicy, report.IncompleteBlock, selected.ID, selected.At.Format(time.RFC3339), keyID)
		if previous.Key != "" {
			_, e = a.jira(r.Context(), base, r.FormValue("email"), r.FormValue("secret"), "POST", "/rest/api/3/issue/"+previous.Key+"/comment", map[string]any{"body": adf(description)})
			if e != nil {
				return e.Error()
			}
			return "Evidence comment added to " + previous.Key + ". Ticket status was not changed."
		}
		if !concern(*report) {
			return "No observed concern to create a new ticket for."
		}
		project := strings.TrimSpace(r.FormValue("project"))
		kind := strings.TrimSpace(r.FormValue("kind"))
		if project == "" || kind == "" {
			return "Project key and issue type are required."
		}
		a.state.Tickets[keyID] = Ticket{State: "pending"}
		if e = a.save(); e != nil {
			a.state.Tickets[keyID] = previous
			return "Cannot persist delivery intent; no request sent."
		}
		key, e := a.jira(r.Context(), base, r.FormValue("email"), r.FormValue("secret"), "POST", "/rest/api/3/issue", map[string]any{"fields": map[string]any{"project": map[string]string{"key": project}, "issuetype": map[string]string{"name": kind}, "summary": "Review S3 configuration: " + report.Name, "description": adf(description)}})
		if e != nil {
			a.state.Tickets[keyID] = Ticket{State: "uncertain"}
			var remote *jiraHTTPError
			if errors.As(e, &remote) && (remote.Status == 400 || remote.Status == 401 || remote.Status == 403 || remote.Status == 404 || remote.Status == 422) {
				a.state.Tickets[keyID] = Ticket{State: "rejected"}
				if se := a.save(); se != nil {
					a.state.Tickets[keyID] = Ticket{State: "uncertain"}
					return "Could not save rejected delivery; reconcile before retry."
				}
				return e.Error() + ". Request rejected; correct the settings and retry."
			}
			if se := a.save(); se != nil {
				return "Jira outcome uncertain and save failed; restart and reconcile before retrying."
			}
			return e.Error() + ". Reconcile in Jira and link the issue key before retrying. Correlation: " + keyID
		}
		a.state.Tickets[keyID] = Ticket{Key: key, State: "linked"}
		if e = a.save(); e != nil {
			a.state.Tickets[keyID] = Ticket{State: "uncertain"}
			return "Created " + key + " but could not save its key. Record and link it before retrying."
		}
		return "Created " + key
	default:
		return "Unknown action."
	}
}
func validKey(s string) bool {
	p := strings.Split(s, "-")
	if len(p) != 2 || p[0] == "" || p[1] == "" {
		return false
	}
	for _, c := range p[0] {
		if !(c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	for _, c := range p[1] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
func launch() error {
	dir := os.Getenv("S3_AUDITOR_DATA_DIR")
	if dir == "" {
		d, e := os.UserConfigDir()
		if e != nil {
			return e
		}
		dir = filepath.Join(d, "S3Auditor")
	}
	if e := os.MkdirAll(dir, 0700); e != nil {
		return e
	}
	lock := filepath.Join(dir, "application.lock")
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("another launcher may be running; close it first. After a crash, remove %s only after confirming no instance is running", lock)
	}
	fmt.Fprintln(f, os.Getpid())
	f.Close()
	defer os.Remove(lock)
	a, e := loadApp(filepath.Join(dir, "history.json"))
	if e != nil {
		return e
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		return e
	}
	a.host = listener.Addr().String()
	address := "http://" + a.host + "/?token=" + a.token
	fmt.Println("S3 Auditor â€” open", address, "\nData:", dir, "\nClose this launcher with Ctrl+C to stop. Closing the browser alone does not stop the server.")
	if os.Getenv("S3_AUDITOR_NO_BROWSER") == "" {
		var cmd *exec.Cmd
		switch runtime.GOOS {
		case "windows":
			cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", address)
		case "darwin":
			cmd = exec.Command("open", address)
		default:
			cmd = exec.Command("xdg-open", address)
		}
		if e := cmd.Start(); e == nil {
			go cmd.Wait()
		}
	}
	server := &http.Server{Handler: http.HandlerFunc(a.handler), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() { <-ctx.Done(); server.Close() }()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

var page = template.Must(template.New("page").Funcs(template.FuncMap{"tid": ticketID}).Parse(pageHTML))
