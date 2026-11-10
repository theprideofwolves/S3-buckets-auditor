// Package onboarding provides a local, explicit first-task guide without changing domain results.
package onboarding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/theprideofwolves/S3-buckets-auditor/internal/webui"
)

type Field struct{ Name, Label, Hint, Default string }
type Config struct {
	Name, Token, Host, Dir, Intro, Expected, Next string
	Steps                                         []string
	Fields                                        []Field
	DemoFields                                    map[string]string
	Jira                                          bool
	Check                                         func(context.Context, map[string]string) (string, error)
	Client                                        *http.Client
}
type Wizard struct {
	mu                  sync.Mutex
	c                   Config
	started, done, demo bool
	ready               bool
	values              map[string]string
	warning             string
}

func New(c Config) *Wizard {
	w := &Wizard{c: c, values: map[string]string{}}
	for _, f := range c.Fields {
		w.values[f.Name] = f.Default
	}
	if c.Client == nil {
		w.c.Client = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	if c.Dir != "" {
		b, e := os.ReadFile(filepath.Join(c.Dir, "onboarding.json"))
		var state struct {
			Version   int
			Completed bool
		}
		if e == nil && json.Unmarshal(b, &state) == nil && state.Version == 1 && state.Completed {
			w.started = true
			w.done = true
		}
	}
	return w
}
func (w *Wizard) Value(key string) string { w.mu.Lock(); defer w.mu.Unlock(); return w.values[key] }
func (w *Wizard) Complete() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.started = true
	w.done = true
	w.ready = true
	if w.c.Dir == "" {
		return
	}
	b := []byte(`{"Version":1,"Completed":true}`)
	f, e := os.CreateTemp(w.c.Dir, "onboarding-*.tmp")
	if e == nil {
		name := f.Name()
		defer os.Remove(name)
		e = f.Chmod(0600)
		if e == nil {
			_, e = f.Write(b)
		}
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e == nil {
			e = os.Rename(name, filepath.Join(w.c.Dir, "onboarding.json"))
		}
	}
	if e != nil {
		w.warning = "Guide progress could not be saved. Your result is still available; export it before closing."
	}
}
func (w *Wizard) Panel() template.HTML {
	w.mu.Lock()
	data := struct {
		Name, Token, Expected, Next, Warning string
		Done, Demo, Ready                    bool
	}{w.c.Name, w.c.Token, w.c.Expected, w.c.Next, w.warning, w.done, w.demo, w.ready}
	w.mu.Unlock()
	var b bytes.Buffer
	panel.Execute(&b, data)
	return template.HTML(b.String())
}

var panel = template.Must(template.New("panel").Parse(`<section class="guide" aria-label="Getting started"><h2>{{if .Ready}}Your first result is ready{{else if .Done}}Welcome back{{else}}Your first task{{end}}</h2>{{if .Demo}}<p><strong>Guided demo - synthetic data.</strong> {{.Expected}}</p>{{else if not .Ready}}<p>Run an assessment or use the offline demo. Review unknowns before exporting evidence.</p>{{end}}{{if .Ready}}<p>{{.Next}}</p><p><a href="#results">Review my result</a></p>{{else if .Done}}<p>Your saved scans are available below.</p>{{end}}{{if .Warning}}<p role="status">{{.Warning}}</p>{{end}}<p class="actions"><a href="/welcome?token={{.Token}}">Restart the guide</a><a href="/setup?token={{.Token}}">Use my data / setup checks</a></p></section>`))

func (w *Wizard) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(out http.ResponseWriter, r *http.Request) {
		out.Header().Set("Cache-Control", "no-store")
		out.Header().Set("Referrer-Policy", "same-origin")
		out.Header().Set("X-Content-Type-Options", "nosniff")
		out.Header().Set("Content-Security-Policy", webui.CSP)
		if r.URL.Query().Get("token") != w.c.Token || (w.c.Host != "" && r.Host != w.c.Host) {
			http.Error(out, "Open the private launcher URL", 403)
			return
		}
		if r.Method != "GET" && r.Method != "POST" {
			http.Error(out, "Method not allowed", 405)
			return
		}
		if r.Method == "POST" {
			if o := r.Header.Get("Origin"); o != "" && o != "http://"+r.Host {
				http.Error(out, "Invalid origin", 403)
				return
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				http.Error(out, "Cross-site request blocked", 403)
				return
			}
		}
		path := r.URL.Path
		if path == "/onboarding/start" {
			if r.Method != "POST" {
				http.Error(out, "POST required", 405)
				return
			}
			r.Body = http.MaxBytesReader(out, r.Body, 16<<10)
			if e := r.ParseForm(); e != nil {
				http.Error(out, "Invalid request", 400)
				return
			}
			if r.FormValue("mode") != "own" && r.FormValue("mode") != "resume" {
				http.Error(out, "Choose your own data or resume", 400)
				return
			}
			w.mu.Lock()
			w.started = true
			w.demo = false
			w.mu.Unlock()
			http.Redirect(out, r, "/?token="+url.QueryEscape(w.c.Token), http.StatusSeeOther)
			return
		}
		if path == "/setup/check" {
			if r.Method != "POST" {
				http.Error(out, "POST required", 405)
				return
			}
			r.Body = http.MaxBytesReader(out, r.Body, 32<<10)
			if e := r.ParseForm(); e != nil {
				http.Error(out, "Invalid or oversized setup request", 400)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
			defer cancel()
			values := map[string]string{}
			for _, f := range w.c.Fields {
				values[f.Name] = strings.TrimSpace(r.FormValue(f.Name))
			}
			message := ""
			ok := false
			switch r.FormValue("check") {
			case "jira":
				if !w.c.Jira {
					http.Error(out, "Unsupported check", 400)
					return
				}
				var e error
				message, e = CheckJira(ctx, w.c.Client, r.FormValue("jira"), r.FormValue("email"), r.FormValue("secret"))
				ok = e == nil
				if e != nil {
					message = e.Error()
				}
			case "input":
				if w.c.Check == nil {
					http.Error(out, "No connection is required for this tool", 400)
					return
				}
				var e error
				message, e = w.c.Check(ctx, values)
				ok = e == nil
				if e != nil {
					message = e.Error()
				}
			default:
				http.Error(out, "Unknown setup action", 400)
				return
			}
			// Only declared non-secret input fields survive in this session. Jira credentials never do.
			w.mu.Lock()
			if r.FormValue("check") != "jira" {
				for key, value := range values {
					w.values[key] = value
				}
			}
			w.mu.Unlock()
			w.render(out, true, message, ok)
			return
		}
		w.mu.Lock()
		started := w.started
		w.mu.Unlock()
		if path == "/welcome" || path == "/setup" || (path == "/" && r.Method == "GET" && !started) {
			if r.Method != "GET" {
				http.Error(out, "GET required", 405)
				return
			}
			w.render(out, path == "/setup", "", false)
			return
		}
		if path == "/" && r.Method == "POST" {
			w.mu.Lock()
			w.started = true
			w.ready = false
			w.demo = r.URL.Query().Get("onboarding") == "demo"
			w.mu.Unlock()
		}
		next.ServeHTTP(out, r)
	})
}
func (w *Wizard) render(out http.ResponseWriter, setup bool, message string, ok bool) {
	w.mu.Lock()
	values := map[string]string{}
	for k, v := range w.values {
		values[k] = v
	}
	data := struct {
		Token     string
		C         Config
		Setup, OK bool
		Message   string
		Values    map[string]string
	}{w.c.Token, w.c, setup, ok, message, values}
	w.mu.Unlock()
	out.Header().Set("Content-Type", "text/html; charset=utf-8")
	welcome.Execute(out, data)
}
func CheckJira(ctx context.Context, client *http.Client, origin, email, secret string) (string, error) {
	u, e := url.Parse(strings.TrimSpace(origin))
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", errors.New("Use the HTTPS Jira site origin, for example https://team.atlassian.net, without a path.")
	}
	if email == "" || secret == "" {
		return "", errors.New("Enter your Jira email and API token. Neither is saved by the setup check.")
	}
	req, e := http.NewRequestWithContext(ctx, "GET", strings.TrimSuffix(u.String(), "/")+"/rest/api/3/myself", nil)
	if e != nil {
		return "", errors.New("Invalid Jira connection settings")
	}
	req.SetBasicAuth(email, secret)
	req.Header.Set("Accept", "application/json")
	c := *client
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	res, e := c.Do(req)
	if e != nil {
		return "", errors.New("Could not reach Jira. Check the site address, network and TLS settings; no ticket was created.")
	}
	defer res.Body.Close()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return "", errors.New("Jira rejected authentication. Check the email/API token and account access; no ticket was created.")
	}
	if res.StatusCode == 429 {
		return "", errors.New("Jira is rate limiting requests. Wait and try the check again; no ticket was created.")
	}
	if res.StatusCode != 200 {
		return "", fmt.Errorf("Jira returned HTTP %d. Check the site and try again; no ticket was created.", res.StatusCode)
	}
	var v struct {
		AccountID string `json:"accountId"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 64<<10)).Decode(&v) != nil || v.AccountID == "" {
		return "", errors.New("The site did not return a valid Jira Cloud identity. Check the Jira origin.")
	}
	return "Jira sign-in works. No ticket was created. Project creation/comment permissions are checked separately when you send a finding. Re-enter your token at handoff; it was not saved.", nil
}

var welcome = template.Must(template.New("welcome").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Get started - {{.C.Name}}</title>` + webui.Head + `</head>
<body>` + webui.Header + `<main id="main">
<p class="eyebrow">Getting started</p>
<h1>Welcome to {{.C.Name}}</h1>
<p>{{.C.Intro}}</p>
<p class="notice">Start with a safe offline example, or use data you are authorized to review. Setup checks never create tickets or change your source data.</p>{{if .Message}}<p role="status" class="notice">{{if .OK}}Check completed: {{else}}Needs attention: {{end}}{{.Message}}</p>{{end}}{{if not .Setup}}<div class="choices">
<section>
<h2>Try the demo</h2>
<p>No accounts or credentials needed. {{.C.Expected}}</p>
<form method="post" action="/?token={{.C.Token}}&onboarding=demo">{{range $k,$v:=.C.DemoFields}}<input type="hidden" name="{{$k}}" value="{{$v}}">{{end}}<button>Try the guided demo</button>
</form>
</section>
<section>
<h2>Use my data</h2>
<p>Check the input requirements and available connections before your first task.</p>
<a href="/setup?token={{.C.Token}}">Set up my workspace</a>
</section>
</div>{{else}}<section>
<h2>Set up your first task</h2>
<ol>{{range .C.Steps}}<li>{{.}}</li>{{end}}</ol>{{if .C.Fields}}<form method="post" action="/setup/check?token={{.C.Token}}">{{range .C.Fields}}<label>{{.Label}}<input name="{{.Name}}" value="{{index $.Values .Name}}">
<small>{{.Hint}}</small>
</label>{{end}}<button name="check" value="input">Check AWS identity without scanning</button>
</form>{{end}}<form method="post" action="/onboarding/start?token={{.C.Token}}">
<input type="hidden" name="mode" value="own">
<button>Open my workspace</button>
<small>You can continue without a setup check; that does not mark a connection as verified.</small>
</form>
</section>{{if .C.Jira}}<section>
<h2>Optional: test Jira sign-in</h2>
<p>Skip this if you only want local results. This makes one read-only identity request. It does not verify project permissions, create a ticket, or save your credentials.</p>
<form method="post" action="/setup/check?token={{.C.Token}}">
<label>Jira site<input name="jira" placeholder="https://team.atlassian.net" required>
</label>
<label>Jira email<input name="email" type="email" required autocomplete="off">
</label>
<label>API token<input name="secret" type="password" required autocomplete="off">
</label>
<button name="check" value="jira">Test Jira sign-in - no ticket</button>
</form>
<p>For handoff, you also need a project key and issue type that your account may create/comment on. Check these with your Jira administrator.</p>
</section>{{end}}{{end}}<section>
<h2>Already have results?</h2>
<form method="post" action="/onboarding/start?token={{.C.Token}}">
<input type="hidden" name="mode" value="resume">
<button>Continue to existing workspace</button>
</form>
<p>Restarting this guide does not delete or reset saved results.</p>
</section>
<p>Close the application with Ctrl+C in its launcher console. Closing only the browser leaves it running.</p>
</main>
</body>
</html>`))
