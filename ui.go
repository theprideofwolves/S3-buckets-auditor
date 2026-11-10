package main

import "github.com/theprideofwolves/S3-buckets-auditor/internal/webui"

const pageHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>S3 Auditor</title>` + webui.Head + `</head><body>` + webui.Header + `
<main id="main">
<div class="intro"><p class="eyebrow">Bucket configuration review</p><h1>S3 assessments</h1>
<p>Review bucket policy public status and bucket-level Public Access Block. Keep observations, compare reassessments, and export evidence.</p>
<p class="muted">Read-only. Account controls, ACLs, access points and effective anonymous access are outside scope.</p></div>
{{.Guide}}
{{if .Message}}<p role="status" class="notice">{{.Message}}</p>{{end}}
{{if .Selected}}
<section id="results"><h2>Evidence {{if .Selected.Demo}}<span class="badge">SYNTHETIC</span>{{end}}</h2>
<p><strong>{{.Selected.Scope}}</strong><br><small>Observed {{.Selected.At.Format "2006-01-02 15:04:05 UTC"}}</small></p>
<a href="/export?token={{.Token}}&id={{.Selected.ID}}">Download JSON evidence</a>
<div class="scroll" role="region" aria-label="Bucket observations" tabindex="0"><table>
<caption>Two configuration checks per bucket. Unknown is not a pass. <span class="scroll-hint">Scroll horizontally to see all columns.</span></caption>
<thead><tr><th scope="col">Bucket</th><th scope="col">Policy observation</th><th scope="col">Public Access Block</th><th scope="col">Reassessment</th></tr></thead><tbody>
{{range .Selected.Reports}}<tr><td>{{.Name}}{{range .Errors}}<p>{{.}}</p>{{end}}</td><td>{{.PolicyState}}</td><td>{{.BlockState}}</td><td>{{index $.Delta .Name}}</td></tr>{{end}}
</tbody></table></div>
<details><summary>All reassessment outcomes, including missing buckets</summary>{{range $name,$value:=.Delta}}<p><span class="mono">{{$name}}</span>: {{$value}}</p>{{end}}</details>
<p class="muted">A clear reassessment verifies only these two checks. Missing buckets are not assessed.</p></section>
<section id="verification"><h2>Remediation verification</h2>
<p>Concerns survive denied inspections and missing buckets. Each control compares with its last successful observation in this scope, up to the selected scan.</p>
<a href="/verification?token={{.Token}}&id={{.Selected.ID}}">Download verification record</a>
{{range .Verification.Buckets}}
<details class="verification-bucket"><summary>{{.Name}} — {{.Assessment}} · {{.OpenConcerns}} unresolved checks</summary>
<p class="muted">The unresolved count covers policy public status and overall bucket Public Access Block. Individual flags below explain the block check; they are not extra findings.</p><small class="scroll-hint">Scroll horizontally to see all columns.</small>
<div class="scroll" role="region" aria-label="Control changes for {{.Name}}" tabindex="0"><table><thead><tr><th scope="col">Control</th><th scope="col">Selected observation</th><th scope="col">Change</th><th scope="col">Last successful observation</th></tr></thead><tbody>
{{range .Controls}}<tr><td>{{.Name}}</td><td>{{.CurrentValue}}{{if .Current.Note}}<p>{{.Current.Note}}</p>{{end}}</td><td>{{.Change}}{{if .ComparedWith}}<p>Compared with {{.ComparedWith.At.Format "2006-01-02 15:04:05 UTC"}}</p>{{end}}</td><td>{{if .LastKnown}}{{.LastKnown.At.Format "2006-01-02 15:04:05 UTC"}}{{else}}None recorded{{end}}</td></tr>{{end}}
</tbody></table></div>
{{range .Controls}}<details><summary>{{.Name}}: observation history</summary>
{{range .Episodes}}<p>Concern first observed {{.FirstObserved.At.Format "2006-01-02 15:04:05 UTC"}}; last observed {{.LastObserved.At.Format "2006-01-02 15:04:05 UTC"}}.<br>{{if .VerifiedClear}}Verified clear {{.VerifiedClear.At.Format "2006-01-02 15:04:05 UTC"}}{{else}}Still unresolved at this selected scan{{end}}. Observed episode duration: {{.AgeSeconds}} seconds.</p>{{else}}<p>No recorded concern episode.</p>{{end}}
<ol>{{range .Timeline}}<li>{{.At.Format "2006-01-02 15:04:05 UTC"}} — {{.State}} <small>(scan {{.ScanID}}){{if .Note}} · {{.Note}}{{end}}</small></li>{{end}}</ol></details>{{end}}
</details>{{else}}<p>No bucket observations recorded in this scope yet.</p>{{end}}
<p class="muted">A public policy can coexist with blocking controls. These observations do not establish effective access. Timestamps identify scans, not the exact time a setting changed. Legacy scans may lack individual flag details.</p></section>
{{if not .Selected.Demo}}
<section><h2>Jira handoff <span class="badge">Optional</span></h2>
<p>Sends the selected bucket, account/region, observations, scan time, scope limitations and correlation ID. No AWS credentials, object contents or raw API errors. Your Jira token is used for this request only.</p>
<p class="muted">Existing links receive evidence comments. Ticket status is never changed automatically.</p>
<form method="post" action="/?token={{.Token}}"><input type="hidden" name="id" value="{{.Selected.ID}}">
<label>Bucket<select name="bucket">{{range .Selected.Reports}}<option>{{.Name}}</option>{{end}}</select></label>
<label>Jira origin<input name="url" type="url" required placeholder="https://team.atlassian.net"></label>
<label>Email<input type="email" name="email" required autocomplete="off"></label>
<label>API token<input type="password" name="secret" required autocomplete="off"></label>
<label>Project key<input name="project" placeholder="SEC"></label>
<label>Issue type<input name="kind" value="Task"></label>
<button name="action" value="ticket">Create issue / append evidence</button>
<p class="muted">If a create outcome is uncertain, search Jira using the correlation in delivery records, then link the issue key.</p>
<label>Existing Jira key<input name="key" placeholder="SEC-123"></label>
<button name="action" value="link">Test connection and link issue</button></form></section>
{{end}}{{end}}
<section><h2>Start a scan</h2>
<form method="post" action="/?token={{.Token}}&onboarding=demo"><button name="action" value="demo">Run offline synthetic demo</button> <small>Four example buckets. No AWS calls.</small></form>
<form method="post" action="/?token={{.Token}}"><button name="action" value="demo-verification">Try the verification walkthrough</button> <small>Saves four synthetic stages: concern, denied, missing, verified clear.</small></form>
<details><summary>Scan an authorized AWS account</summary>
<p>Uses your signed-in AWS profile. Choose the bucket region; denied and wrong-region checks remain unknown. Blank targets discover up to 1,000 buckets. Scans may take three minutes; other actions wait.</p>
<form method="post" action="/?token={{.Token}}"><input type="hidden" name="action" value="scan">
<label>Profile <small>Blank uses the default AWS credential chain.</small><input name="profile" value="{{.Profile}}" autocomplete="off"></label>
<label>Region<input name="region" value="{{.Region}}" required placeholder="us-east-1" autocomplete="off"></label>
<label>Bucket names <small>One per line or comma-separated. Blank enables discovery.</small><textarea name="targets">{{.Targets}}</textarea></label>
<button>Run read-only assessment</button></form></details></section>
<section><h2>Scan history</h2><ul class="history">{{range .Scans}}<li><a href="/?token={{$.Token}}&scan={{.ID}}"><span>{{.Scope}}{{if .Label}} · {{.Label}}{{end}}{{if .Demo}} · Synthetic{{end}}</span><time>{{.At.Format "2006-01-02 15:04:05 UTC"}}</time></a></li>{{else}}<li>No scans saved. Run the offline demo to start.</li>{{end}}</ul>
<details><summary>Jira delivery records</summary>{{range $id,$value:=.Tickets}}<p><small>{{$id}}: {{$value.Key}} ({{$value.State}})</small></p>{{else}}<p>No deliveries.</p>{{end}}</details></section>
</main><footer>Private local application. Stop with Ctrl+C in the launcher; closing the browser leaves it running. Back up your data directory with the app stopped. History is not tamper-proof.</footer>
</body></html>`
