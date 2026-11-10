// Package webui shares the local application's presentation and theme control.
package webui

import (
	"crypto/sha256"
	"encoding/base64"
)

// Only this fixed script is allowed; user input is never inserted into it.
const Script = `(function(){
function apply(dark){document.documentElement.dataset.theme=dark?'dark':'light';var b=document.querySelector('[data-theme-toggle]');if(b)b.setAttribute('aria-pressed',String(dark));}
try{apply(document.cookie.split('; ').includes('s3-auditor-theme=dark'));}catch(e){apply(false);}
document.addEventListener('DOMContentLoaded',function(){var b=document.querySelector('[data-theme-toggle]');if(!b)return;b.hidden=false;b.setAttribute('aria-pressed',String(document.documentElement.dataset.theme==='dark'));b.addEventListener('click',function(){var dark=document.documentElement.dataset.theme!=='dark';apply(dark);document.cookie='s3-auditor-theme='+(dark?'dark':'light')+'; Path=/; Max-Age=31536000; SameSite=Strict';});});
})();`

var CSP = "default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-" + scriptHash() + "'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

func scriptHash() string {
	hash := sha256.Sum256([]byte(Script))
	return base64.StdEncoding.EncodeToString(hash[:])
}

const Head = `<style>` + Style + `</style><script>` + Script + `</script>`
const Header = `<a class="skip" href="#main">Skip to content</a><header class="topbar"><a class="brand" href="/?token={{.Token}}">S3 Auditor</a><button class="theme" type="button" data-theme-toggle aria-pressed="false" hidden>Dark mode</button></header>`

const Style = `
:root{color-scheme:light;--bg:#fff;--surface:#f6f7f7;--fg:#181b1b;--muted:#586161;--line:#d7dede;--accent:#087e83;--link:#066b70;--on-accent:#fff;--tint:#edf8f8}
:root[data-theme="dark"]{color-scheme:dark;--bg:#000;--surface:#101313;--fg:#ecf0f0;--muted:#a4b1b1;--line:#333e3e;--accent:#087e83;--link:#6cd5d9;--on-accent:#fff;--tint:#071e1f}
*{box-sizing:border-box}html{background:var(--bg);scroll-padding-top:20px}body{font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--fg);background:var(--bg);max-width:1120px;margin:0 auto;padding:0 28px 40px}a{color:var(--link);text-underline-offset:3px}a:hover{text-decoration-thickness:2px}.topbar{display:flex;justify-content:space-between;align-items:center;gap:20px;border-bottom:1px solid var(--line);padding:20px 0;margin-bottom:38px}.brand{font-size:17px;font-weight:700;text-decoration:none;color:var(--fg)}h1{font-size:clamp(28px,4vw,38px);line-height:1.2;letter-spacing:-.035em;margin:0 0 12px}h2{font-size:20px;line-height:1.35;margin:0 0 12px}h3{font-size:16px;margin:24px 0 12px}p{margin:10px 0 16px}small,.muted,footer{color:var(--muted)}small{font-size:13px}section{padding:26px 0;border-top:1px solid var(--line);margin-top:28px}.intro{max-width:760px}.eyebrow{font-size:12px;text-transform:uppercase;letter-spacing:.1em;color:var(--link);font-weight:650;margin-bottom:12px}.notice{padding:14px 18px;background:var(--tint);border-left:3px solid var(--accent)}.choices{display:grid;grid-template-columns:1fr 1fr;gap:36px}.choices section{margin-top:8px}.choices form{margin:0}form{margin:16px 0}label{display:block;font-weight:600;margin:16px 0 6px}label small{display:block;font-weight:400}input,textarea,select{display:block;width:100%;max-width:620px;font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--muted);border-radius:3px;padding:10px 12px;margin:6px 0}textarea{min-height:110px;resize:vertical}button,.button{display:inline-block;font:inherit;font-weight:600;border:1px solid var(--accent);border-radius:3px;background:var(--accent);color:var(--on-accent);padding:9px 16px;cursor:pointer;text-decoration:none;margin:6px 0}button:hover,.button:hover{filter:brightness(.92)}button.theme{background:var(--bg);border-color:var(--line);color:var(--fg);font-size:13px;padding:7px 12px;margin:0}button.theme[aria-pressed="true"]{border-color:var(--accent);color:var(--link)}button[hidden]{display:none}summary{cursor:pointer;font-weight:600;color:var(--link);padding:10px 0}details[open]>summary{margin-bottom:12px}table{width:100%;border-collapse:collapse;font-size:14px}caption{text-align:left;padding:16px 0;color:var(--muted)}th,td{padding:14px 16px 14px 0;text-align:left;vertical-align:top;border-bottom:1px solid var(--line);overflow-wrap:anywhere}th{font-weight:600;color:var(--muted)}td:first-child{font-weight:600;min-width:170px}td p{font-size:13px;font-weight:400;margin:8px 0;color:var(--muted)}.scroll{overflow-x:auto;max-width:100%}.scroll table{min-width:720px}.scroll-hint{display:none}code,.mono{font-family:ui-monospace,Consolas,monospace;font-size:.9em}.badge{display:inline-block;background:var(--tint);border:1px solid var(--line);padding:2px 8px;font-size:12px;font-weight:600;color:var(--link);vertical-align:middle;letter-spacing:0}.history{list-style:none;padding:0}.history li{padding:10px 0;border-bottom:1px solid var(--line)}.history a{display:flex;justify-content:space-between;gap:16px}.actions{display:flex;gap:18px;flex-wrap:wrap;align-items:center}.guide{border:1px solid var(--line);padding:18px 20px;background:var(--surface)}.guide h2{font-size:17px}.guide p:last-child{margin-bottom:0}footer{font-size:13px;border-top:1px solid var(--line);padding-top:18px;margin-top:36px}pre{white-space:pre-wrap;overflow-wrap:anywhere}:focus-visible{outline:3px solid var(--link);outline-offset:4px}.skip{position:absolute;left:-9999px}.skip:focus{left:24px;top:12px;background:var(--bg);padding:12px;z-index:1}li{margin:7px 0}
@media(max-width:600px){.scroll-hint{display:block}body{padding:0 18px 28px}.topbar{margin-bottom:28px}.choices{grid-template-columns:1fr;gap:0}section{margin-top:24px;padding-top:22px}.history a{flex-direction:column;gap:2px}td,th{padding-right:14px}.guide{padding:16px}}
@media print{.topbar,.skip,form,details,footer{display:none}body{max-width:none;color:#000;background:#fff}.scroll{overflow:visible}}
`
