# KING REAPER X

**Ultimate Cyber Intelligence & Security Framework — v2.0.0**

A modular, standard-library-only Python framework for authorized security
assessment, OSINT and threat intelligence. Runs on Kali Linux, any Debian or
Ubuntu host, and Termux on Android — with **no pip dependencies at all**, so
nothing is ever compiled on a phone.

```
     ██╗  ██╗██╗███╗   ██╗ ██████╗     ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗
     ██║ ██╔╝██║████╗  ██║██╔════╝     ██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
     █████╔╝ ██║██╔██╗ ██║██║  ███╗    ██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
     ██╔═██╗ ██║██║╚██╗██║██║   ██║    ██╔══██╗██╔══╝  ██╔══██║██╔══██╗██╔══╝  ██╔══██╗
     ██║  ██╗██║██║ ╚████║╚██████╔╝    ██║  ██║███████╗██║  ██║██║  ██║███████╗██║  ██║
     ╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝ ╚═════╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
                                        ██╗  ██╗
                                        ╚██╗██╔╝  ultimate cyber intelligence
                                         ╚███╔╝
                                         ██╔██╗
                                        ██╔╝ ██╗
                                        ╚═╝  ╚═╝
```

---

## ⚠️ Authorized use only

KING REAPER X is built for **systems you own or have written permission to test**.
Every active module (port scanning, subdomain brute force, web probing) refuses to
run without `--authorized`, and the framework records an audit trail of what was
run against what.

It deliberately **cannot** and **will not**:

- secretly track a person's phone or location
- access WhatsApp messages, private accounts or verification codes
- bypass device permissions or consent
- run spyware, keyloggers, or hidden camera/microphone access
- use sources that are not public or explicitly authorized

If you need a capability that is not in that list, it is not in the code either.

---

## Why it actually runs on Termux

Most recon tooling drags in `dnspython`, `requests`, `cryptography`, `geoip2` and a
C compiler. On Android that means a 20-minute build that usually fails. This
framework implements the parts it needs directly:

| Normally a dependency | What KING REAPER X does instead |
|---|---|
| `dnspython` | a DNS client written against the wire format (`core/dnsclient.py`), UDP + TCP fallback |
| `python-whois` | a raw port-43 WHOIS client with server referral following (`core/whois_client.py`) |
| `requests` | `http.client` with redirect handling, size caps and per-request timeouts (`core/net.py`) |
| `python-whois-parser` | a key-mapping parser that handles RDAP-style and legacy output |
| `geoip2` | keyless public geolocation lookups with an offline private-IP short-circuit |
| `flask` (dashboard) | `ThreadingHTTPServer` with JSON API routes |
| `reportlab` (PDF) | self-contained printable HTML — open it and "Save as PDF" |
| `rich` / `colorama` | a 20-line ANSI layer that honours `NO_COLOR` |

Result: `git clone`, run, done. Nothing to install, nothing to compile.

---

## Install

### Kali Linux / Debian / Ubuntu

```bash
git clone https://github.com/Janrahat/king-reaper-x.git
cd king-reaper-x
./scripts/install.sh
```

That verifies Python 3.8+, checks the standard-library modules are present,
creates `~/.king-reaper-x` with mode `0700`, and installs a `reaper-x` launcher
into `~/.local/bin`.

No `sudo` needed. No apt package is required beyond `python3` itself.

### Termux (Android)

```bash
pkg update && pkg install -y python git
git clone https://github.com/Janrahat/king-reaper-x.git
cd king-reaper-x
./scripts/install-termux.sh
```

The Termux installer **never uses root**, never compiles anything, and puts the
`reaper-x` launcher in `$PREFIX/bin`.

### Verify either install

```bash
reaper-x doctor       # environment diagnosis
reaper-x status       # runtime, database and provider state
```

---

## Quick start

```bash
reaper-x                      # interactive command-centre console
reaper-x --help               # every command
reaper-x tools                # list the 13 modules
```

### The console (v2.0.0)

`reaper-x` (or `python3 main.py menu`) opens the command-centre interface: a
boot sequence that verifies six subsystems, a live system dashboard, and a
16-entry menu. Every entry resolves to a real module or handler — there are no
placeholder rows.

```
[01] Mobile Intelligence           phone · whatsapp
[02] IP Geo Intelligence           geoip
[03] Domain Reconnaissance         domain
[04] SSL/TLS Security Audit        ssl
[05] Technology Fingerprint        fingerprint
[06] Subdomain Intelligence        subdomains
[07] Web Security Assessment       webscan
[08] Username/Email OSINT          username
[09] Threat Intelligence           threat
[10] Dependency Security Audit     deps
[11] Authorized Port Scanner       ports ⚿
[12] System Status                 status
[13] Scan History                  history
[14] Full Target Audit             audit
[15] API Providers & Configuration config
[16] Settings                      settings
[00] Exit
```

`⚿` marks the entry that demands a per-run authorization confirmation.

Animations are **off by default on Termux and on any non-tty**, and can be
disabled anywhere with `REAPER_NO_ANIM=1` or `config set animations false`.
The interface is then instant — it prints the final frame instead of animating.

### Phone intelligence

```bash
reaper-x phone +966501234567
reaper-x phone "+1 (415) 555-2671" --json
```

Offline structural analysis: E.164 parsing, country/region, dialing code,
national formatting, line type (mobile/landline), length plausibility.
Carrier and reachability enrichment need an optional key:

```bash
export NUMVERIFY_API_KEY='…'    # https://numverify.com — free tier available
reaper-x phone +966501234567 --enrich
```

Without the key the module still returns full structural analysis and says
plainly that enrichment was skipped — it never invents carrier data.

### Reconnaissance

```bash
reaper-x domain example.com              # DNS + WHOIS + mail topology + hosting
reaper-x subdomains example.com          # passive (crt.sh + hackertarget)
reaper-x subdomains example.com --brute  # + DNS brute force
reaper-x ssl example.com                 # certificate + TLS config audit
reaper-x fingerprint https://example.com # tech stack detection
```

Active modules require explicit authorization:

```bash
reaper-x ports 10.0.0.5 --authorized --ports 22,80,443
reaper-x webscan https://staging.internal --authorized
```

`ports` and `webscan` refuse to run without `--authorized`, and the refusal is
recorded in the audit log. `subdomains --brute` is gated the same way; the
passive mode is not, because it only reads data the owner already published.

### Threat intelligence

```bash
reaper-x threat 8.8.8.8
reaper-x username torvalds
reaper-x deps                      # audits this repo's dependency hygiene
```

Keyless by default (URLhaus, OpenPhish, crt.sh). Optional richer sources:

```bash
export VIRUSTOTAL_API_KEY='…'
export ABUSEIPDB_API_KEY='…'
export SHODAN_API_KEY='…'
export IPINFO_TOKEN='…'
```

### Reports

```bash
reaper-x domain example.com --format all --out ./reports
# → reports/domain_example.com_<ts>.json / .md / .html / _print.html
```

`_print.html` is self-contained: open it in any browser and choose
**Print → Save as PDF**. No PDF library, no system fonts to install.

### Dashboard

```bash
reaper-x dashboard                 # http://127.0.0.1:8899
reaper-x dashboard --port 9000
```

Live data from the real SQLite database: system status, module health, scan
history, findings by severity, provider/key status, audit log. Binding to a
public interface is **refused** unless you pass `--allow-public`, because the
dashboard exposes your scan history.

---

## Modules

| Command | Category | What it really does | Keys needed |
|---|---|---|---|
| `phone` | mobile | E.164 validation, country, line type, formatting | none (optional `NUMVERIFY_API_KEY`) |
| `whatsapp` | mobile | public WhatsApp Business profile via official Cloud API | `WHATSAPP_BUSINESS_TOKEN` |
| `geoip` | location | IP geolocation + ASN from public sources | none (optional `IPINFO_TOKEN`) |
| `location` | location | consented share tokens with expiry + HMAC | none |
| `domain` | recon | DNS, WHOIS, MX/SPF topology, hosting provider | none |
| `subdomains` | recon | passive discovery + optional DNS brute force | none |
| `ssl` | recon | certificate chain, expiry, protocol/cipher audit | none |
| `ports` | recon | TCP scan with banner grab + risk annotation | none (needs `--authorized`) |
| `fingerprint` | recon | server/framework/CDN detection from headers+body | none |
| `webscan` | web | security headers, cookies, exposed paths | none (needs `--authorized`) |
| `deps` | network | local dependency + config hygiene audit | none |
| `username` | osint | public profile existence across 20 sites | none |
| `threat` | threat | reputation from public feeds | none (optional VT/AbuseIPDB/Shodan) |

Every module returns the same envelope:

```json
{"ok": true, "module": "phone", "target": "…", "findings": [],
 "risk": "info", "score": 0, "summary": "…"}
```

so reports, the dashboard and the tests all consume one shape.

---

## Configuration

Secrets live only in `~/.king-reaper-x/config.json`, written atomically at mode
**0600**, in a directory at mode **0700**. Environment variables always win over
the file, so `export FOO_API_KEY=…` overrides without touching disk.

```bash
reaper-x config show                  # show settings (secrets masked)
reaper-x config set-key virustotal    # prompts, never echoes
reaper-x config providers             # which providers are configured
reaper-x config clear-key virustotal
```

Plain-text keys on disk are a compromise for portability; `reaper-x doctor`
reports the file mode and warns if it is too permissive. Missing keys never
break a run — the module reports `degraded` with the exact variable name and the
steps to obtain it.

---

## Tests

```bash
./scripts/run_tests.sh
```

Three suites, 156 tests, no network required:

- `tests/test_offline.py` (65) — parsing, validation, E.164 tables, DNS wire
  format, WHOIS parsing, SQLite, consent gates, secret storage, report escaping.
- `tests/test_smoke.py` (37) — real HTTP/TCP/TLS servers on `127.0.0.1`, port
  scanning, header audit, cookie checks, TLS certificate decode, CLI run as a
  subprocess, dashboard routes.
- `tests/test_ui.py` (54) — the v2.0.0 interface layer: palette and colour
  gating, animation auto-disable, banner geometry, all 16 menu entries
  resolving to real destinations, invalid input, Ctrl+C, EOF, the phone
  sub-menu against a real number, the authorization gate, and the boot checks.

```bash
python3 -m unittest tests.test_offline -v
python3 -m unittest tests.test_smoke -v
python3 -m unittest tests.test_ui -v
```

Tests set `REAPER_NONINTERACTIVE=1` so a consent prompt can never hang CI, and
each run uses a throwaway `HOME` so your real config is untouched.

---

## Documentation

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — module contract, data flow, why each layer exists
- [`docs/USAGE.md`](docs/USAGE.md) — every command with real examples and output
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — **what does not work, and why** — read this before filing a bug
- [`docs/SECURITY.md`](docs/SECURITY.md) — threat model, secret handling, audit trail

---

## Project layout

```
king-reaper-x/
├── main.py                  # launcher (works from any cwd)
├── core/                    # config, net, dns, whois, db, report, cli, consent
│   └── ui/                  # v2.0.0 interface layer (theme, banner, widgets,
│                            #   boot, menu) — no scanning code lives here
├── modules/
│   ├── mobile_intelligence/     phone_intel
│   ├── whatsapp_intelligence/   business_profile
│   ├── location_intelligence/   geo_ip, consent_share
│   ├── reconnaissance/          domain_intel, subdomain_scan, ssl_audit,
│   │                            port_scan, fingerprint
│   ├── web_security/            web_assess
│   ├── network_security/        dependency_audit
│   ├── osint/                   username_scan
│   └── threat_intelligence/     reputation
├── data/                    # offline calling-code table, wordlists
├── dashboard/               # command-centre HTTP server
├── tests/                   # offline + localhost integration suites
├── scripts/                 # install.sh, install-termux.sh, run_tests.sh
└── docs/                    # architecture, usage, limitations, security
```

---

## License

MIT — see [LICENSE](LICENSE).

Built for defenders. Use it on systems you are allowed to test.
