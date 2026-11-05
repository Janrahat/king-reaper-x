# Usage

Every command below was executed during development; the output shape shown is
the real one. `reaper-x` is the installed launcher; from a clone use
`python3 main.py` instead.

```
reaper-x <command> [target] [options]
```

Global options work in either position (`reaper-x --json phone X` and
`reaper-x phone X --json` are identical):

| Option | Effect |
|---|---|
| `--json` | machine-readable result on stdout |
| `--out DIR` | report directory (default `./reports`) |
| `--format F` | `json,md,html,print` (comma list) |
| `--timeout N` | per-request timeout in seconds |
| `--threads N` | worker threads |
| `--rate N` | requests per second ceiling |
| `--quiet` | suppress progress |

---

## Interactive menu

```bash
reaper-x
```

Numbered menu over the same handlers the subcommands use - one code path, so a
menu session and a scripted run cannot drift apart.

---

## System

```bash
reaper-x status      # version, host, module count, database size
reaper-x doctor      # environment diagnosis; exit 1 on a blocking problem
reaper-x tools       # the 13 modules with category and key requirements
reaper-x history     # past runs from SQLite
reaper-x history --limit 20 --module ports
reaper-x show 12     # full stored payload for one scan id
```

`doctor` checks: Python version, config dir and file modes, SQLite, the
subdomain wordlist, live DNS resolution, outbound HTTPS, Termux detection, the
certificate decoder, and which provider keys are configured.

---

## Mobile intelligence

```bash
reaper-x phone +966501234567
```

```
-- PHONE --------------------------------------------------
  target                +966501234567
  status                OK
  e164                  +966501234567
  country               Saudi Arabia (SA) +966
  line type             mobile
  summary               +966501234567 - Saudi Arabia (SA), mobile
  risk                  info (score 0/100)

  findings
    no findings
```

Also prints `national`, `international`, `tel:` URI and `e164` formats, length
plausibility against the country's known ranges, and the basis for the line-type
verdict.

Accepted input: `+966...`, `00966...`, `+1 (415) 555-2671`, extensions
(`ext 42`). Rejected cleanly: empty, letters, a lone `+`, anything past 17
digits. A number without a `+` and without a matching calling code is refused
with a hint to use international format - the framework does not guess a country.

```bash
reaper-x phone +966501234567 --enrich     # adds carrier + reachability
```

`--enrich` needs `NUMVERIFY_API_KEY`. Without it the result is `degraded` and
names the variable plus how to obtain it - it never invents carrier data.

---

## WhatsApp public business profile

```bash
reaper-x whatsapp +966501234567
reaper-x whatsapp +966501234567 --check-contact
```

Without `WHATSAPP_BUSINESS_TOKEN` the status is `DEGRADED` and the steps to
obtain a token are printed. With it, returns the business's **public** display
name, verified-name status, description, website, vertical and address as
published by the business through Meta's Cloud API.

Personal accounts, messages, profile photos and online status are out of scope
and are not attempted.

---

## Location intelligence

```bash
reaper-x geoip 8.8.8.8
```

Returns country, region, city, coordinates, ASN, ISP and hosting/VPN flags.
Private and reserved ranges are answered offline:

```
reaper-x geoip 192.168.1.10
# -> private true, no external request made
```

### Consented sharing

```bash
reaper-x location "24.7136,46.6753" --shared-by "operator" --ttl-hours 4
```

Issues an HMAC-signed, expiring share token for coordinates a device chose to
share, plus an OpenStreetMap link. This is the only location feature: there is no
phone-to-location lookup.

---

## Reconnaissance

### Domain

```bash
reaper-x domain example.com
```

Collects A/AAAA/MX/NS/TXT/SOA records, registrar and dates from WHOIS, mail
topology (SPF/DMARC presence and policy), and the hosting provider. Reports
missing SPF, multiple SPF records or a `+all` SPF as findings.

### Subdomains

```bash
reaper-x subdomains example.com            # passive: crt.sh + hackertarget
reaper-x subdomains example.com --brute    # + DNS brute force
reaper-x subdomains example.com --brute --words ./my-list.txt
```

Live hosts are resolved and de-duplicated. Names that appear in CT logs but no
longer resolve are reported as `historical`, not as live. A source that fails is
listed as failed while the other source's results still come back.

### TLS

```bash
reaper-x ssl example.com
reaper-x ssl example.com:8443
```

Subject, SANs, issuer, validity window, days remaining, negotiated protocol and
cipher, plus findings for expiry (<14 days), self-signed, hostname mismatch and
deprecated protocol versions.

Expired and self-signed certificates are **analysed**, not refused - the tool
connects with verification off and decodes the DER separately.

### Ports - requires authorization

```bash
reaper-x ports 10.0.0.5 --authorized --ports 22,80,443
reaper-x ports scanme.example --authorized --ports top
```

Without `--authorized`:

```
[x] Port scanning requires an explicit authorization confirmation for this
    target. Re-run with --authorized.
```

Open ports are annotated with the service and a risk note (e.g. 3306 exposed,
21 FTP, 23 telnet). Only ports that actually accepted a connection are listed.

### Fingerprint

```bash
reaper-x fingerprint https://example.com
```

Server header, framework hints, CDN, language/runtime, generator meta tags and
notable response headers. Every detection carries the evidence that produced it.

---

## Web security - requires authorization

```bash
reaper-x webscan https://staging.internal --authorized
reaper-x webscan https://example.com --format all --out ./reports
```

Checks CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, cookie `Secure`/`HttpOnly`/`SameSite` flags, and four
well-known exposed paths. Non-HTTP schemes are refused:

```
[x] unsupported_scheme: 'ftp://' is not supported; this module assesses HTTP(S) endpoints.
```

---

## Dependency hygiene

```bash
reaper-x deps
reaper-x deps ./path/to/project
```

Audits the local project: requirement pinning, `.gitignore` coverage of secrets,
committed `.env` files, world-readable config, and provider-key count.

---

## OSINT

```bash
reaper-x username torvalds
reaper-x username torvalds --json
```

Checks 20 sites with predictable profile URLs. Results are `found`,
`not found`, `blocked` (bot wall / login redirect) or `inconclusive` - the extra
states exist so a blocked check is never reported as absence.

---

## Threat intelligence

```bash
reaper-x threat 8.8.8.8
reaper-x threat example.com
reaper-x threat 8.8.8.8 --no-feeds   # skip the live feed queries
```

Keyless sources: URLhaus and OpenPhish for URL/domain reputation, plus the
crt.sh issuance count for domains. Optional keys widen coverage; without them the
summary says explicitly that no reputation provider was queried.

---

## Reports

```bash
reaper-x domain example.com --format all --out ./reports
```

```
reports/domain_example.com_20261105T154218Z.json
reports/domain_example.com_20261105T154218Z.md
reports/domain_example.com_20261105T154218Z.html
reports/domain_example.com_20261105T154218Z_print.html   <- PDF via browser
```

`reaper-x audit example.com --format all` runs a baseline set and writes one
combined report.

---

## Dashboard

```bash
reaper-x dashboard
reaper-x dashboard --port 9000
```

Serves at `http://127.0.0.1:8899`:

| Route | Content |
|---|---|
| `/` | command-centre UI (polls the API) |
| `/healthz` | liveness |
| `/api/system` | version, host, modules, DB stats, provider count |
| `/api/history` | recent scans (`?limit=&module=`) |
| `/api/scan/<id>` | one scan with full payload |
| `/api/stats` | aggregates by module/severity/risk |
| `/api/providers` | which keys are configured (never values) |
| `/api/audit` | consent and authorization decisions |
| `/api/assets` | discovered hosts/assets (`?target=`) |

Binding to a non-loopback address is refused:

```
[x] Refusing to bind the dashboard to 0.0.0.0: it exposes scan history.
    use --allow-public to override
```

---

## Configuration

```bash
reaper-x config show                     # show settings, secrets masked
reaper-x config set-key virustotal       # prompt, never echoed
reaper-x config providers                # configured / not configured
reaper-x config clear-key virustotal
reaper-x config set timeout 12
```

Environment variables override the config file, so a one-off run never needs the
key written to disk:

```bash
VIRUSTOTAL_API_KEY=... reaper-x threat 8.8.8.8
```

---

## Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | the check ran and reported a failure (unreachable, degraded below threshold) |
| 2 | usage error, or a consent/terms gate refused |
| 3 | the authorization gate refused an active module |
| 130 | interrupted with Ctrl+C |

`--json` output is always valid JSON on stdout, including refusals, so scripts can
branch on `ok` and `error` without parsing prose.
