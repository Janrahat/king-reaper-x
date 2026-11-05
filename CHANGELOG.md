# Changelog

All notable changes to KING REAPER X are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-05

First release. Everything below was executed and verified on Debian 12 with
Python 3.11; see **Verification** at the end for what was *not* run.

### Added

**Framework core** - `net` (TCP, HTTP with redirects and body caps, TLS with
manual DER decode), `dnsclient` (DNS over the wire, UDP + TCP fallback),
`whois_client` (raw port 43 with referral following), `config` (env > file >
defaults, atomic 0600 writes), `db` (SQLite, WAL, scans/results/findings/audit/
assets), `consent` (separate terms and authorization gates), `report` (JSON, MD,
HTML, printable HTML, all escaped), `registry` (discovery + envelope
normalisation), `cli` (19 subcommands + interactive menu), `dashboard/server`
(command-centre UI and 8 JSON routes, loopback-only by default).

**Modules (13)**
- `phone` - E.164 parsing, country from a bundled calling-code table with NANP
  area-code resolution, formatting, line-type inference, length plausibility,
  optional numverify enrichment.
- `whatsapp` - public business profile through the official Cloud API only.
- `geoip` - geolocation and ASN, offline private-range short-circuit.
- `location` - HMAC-signed, expiring consented share tokens.
- `domain` - DNS, WHOIS, mail topology (SPF/DMARC), hosting provider.
- `subdomains` - passive (crt.sh, hackertarget) plus optional DNS brute force.
- `ssl` - certificate metadata, expiry, protocol and cipher audit.
- `ports` - TCP scan with banner grab, service naming, risk annotation.
- `fingerprint` - server, framework, CDN and runtime detection.
- `webscan` - security headers, cookie flags, exposed paths.
- `deps` - local dependency and configuration hygiene audit.
- `username` - public profile existence across 20 sites, three-state result.
- `threat` - reputation from public feeds plus optional keyed providers.

**Packaging** - `scripts/install.sh` (Kali/Debian/Ubuntu), `install-termux.sh`
(refuses to run outside Termux, never root, never compiles), `run_tests.sh`, and
`.github/workflows/ci.yml` (4 Python versions, CLI smoke checks, dashboard
routes, installer syntax, secret-literal scan).

**Tests - 102 total, all network-free** - `test_offline.py` (65): E.164 tables,
NANP, phone analysis, validation, port specs, rate limiter, thread-pool error
isolation, envelope normalisation, SQLite, consent gates, secret storage and
masking, report escaping, WHOIS parsing, DNS wire format. `test_smoke.py` (37):
real HTTP/TCP/TLS servers on 127.0.0.1, port scanning, header and cookie audits,
certificate decode, CLI subprocess runs, dashboard routes, public-bind refusal.

### Fixed during development

Found by running the code, not by reading it:

- **Global `--json` was silently ignored** - a subparser's `default=False`
  overwrote the global value, so `main.py --json phone X` printed human text.
  Fixed with `default=SUPPRESS`.
- **`--ports` was ignored by the CLI** - not forwarded into module options, so
  `--ports 80,443` scanned the default 118-port list.
- **`ftp://` and `ssh://` were coerced to `https://`** - the web module now
  refuses any scheme it cannot speak instead of assessing a different service.
- **Missing `env_flag` import** in `consent.py` raised `NameError` on the first
  prompt attempt.
- **Consent prompt hung under tmux/CI** - a real tty with no human behind it
  blocked `input()` forever; `REAPER_NONINTERACTIVE=1` forces the refusal path.
- **NANP territories were swallowed by `+1`** - `+1 242` (Bahamas) resolved to
  the US; area codes are now checked before falling back.
- **Module discovery returned nothing** - the loader only accepted packages, not
  single-file modules.
- **Provider-gated modules looked like clean successes** - they now return
  `degraded` with the exact variable name, so an absent key can never be
  mistaken for "no findings".

### Notes

- `requirements.txt` deliberately declares no packages - the framework imports
  only the standard library.
- No provider-keyed API call was executed during development (no keys were
  available). Those paths are implemented and reviewed, not battle-tested. See
  `docs/LIMITATIONS.md`.

### Verification

| Check | Result |
|---|---|
| `unittest tests.test_offline` | 65 passed |
| `unittest tests.test_smoke` | 37 passed |
| `scripts/run_tests.sh` | ALL TESTS PASSED |
| `--version`, `--help`, `tools`, `status`, `doctor` | exit 0 |
| live-host modules | real data, no traceback |
| Dashboard routes | 200; unknown 404; public bind refused |
| Installer syntax (`bash -n`) | all three pass |
| Hardcoded-secret scan | clean |
| Debian 12 / Python 3.11 | yes |
| Kali / Ubuntu / Termux | **no - not executed** |

[1.0.0]: https://github.com/Janrahat/king-reaper-x/releases/tag/v1.0.0
