# Changelog

All notable changes to KING REAPER X are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-05

First release. Everything below was executed and verified on Debian 12 with
Python 3.11; see **Verification** at the end for what was *not* run.

### Added

**Framework core**
- `core/net.py` - TCP connect with timing, banner grab, HTTP client with redirect
  handling and body caps, TLS fetch with manual DER decode.
- `core/dnsclient.py` - DNS over the wire: query builder, compression-pointer
  parser with depth guard, 9 record type formatters, UDP with TCP fallback,
  `/etc/resolv.conf` resolver discovery.
- `core/whois_client.py` - raw TCP 43 client, one-level referral following,
  field mapping across ~20 registry vocabularies, IP WHOIS with RIR referral.
- `core/config.py` - layered config (env > file > defaults), atomic `0600` writes,
  `0700` config dir, provider registry with masked reporting.
- `core/db.py` - SQLite with `scans`, `results`, `findings`, `audit` and `assets`
  tables, WAL mode, filtered queries and aggregate stats.
- `core/consent.py` - separate terms and authorization gates, both
  non-interactive safe.
- `core/report.py` - JSON, Markdown, styled HTML and printable-HTML output from
  one result dict; every interpolated value escaped.
- `core/registry.py` - module discovery, contract validation, envelope
  normalisation.
- `core/cli.py` - 19 subcommands, interactive menu, global options accepted in
  either position.
- `dashboard/server.py` - command-centre UI and 8 JSON API routes on
  `ThreadingHTTPServer`, loopback-only by default.

**Modules (13)**
- `phone` - E.164 parsing and validation, country/region identification from a
  bundled calling-code table with NANP area-code resolution, national and
  international formatting, line-type inference, length plausibility, optional
  numverify enrichment.
- `whatsapp` - public business profile through the official Cloud API only.
- `geoip` - geolocation and ASN, with an offline private-range short-circuit.
- `location` - HMAC-signed, expiring consented share tokens.
- `domain` - DNS, WHOIS, mail topology (SPF/DMARC), hosting provider.
- `subdomains` - passive (crt.sh, hackertarget) plus optional DNS brute force
  with wildcard detection.
- `ssl` - certificate metadata, expiry, protocol and cipher audit.
- `ports` - TCP scan with banner grab, service naming and risk annotation.
- `fingerprint` - server, framework, CDN and runtime detection.
- `webscan` - security headers, cookie flags, exposed paths.
- `deps` - local dependency and configuration hygiene audit.
- `username` - public profile existence across 20 sites with a three-state
  result (`found` / `not found` / `blocked`).
- `threat` - reputation from public feeds plus optional keyed providers.
