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
