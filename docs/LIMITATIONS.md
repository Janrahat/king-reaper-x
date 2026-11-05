# Known limitations

This file exists so nobody has to guess what is real. Every item below is a
deliberate boundary, not an unfinished feature.

## Provider-gated modules

These work only with a key you supply. Without it they return a `degraded`
result that names the variable and how to obtain it - they never fabricate data.

| Module | Variable | Source |
|---|---|---|
| `phone --enrich` | `NUMVERIFY_API_KEY` | numverify.com (free tier) |
| `whatsapp` | `WHATSAPP_BUSINESS_TOKEN` + `WHATSAPP_PHONE_NUMBER_ID` | Meta WhatsApp Business Cloud API |
| `threat` | `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` | optional, widens coverage |
| `geoip` | `IPINFO_TOKEN` | optional, higher accuracy |
| `username` (email) | `HIBP_API_KEY` | optional, breach lookup |

**Not verified against live APIs in this environment.** The public keyless
sources (`crt.sh`, `hackertarget`, `ip-api`, URLhaus, OpenPhish) were exercised
during development, but no provider-keyed call was ever executed here because no
key was available. Treat the keyed paths as implemented-and-reviewed, not
battle-tested.

## WhatsApp

Only **public business profiles** reachable through the official Cloud API.
There is no endpoint - official or otherwise - that returns a personal account's
name, photo, status or online state, and no attempt is made to find one. The
contact-status check uses Meta's own `contacts` endpoint and returns only
`wa_id` presence, never a name or photo.

## Location

Two capabilities, both legitimate:

1. **IP geolocation** - approximate, city-level at best, and wrong for VPNs,
   CGNAT and mobile carriers. Private and reserved ranges are short-circuited
   offline and never sent to a third party. The result carries an explicit
   accuracy note saying an IP locates a network block, not a device.
2. **Consented share tokens** - you supply coordinates a device voluntarily
   shared. Tokens are HMAC-signed against a local secret and expire.

There is no phone-number-to-location lookup. It does not exist for good reason,
and this framework does not pretend otherwise.

## Port scanning

- TCP connect scan only. No SYN/half-open scan (needs raw sockets = root, and
  Termux has no root), no UDP scan (unreliable without raw sockets), no OS
  detection, no stealth techniques.
- 100 threads by default, capped at 200. On Termux, higher values are throttled
  by the OS.
- IPv6 targets are supported, but `--ports top` sweeps are slower over IPv6 on
  mobile networks.

## Subdomain discovery

- Passive sources are `crt.sh` and `hackertarget`. Both are free public services
  that rate-limit and occasionally return 502. A failed source is reported, not
  hidden, and the other source's results still return.
- DNS brute force uses the bundled ~170-entry wordlist in `data/subdomains.txt`.
  It is intentionally small: a big list on a phone is a battery drain, and a big
  list against someone else's DNS is abuse. Point `--words` at your own file.
- Every candidate is confirmed with a real resolution, so a name that appears in
  a CT log but no longer resolves is reported as `historical`, not as live.

## Web assessment

- Passive header/cookie/path checks only. No SQL injection, XSS, SSRF or auth
  bypass testing. Those need per-application logic and, more importantly, they
  are the ones that break things.
- The path list is exactly four documented conventions (`/.git/config`, `/.env`,
  `/server-status`, `/phpinfo.php`). It is not a directory buster. A path only
  counts as exposed when the body contains content that proves it, so a
  single-page-app catch-all answering 200 for everything is not a false positive.
- Non-HTTP schemes are refused outright rather than being coerced into `https`.

## TLS audit

- Certificate validity, SANs, issuer, expiry and protocol version are read.
  Cipher-suite grading and vulnerability checks (Heartbleed, ROBOT) are **not**
  implemented.
- `ssl._ssl._test_decode_cert` is a private API. If CPython removes it, decoding
  falls back to `getpeercert()` - which returns `{}` for unverified connections,
  so the certificate block comes back empty and the result says so rather than
  being wrong. `doctor` reports whether the private decoder is available.

## Username OSINT

20 sites with predictable profile URLs. Each site is checked with one GET and a
three-state heuristic: a hit needs the site's negative marker to be absent **and**
a positive marker present. A site that answers 200 without a decisive marker is
reported as `inconclusive`, not as a hit. Rate limiting, bot walls and login
redirects still produce false negatives.

## Dashboard

- Binds to `127.0.0.1` only. `--allow-public` exists but exposes your entire scan
  history to the network with **no authentication**; only use it behind a tunnel
  or a reverse proxy you control.
- No websockets; the page polls the JSON API every 15 seconds.
- Single-user by design. There are no accounts or sessions.

## PDF

`--format print` produces self-contained HTML with print CSS. There is no native
PDF writer: open the file and use the browser's "Save as PDF". On Termux, open
the file from the dashboard or copy it out with `termux-open`.

## Platform coverage actually tested

| Platform | Status |
|---|---|
| Debian 12 / Python 3.11 | **tested** - full suite, CLI, dashboard |
| Kali Linux | **not run here** - Debian-based, same installer path, but unverified |
| Ubuntu | **not run here** - same caveat |
| Termux / Android | **not run here** - no Android environment available; the installer detects Termux via `$PREFIX` and refuses to run elsewhere, but it has not been executed on a real device |

Anything not marked *tested* above was written and reviewed, not executed. Say
so before trusting it in production.
