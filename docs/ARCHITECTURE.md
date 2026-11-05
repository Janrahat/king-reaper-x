# Architecture

## Design constraint that shaped everything

The framework had to install and run on **Termux with no build step**. That
single requirement rules out `cryptography`, `lxml`, `geoip2` and anything with a
C extension, because a phone either has no compiler or takes twenty minutes to
lose the fight with one. So every dependency was replaced with a direct
implementation of the protocol underneath it.

The payoff is not just packaging: the DNS client, WHOIS client and TLS decoder
are each about a hundred lines, fully testable offline, and their behaviour is
visible in the test suite instead of hidden behind a library.

## Layering

```
                    main.py  (sys.path bootstrap, then core.cli.main)
                       |
    +------------------+------------------+
    |              core/cli.py            |  argparse subcommands + menu
    |   consent gates . report writing    |  one code path for both entries
    +------------------+------------------+
                       | registry.call(name, target, **options)
    +------------------+------------------+
    |           core/registry.py          |  discovery, envelope normalisation
    +------------------+------------------+
                       | module.run(target, config=..., **options) -> dict
    +------------------+------------------+
    |              modules/               |  13 capability modules, one file each
    +------------------+------------------+
                       |
    +------------------+------------------+
    |  core/net . dnsclient . whois_client |  protocol layer, stdlib only
    |  core/utils . config . db . report   |
    +-------------------------------------+
```

Nothing in `modules/` opens a raw socket itself; everything goes through
`core/net.py` or `core/dnsclient.py`. That is what makes the localhost test
suite able to exercise the real code paths.

## The module contract

Every module exposes exactly this surface, and `core/registry.py` verifies it:

```python
NAME        = "ports"                  # CLI subcommand name
TITLE       = "Port Scanner"           # human label for `tools` and the dashboard
DESCRIPTION = "TCP connect scan ..."   # one line
CATEGORY    = "recon"
ACTIVE      = True                     # requires --authorized
REQUIRES    = ()                       # provider keys, empty when offline-capable

def run(target: str, config: Config | None = None, **options) -> dict: ...
```

`run()` returns a plain dict and **must not raise** for expected failures. The
registry normalises it:

```python
{"ok": bool, "module": str, "target": str,
 "findings": [{"severity", "title", "detail", "reference"}],
 "risk": "info|low|medium|high|critical", "score": int,
 "summary": str, "queried_at": iso}
```

Three outcomes are deliberately distinct:

| Outcome | Shape | Meaning |
|---|---|---|
| success | `ok: True` | the check ran |
| degraded | `ok: True, degraded: True, message: ...` | ran, but an optional provider was unavailable; the CLI prints the missing variable and how to get it |
| error | `ok: False, error: str, message: str` | the check could not run at all |

A degraded result is never dressed up as a finding-free success: the CLI prints
a warning block naming the exact environment variable, and `score` stays 0
rather than implying a clean bill of health.

## Why the protocol layer is hand-written

**DNS** (`core/dnsclient.py`): builds the query, parses the response, follows
compression pointers with a depth guard, formats A/AAAA/CNAME/MX/NS/TXT/SOA/SRV/
CAA, retries over TCP when a UDP answer is truncated, and falls back through the
resolvers in `/etc/resolv.conf`. An `NXDOMAIN` is `ok: True` with
`status: NXDOMAIN`, not an error - the distinction matters for subdomain
enumeration, where "does not exist" is a valid answer.

**WHOIS** (`core/whois_client.py`): raw TCP 43, follows a `refer:` /
`whois:` referral once, and maps the wildly inconsistent field names of ~20
registries onto one vocabulary. Returns the raw text alongside the parsed dict so
an unexpected registry never loses data.

**TLS** (`core/net.py`): fetches the DER certificate with verification disabled
(so expired and self-signed certs can be *analysed* rather than refused), then
decodes it with `ssl._ssl._test_decode_cert` on a temp PEM. `getpeercert()`
returns `{}` when verification is off, so relying on it would silently produce a
report with no subject and no SANs. When the private decoder is absent the
result says so instead of pretending the certificate had no fields.

## Consent, two separate gates

**Terms** - accepted once, persisted at `consent_version`, or forced per run
with `--accept-terms` / `REAPER_ACCEPT_TERMS=1`.

**Authorization** - per run, per target, for active modules only (ports,
subdomain brute force, web probing). `--authorized` records intent; the audit
log records what happened. The port scanner re-checks the flag inside the module
as well, so a direct API call cannot bypass the CLI gate.

Both are non-interactive safe. `REAPER_NONINTERACTIVE=1` forces the refusal path
even when a tty is present, because tmux, CI runners and `script` sessions all
hand you a tty with nobody behind it - prompting there hangs the run forever
instead of failing cleanly. This is the single most important detail in the
whole codebase and it is covered by tests.

## Storage

SQLite at `~/.king-reaper-x/reaper.db`, four tables:

- `scans` - one row per run (module, target, risk, score, duration)
- `results` - the full JSON payload, so any past report can be regenerated
- `findings` - individual findings, queryable by severity
- `audit` - every gate decision and every scan, in order

The dashboard reads these tables directly; it has no cache and no mock data.

## Reporting

`core/report.py` renders one result dict four ways: JSON, Markdown, a styled
HTML page, and a **printable** HTML page with print CSS. The last one is the PDF
path - no PDF library, no fonts to install, works identically on Android.

All interpolated values pass through `html.escape`, which is covered by a test
that injects `<script>` into a target and asserts it comes back escaped.
