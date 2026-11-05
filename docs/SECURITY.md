# Security model

## Scope of the tool

KING REAPER X performs **public-source collection** and **authorized active
testing**. It is not a spyware toolkit and contains no code path that could be
repurposed as one.

### Deliberately absent

These are not "not yet implemented" - they are excluded by design, and a pull
request adding them will be rejected:

- phone-number-to-location lookup or cell-tower triangulation
- WhatsApp message, contact or profile interception; unofficial WhatsApp libs
- OTP, 2FA or verification-code capture
- credential harvesting, keylogging, screen capture
- hidden camera/microphone access
- covert device tracking or beaconing
- bypassing any authentication or permission boundary
- using leaked/breach data as a discovery source

### Sources used

| Source | Type | Notes |
|---|---|---|
| Public DNS | public | wire protocol, no third party |
| WHOIS (port 43) | public | registry-published |
| crt.sh | public | Certificate Transparency logs |
| hackertarget | public | passive DNS |
| ip-api | public | geolocation and ASN |
| URLhaus, OpenPhish | public | threat feeds |
| numverify, VirusTotal, AbuseIPDB, ipinfo, HIBP | **keyed** | you supply the key |
| WhatsApp Cloud API | **keyed** | official business profile only |

---

## Consent gates

Two independent gates, both **non-interactive safe**.

### Terms gate

Accepted once; persisted with a version number so a wording change re-prompts.

```bash
reaper-x --accept-terms <command>      # per run
export REAPER_ACCEPT_TERMS=1           # per shell
```

With no tty, the gate returns a refusal instead of calling `input()`:

```json
{"ok": false, "error": "terms_not_accepted",
 "message": "Terms not accepted and no terminal available. ...",
 "hint": "--accept-terms"}
```

`REAPER_NONINTERACTIVE=1` forces that path **even when a tty exists** - tmux, CI
runners and `script` sessions hand you a tty with no human behind it, and
prompting there hangs forever.

### Authorization gate

Applies only to active modules: `ports`, `subdomains --brute`, `webscan`.

```bash
reaper-x ports 10.0.0.5 --authorized
```

Every grant **and** every refusal is written to the `audit` table with timestamp,
module and target. The audit log is readable through `reaper-x history` and the
dashboard's `/api/audit`.

---

## Secret handling

- Keys live in `~/.king-reaper-x/config.json`, directory `0700`, file `0600`.
- Written atomically (temp file in the same directory, `fsync`, then `os.replace`)
  so an interrupted write cannot truncate an existing config.
- The key is never echoed: `config set-key` uses a no-echo prompt.
- Display paths mask it, and `provider_report()` returns only
  `configured: true/false` - never the value.
- Environment variables take precedence, so CI can inject a key without it ever
  touching disk.
- Log records pass through a redaction filter that strips anything shaped like a
  key before it reaches `~/.king-reaper-x/logs/`.

Nothing is hardcoded. A `grep` for key-shaped literals across the repo returns
no hits, and the test suite asserts that `provider_report()` contains no secret
material.

### If a key leaks

1. Revoke it at the provider - assume it is compromised.
2. `reaper-x config clear-key <provider>`
3. Rotate anything else that key could reach.

---

## Input validation

Everything crossing into a socket is validated first:

| Input | Rule |
|---|---|
| domain | RFC-1123 label rules, <=253 chars, no scheme, no spaces |
| IP | `ipaddress.ip_address()` for both families |
| port spec | `80,443` / `100-200`, normalised, deduped, 1-65535 only |
| URL scheme | `http`/`https` only; anything else is refused, not coerced |
| username | alphanumeric plus `._-`, length-capped |
| coordinates | numeric, range-checked |
| phone | digits only, <=17 (E.164) |

Invalid input produces `{"ok": false, "error": "bad_target", "message": ...}` and
exit code 2 - never a traceback, never a partially-executed scan.

---

## Command execution

There is **no** `subprocess`, `os.system`, `eval`, `exec` or `shell=True` anywhere
in the framework code. `openssl` is invoked by the *test suite only*, to mint a
throwaway self-signed certificate for the TLS test, using an argument list (never
a shell string).

The only files that touch the network are `core/net.py`, `core/dnsclient.py` and
`core/whois_client.py`; everything else goes through them. That is the entire
attack surface for SSRF-style issues, and it is where the scheme allow-list
lives.

---

## Report safety

Every value interpolated into HTML passes through `html.escape`, including the
target itself. A test injects `<script>alert(1)</script>` as a target and asserts
it renders escaped. JSON reports are produced by `json.dumps`, so no injection is
possible there.

---

## Network exposure

The dashboard binds `127.0.0.1` and refuses other addresses unless
`--allow-public` is passed, because it serves your entire scan history with **no
authentication**. If you must expose it, put it behind a reverse proxy with auth
and TLS - `--allow-public` alone is not a security control.

Set `--quiet` to keep request logs off stdout in shared environments.

---

## Rate limiting and etiquette

- `--rate N` enforces a global requests-per-second ceiling (`RateLimiter`, thread
  safe).
- Default is 8 rps; the module defaults are deliberately conservative.
- DNS brute force caps resolution attempts and checks wildcards first, so a
  mistake does not become a flood.
- Public sources (crt.sh, hackertarget) are called once per query with no retry
  storm.

---

## Reporting a vulnerability

Open a private security advisory on the repository rather than a public issue.
Include reproduction steps and the affected file. Expect an acknowledgement
within a few days.
