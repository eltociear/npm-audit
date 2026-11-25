# What we found scanning 4,967 n8n and Node-RED nodes

n8n community nodes and Node-RED nodes are ordinary npm packages, but they run **inside an
automation server that holds the credentials of every service its workflows touch**: CRMs,
mailboxes, databases, cloud accounts, chat bots. A node is supposed to read *its own*
credentials. This is a scan of what popular and random nodes actually do, with the same engine
and the same rule: calibrate first, so that "clean" means clean.

Scan date: 2026-11-26. Latest version of each package at that time. Nothing was installed or
executed; every tarball was read as text.

## Method

| Set | Source | Picked | Scanned |
| --- | --- | --- | --- |
| n8n calibration | npm search, keyword `n8n-community-node-package` | top 1,500 by monthly downloads | 1,500 |
| n8n held-out | same | random 1,000 of ranks 1,501–5,250 (seed 20261126) | 1,000 |
| Node-RED calibration | flows.nodered.org catalogue (6,441 modules) | top 1,500 by weekly downloads | 1,490 |
| Node-RED held-out | same | random 1,000 of the rest (seed 20261126) | 977 |

- The keyword has 14,778 packages, but the registry search API only returns about 5,250
  distinct results for it, so the n8n sample is drawn from those. It is the popular end of the
  ecosystem, not all of it.
- 33 Node-RED catalogue entries point at versions that are no longer on npm (HTTP 404).
- Every package was scanned in its own process with a hard timeout; none timed out on the final
  rules. 1.1 GB of text in total.
- The rules were tuned on the calibration sets only, committed (`f16570f`), and then the
  held-out sets were scanned **once**.

## Headline

| Set | Naive rules: HIGH or worse | Final rules: HIGH or worse | …of which false |
| --- | --- | --- | --- |
| n8n calibration (1,500) | 47 (3.1%) | 9 (0.6%) | **0** |
| n8n held-out (1,000) | 33 (3.3%) | 1 (0.1%) | **0** |
| Node-RED calibration (1,490) | 240 (16.1%) | 14 (0.9%) | **0** |
| Node-RED held-out (977) | 84 (8.6%) | 8 (0.8%) | **0** |

"Naive" means the same signatures with every context and combination rule switched off: any
collector-host string, any credential-store path, any env serialisation, any install script that
touches the network or a process, any admin route without an auth check. Before calibration the
drafted rules flagged at least 14 benign packages HIGH or worse (5 n8n, 9 Node-RED); every one of
those classes is fixed and has a regression fixture. One held-out line-level hit was help text in
a Node-RED editor template; the same package also sets the flag in code, so the package-level
result stands.

**No credential stealer, worm, reverse shell or wiper was found in either ecosystem.** What the
remaining HIGH and CRITICAL results do find is real, and specific to automation hosts.

## What surfaced

All of these are stated as observed behaviour, not intent. No package is named here.

**A user's API token sent to a hard-coded webhook.site URL (n8n, CRITICAL, 1 package).** An
e-invoicing node posts its payload *and* the user's access token for the accounting service to a
fixed `webhook.site` address. It reads like a development endpoint that was never replaced, but
anyone holding that webhook.site page receives every user's token and documents. This is exactly
the shape the `automation_credential_exfil` rule exists for.

**A hard-coded collector as a callback URL (n8n, HIGH, 1 package).** A video-generation node
passes a fixed `webhook.site` URL as the vendor's `callback_url`, so every job result is delivered
to that page. The credential itself goes to the vendor, which is why this stays HIGH and is not
counted as credential theft.

**A node that harvests instance secrets (n8n, HIGH, 1 package).** Published as a "security test
PoC", it returns a filtered dump of the environment (DB, Redis, secret, token and password
variables), the contents of `~/.n8n/config` (which holds the instance encryption key) and
container metadata as node output. It also ships an unwired script that runs
`id && hostname && whoami && uname -a` and posts the result; the new `recon_beacon` rule catches
that shape.

**Nodes reaching into n8n itself (n8n, HIGH, 2 packages).** One agent node opens n8n's own
database (SQLite or Postgres, using the instance's DB credentials) and reads `credentials_entity`
directly, bypassing the credential model that limits a node to the types it declares. Another
reads `N8N_ENCRYPTION_KEY` and sends a truncated hash of it to a licence server as an instance
fingerprint. Neither looks malicious; both mean the node can see far more than its own
credentials.

**Global TLS verification switched off (Node-RED, HIGH, 19 packages).** They set
`process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'` in code. In Node-RED that is not local to the
node: it turns certificate checking off for **every node and flow in the same runtime**, so
installing one such node silently makes all other HTTPS connections interceptable.

**Obfuscated bundles (9 packages: 5 n8n, 4 Node-RED).** javascript-obfuscator output, mostly
licence-protected commercial nodes. Not malicious as far as can be told, but unreadable, so a
static review (this one included) can't vouch for them. One obfuscated n8n node is a credentials
backup/restore tool.

## The Node-RED admin API

The weakness that shows up most is not malware. Node-RED nodes can add HTTP endpoints to the
editor's admin API with `RED.httpAdmin`. Those routes are only protected when the node adds
`RED.auth.needsPermission(...)`; otherwise they are reachable without logging in even when
`adminAuth` is enabled.

| Node-RED | Calibration (1,490) | Held-out (977) |
| --- | --- | --- |
| Define admin routes at all | 387 (26.0%) | |
| Unauthenticated POST/PUT/DELETE/`use`, or a GET that touches credentials, files or processes (MEDIUM) | 94 (6.3%) | 27 (2.8%) |
| Look up credentials by a node id taken from the request (`getCredentials(req.params…)`, MEDIUM) | 10 (0.7%) | 3 (0.3%) |
| Unauthenticated GETs serving static UI data (INFO only) | 155 (10.4%) | |

A credential lookup keyed by a request parameter on an unauthenticated route is a credential
disclosure endpoint for anyone who can reach the editor port. These are reported as MEDIUM:
they are weaknesses for the maintainer to fix, not attacks.

## The noise: what looked dangerous but wasn't

| Signal | Why it was noise | Fix |
| --- | --- | --- |
| `curl … \| bash` in an error message ("install the CLI with …") | Shown to the user, never run | Only scored when the same line hands it to exec/spawn, in shell scripts, or at install time |
| `https://api.telegram.org/bot' + token` | A Telegram node calling Telegram with the user's own bot token | Chat/webhook APIs count as collectors only with a literal, hard-coded token or webhook id |
| `N8N_ENCRYPTION_KEY` in credential help text; a node's own `getEncryptionKey()` | Documentation; an unrelated function | Only `process.env.N8N_ENCRYPTION_KEY` and n8n's own APIs count |
| `// To publish: npm publish --access public`; a shipped `release.sh` | The maintainer's release instructions | `npm publish` needs a token, the `-/whoami` probe, or exec from JS |
| Commented-out `NODE_TLS_REJECT_UNAUTHORIZED = 0`, `rm -rf /`, `JSON.stringify(process.env)` | Comments | Comment-only lines are ignored for those rules |
| `flows_cred.json` / `credentialSecret` in help pages and typedefs | Documentation | Only real file reads of the store count; `credentialSecret` use is context unless a collector is present |
| `/oauth2/...` route path read as "has auth middleware" | The word was in the path | The route path is excluded from the middleware check |
| Tunnel hosts in an ngrok integration node, or in `https://123456.ngrok.io` examples | The node *is* the integration; placeholders | Brand-named integrations and placeholder URLs are context |
| `echo '… curl …'` in a postinstall banner | Printed text | echo/printf text is ignored when checking lifecycle scripts |
| Findings under `test/`, `examples/`, `docs/` | Never loaded by the runtime | Context unless a lifecycle script runs them |

## Capabilities (context, never scored)

| | n8n calibration | Node-RED calibration |
| --- | --- | --- |
| Call `getCredentials` | 65.7% | 5.3% |
| Use a network primitive the scanner recognises | 34.3% | 35.7% |
| Read environment variables | 6.3% | 15.6% |
| Spawn processes | 2.3% | 7.5% |
| Declare an install script | 3.3% | 1.7% |
| Have a JS file over 1.5 MB (skipped, see Limits) | 1.2% | 1.2% |

## Takeaways for operators

1. **One node's choices apply to the whole runtime.** A Node-RED node that disables TLS, or an n8n
   node that reads the encryption key, affects every workflow on that server.
2. **Check admin routes.** In Node-RED, treat any third-party node that adds unauthenticated
   `RED.httpAdmin` routes as part of your attack surface, especially routes that return credentials.
3. **Hard-coded collectors are bugs that leak data.** A forgotten `webhook.site` URL in a node is as
   damaging to its users as a deliberate stealer.
4. **Scan before installing, and on every update:**
   `python npm_audit.py <package>` auto-detects both ecosystems, and
   `python npm_audit.py --keyword n8n-community-node-package --limit 500` scans in bulk.

## Limits

Static and pattern-based. Files over 1.5 MB are skipped (1.2% of packages here have one);
compiled or obfuscated code can't be read; a node can fetch a second stage at run time. The
held-out numbers are blind, but each set is a sample of one snapshot. SAFE means "no known-bad
shape", not proof.

*Findings are pattern matches warranting human review, not verdicts. Packages that appear to leak
user credentials have been passed on for responsible disclosure and are not named here.*
