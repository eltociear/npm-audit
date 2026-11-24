# npm-audit

**Scan npm packages for *malicious* patterns before you install them.** `npm audit` tells you
whether a version has a known CVE. It says nothing about the package published an hour ago whose
`postinstall` ships your `process.env` to a Discord webhook. This fills that gap.
Zero dependencies, one file, MIT.

```bash
python npm_audit.py some-package            # fetch the tarball from the registry and scan it
python npm_audit.py @scope/pkg@1.2.3
python npm_audit.py --lockfile package-lock.json
# 🔴 evil-pkg@1.0.0  [CRITICAL]  score=50  (2 findings, 4 info)
#     script   postinstall: node index.js
#     CRITICAL Environment Dump  index.js:2
#              const data = Buffer.from(JSON.stringify(process.env)).toString('base64');
```

**The package is never installed and none of its code runs.** The tarball is downloaded into
memory and read as text. Exit code `2` if anything is HIGH/CRITICAL, so it drops into CI.

## Why this exists

Real npm supply-chain attacks rarely look like a CVE. They look like:

- an install script that runs `curl … | sh` or `node -e` with network code the moment you `npm install`;
- a bundle that serialises `process.env` (every CI token and cloud key) and POSTs it out;
- a "utility" that reads `~/.npmrc` / `~/.ssh` / browser and wallet storage and sends it to a webhook;
- a dependency-confusion beacon that encodes your hostname into a DNS lookup to an OAST collector;
- a worm that uses a stolen npm token to republish itself into every package the victim maintains
  (the 2025 Shai-Hulud incident), often downloading TruffleHog to harvest more secrets;
- javascript-obfuscator output (`_0x4f2a…`) hiding any of the above;
- protestware / wipers that `rm -rf` the home directory.

`npm audit`, Dependabot and friends match **known advisories**. They cannot see any of this until
someone has been hit, reported it, and an advisory has been written. `npm-audit` looks at what the
code *does*.

## What it flags

| Pattern | Severity |
| --- | --- |
| Download & execute (`curl … \| sh`, `eval(fetch(…))`, encoded PowerShell) | CRITICAL |
| Environment dump (`JSON.stringify(process.env)`) **in a file that also does network I/O** | CRITICAL |
| Credential store (`~/.npmrc`, `~/.ssh/id_*`, `~/.aws/credentials`, …) **+ exfil endpoint** | CRITICAL |
| Reverse shell (`/dev/tcp/…`, socket piped into `/bin/sh`) | CRITICAL |
| Destructive payload (`rm -rf ~`, `fs.rmSync(os.homedir())`) | CRITICAL |
| Worm propagation (`npm publish` with a token, `-/whoami`, TruffleHog harvest) | CRITICAL |
| `node -e` with network code in a lifecycle script | CRITICAL |
| Exfiltration endpoint (Discord/Telegram/Slack webhooks, webhook.site, pipedream, paste sites, ngrok/cloudflared tunnels, OAST/interactsh/Burp collaborator) | HIGH |
| Crypto-wallet / browser credential theft (MetaMask & co. extension IDs, `Login Data`, Keychain) | HIGH |
| Obfuscated payload (`eval(atob(…))`, `new Function(Buffer.from(…,'base64'))`, ≥25 `_0x` identifiers) | HIGH |
| DNS exfiltration (hostname / username / env encoded into `dns.lookup`) | HIGH |
| Install-time `curl`/`wget` | HIGH |
| `NODE_TLS_REJECT_UNAUTHORIZED=0` | HIGH |
| Raw public-IP URL (only at install time or next to a credential/env read) | MEDIUM |

**Anything HIGH or MEDIUM found in a file that a `preinstall` / `install` / `postinstall` script
runs is escalated to CRITICAL.** Code that executes automatically on `npm install` gets no benefit
of the doubt.

## Calibrated, not noisy

A scanner that flags every `child_process` gets ignored within a day. Popular packages
legitimately download prebuilt binaries at install time (esbuild, sharp, @swc/core, Sentry CLI),
spawn processes, read `~/.npmrc` (every npm config library) and `~/.aws/credentials` (the AWS SDK).
These are **capabilities**, reported in an informational tier (`--verbose`) that never touches the
risk score. Risk comes from **combinations** and **specific sinks**.

Measured on **680 real npm packages** (the 600 most-downloaded found via registry search, plus
every package in the top 2,000 that declares a `preinstall`/`install`/`postinstall` script,
which came to 83):

| | Flagged HIGH/CRITICAL |
| --- | --- |
| Naive rules (install-time network or exec, any credential-store path, any exfil-host string, any env serialisation) | 59 / 380 (15.5%) |
| Calibrated engine, calibration set (380) | 3 / 380 (0.8%) → **0** after one fix |
| Calibrated engine, **held-out** set (next 300 by downloads, never tuned against) | **0 / 300** |

The one fix was a substring bug: the `requestbin` collector pattern matched `requestBinary(…)`
in TypeScript and two binary installers. It is now anchored to the real domains. 14 scored
patterns / 44 signatures plus combination rules, and 5 informational context patterns. Fully
deterministic, no LLM, no network needed except to fetch the tarball.

**Full results: [FINDINGS.md](FINDINGS.md)** (method, noise taxonomy, what surfaced).

## Usage

```bash
python npm_audit.py <pkg>[@version] [...]         # registry fetch (NPM_AUDIT_REGISTRY to override)
python npm_audit.py ./path/to/package             # a local package directory (node_modules skipped)
python npm_audit.py package.json                  # the package that owns this package.json
python npm_audit.py suspicious.js                 # one file
python npm_audit.py --lockfile package-lock.json  # every dependency in a v1/v2/v3 lockfile
python npm_audit.py --node-modules ./node_modules # every installed package, separately
python npm_audit.py --text "…"                    # a string
python npm_audit.py <target> --json               # machine-readable
python npm_audit.py <target> --verbose            # also print INFO context
```

Safest workflow for a new dependency: scan it **before** `npm install`, then install with
`npm install --ignore-scripts` if you want to inspect further.

As a library:

```python
import npm_audit
r = npm_audit.audit_registry("left-pad")
r["risk_level"], r["findings"], r["install_scripts"]
```

## Tests

```bash
python tests/run.py
```

Ten inert malicious canaries (env exfil, webhook stealer, pipe-to-shell, inline `node -e`
beacon, obfuscation, reverse shell, wallet theft, DNS beacon, worm, wiper) must each fire at the
right severity. Six benign controls modelled on real top packages (binary installer, node-gyp,
funding banner, config loader, CLI wrapper, env debug print) must all scan SAFE. The canaries
use reserved `.invalid` / TEST-NET hosts, and nothing in `tests/` is ever executed.

## Limits

Static and pattern-based. A determined attacker can split a payload across files, fetch stage 2
at runtime, or use a fresh host. Treat a SAFE result as "no known-bad shape", not as a proof,
and treat findings as leads for human review, not verdicts. Bundles over 1.5 MB per file are
skipped (malicious install-time payloads are almost always small).

Sibling projects: [mcp-audit](https://github.com/eltociear/mcp-audit) (MCP servers & agent
skills) and [skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp) (the same engine as
an MCP server, GitHub Action and hosted API).

MIT licensed.
