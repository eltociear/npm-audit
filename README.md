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
| Host-fingerprint beacon (hostname / username / home dir / DNS servers collected and sent home: the dependency-confusion callback) | HIGH |
| Off-registry dependency URL (`"dep": "https://packages.<host>/…"`) | HIGH |
| Code hidden past hundreds of spaces, encoded `require()`, eval over char-code arrays, obfuscator.io string rotation | HIGH |
| Wallet seed / mnemonic / private key sent to a hard-coded URL | HIGH |
| XOR string decoder next to a process or network sink | MEDIUM |
| `binding.gyp` `<!(node file.js)` (node-gyp runs it on install, no `scripts` entry needed) | MEDIUM |

**Anything HIGH or MEDIUM found in a file that a `preinstall` / `install` / `postinstall` script
runs (or that such a file `require`s or spawns, two hops deep, or that `binding.gyp` executes) is
escalated to CRITICAL.** Code that executes automatically on `npm install` gets no benefit
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
in TypeScript and two binary installers. It is now anchored to the real domains. 12 scored
pattern groups / 57 signatures plus file-level combination rules, and 5 informational context patterns. Fully
deterministic, no LLM, no network needed except to fetch the tarball.

**Full results: [FINDINGS.md](FINDINGS.md)** (method, noise taxonomy, what surfaced).

## Recall on real malware

Precision only means something next to recall, and canaries we wrote ourselves cannot measure
recall. So `npm-audit` was benchmarked on **995 real malicious npm packages** from the
[DataDog malicious-software-packages dataset](https://github.com/DataDog/malicious-software-packages-dataset)
(2024 to 2026, stratified by half-year and campaign, read in memory and never executed). The
rules were tuned on 60% of them, frozen, and then scanned once against a 40% held-out split
whose malware *families* the rules had never seen:

| Distinct samples flagged HIGH/CRITICAL | 0.1.0 | 0.2.0 |
| --- | --- | --- |
| Tune split (405) | 64.7% | 82.0% |
| **Held-out split (267, unseen families)**, frozen rules scanned once | 58.8% | **73.4%** (73.0% after the precision fixes) |
| Compromised popular libraries, held-out (40: Shai-Hulud, xrpl, react-native-aria, …) | 20.0% | **90.0%** |
| Benign popular packages flagged HIGH+ (2,063: the FINDINGS.md 680 plus 1,383 more, ranks 602-1999) | 4 | 5 |

Precision held roughly level, and did not improve. The frozen rules produced 3 new false
positives on blind benign sets, and the first fix produced 2 more on the next blind set. Both
rounds were fixed, each checked on a set nobody had looked at yet. The final engine has 1 false
positive in its last blind set (383), where 0.1.0 has none. About a quarter of real samples still
get through: packages with no payload of their own (placeholders, stubs, dependency shims),
trojanised clones of popular libraries, and loader shapes no rule names yet.
**Full method, per-stratum numbers and miss classes: [RECALL.md](RECALL.md).**

### n8n community nodes and Node-RED nodes

Both are npm packages that run inside an automation server holding every workflow's credentials,
so `npm-audit` auto-detects them (from the `n8n` / `node-red` field in `package.json`, or force
it with `--n8n` / `--node-red`) and adds host-specific rules:

| Pattern | Severity |
| --- | --- |
| Workflow credentials + a hard-coded collector (webhook.site, paste site, tunnel, literal chat webhook) + a send | CRITICAL |
| n8n: reaching into the instance (`N8N_ENCRYPTION_KEY`, `~/.n8n/config`, the credential DB, n8n internals) | HIGH |
| Node-RED: reading `flows_cred.json` / `.config.*.json` (HIGH with network, CRITICAL with a collector) | MEDIUM+ |
| Node-RED: `RED.httpAdmin` routes without `RED.auth.needsPermission`, credential lookups by request id | MEDIUM |
| n8n: `getCredentials()` for a type the package never declares | MEDIUM |

Measured on 4,967 nodes (2,500 n8n, 2,467 Node-RED; calibration plus blind held-out sets): 0
false positives at HIGH or worse after calibration, and 0 in the held-out sets.
**Results: [FINDINGS-n8n-node-red.md](FINDINGS-n8n-node-red.md)**.

## Usage

```bash
python npm_audit.py <pkg>[@version] [...]         # registry fetch (NPM_AUDIT_REGISTRY to override)
python npm_audit.py ./path/to/package             # a local package directory (node_modules skipped)
python npm_audit.py package.json                  # the package that owns this package.json
python npm_audit.py suspicious.js                 # one file
python npm_audit.py pkg-1.0.0.tgz                 # a local tarball (npm pack output), read in memory
python npm_audit.py --lockfile package-lock.json  # every dependency in a v1/v2/v3 lockfile
python npm_audit.py --node-modules ./node_modules # every installed package, separately
python npm_audit.py --text "…"                    # a string
python npm_audit.py --keyword n8n-community-node-package --limit 500  # bulk: registry search
python npm_audit.py <target> --n8n | --node-red   # force the host-specific rules
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

Twenty-eight inert malicious canaries (env exfil, webhook stealer, pipe-to-shell, runtime exec of
`curl | sh`, inline `node -e` beacon, obfuscation, reverse shell, wallet theft, DNS beacon, host
recon beacon, worm, wiper, n8n credential exfil / encryption-key theft / undeclared
credential and Node-RED credential-store theft / unauthenticated credential routes, plus ten
shapes taken from the real-malware benchmark: dependency-confusion fingerprint beacon, off-registry
dependency URL, encoded `require`, eval of a fetched response, whitespace-hidden code,
`binding.gyp` command execution, an install script that spawns the real payload, wallet-seed exfil,
char-code-array eval and obfuscator.io string rotation) must each fire at the right severity.
Fifteen benign controls modelled on real packages (binary installer, node-gyp, funding banner,
config loader, CLI wrapper, env debug print, install-hint strings, release scripts, typical n8n
and Node-RED nodes, a Telegram integration, a vendor callback URL, a node-addon-api
`binding.gyp`, a host-info helper, GitHub dependency URLs) must land where expected. The canaries
use reserved `.invalid` / TEST-NET hosts, and nothing in `tests/` is ever executed.

## Limits

Static and pattern-based. A determined attacker can split a payload across files, fetch stage 2
at runtime, or use a fresh host. Treat a SAFE result as "no known-bad shape", not as a proof,
and treat findings as leads for human review, not verdicts. Files over 1.5 MB are read only when an
install script runs them (up to 16 MB) or while they fit in the 12 MB per-package budget, and
scanning a multi-megabyte minified payload takes seconds, not milliseconds. Malicious code that
lives in a dependency, in a prebuilt binary, or in a stage 2 fetched at runtime is invisible to
any static scan of the package itself ([RECALL.md](RECALL.md) breaks down what gets through).

Sibling projects: [mcp-audit](https://github.com/eltociear/mcp-audit) (MCP servers & agent
skills) and [skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp) (the same engine as
an MCP server, GitHub Action and hosted API).

MIT licensed.
