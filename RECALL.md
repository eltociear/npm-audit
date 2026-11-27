# Recall on real npm malware

[FINDINGS.md](FINDINGS.md) measured false positives honestly. Until now, recall had only been
measured on canaries we wrote ourselves, which shows that a rule fires but not how much real
malware gets through. This report measures recall on **995 real malicious npm packages** from
the [DataDog malicious-software-packages dataset](https://github.com/DataDog/malicious-software-packages-dataset),
uses the misses to improve the rules, and then checks that precision on popular packages did not
get worse.

Scan date: 2026-11-27. Engine before: `cfa1e2b` (0.1.0). Engine with frozen rules: `a753143`.
Final engine after two post-hoc precision fixes: 0.2.0, in this commit (see *Precision check*).

## Method

1. **Sampling.** The dataset's npm tree holds 25,267 `malicious_intent` samples (12,819 packages)
   and 1,448 `compromised_lib` samples (1,004 packages), dated 2024 to 2026. One version per
   package, zips of 20 MB or less, stratified by half-year with √-proportional allocation. Within
   each stratum, at most 10 samples per publication day and 3 per 5-character name prefix, so
   that a single campaign burst (hundreds of `000webhost-*`-style clones on one day) cannot fill
   the sample. Result: **879 malicious_intent + 116 compromised_lib = 995 samples**, seed fixed.
2. **Reading.** Samples are password-protected zips (ZipCrypto, password `infected`). They are
   decrypted **in memory** with the standard-library `zipfile` and passed straight to
   `scan_package()`, so nothing is extracted to disk and nothing is executed, installed or
   imported. Lifecycle scripts come from the tarball's `package.json`, falling back to the
   registry packument shipped in the zip.
3. **Dedup.** Each sample gets a content key: the hash of every file with the package's own name
   and version replaced by a placeholder and whitespace removed, plus its normalised lifecycle
   scripts. Typosquat clones that differ only by name collapse to one key. 995 samples give 672
   distinct keys. Numbers are reported both **raw** and **deduped**. Dedup keys come from the
   baseline run, so every engine is scored on the same deduped set.
4. **Families and split.** Samples that share any normalised file of 150 bytes or more (ignoring
   README, LICENSE and CHANGELOG) are joined into one family (union-find). That gives 561
   families, the largest with 143 samples. **Whole families** go to *tune* (60%) or *held-out*
   (40%), so every held-out family is one the rules never saw: 597 / 398 samples, 334 / 227
   families.
5. **Protocol.** Rules were changed only after looking at *tune* misses. The rules were then
   frozen and committed (`a753143`). Only after that commit was the held-out split scanned, once.
   The benign calibration set (380) was re-checked during tuning. Each benign held-out set was
   scanned blind exactly once by one engine version, and every later precision fix was judged on
   a set that had not been looked at yet.
6. **Detection** means the package-level verdict is `HIGH` or `CRITICAL` (`HIGH+`), or anything
   from `MEDIUM` up (`MEDIUM+`).

A manifest of every sample (dataset path, package, version, zip sha256, split, family, verdicts
for 0.1.0, the frozen rules and 0.2.0, and the rules fired) is in
[`benchmarks/recall-manifest.json`](benchmarks/recall-manifest.json). No sample content is in
this repository. 34 of the 995 sampled versions were still served by registry.npmjs.org when
checked on 2026-11-27. Their names, versions and hashes are **redacted** in the manifest (only
split, date and verdicts are kept) and were reported privately instead of published.

## Results

| Split | Engine | raw HIGH+ | deduped HIGH+ | deduped MEDIUM+ |
| --- | --- | --- | --- | --- |
| tune (597 / 405 dedup) | before (0.1.0) | 413 (69.2%) | 262 (64.7%) | 262 (64.7%) |
| tune | **frozen rules** | 509 (85.3%) | **340 (84.0%)** | 340 (84.0%) |
| **held-out** (398 / 267 dedup, unseen families) | before (0.1.0) | 235 (59.0%) | 157 (58.8%) | 157 (58.8%) |
| **held-out** | **frozen rules, scanned once** | 276 (69.3%) | **196 (73.4%)** | 197 (73.8%) |

The honest number is the held-out one: **58.8% → 73.4%** of distinct real malware samples flagged
HIGH or worse. The gap between tune (84.0%) and held-out (73.4%) is the part of the improvement
that did not carry over to unseen families. Much of it is one held-out family that tuning never
saw (see the miss classes below). `MEDIUM` adds almost nothing because nearly every rule that fires
on real malware is HIGH or CRITICAL already.

By kind and half-year (deduped, HIGH+):

| Stratum | tune before → after | held-out before → after |
| --- | --- | --- |
| malicious_intent | 68.2% → 82.6% (n=333) | 65.6% → 70.5% (n=227) |
| compromised_lib | 48.6% → 90.3% (n=72) | **20.0% → 90.0%** (n=40) |
| 2024 H1 | 90.9% → 90.9% (n=22) | none in this split |
| 2024 H2 | 77.8% → 88.9% (n=45) | 84.6% → 84.6% (n=39) |
| 2025 H1 | 66.3% → 90.7% (n=86) | 83.6% → 89.1% (n=55) |
| 2025 H2 | 68.5% → 88.4% (n=146) | 58.6% → 77.1% (n=70) |
| 2026 H1 | 52.9% → 77.0% (n=87) | 42.5% → 70.0% (n=80) |
| 2026 H2 | 21.1% → 31.6% (n=19) | 13.0% → 17.4% (n=23) |

The biggest single gain is **compromised libraries** (hijacked maintainer accounts publishing a
poisoned version of a real package), from 20% to 90% on held-out. Before, the engine skipped every
file over 1.5 MB and read only the first 20,000 characters of each line. Shai-Hulud's
`bundle.js` (3.7 MB, run by `postinstall`), its 10 MB `bun_environment.js` successor and the
2026 eval-wrapped payloads are all one-line megabyte files, so the engine never looked at them.

The newest samples (2026 H2) are mostly undetected. Many of them are near-empty placeholders or
stubs (see below), and the recent campaigns are the ones the rules have seen least.

## What changed (all from tune misses)

| Miss class in *tune* (before) | Fix |
| --- | --- |
| Payload in a megabyte minified file or line (Shai-Hulud `bundle.js`, eval-wrapped 2026 payloads) | Files that install scripts run are read up to 16 MB. Long lines are scanned in overlapping 20 kB windows. Other big files are scanned within the 12 MB package budget, after the small ones |
| Install script only spawns or requires the real payload (`postinstall.js` → `spawn('node', [main.js])`) | Install context follows relative `require`/`import`/script-name references two hops |
| `binding.gyp` `<!(node index.js)` (node-gyp runs it on install with no `scripts` entry) | gyp command expansions that run a package file → `gyp_exec` + install context |
| Dependency-confusion callbacks: `{hostname(), userInfo(), homedir(), dns.getServers()}` POSTed home | `host_fingerprint_exfil`: 3+ identity calls and a send, or 2 plus a hard-coded destination IP, collector or install-time execution. DNS names built from host data → `dns_exfil` |
| Install-time `net.Socket` to `'8.152.163.60'` | Install-time send to a quoted public IP used as a destination → raw-IP finding, CRITICAL at install time |
| `"dep": "https://packages.<attacker>.com/…"` (payload kept off the registry) | `remote_dependency`: dependencies from non-registry, non-forge URLs |
| `require(Buffer.from("6f73","hex").toString())`, `Object.keys(process["env"]).map(…)` | Encoded-`require` obfuscation. Bracket-form env dumps count as an env dump. Install-time or encoded-require files with a `.request(` count as sending |
| `axios.post(…).then(r => eval(r.data))`, `res.on('data', d => body += d); … eval(body)`, `spawn('node', [], {stdio: ['pipe'…]})` fed from `axios.get` | Remote-code-execution shapes added to `download_execute` |
| obfuscator.io output with renamed identifiers (no `_0x`), `eval(function(s,n){…}([40,102,…]))`, Jscrambler-style `eval("(function f(…)…")` | String-array rotation idiom, char-code-array eval and self-decoding eval strings → `obfuscation` |
| react-native-aria / gluestack 2025: code after hundreds of spaces on one line | `hidden_code` |
| xrpl 2025 backdoor: `fetch('https://…', {headers: {'ad-referral': seed}})` | `wallet_secret_exfil`: seed, mnemonic or private key sent to a hard-coded URL |
| XOR-masked C2 host and commands next to `child_process` | `xor_decoder` (MEDIUM, CRITICAL at install time) |
| Shai-Hulud repack-and-republish (`tar -uf … package/bundle.js`, `` `npm publish ${tgz}` ``) | More `worm_propagation` signatures |

Each new rule has an inert canary in `tests/fixtures/` (reserved `.invalid` hosts, TEST-NET IPs),
plus three benign controls (a node-addon-api `binding.gyp`, a host-info helper with no send, and
GitHub/codeload dependency URLs). `npm_audit.py pkg-1.0.0.tgz` now scans a local tarball in memory.

## Precision check

HIGH+ false positives on popular packages (latest versions, re-fetched 2026-11-27). Ranks are
by weekly downloads in the same registry-search ranking FINDINGS.md used.

| Benign set | 0.1.0 | frozen rules `a753143` | fix 1 | **0.2.0 (fix 2)** |
| --- | --- | --- | --- | --- |
| Calibration: top 300 + install-script packages (380, the FINDINGS.md set) | 0 | 0 | 0 | **0** |
| Original held-out: next 300 (FINDINGS.md) | 0 | **1** (blind) | 0 | 0 |
| Fresh A: ranks 602-1103 (500), never used before | 0 | **2** (blind) | 0 | 0 |
| Fresh B: ranks 1104-1610 (500) | 4 | n/a | **6** (blind) | 4 |
| Fresh C: ranks 1611-1999 (383), scanned once with the final engine | 0 | n/a | n/a | **1** (blind) |
| **Total (2,063)** | **4** | | | **5** |

"Blind" marks the first time an engine saw that set. Each fix round looked at the false positives
of the round before, so the next round was judged on a set nobody had looked at.

This also closes an open gap: the n8n / Node-RED engine changes (`f16570f`) had never been
re-checked on the original 680-package corpus. Re-fetched at current versions, 0.1.0 (which
includes those changes) scores **0 / 680** at HIGH+.

**The honest summary: precision is about where it was, not better.** On the 2,063 benign
packages, 0.2.0 flags 5 and 0.1.0 flags 4. On the only set that was blind for the final engine
(Fresh C), 0.2.0 has 1 false positive in 383 and 0.1.0 has none.

- **Frozen rules → fix 1** (the three blind false positives in the original held-out and Fresh A):
  `@typescript/vfs` hides `require(String.fromCharCode(…))` from bundlers, so only hex/base64
  `Buffer.from` module names count now. `@napi-rs/cli` builds a child environment with
  `Object.fromEntries(Object.entries(process.env).filter(…))`, so only the bracket form
  `process["env"]` counts. `react-doctor`'s 2 MB bundle had a Node version string `"2.3.8.0"`
  that matched the bare-IP check, so bare IPs now count only as a destination (host/ip/server key,
  `:port`, `connect(` argument).
- **Fix 1 → fix 2** (two new blind false positives in Fresh B, `@devcontainers/cli` and
  `@mintlify/cli`, both from scanning multi-megabyte CLI bundles): a file over 1.5 MB that no
  install script runs now only reports payload-specific rules (worm propagation, obfuscation,
  hidden code, wallet-secret exfiltration, reverse shell). Env plumbing, telemetry and `.npmrc`
  handling inside a big bundle stay informational. This cost **no** malware recall.
- **Still open:** Fresh C `vue-i18n-extract` (an `obfuscation` hit in a vendored
  `.yarn/plugins/*.cjs` file, new in 0.2.0), and four Fresh B packages that 0.1.0 already flagged:
  a `curl … | bash` install hint passed to an exec helper, a literal `curl bit.ly/… | bash` in a
  CLI command, a `security find-generic-password` + `.npmrc` combination in a vendor CLI, and a
  test helper that sets `NODE_TLS_REJECT_UNAUTHORIZED=0`. They are left as they are, unfixed and
  reported, rather than tuned away on the sets used to measure them.

### Recall of the final engine (post-hoc, not a blind number)

| Split | 0.1.0 | frozen (blind for held-out) | **0.2.0** |
| --- | --- | --- | --- |
| tune, deduped HIGH+ | 262 / 405 (64.7%) | 340 / 405 (84.0%) | 332 / 405 (82.0%) |
| held-out, deduped HIGH+ | 157 / 267 (58.8%) | **196 / 267 (73.4%)** | 195 / 267 (73.0%) |
| held-out, raw HIGH+ | 235 / 398 (59.0%) | 276 / 398 (69.3%) | 275 / 398 (69.1%) |

The destination-IP tightening in fix 1 dropped one tune family (8 samples, where the IP and the
port sit in separately named variables passed to `net.Socket().connect()`) and one held-out
sample. Fix 2 changed no malware verdict at HIGH+.

## What still gets through (held-out misses, frozen rules, 71 distinct)

| Class | Held-out | What it is | Statically detectable? |
| --- | --- | --- | --- |
| Packed or trojanised clones | 28 | Mostly one 2025-26 family absent from tune: copies of popular libraries (pino, chai and similar, about 92 kB) with the payload folded into otherwise ordinary code, plus custom packers | Partly. Diffing against the upstream package it clones would catch it. Pattern rules do not generalise to a new packer |
| Other behaviour | 32 | Loaders that fetch and run code through an indirection the rules do not name (`new Function('require', …)` over downloaded text), browser-side phishing pages and fake captchas shipped as npm packages, novel sinks | Some of it. Each new shape needs a rule, which is the limit of signatures |
| No payload in the package | 7 | Placeholders (`999.9.9` with an empty `index.js`), `echo "poc"` install scripts, tea.xyz spam, packages whose only job is to depend on another malicious package | **No.** There is nothing malicious in the tarball. Name-squatting, publisher reputation and the dependency graph are the signal |
| Compromised library, subtle backdoor | 4 | A few lines inside a large legitimate bundle (for example `@solana/web3.js` 2024: key bytes sent through a fetch header, with no keyword) | Rarely. Diffing against the previous version is the right tool |

In *tune*, after tuning, the remaining misses (66 content keys missed in at least one copy) split
21 no-payload, 23 other, 15 packed, 7 compromised-library. (The class labels come from a coarse feature heuristic plus manual
reading of a subset, so treat the counts as approximate.)

**What static scanning cannot see:** a stage-2 payload fetched at runtime from a URL that is not
hard-coded, malicious code in a dependency instead of in the package itself, prebuilt native
binaries (`.node`, platform tarballs), and packages that are malicious only by name. A SAFE
verdict still means "no known-bad shape", not "safe".

## Reproduce

The benchmark tooling stays outside the repository so that no malware-handling code ships with
the scanner. In outline:

1. List `samples/npm/{malicious_intent,compromised_lib}` with the GitHub git-trees API and sample
   with the strata above.
2. Download the zips into an empty directory and never use it as a working directory.
3. For each zip, `zipfile.ZipFile(p).setpassword(b"infected")`, read the members under
   `<pkg>/package/` into a `{path: text}` dict (using `npm_audit._wanted` as the filter), and call
   `npm_audit.scan_package(files)`. Use `python -I`, a subprocess timeout and at most 3 workers.
4. Delete the samples when done.

*Package names in the manifest are publicly documented malware from the DataDog dataset, already
removed from npm. They are listed only to make the benchmark reproducible.*
