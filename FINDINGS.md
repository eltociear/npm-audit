# What we found scanning 680 popular npm packages

This is the research behind `npm-audit`, a real scan of the most-installed corner of the npm
registry using this exact engine. Like [mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md),
it is calibrated so that "clean" means clean before any number is reported.

## Method

1. Ranked ~3,100 packages by weekly downloads using registry search across 150 topic keywords.
2. **Calibration set (380):** the top 300 by downloads, plus every package in the top 2,000 (and
   a hand list of known native/binary packages) whose latest version declares a `preinstall`,
   `install` or `postinstall` script. That came to 83 install-script packages, the population
   where install-time attacks live.
3. **Held-out set (300):** the next 300 by downloads, scanned only once, with the final engine.
4. For each package: fetch the latest tarball from `registry.npmjs.org` into memory, read every
   JS/TS/shell/Python file up to 1.5 MB (12 MB per package), and take lifecycle scripts from the
   registry manifest. Nothing is installed and nothing is executed.

Scan date: 2026-11-24/25. Latest versions at that time.

## Headline

| Result | Calibration (380) | Held-out (300) |
| --- | --- | --- |
| **Clean** | 380 (after one fix) | **300** |
| HIGH / CRITICAL | 3 → 0 | **0** |
| Fetch errors | 0 | 0 |

**The most-downloaded part of npm, as published right now, is clean by every malicious-pattern
rule here.** That is the expected result, and it is what makes the scanner usable. A tool that
flags the packages everyone already depends on teaches its users to ignore it. The point of
the corpus is to show that a CRITICAL from `npm-audit` on a package you have *never* heard of
means something.

All three calibration hits came from one bug: the `requestbin` collector pattern matched
`requestBinary(` (TypeScript's API client, phantomjs-prebuilt's and chromedriver's installers).
The pattern is now anchored to the actual domains (`requestbin.com/.net/.io`, `requestb.in`).

## The noise: what looks dangerous in npm but isn't

A naive rule set flagged **59 of 380 (15.5%)** packages. Every one was a false positive.
The drivers, measured per package:

| Signal | Packages | Why it's noise |
| --- | --- | --- |
| Reads `process.env` | 110 / 380 | Configuration. The risk is serialising **all** of it **and** sending it |
| Spawns processes (`child_process`) | 63 / 380 | Build tools, CLIs and binary wrappers |
| Lifecycle install script present | 83 / 380 | 55 run `node <file>`, 21 are `node-gyp` / `node-gyp-build` / `prebuild-install` native builds |
| Network I/O inside install-script packages | 34 / 83 | Prebuilt-binary downloads (esbuild-style, Sentry CLI, chromedriver, phantomjs) |
| Exec + network in the same install script | 48 / 83 use exec, 34 network | Download a platform binary, `chmod`, verify by running it. The normal installer shape |
| References `~/.npmrc` / `~/.aws/credentials` / `~/.ssh` | 4 / 380 | Config loaders and CLIs reading their *own* auth. Not a send |
| `JSON.stringify(process.env)` | 1 / 380 | Debug/diagnostic output in a file with no network sink |
| Long encoded / escaped strings | 1 / 380 | Framework runtime tables, not `eval`'d |

The lesson matches what we saw in MCP: **every one of these is a capability, not an attack.**
Installers *must* download and execute binaries, and config libraries *must* read `.npmrc`.
The attack is a **combination**: the env dump in a file that also POSTs, the credential read in
a file that also names a webhook, the install script that pipes into `sh`, the hostname encoded
into a DNS query to an OAST domain. `npm-audit` scores only those. The capabilities go to an
informational tier that never touches the score.

## Install scripts are the real attack surface

83 of the top ~2,000 packages run code on `npm install`. For an attacker who takes over a
maintainer account, this is the whole game: the payload runs with the developer's or CI's full
environment before anyone has imported anything. That is why `npm-audit` escalates any HIGH
or MEDIUM finding to CRITICAL when it sits in a file that a lifecycle script executes.

It is also why the known incidents look the way they do:

- **event-stream (2018):** an obfuscated, encrypted payload targeting a specific wallet app,
  added through a transferred dependency. This is the `obfuscation` + `wallet_browser_theft` shape.
- **ua-parser-js / coa / rc (2021):** hijacked maintainer accounts shipped `preinstall` scripts
  that fetched and ran miners and credential stealers. This is the `download_execute` /
  `install_fetch` shape at install time.
- **node-ipc (2022):** protestware that overwrote files on machines geolocated to specific
  countries. This is the `destructive` shape.
- **Shai-Hulud (2025):** a worm that ran on install, harvested secrets (including by
  downloading TruffleHog), and used stolen npm tokens to republish itself into the victim's other
  packages. This is the `worm_propagation` + `env_exfil` shape.

Each of these has an inert canary in `tests/fixtures/`, and each fires at CRITICAL or HIGH.

## Takeaways

1. **`npm audit` passing tells you nothing about malice.** It only covers what has already been
   reported. Scan new or changed dependencies for behaviour.
2. **Install scripts deserve the most suspicion.** Consider `npm install --ignore-scripts` by
   default, plus an allow-list of the packages that genuinely need them (native builds, binary
   fetchers).
3. **Score combinations, not capabilities.** `child_process`, `https.get` and `~/.npmrc` are in
   the most-depended-on packages on Earth.
4. **Re-scan on every version bump.** Every incident above was a *new version* of a package
   people already trusted. `npm_audit.py --lockfile package-lock.json` in CI covers it.

---

Run it yourself: `python npm_audit.py <package>` or `python npm_audit.py --lockfile package-lock.json`.

*Findings are pattern matches warranting human review, not verdicts. No package in the scanned
corpus is accused of anything. Suspected malicious packages should be reported to npm
(`npm report`/security@npmjs.com) and the maintainer, not published as unverified accusations.*
