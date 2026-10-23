# CleanInspect

A Chrome DevTools panel that shows only the requests that matter, and flags
possible secrets in the JavaScript and responses a page loads.

Everything runs locally. No telemetry, no network calls, no dependencies, no
build step.

## Install

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and select the folder that contains `manifest.json`.
3. Open DevTools on any page and choose the **CleanInspect** tab.

## What it does

**Clean request list**
- Hides browser noise: `chrome-extension:`, `chrome:`, `devtools:`, `about:`.
- Scope: **Same origin** (default), **Include subdomains**, or **All**.
  Grouping uses the Public Suffix List, so `a.github.io` and `b.github.io` are
  treated as different sites.
- Filter out images, fonts, CSS and media. Search with plain text or regex.
- Shows WebSocket requests, flags writes, JSON, auth headers and cookies, and
  marks requests that are new since the last reload.
- Save filters per site, keep the log across navigation, add notes and tags,
  and import an in-scope domain list (`*.example.com` supported).

**Scripts and endpoints**
- Lists every loaded script and source map. Click one to open it in Sources.
- Extracts API paths and URLs from loaded JavaScript. Copy one or all.

**Findings**
- 48 detection rules for API keys, tokens, private keys, database URLs, cloud
  buckets, internal hosts and more (see `patterns.js`).
- Each finding shows a severity badge, the full matched value, how many times
  it appeared, and the surrounding code.

| Severity | Meaning |
|----------|---------|
| HIGH | Secret by design (AWS, GitHub, Stripe, OpenAI, private keys, ...) |
| MEDIUM | Credential-shaped values, ordinary JWTs, generic key assignments |
| LOW | Public by design, such as Google API keys and anonymous JWTs |
| INFO | Recon only (buckets, internal URLs). Hidden until you turn on **Show recon / info** |

One finding is shown per value, so a key matched by two rules appears once
under the most specific rule. Findings stay in memory and are never written to
storage.

## Exports and privacy

**Download filtered HAR**, **Copy cURL** and **Download URL list** export what
is currently visible.

**Redact sensitive data** is on by default for HAR and cURL. It replaces auth
headers, cookies, response bodies, and values of sensitive-named query
parameters and form or JSON fields (token, key, secret, password, session,
code, and similar). Turn it off when you need raw output, and review the file
before you share it. The URL list is not redacted.

The reload-diff stores only hashes, never full URLs or query values.

## Limitations

- Chrome may not expose some response bodies, script text or headers.
- Detection is heuristic. A match can be a false positive, and no match does
  not mean a page is safe. Always read the context before reporting.
- Public Suffix data is a bundled snapshot. Refresh it with
  `node tools/update-psl.js`.

## Development

```sh
node tests/run.js
```

Runs the dependency-free test suite: pattern matches and false-positive checks,
domain grouping, redaction, a regex speed stress test, and a 2,000-request
filter performance check.

The Public Suffix List data is covered by `PSL-LICENSE.txt`.
