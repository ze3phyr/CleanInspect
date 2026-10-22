# CleanInspect 1.3.0

CleanInspect is a local Manifest V3 Chrome DevTools extension. Its panel
organizes requests and page resources, helps inspect scripts and endpoints, and
scans available text for configured patterns. The extension has no runtime
dependencies, background service worker, telemetry, or network calls. The Public
Suffix List updater is a developer tool; it downloads only when someone runs it.

## Install

1. Open `chrome://extensions` in Chrome and enable **Developer mode**.
2. Click **Load unpacked** and select the `CleanInspect` folder containing
   `manifest.json`.
3. Open or reload a webpage, open DevTools, then choose the **CleanInspect**
   panel.

## Requests and scope

- Requests come from DevTools network events and the available HAR. Loaded
  resources are added when Chrome exposes them.
- Click a column heading to sort. The request list renders in batches as you
  scroll.
- **Same origin only** is the default. **Include subdomains** groups by the
  bundled Public Suffix List (ICANN and private rules); **All** includes
  supported web and WebSocket requests.
- The bundled suffix data treats private hosting suffixes such as `github.io` as
  tenant boundaries. IPv4, IPv6, and localhost hosts are kept separate.
- `data:` URLs show in every scope mode unless **Hide data/blob** is checked.
  `blob:` URLs use their creator origin and remain subject to the selected
  scope.
- Browser and extension schemes such as `chrome-extension:`, `chrome:`,
  `devtools:`, and `about:` are excluded. `ws:` and `wss:` requests appear as
  **websocket**.
- Hide Images, Fonts, CSS, or Media to filter those request types. Search
  accepts plain text or JavaScript regular expressions.
- **Save site preset** stores filters in `chrome.storage.local`, keyed by
  inspected hostname. Presets are applied when the panel loads.
- **Preserve log** keeps captured rows during navigation. **Clear** empties the
  current request and finding lists and resets scan counts.
- First-party grouping is based on the same bundled PSL rules used by the
  subdomain scope.

## Scripts and endpoints

- **Scripts** lists JavaScript and source-map resources discovered by DevTools.
  Click a row to open it in Sources. **Copy all URLs** copies the visible script
  list.
- Source-map comments are detected when script text is available.
- **Endpoints** combines observed request paths with likely paths and absolute
  URLs found in readable loaded JavaScript. Query values are omitted from
  endpoint entries; parameter names are shown. Use the endpoint search box,
  per-row **Copy**, or **Copy endpoints**.
- These are best-effort heuristics. Minified, compressed, inaccessible,
  dynamically generated, or otherwise unavailable text may not be scanned.

## Findings

- The scanner reads text-like JavaScript and response bodies exposed by Chrome.
  It skips image, font, audio, and video MIME types and bodies that look like
  base64 binary. Unavailable or unreadable bodies are skipped.
- `patterns.js` contains 48 rules. Matches are checked with each rule's
  validator and grouped by exact value. When rules overlap, provider-specific
  rules take priority over token rules, generic assignments, hardcoded
  passwords, and reconnaissance rules. Generic and password findings are
  capped at MEDIUM; a rule labeled **public by design** cannot be HIGH. Rules
  otherwise keep their declared severity. Provider keys such as GitLab,
  Shopify, OpenAI, and Anthropic remain HIGH.
- JWTs with the `service_role` role are HIGH. JWTs with `anon` or `public` roles,
  or an issuer indicating Firebase, Supabase, an anonymous key, or a public
  client, are LOW with the note **likely public client token**. Other JWTs are
  MEDIUM.
- Findings have severity badges, occurrence counts, character offsets, nearby
  context, and clickable locations. **INFO** findings are hidden until **Show
  recon / info** is enabled. Filter-chip state is saved in local storage.
- Matched values are displayed in full for researcher review. Findings
  themselves are kept in panel memory and are not written to local storage.
- The scanner is heuristic: a match can be a false positive, and a missing match
  does not establish that a page is safe.
- **View findings (N)** counts HIGH, MEDIUM, and LOW findings; the smaller
  `+N info` count reports INFO findings separately.

## Scope import, notes, and reload differences

- **Paste scope** opens the inline editor. **Upload scope** accepts text or CSV
  with one hostname or wildcard such as `*.example.com` per line. Toggle **In
  scope only** to filter the table. Scope entries are stored per site.
- Click a request's **Notes / tags** cell to edit it in the inline editor. Notes
  and tags are stored per site.
- **Preserve log** and reload differences are separate. The reload-diff store
  contains only SHA-256 hashes of method, origin, path, and sorted query
  parameter names; query values and full URLs are not stored in the diff.
  Existing diff entries from earlier versions are discarded if they contain
  unhashed values.
- Per-site scope, notes, presets, and diff lists have size and entry limits.
  When a limit is reached, oldest entries are dropped.

## Exports and privacy

- **Download filtered HAR**, **Copy cURL**, and **Download URL list** use the
  currently visible requests. HAR and cURL share **Redact sensitive data**,
  which is on by default. The URL list is not redacted by this option.
- With redaction enabled, Authorization, Proxy-Authorization, Cookie,
  Set-Cookie, and API-key/token/secret/password/credential-style header values
  are replaced. HAR request and response cookie-record values are replaced.
  HAR request `postData.text`, every `postData.params` value, and response body
  text are replaced while parameter and field names remain. Query values for
  names containing `token`, `key`, `secret`, `auth`, or `session` are replaced
  in URLs stored in the HAR entry, including request URLs, redirect URLs, and
  `Location` headers; matching HAR `queryString` values are also replaced.
- Redacted cURL commands redact sensitive query values and sensitive header
  values, omit Cookie/Set-Cookie headers, and omit request bodies entirely, so
  no `--data-raw` argument is copied. With redaction turned off, cURL includes
  request headers and a text body when available.
- Turning redaction off displays a warning. The resulting export or copied
  command may contain credentials or private response data. Review the output
  before sharing it.
- Redaction does not rewrite data elsewhere in the page or DevTools. URL lists
  are not redacted by this option.

## Development and tests

Run the dependency-free test suite with:

```sh
node tests/run.js
```

The tests load `patterns.js` in a VM, verify synthetic matches and
false-positive cases, exercise domain grouping and privacy helpers, stress every
rule with 400 KB inputs, and check a 2,000-request filter-and-sort path against
a 100 ms budget.

To refresh the bundled suffix data from the official source, run:

```sh
node tools/update-psl.js
```

The updater retrieves the canonical file from
`https://publicsuffix.org/list/public_suffix_list.dat`. To generate from an
already downloaded copy, pass its path as an argument. The generated data is
bundled in `public-suffix-list.js`; the extension itself does not fetch the
list. See `PSL-LICENSE.txt` for the Public Suffix List data license.

## Manual checks

1. Load the folder unpacked and open CleanInspect in DevTools on a normal
   website. Confirm page requests appear and extension/browser schemes do not.
2. Compare **Same origin only**, **Include subdomains**, and **All**. Toggle
   **Hide data/blob** and verify `data:` entries follow it in all scopes.
   Confirm `ws:`/`wss:` entries show as **websocket** when present.
3. Search, sort, and scroll a request-heavy page. Test type filters, saved
   presets, Preserve log, and Clear.
4. Open **Scripts** and **Endpoints**, copy a single URL or endpoint, and verify
   script rows open in Sources.
5. Review findings in both light and dark DevTools themes. A page containing
   only the word `internal` should not produce an internal-hostname finding. A
   synthetic Google API key should appear once as LOW and tagged **usually not a
   vulnerability**.
6. Turn **Show recon / info** on and off. Confirm INFO is hidden by default and
   the count is displayed separately.
7. Add a request note and a scope list through the inline editor. Reload the
   panel and verify they persist.
8. Export a HAR and copy cURL with redaction enabled. Confirm sensitive headers,
   matching query values, HAR cookies, and response bodies are redacted. Turn
   redaction off and confirm the warning appears.
9. Reload the inspected page and verify diff markers compare request method,
   origin, path, and query parameter names without storing query values.

## Limitations

Chrome DevTools may omit response bodies, script text, headers, or transfer
sizes. Resource access depends on what Chrome exposes; cross-origin restrictions
and browser behavior can limit findings. Domain grouping depends on the bundled
PSL snapshot until it is manually refreshed. The panel does not make
vulnerability determinations and does not send collected page data anywhere.
