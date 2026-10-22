# CleanInspect

CleanInspect is a local Chrome DevTools extension that provides a focused request table and filters out browser-owned URL schemes. It uses plain JavaScript and has no build step, external dependencies, network calls, or telemetry.

## Install

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Choose **Load unpacked** and select this `CleanInspect` directory (the one containing `manifest.json`).
3. Open or reload a webpage, open DevTools, then select the **CleanInspect** panel.

## Use

- Requests come from the DevTools HAR/network events. Loaded resources are also included when available.
- Click column headings to sort. Scroll down to render additional rows for large lists.
- Same-origin is the default. The panel excludes non-web browser/extension schemes and filters requests, scripts, and endpoints using the selected origin scope.
- Choose same origin, the same registrable domain (including subdomains), or all hosts.
- Use checkboxes to hide images, fonts, CSS, media, or data/blob URLs. Those URL types remain visible by default.
- Search with plain text, or enable Regex for JavaScript regular expressions.
- **Save site preset** stores the current filters in `chrome.storage.local`, keyed by the inspected hostname. A matching preset is applied when the panel loads or the page navigates.
- **Preserve log** keeps captured requests when navigation occurs; **Clear** empties the current list.
- **Scripts** lists loaded JavaScript and source map URLs. `sourceMappingURL` comments are flagged when Chrome makes the script text available. Click a script to open it in Sources; use **Copy all URLs** to copy the visible list.
- **Endpoints** combines URLs seen in requests with likely API paths and absolute URLs found in loaded JavaScript. Query values are left out; observed query parameter names are shown. Filter with the search field, copy an individual endpoint, or use **Copy endpoints** to copy the visible results.
- Use the **Copy** button beside any request URL to copy that one URL.
- Request rows are marked for write methods, JSON responses, Authorization request headers, and Set-Cookie response headers. Hover a marked row to see the reasons.
- **View findings** stays visible in the action bar and shows the number of secret and technology findings. Each secret finding shows its full matched value, pattern, occurrence count, and source location. Edit `patterns.js` to customize the local patterns; the scanner stores findings only in the panel session.
- **Import scope** pastes domains and **Upload scope** reads a text or CSV file. Put one hostname or wildcard (such as `*.example.com`) per line, then turn on **In scope only**. The imported list is saved for that site.
- Click a request's **Notes / tags** cell to add or edit its note and comma-separated tags. These are saved per site.
- **Download filtered HAR** and **Download URL list** export requests currently shown after filtering. **Copy cURL** copies one command per observed network request currently shown.
- Reload differences mark requests whose method and URL did not appear in the previous recorded load. Findings also show basic framework and server-header hints when recognizable.

## Feature checklist

- [x] Manifest V3 DevTools panel
- [x] Request/resource table with sortable columns
- [x] Filter browser and extension schemes
- [x] Origin scope, first/third-party domain indication, type and URL filters
- [x] Text and regex search
- [x] Per-host filter presets
- [x] Clear and preserve log
- [x] DevTools theme and incremental row rendering
- [x] JavaScript collector, source map detection, endpoint extraction and deduplication
- [x] Write method, JSON, Authorization, and Set-Cookie row indicators
- [x] Masked secret pattern scan, reload diff, scope import, exports, notes/tags, and basic fingerprints

## Manual test plan

1. Load unpacked, open `https://example.com`, open DevTools and choose CleanInspect. Confirm page requests appear and extension/devtools URLs do not.
2. Try a page with subresources such as `https://developer.mozilla.org/`. Compare **Same origin only**, **Include subdomains**, and **All**; inspect third-party dimming and the grouping summary.
3. Toggle Images, Fonts, CSS, and Media individually. Search for a known URL fragment; enable Regex and try `\.css(\?|$)`.
4. Save a distinctive filter preset on a hostname, reload that hostname, and verify it reapplies. Disable Preserve log and reload; then enable it and reload again. Use Clear to empty the table.
5. Check the panel in both DevTools light and dark themes. On a request-heavy page, scroll through the table and verify more rows appear as you reach the bottom.
6. Open **Scripts** on a modern site and confirm JavaScript URLs appear. Try **Copy all URLs** and paste into a text field. If a site exposes source maps, check for the source map badge.
7. Open **Endpoints** and confirm observed API requests and recognizable API paths are listed once per method and path. Try **Copy endpoints** and paste the result.
8. On a site that makes API requests, check that POST/PUT/PATCH/DELETE, JSON, Authorization, and Set-Cookie rows receive indicators when those request or response details are available.
9. In **Findings**, check the scan status shows how many JavaScript resources and response bodies Chrome made available. Review the full matched value and source location for any potential secret. For a safe test, you can add a dummy token string to a local test page; do not paste real credentials into a page to test the scanner.
10. Import `example.com` and `*.mozilla.org` as scope rules, turn on **In scope only**, and confirm matching requests remain. Try both paste and upload with a small text file.
11. Click a request's Notes / tags cell, enter a note and tags, reload the panel, and confirm they remain. Test each export button with the current filters and open the downloaded files or paste the cURL commands into a text editor without running them.
12. Reload the inspected page and confirm requests not seen on the previous load receive a **NEW** marker. Check **Findings** for framework and server-header hints on a site that exposes recognizable versions.
13. Click a script in **Scripts** and verify DevTools opens its source. Search for a known path in **Endpoints**, then use that endpoint's **Copy** button.

## Notes

Registrable-domain grouping uses a bundled compact public-suffix list covering common suffixes and country-code patterns; it is intentionally small and may not classify every uncommon public suffix correctly. Chrome DevTools network APIs can omit request bodies, script text, headers, or exact transfer sizes. Source-map comments, endpoints, secret matches, and fingerprints are best-effort heuristics and can miss items or report false positives. The HAR may only include fields Chrome made available. Unavailable content is skipped without breaking the panel.
