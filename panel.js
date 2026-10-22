(() => {
  const $ = (id) => document.getElementById(id);
  const state = {
    all: [],
    shown: [],
    requestMap: new Map(),
    resourceKeys: new Set(),
    refreshPending: false,
    scriptsRenderPending: false,
    endpointsRenderPending: false,
    searchRegexKey: "",
    searchRegex: null,
    searchRegexInvalid: false,
    editorSave: null,
    requestHashCache: new Map(),
    diffGeneration: 0,
    scripts: new Map(),
    endpoints: new Map(),
    secrets: new Map(),
    tech: new Map(),
    notes: {},
    scopeRules: [],
    previousKeys: new Set(),
    scannedResponses: new Set(),
    severityFilters: { high: true, medium: true, low: true, info: false },
    diffReady: false,
    scannedScriptCount: 0,
    scannedResponseCount: 0,
    findingsRenderPending: false,
    sort: "time",
    direction: -1,
    cursor: 0,
    batch: 250,
    host: "",
    origin: "",
    domain: "",
    observer: null,
  };
  const severityStorageKey = "cleaninspect-severity-filters";
  const severityOrder = { high: 0, medium: 1, low: 2, info: 3 };
  const controls = ["scope", "search", "regex", "hideData", "preserve"];
  const presetsKey = "cleaninspect-presets";
  const registrable = (host) =>
    window.CleanInspectDomainUtils.registrableDomain(host);
  const sameParty = (a, b) => window.CleanInspectDomainUtils.sameParty(a, b);
  function scheme(url) {
    try {
      return new URL(url).protocol.toLowerCase();
    } catch {
      return "";
    }
  }
  function safeHost(url) {
    try {
      const u = new URL(url);
      return (
        u.protocol === "blob:" ? new URL(u.origin).hostname : u.hostname
      ).toLowerCase();
    } catch {
      return "";
    }
  }
  function allowedResource(url) {
    try {
      const u = new URL(url),
        scope = $("scope").value;
      if (u.protocol === "data:")
        return window.CleanInspectRequestView.dataUrlVisible(
          $("hideData").checked,
        );
      if (u.protocol === "blob:") {
        const origin = u.origin;
        if ($("hideData").checked || !origin || origin === "null") return false;
        if (scope === "all") return true;
        if (scope === "same") return origin === state.origin;
        if (scope === "subdomains")
          return sameParty(new URL(origin).hostname, state.host);
        return false;
      }
      if (!["http:", "https:", "ws:", "wss:"].includes(u.protocol))
        return false;
      const host = u.hostname.toLowerCase();
      if (scope === "all" || !state.host) return true;
      if (scope === "same") {
        const page = new URL(state.origin);
        const allowedProtocols =
          page.protocol === "https:" ? ["https:", "wss:"] : ["http:", "ws:"];
        return (
          host === page.hostname &&
          u.port === page.port &&
          allowedProtocols.includes(u.protocol)
        );
      }
      return sameParty(host, state.host);
    } catch {
      return false;
    }
  }
  function resourceType(r) {
    const type = String(r.type || r._resourceType || "other").toLowerCase();
    return type.includes("websocket") ? "websocket" : type;
  }
  function headersHave(headers, name) {
    return (headers || []).some(
      (h) => String(h.name || "").toLowerCase() === name.toLowerCase(),
    );
  }
  function requestFromHar(e) {
    const req = e.request || {},
      res = e.response || {},
      content = res.content || {};
    const mime = String(content.mimeType || "").toLowerCase();
    const raw = String(e._resourceType || mime || "other").toLowerCase();
    const type = raw.includes("websocket")
      ? "websocket"
      : raw.includes("image")
        ? "image"
        : raw.includes("font")
          ? "font"
          : raw.includes("stylesheet") || raw.includes("css")
            ? "stylesheet"
            : raw.includes("media") ||
                raw.includes("video") ||
                raw.includes("audio")
              ? "media"
              : raw.includes("script") || raw.includes("javascript")
                ? "script"
                : raw;
    return {
      method: req.method || "GET",
      status: Number(res.status) || 0,
      type,
      url: req.url || "",
      size:
        Number(content.size) ||
        Number(res.bodySize) ||
        Number(e._transferSize) ||
        0,
      time: Number(e.time) || 0,
      host: safeHost(req.url),
      source: "network",
      mimeType: mime,
      json: mime.includes("json"),
      auth: headersHave(req.headers, "authorization"),
      cookie: headersHave(res.headers, "set-cookie"),
      requestHeaders: req.headers || [],
      responseHeaders: res.headers || [],
      postData: req.postData,
      harEntry: e,
    };
  }
  function resourceFrom(r) {
    return {
      method: "—",
      status: "—",
      type: resourceType(r),
      url: r.url || "",
      size: 0,
      time: 0,
      host: safeHost(r.url),
      source: "resource",
    };
  }
  function setTheme() {
    try {
      document.body.classList.toggle(
        "dark",
        chrome.devtools.panels.themeName === "dark",
      );
      document.body.classList.toggle(
        "light",
        chrome.devtools.panels.themeName !== "dark",
      );
    } catch {}
  }
  function setMessage(s) {
    $("message").textContent = s;
    if (s)
      setTimeout(() => {
        if ($("message").textContent === s) $("message").textContent = "";
      }, 2200);
  }
  function saveControlState() {
    const values = {};
    for (const id of controls)
      values[id] = $(id).type === "checkbox" ? $(id).checked : $(id).value;
    values.hiddenTypes = [
      ...document.querySelectorAll(".hideType:checked"),
    ].map((x) => x.dataset.type);
    chrome.storage.local.set({ cleaninspectUi: values });
  }
  function requestKey(r) {
    return `${String(r.method || "GET").toUpperCase()} ${r.url}`;
  }
  function siteKey(prefix) {
    return `${prefix}:${state.host || "unknown"}`;
  }
  function inScope(host) {
    if (!state.scopeRules.length) return false;
    return state.scopeRules.some((rule) => {
      if (rule.startsWith("*.")) {
        const suffix = rule.slice(2);
        return host === suffix || host.endsWith("." + suffix);
      }
      return host === rule;
    });
  }
  function saveScope() {
    const value = window.CleanInspectPrivacyUtils.capStoredValue(
      state.scopeRules,
      1000,
      65536,
    );
    state.scopeRules = value;
    chrome.storage.local.set({ [siteKey("cleaninspect-scope")]: value });
  }
  function hashRequest(r) {
    const key = requestKey(r);
    if (!state.requestHashCache.has(key)) {
      state.requestHashCache.set(
        key,
        window.CleanInspectPrivacyUtils.hashRequest(r),
      );
      if (state.requestHashCache.size > 5000)
        state.requestHashCache.delete(
          state.requestHashCache.keys().next().value,
        );
    }
    return state.requestHashCache.get(key);
  }
  function markRequestDiff(r) {
    if (!state.diffReady || r.source !== "network") return;
    const generation = state.diffGeneration;
    hashRequest(r)
      .then((hash) => {
        if (generation !== state.diffGeneration) return;
        r.isNew = !state.previousKeys.has(hash);
        scheduleRefresh();
      })
      .catch(() => {
        r.isNew = false;
      });
  }
  function snapshotDiff() {
    const key = siteKey("cleaninspect-diff"),
      entries = state.all.filter((r) => r.source === "network");
    return Promise.all(entries.map(hashRequest))
      .then((hashes) => {
        const unique = [...new Set(hashes)];
        return window.CleanInspectPrivacyUtils.capStoredValue(
          unique,
          5000,
          320000,
        );
      })
      .then(
        (keys) =>
          new Promise((resolve) =>
            chrome.storage.local.set(
              { [key]: { keys, savedAt: Date.now() } },
              () => resolve(keys),
            ),
          ),
      );
  }
  function loadState() {
    chrome.storage.local.get(
      [
        "cleaninspectUi",
        presetsKey,
        siteKey("cleaninspect-scope"),
        siteKey("cleaninspect-notes"),
        siteKey("cleaninspect-diff"),
        severityStorageKey,
      ],
      (data) => {
        const ui = data.cleaninspectUi || {};
        for (const id of controls)
          if (ui[id] !== undefined)
            $(id).type === "checkbox"
              ? ($(id).checked = ui[id])
              : ($(id).value = ui[id]);
        (ui.hiddenTypes || []).forEach((t) => {
          const x = document.querySelector(`.hideType[data-type="${t}"]`);
          if (x) x.checked = true;
        });
        const preset = (data[presetsKey] || {})[state.host];
        if (preset) {
          applyPreset(preset);
          setMessage("Site preset applied");
        }
        const scopeKey = siteKey("cleaninspect-scope"),
          notesKey = siteKey("cleaninspect-notes"),
          diffKey = siteKey("cleaninspect-diff");
        const oldScope = data[scopeKey] || [],
          oldNotes = data[notesKey] || {};
        state.scopeRules = window.CleanInspectPrivacyUtils.capStoredValue(
          oldScope,
          1000,
          65536,
        );
        state.notes = window.CleanInspectPrivacyUtils.capStoredValue(
          oldNotes,
          500,
          131072,
        );
        if (
          JSON.stringify(oldScope) !== JSON.stringify(state.scopeRules) ||
          JSON.stringify(oldNotes) !== JSON.stringify(state.notes)
        )
          chrome.storage.local.set({
            [scopeKey]: state.scopeRules,
            [notesKey]: state.notes,
          });
        let diff = data[diffKey];
        if (
          diff &&
          (!Array.isArray(diff.keys) ||
            diff.keys.some((key) => !/^([a-f0-9]{64})$/i.test(key)))
        ) {
          chrome.storage.local.remove(diffKey);
          diff = null;
        }
        if (diff) {
          const hashes = window.CleanInspectPrivacyUtils.capStoredValue(
            diff.keys,
            5000,
            320000,
          );
          if (hashes.length !== diff.keys.length)
            chrome.storage.local.set({
              [diffKey]: { keys: hashes, savedAt: diff.savedAt || Date.now() },
            });
          diff = { ...diff, keys: hashes };
        }
        state.diffReady = !!diff;
        state.diffGeneration++;
        state.previousKeys = new Set((diff && diff.keys) || []);
        state.severityFilters = {
          ...state.severityFilters,
          ...(data[severityStorageKey] || {}),
        };
        $("showInfo").checked = state.severityFilters.info;
        state.all.forEach((request) => {
          if (state.diffReady) markRequestDiff(request);
          else if (request.source === "network") request.isNew = false;
        });
        refresh();
        renderFindings();
      },
    );
  }
  function getPreset() {
    return {
      scope: $("scope").value,
      search: $("search").value,
      regex: $("regex").checked,
      hideData: $("hideData").checked,
      hiddenTypes: [...document.querySelectorAll(".hideType:checked")].map(
        (x) => x.dataset.type,
      ),
    };
  }
  function applyPreset(p) {
    if (p.scope) $("scope").value = p.scope;
    $("search").value = p.search || "";
    $("regex").checked = !!p.regex;
    $("hideData").checked = !!p.hideData;
    document
      .querySelectorAll(".hideType")
      .forEach(
        (x) => (x.checked = (p.hiddenTypes || []).includes(x.dataset.type)),
      );
  }
  function getSearchRegex() {
    const query = $("search").value;
    if (!$("regex").checked || !query) return null;
    const key = query;
    if (state.searchRegexKey !== key) {
      state.searchRegexKey = key;
      try {
        if (!window.CleanInspectRequestView.hasOnlyBoundedQuantifiers(query)) {
          state.searchRegex = null;
          state.searchRegexInvalid = true;
          setMessage("Regex must use bounded quantifiers (for example {1,20})");
        } else {
          state.searchRegex = new RegExp(query, "i");
          state.searchRegexInvalid = false;
        }
      } catch {
        state.searchRegex = null;
        state.searchRegexInvalid = true;
      }
    }
    return state.searchRegex;
  }
  function isVisible(r) {
    if (!allowedResource(r.url)) return false;
    const host = r.host || safeHost(r.url);
    if ($("onlyScope").checked && !inScope(host)) return false;
    if (
      [...document.querySelectorAll(".hideType:checked")].some((x) =>
        r.type.includes(x.dataset.type),
      )
    )
      return false;
    const q = $("search").value;
    if (q) {
      const text = [r.method, r.status, r.type, r.url].join(" ");
      if ($("regex").checked) {
        const re = getSearchRegex();
        if (!re || !re.test(text)) return false;
      } else if (!text.toLowerCase().includes(q.toLowerCase())) return false;
    }
    return true;
  }
  function refresh() {
    state.shown = window.CleanInspectRequestView.build(
      state.all,
      isVisible,
      state.sort,
      state.direction,
    );
    state.cursor = 0;
    $("rows").replaceChildren();
    $("count").textContent =
      `${state.shown.length} request${state.shown.length === 1 ? "" : "s"}`;
    $("empty").hidden = state.shown.length > 0;
    const domains = new Set(
      state.shown.map((r) => registrable(r.host)).filter(Boolean),
    );
    $("groups").textContent = domains.size
      ? `${state.domain || "page"} (first-party) · ${[...domains].filter((d) => d !== state.domain).join(", ") || "no third-party domains"}`
      : "—";
    renderMore();
  }
  function scheduleRefresh() {
    if (state.refreshPending) return;
    state.refreshPending = true;
    const run = () => {
      state.refreshPending = false;
      refresh();
    };
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(run);
    else setTimeout(run, 100);
  }
  function scheduleScriptsRender() {
    if (state.scriptsRenderPending) return;
    state.scriptsRenderPending = true;
    const run = () => {
      state.scriptsRenderPending = false;
      renderScripts();
    };
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(run);
    else setTimeout(run, 100);
  }
  function scheduleEndpointsRender() {
    if (state.endpointsRenderPending) return;
    state.endpointsRenderPending = true;
    const run = () => {
      state.endpointsRenderPending = false;
      renderEndpoints();
    };
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(run);
    else setTimeout(run, 100);
  }
  function formatSize(n) {
    return n ? `${n < 1024 ? n + " B" : (n / 1024).toFixed(1) + " KB"}` : "—";
  }
  function renderMore() {
    const end = Math.min(state.cursor + state.batch, state.shown.length),
      frag = document.createDocumentFragment();
    for (let i = state.cursor; i < end; i++) {
      const r = state.shown[i],
        tr = document.createElement("tr"),
        reasons = [];
      if (
        ["POST", "PUT", "PATCH", "DELETE"].includes(
          String(r.method).toUpperCase(),
        )
      ) {
        tr.classList.add("row-write");
        reasons.push("write method");
      }
      if (r.json) {
        tr.classList.add("row-json");
        reasons.push("JSON response");
      }
      if (r.auth) {
        tr.classList.add("row-auth");
        reasons.push("Authorization header");
      }
      if (r.cookie) {
        tr.classList.add("row-cookie");
        reasons.push("Set-Cookie response");
      }
      if (r.isNew) {
        tr.classList.add("row-new");
        reasons.push("new since previous load");
      }
      if (registrable(r.host) !== state.domain) tr.classList.add("third");
      if (reasons.length) tr.title = reasons.join(" · ");
      [
        r.method,
        r.status,
        r.type,
        r.url,
        formatSize(r.size),
        r.time ? `${r.time.toFixed(1)} ms` : "—",
      ].forEach((v, j) => {
        const td = document.createElement("td");
        td.title = String(v);
        if (j === 3) {
          td.className = "url";
          if (r.isNew) {
            const badge = document.createElement("span");
            badge.className = "badge";
            badge.textContent = "NEW ";
            td.appendChild(badge);
          }
          const label = document.createElement("span");
          label.textContent = v;
          td.appendChild(label);
          const copy = document.createElement("button");
          copy.className = "copyOne";
          copy.textContent = "Copy";
          copy.title = "Copy this request URL";
          copy.addEventListener("click", (e) => {
            e.stopPropagation();
            copyText(r.url, "URL copied");
          });
          td.appendChild(copy);
        } else td.textContent = v;
        tr.appendChild(td);
      });
      const td = document.createElement("td"),
        meta = state.notes[requestKey(r)] || {};
      td.className = "noteCell";
      td.textContent =
        [meta.note, meta.tags].filter(Boolean).join(" · ") || "—";
      td.title = "Click to edit note and tags";
      td.addEventListener("click", () => editNote(r));
      tr.appendChild(td);
      frag.appendChild(tr);
    }
    $("rows").appendChild(frag);
    state.cursor = end;
  }
  async function copyText(text, message) {
    try {
      await navigator.clipboard.writeText(text);
      setMessage(message);
    } catch {
      setMessage("Clipboard unavailable");
    }
  }
  function openEditor(
    title,
    primaryLabel,
    primaryValue,
    secondaryLabel,
    secondaryValue,
    onSave,
  ) {
    $("editorTitle").textContent = title;
    $("editorPrimaryLabel").textContent = primaryLabel;
    $("editorPrimary").value = primaryValue || "";
    $("editorSecondaryLabel").textContent = secondaryLabel;
    $("editorSecondary").value = secondaryValue || "";
    $("editorDialog").hidden = false;
    state.editorSave = onSave;
    $("editorPrimary").focus();
  }
  function closeEditor() {
    $("editorDialog").hidden = true;
    state.editorSave = null;
  }
  function editNote(r) {
    const key = requestKey(r),
      old = state.notes[key] || {};
    openEditor(
      "Request note and tags",
      "Note",
      old.note,
      "Tags (comma separated)",
      old.tags,
      () => {
        state.notes[key] = {
          note: $("editorPrimary").value,
          tags: $("editorSecondary").value,
        };
        state.notes = window.CleanInspectPrivacyUtils.capStoredValue(
          state.notes,
          500,
          131072,
        );
        closeEditor();
        chrome.storage.local.set(
          { [siteKey("cleaninspect-notes")]: state.notes },
          refresh,
        );
      },
    );
  }
  function addEndpoint(method, url, source) {
    try {
      const u = new URL(url, state.origin || undefined);
      if (!/^https?:$/.test(u.protocol)) return;
      const path = u.pathname || "/",
        key = `${method} ${path}`;
      let item = state.endpoints.get(key);
      if (!item) {
        item = {
          method,
          path,
          origin: u.origin,
          params: new Set(),
          sources: new Set(),
        };
        state.endpoints.set(key, item);
      }
      u.searchParams.forEach((_, p) => item.params.add(p));
      item.sources.add(source);
      scheduleEndpointsRender();
    } catch {}
  }
  function scheduleFindingsRender() {
    if (state.findingsRenderPending) return;
    state.findingsRenderPending = true;
    const run = () => {
      state.findingsRenderPending = false;
      renderFindings();
    };
    if (typeof requestAnimationFrame === "function") requestAnimationFrame(run);
    else setTimeout(run, 100);
  }
  function scanText(text, source = "JavaScript") {
    if (!text || typeof text !== "string") return;
    const found = new Set();
    for (const m of text.matchAll(/https?:\/\/[^\s"'`<>\\)\]}]{1,2048}/gi))
      found.add(m[0].replace(/[.,;]{1,20}$/, ""));
    for (const m of text.matchAll(
      /\/(?:api|apis|graphql|graphiql|v\d{1,6}(?:\.\d{1,6})?|auth|oauth|users?|accounts?|search|login|logout|orders?|products?)(?:\/[\w.$~!%*'():@&=+-]{1,512}){0,16}/gi,
    ))
      found.add(m[0]);
    for (const url of found) addEndpoint("GET", url, "JavaScript");
    scanSecrets(text, source);
    fingerprint(text, source);
  }
  function scanSecrets(text, source) {
    const rules = window.CLEANINSPECT_RULES || window.CLEANINSPECT_PATTERNS,
      resolver = window.CleanInspectFindingResolver;
    if (
      !text ||
      typeof text !== "string" ||
      !Array.isArray(rules) ||
      !resolver ||
      state.secrets.size >= 500
    )
      return;
    let sourceUrl = "",
      safeSource = String(source || "body");
    try {
      const u = new URL(source);
      sourceUrl = u.href;
      safeSource = u.hostname + u.pathname;
    } catch {}
    let changed = false;
    for (const group of resolver.resolve(text, rules)) {
      const rule = group.rule,
        value = group.value,
        label = group.label,
        name = rule.name || label,
        id = value,
        publicByDesign =
          group.publicByDesign || /public by design/i.test(label);
      let item = state.secrets.get(id);
      if (!item) {
        if (state.secrets.size >= 500) break;
        item = {
          name,
          label,
          note: group.note || rule.note || "",
          severity: group.severity,
          value,
          specificity: group.specificity,
          publicByDesign,
          locations: new Map(),
          occurrenceCount: 0,
        };
        state.secrets.set(id, item);
      } else if (
        group.specificity > item.specificity ||
        (group.specificity === item.specificity &&
          severityOrder[group.severity] < severityOrder[item.severity])
      ) {
        item.name = name;
        item.label = label;
        item.note = group.note || rule.note || "";
        item.severity =
          group.publicByDesign && group.severity === "high"
            ? "medium"
            : group.severity;
        item.specificity = group.specificity;
        item.publicByDesign = publicByDesign;
      }
      if (publicByDesign) {
        item.publicByDesign = true;
        if (item.severity === "high") item.severity = "medium";
      }
      for (const entry of group.matches) {
        const match = entry.match,
          matchedRule = entry.rule,
          relative = matchedRule.capture
            ? Math.max(0, match[0].indexOf(value))
            : 0,
          offset = (match.index || 0) + relative,
          key = `${safeSource}:${offset}`;
        if (!item.locations.has(key)) {
          const start = Math.max(0, offset - 30),
            end = Math.min(text.length, offset + value.length + 30),
            context = text.slice(start, end);
          item.locations.set(key, {
            label: `${safeSource} · char ${offset}`,
            url: sourceUrl,
            offset,
            context,
          });
          item.occurrenceCount++;
          changed = true;
        }
      }
    }
    if (changed) scheduleFindingsRender();
  }
  function isTextLike(body, mime, type) {
    if (typeof body !== "string" || !body) return false;
    const m = String(mime || "")
        .toLowerCase()
        .split(";")[0]
        .trim(),
      t = String(type || "").toLowerCase();
    if (/^(image|font|audio|video)\//.test(m)) return false;
    if (
      m &&
      !(
        m.startsWith("text/") ||
        m === "application/json" ||
        m === "application/javascript" ||
        m === "application/ecmascript" ||
        m === "application/xml" ||
        m === "application/xhtml+xml" ||
        m === "application/graphql" ||
        m.endsWith("+json") ||
        m.endsWith("+xml")
      )
    )
      return false;
    if (
      !m &&
      ![
        "script",
        "stylesheet",
        "document",
        "xhr",
        "fetch",
        "websocket",
        "other",
      ].some((x) => t.includes(x))
    )
      return false;
    let validBase64 = true,
      controls = 0,
      base64Chars = 0,
      whitespace = 0;
    for (let i = 0; i < body.length; i++) {
      const c = body.charCodeAt(i);
      if (c === 0 || (c < 32 && c !== 9 && c !== 10 && c !== 13)) controls++;
      if (c === 9 || c === 10 || c === 13 || c === 32) {
        whitespace++;
        continue;
      }
      if (
        (c >= 65 && c <= 90) ||
        (c >= 97 && c <= 122) ||
        (c >= 48 && c <= 57) ||
        c === 43 ||
        c === 47 ||
        c === 61 ||
        c === 45 ||
        c === 95
      )
        base64Chars++;
      else validBase64 = false;
    }
    if (controls > 0) return false;
    if (
      body.length >= 128 &&
      validBase64 &&
      whitespace <= body.length / 20 &&
      base64Chars >= 128
    )
      return false;
    return true;
  }
  function scanResponse(body, r) {
    if (!isTextLike(body, r.mimeType, r.type)) return;
    const key =
      requestKey(r) +
      " " +
      String((r.harEntry && r.harEntry.startedDateTime) || "");
    if (state.scannedResponses.has(key)) return;
    state.scannedResponses.add(key);
    state.scannedResponseCount++;
    scanSecrets(body, r.url || "Response body");
  }
  function fingerprint(text, source) {
    const checks = [
      [
        "React",
        /React(?:\.version)?[^\n]{0,30}?\b([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)/i,
      ],
      [
        "Vue",
        /Vue(?:\.version)?[^\n]{0,30}?\b([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)/i,
      ],
      [
        "Angular",
        /@angular\/core[^\n]{0,40}?\b([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)/i,
      ],
      ["jQuery", /jQuery[\s]{0,1}v?([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)/i],
      [
        "Next.js",
        /Next\.js[^\n]{0,30}?\b([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)/i,
      ],
      ["Svelte", /svelte(?:\/|[\s]{1,20})([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)/i],
      [
        "Bootstrap",
        /Bootstrap[^\n]{0,30}?\b([0-9]{1,6}\.[0-9]{1,6}(?:\.[0-9]{1,6})?)/i,
      ],
    ];
    for (const [name, re] of checks) {
      const m = text.match(re);
      if (m) state.tech.set(name, { name, version: m[1] || "", source });
    }
    scheduleFindingsRender();
  }
  function scanHeaders(r) {
    for (const h of r.responseHeaders || []) {
      const n = String(h.name || "").toLowerCase(),
        v = String(h.value || "");
      if (n === "server" || n === "x-powered-by" || n === "x-generator")
        state.tech.set(`${n}:${v}`, {
          name: n,
          version: v,
          source: "Response header",
        });
    }
    scheduleFindingsRender();
  }
  function addScript(url, resource, mimeType = "") {
    if (
      !url ||
      !(
        /\.(?:m?js|map)(?:[?#]|$)/i.test(url) ||
        (resource &&
          String(resource.type || "")
            .toLowerCase()
            .includes("script"))
      )
    )
      return;
    let item = state.scripts.get(url);
    if (item) {
      if (mimeType) item.mimeType = mimeType;
      if (resource && resource.getContent && !item.scanned)
        scanScript(resource, item);
      return;
    }
    item = {
      url,
      mimeType,
      map: /\.map(?:[?#]|$)/i.test(url),
      commentMap: false,
      scanned: false,
    };
    state.scripts.set(url, item);
    if (resource && typeof resource.getContent === "function")
      scanScript(resource, item);
    scheduleScriptsRender();
  }
  function scanScript(resource, item) {
    item.scanned = true;
    try {
      resource.getContent((content, encoding) => {
        try {
          if (isTextLike(content, item.mimeType, "script")) {
            state.scannedScriptCount++;
            const m = content.match(
              /\/\/[#@][\s]{0,8}sourceMappingURL[\s]{0,8}=[\s]{0,8}([^\s*]{1,2048})/,
            );
            if (m) {
              item.commentMap = true;
              item.mapUrl = m[1];
            }
            scanText(content, item.url);
          }
          scheduleScriptsRender();
          scheduleFindingsRender();
        } catch {}
      });
    } catch {
      /* DevTools may deny or lose a resource body; its URL remains listed. */
    }
  }
  function renderScripts() {
    const box = $("scriptsList");
    box.replaceChildren();
    const visible = [...state.scripts.values()].filter((item) =>
      allowedResource(item.url),
    );
    $("scriptCount").textContent = visible.length;
    $("scriptsEmpty").hidden = visible.length > 0;
    for (const item of visible) {
      const row = document.createElement("div");
      row.className = "item scriptItem";
      row.title = "Open in DevTools Sources";
      row.addEventListener("click", () => {
        try {
          chrome.devtools.panels.openResource(item.url, 1);
        } catch {
          setMessage("Could not open this resource in Sources");
        }
      });
      const code = document.createElement("code");
      code.textContent = item.url;
      row.appendChild(code);
      if (item.map || item.commentMap) {
        const b = document.createElement("span");
        b.className = "badge map";
        b.textContent = "source map";
        row.appendChild(b);
        if (item.mapUrl) {
          const small = document.createElement("span");
          small.className = "hint";
          small.textContent = ` ${item.mapUrl}`;
          row.appendChild(small);
        }
      }
      box.appendChild(row);
    }
  }
  function visibleEndpoints() {
    const q = $("endpointSearch").value.trim().toLowerCase();
    return [...state.endpoints.values()].filter(
      (item) =>
        allowedResource(item.origin + item.path) &&
        `${item.method} ${item.origin}${item.path} ${[...item.params].join(" ")}`
          .toLowerCase()
          .includes(q),
    );
  }
  function renderEndpoints() {
    const box = $("endpointsList");
    box.replaceChildren();
    const visible = visibleEndpoints();
    $("endpointCount").textContent = visible.length;
    $("endpointsEmpty").hidden = visible.length > 0;
    for (const item of visible) {
      const row = document.createElement("div");
      row.className = "item endpointItem";
      const b = document.createElement("span");
      b.className = "badge";
      b.textContent = item.method;
      row.appendChild(b);
      const code = document.createElement("code");
      code.textContent = item.origin + item.path;
      row.appendChild(code);
      if (item.params.size) {
        const p = document.createElement("span");
        p.className = "hint";
        p.textContent = ` · query: ${[...item.params].join(", ")}`;
        row.appendChild(p);
      }
      const s = document.createElement("span");
      s.className = "hint";
      s.textContent = ` · ${[...item.sources].join(", ")}`;
      row.appendChild(s);
      const copy = document.createElement("button");
      copy.className = "copyOne";
      copy.textContent = "Copy";
      copy.title = "Copy this endpoint";
      copy.addEventListener("click", () =>
        copyText(item.origin + item.path, "Endpoint copied"),
      );
      row.appendChild(copy);
      box.appendChild(row);
    }
  }
  function openLocation(location) {
    if (!location || !location.url) {
      setMessage("Chrome did not provide a source URL for this finding");
      return;
    }
    try {
      chrome.devtools.panels.openResource(location.url, 1, () => {});
    } catch {
      setMessage("Could not open this finding in Sources");
    }
  }
  function saveSeverityFilters() {
    chrome.storage.local.set({ [severityStorageKey]: state.severityFilters });
  }
  function renderFindings() {
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    for (const item of state.secrets.values()) counts[item.severity]++;
    const primary = counts.high + counts.medium + counts.low;
    $("secretCount").textContent = primary;
    $("findingsHeaderCount").textContent =
      `${primary} finding${primary === 1 ? "" : "s"}${counts.info ? ` · +${counts.info} info` : ""}`;
    $("findingsShortcut").replaceChildren(
      document.createTextNode(`View findings (${primary}) `),
    );
    if (counts.info) {
      const extra = document.createElement("small");
      extra.textContent = `+${counts.info} info`;
      $("findingsShortcut").appendChild(extra);
    }
    $("scanStatus").textContent =
      `Checked ${state.scannedScriptCount} JavaScript resource(s) and ${state.scannedResponseCount} text response(s) available to Chrome · ${(window.CLEANINSPECT_RULES || window.CLEANINSPECT_PATTERNS || []).length} rules loaded`;
    $("showInfo").checked = state.severityFilters.info;
    const chips = $("severityChips");
    chips.replaceChildren();
    for (const sev of ["high", "medium", "low", "info"]) {
      const chip = document.createElement("button");
      chip.type = "button";
      chip.className = `severityChip severity-${sev}${state.severityFilters[sev] ? " selected" : ""}`;
      chip.textContent = `${sev.toUpperCase()} ${counts[sev]}`;
      chip.setAttribute("aria-pressed", String(!!state.severityFilters[sev]));
      chip.addEventListener("click", () => {
        state.severityFilters[sev] = !state.severityFilters[sev];
        if (sev === "info") $("showInfo").checked = state.severityFilters.info;
        saveSeverityFilters();
        renderFindings();
      });
      chips.appendChild(chip);
    }
    const visible = [...state.secrets.values()].filter(
      (item) => state.severityFilters[item.severity],
    );
    let maxCount = 0;
    for (const item of visible)
      if (item.occurrenceCount > maxCount) maxCount = item.occurrenceCount;
    const bySeverity = {};
    for (const sev of ["high", "medium", "low", "info"]) {
      bySeverity[sev] = [new Map(), new Map()];
    }
    for (const item of visible) {
      const kind = item.publicByDesign ? 1 : 0,
        bucket = bySeverity[item.severity][kind],
        count = item.occurrenceCount;
      if (!bucket.has(count)) bucket.set(count, []);
      bucket.get(count).push(item);
    }
    const ordered = [];
    for (const sev of ["high", "medium", "low", "info"])
      for (const kind of [0, 1])
        for (let count = maxCount; count >= 1; count--) {
          const bucket = bySeverity[sev][kind].get(count);
          if (bucket) ordered.push(...bucket);
        }
    const secrets = $("secretsList");
    secrets.replaceChildren();
    $("secretsEmpty").hidden = ordered.length > 0;
    for (const item of ordered) {
      const row = document.createElement("div");
      row.className = `item finding severity-border-${item.severity}`;
      const severity = document.createElement("span");
      severity.className = `severityBadge severity-${item.severity}`;
      severity.textContent = item.severity.toUpperCase();
      row.appendChild(severity);
      const label = document.createElement("strong");
      label.className = "findingLabel";
      label.textContent = item.label;
      row.appendChild(label);
      if (item.publicByDesign) {
        const tag = document.createElement("span");
        tag.className = "publicTag";
        tag.textContent = "usually not a vulnerability";
        row.appendChild(tag);
      }
      const code = document.createElement("code");
      code.className = "secretValue";
      code.textContent = item.value;
      row.appendChild(code);
      const copy = document.createElement("button");
      copy.textContent = "Copy full value";
      copy.addEventListener("click", () =>
        copyText(item.value, "Finding value copied"),
      );
      row.appendChild(copy);
      const count = document.createElement("span");
      count.className = "badge occurrenceBadge";
      count.textContent = `${item.occurrenceCount} occurrence${item.occurrenceCount === 1 ? "" : "s"}`;
      row.appendChild(count);
      if (item.note) {
        const note = document.createElement("div");
        note.className = "findingNote";
        note.textContent = item.note;
        row.appendChild(note);
      }
      const src = document.createElement("div");
      src.className = "hint findingSource";
      for (const location of item.locations.values()) {
        const link = document.createElement("button");
        link.className = "findingLocation";
        link.textContent = `${location.label} · ${location.context}`;
        link.title = "Open this source location in DevTools";
        link.addEventListener("click", () => openLocation(location));
        src.appendChild(link);
      }
      row.appendChild(src);
      secrets.appendChild(row);
    }
    const tech = $("techList");
    tech.replaceChildren();
    $("techEmpty").hidden = state.tech.size > 0;
    for (const item of state.tech.values()) {
      const row = document.createElement("div");
      row.className = "item";
      row.textContent = `${item.name}${item.version ? " " + item.version : ""} · ${item.source}`;
      tech.appendChild(row);
    }
  }
  function renderMoreIfVisible() {
    if (!$("requestsView").hidden) renderMore();
  }
  function resetScanCounts() {
    state.scannedResponses.clear();
    state.scannedScriptCount = 0;
    state.scannedResponseCount = 0;
  }
  function add(r) {
    if (!r.url) return;
    if (r.source === "network") {
      markRequestDiff(r);
      const key = requestKey(r);
      if (state.requestMap.has(key)) state.all[state.requestMap.get(key)] = r;
      else {
        state.requestMap.set(key, state.all.length);
        state.all.push(r);
      }
      addEndpoint(r.method, r.url, "Observed request");
      scanHeaders(r);
      if (r.type.includes("script") || /\.map(?:[?#]|$)/i.test(r.url))
        addScript(r.url, null, r.mimeType);
      const harBody =
        r.harEntry &&
        r.harEntry.response &&
        r.harEntry.response.content &&
        r.harEntry.response.content.text;
      if (harBody) {
        scanResponse(harBody, r);
        if (
          r.type.includes("script") &&
          isTextLike(harBody, r.mimeType, r.type)
        )
          scanText(harBody, r.url);
      }
      try {
        if (r.harEntry && typeof r.harEntry.getContent === "function")
          r.harEntry.getContent((body) => {
            try {
              scanResponse(body, r);
              if (
                r.type.includes("script") &&
                isTextLike(body, r.mimeType, r.type)
              )
                scanText(body, r.url);
            } catch {
              /* Body APIs may fail for binary or unavailable responses. */
            }
          });
      } catch {
        /* Continue collecting metadata if a response body cannot be read. */
      }
    } else {
      const resourceKey = `${r.source}:${r.url}`;
      if (!state.resourceKeys.has(resourceKey)) {
        state.resourceKeys.add(resourceKey);
        state.all.push(r);
      }
    }
    scheduleRefresh();
  }
  function init() {
    setTheme();
    chrome.devtools.network.onRequestFinished.addListener((e) =>
      add(requestFromHar(e)),
    );
    chrome.devtools.inspectedWindow.onResourceAdded.addListener((r) => {
      add(resourceFrom(r));
      addScript(r.url, r);
    });
    chrome.devtools.network.onNavigated.addListener((url) => {
      state.diffReady = false;
      state.diffGeneration++;
      const oldDiffKey = siteKey("cleaninspect-diff");
      snapshotDiff()
        .then((keys) => {
          state.previousKeys = new Set(keys);
          state.diffReady = true;
          state.requestHashCache.clear();
          try {
            const u = new URL(url);
            state.host = u.hostname.toLowerCase();
            state.origin = u.origin;
            state.domain = registrable(state.host);
          } catch {}
          if (!$("preserve").checked) {
            state.all = [];
            state.requestMap.clear();
            state.resourceKeys.clear();
            state.requestHashCache.clear();
            state.scripts.clear();
            state.endpoints.clear();
            state.secrets.clear();
            state.tech.clear();
            resetScanCounts();
            renderScripts();
            renderEndpoints();
            renderFindings();
          }
          loadState();
        })
        .catch(() => {
          chrome.storage.local.remove(oldDiffKey);
          try {
            const u = new URL(url);
            state.host = u.hostname.toLowerCase();
            state.origin = u.origin;
            state.domain = registrable(state.host);
          } catch {}
          loadState();
        });
    });
    chrome.devtools.inspectedWindow.eval("location.href", (href, err) => {
      try {
        const u = new URL(href);
        state.host = u.hostname.toLowerCase();
        state.origin = u.origin;
        state.domain = registrable(state.host);
      } catch {}
      loadState();
      chrome.devtools.network.getHAR((har) => {
        (har.entries || []).map(requestFromHar).forEach(add);
      });
      chrome.devtools.inspectedWindow.getResources((resources) =>
        resources.forEach((r) => {
          const rr = resourceFrom(r);
          add(rr);
          addScript(rr.url, r);
        }),
      );
    });
  }
  function download(name, text, type) {
    const a = document.createElement("a"),
      url = URL.createObjectURL(new Blob([text], { type }));
    a.href = url;
    a.download = name;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  function harEntry(r, redact) {
    const entry = r.harEntry
      ? JSON.parse(JSON.stringify(r.harEntry))
      : {
          startedDateTime: new Date().toISOString(),
          time: r.time || 0,
          request: {
            method: r.method || "GET",
            url: r.url,
            httpVersion: "",
            headers: [],
            queryString: [],
            headersSize: -1,
            bodySize: 0,
          },
          response: {
            status: Number(r.status) || 0,
            statusText: "",
            httpVersion: "",
            headers: [],
            cookies: [],
            content: {
              size: r.size || 0,
              mimeType: r.type || "application/octet-stream",
            },
            redirectURL: "",
            headersSize: -1,
            bodySize: -1,
          },
          cache: {},
          timings: { send: 0, wait: r.time || 0, receive: 0 },
        };
    return redact
      ? window.CleanInspectPrivacyUtils.redactHarEntry(entry)
      : entry;
  }
  function parseScope(text) {
    const tokens = text.split(/[\n,]{1,1000}/).flatMap((line) =>
      line
        .replace(/#.{0,2048}$/, "")
        .trim()
        .split(/[\s]{1,64}/),
    );
    state.scopeRules = [
      ...new Set(
        tokens
          .map((x) =>
            x
              .trim()
              .replace(/^https?:\/\//i, "")
              .replace(/\/.{0,2048}$/, "")
              .toLowerCase(),
          )
          .filter((x) => x && /^(\*\.)?[a-z0-9.-]{1,253}$/.test(x)),
      ),
    ];
    saveScope();
    refresh();
    setMessage(`${state.scopeRules.length} scope rules imported`);
  }
  document.querySelectorAll("th[data-key]").forEach((th) =>
    th.addEventListener("click", () => {
      const key = th.dataset.key;
      if (state.sort === key) state.direction *= -1;
      else {
        state.sort = key;
        state.direction = 1;
      }
      refresh();
    }),
  );
  [...controls, "hideData"].forEach((id) =>
    $(id).addEventListener("input", () => {
      saveControlState();
      refresh();
      renderScripts();
      renderEndpoints();
    }),
  );
  document.querySelectorAll(".hideType").forEach((x) =>
    x.addEventListener("change", () => {
      saveControlState();
      refresh();
    }),
  );
  $("endpointSearch").addEventListener("input", renderEndpoints);
  document.querySelectorAll(".tab").forEach((btn) =>
    btn.addEventListener("click", () => {
      document
        .querySelectorAll(".tab")
        .forEach((x) => x.classList.toggle("active", x === btn));
      $("requestsView").hidden = btn.dataset.view !== "requests";
      $("scriptsView").hidden = btn.dataset.view !== "scripts";
      $("endpointsView").hidden = btn.dataset.view !== "endpoints";
      $("findingsView").hidden = btn.dataset.view !== "findings";
    }),
  );
  $("redactSensitive").addEventListener("change", () => {
    $("redactWarning").hidden = $("redactSensitive").checked;
  });
  $("onlyScope").addEventListener("change", refresh);
  $("findingsShortcut").addEventListener("click", () =>
    document.querySelector('.tab[data-view="findings"]').click(),
  );
  $("showInfo").addEventListener("change", () => {
    state.severityFilters.info = $("showInfo").checked;
    saveSeverityFilters();
    renderFindings();
  });
  $("importScope").addEventListener("click", () =>
    openEditor(
      "Import in-scope domains",
      "Domains (one per line; wildcards such as *.example.com are supported)",
      "",
      "Optional notes or comments",
      "",
      () => {
        const text = $("editorPrimary").value;
        closeEditor();
        parseScope(text);
      },
    ),
  );
  $("editorCancel").addEventListener("click", closeEditor);
  $("editorSave").addEventListener("click", () => {
    if (state.editorSave) state.editorSave();
  });
  $("uploadScope").addEventListener("click", () => $("scopeFile").click());
  $("scopeFile").addEventListener("change", (e) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => parseScope(String(reader.result || ""));
    reader.onerror = () => setMessage("Could not read scope file");
    reader.readAsText(file);
    e.target.value = "";
  });
  $("exportHar").addEventListener("click", () =>
    download(
      "cleaninspect-filtered.har",
      JSON.stringify(
        {
          log: {
            version: "1.2",
            creator: { name: "CleanInspect", version: "1.3.0" },
            entries: state.shown.map((r) =>
              harEntry(r, $("redactSensitive").checked),
            ),
          },
        },
        null,
        2,
      ),
      "application/json",
    ),
  );
  $("exportUrls").addEventListener("click", () =>
    download(
      "cleaninspect-urls.txt",
      [...new Set(state.shown.map((r) => r.url))].join("\n"),
      "text/plain",
    ),
  );
  $("copyCurl").addEventListener("click", async () => {
    const commands = state.shown
      .filter((r) => r.source === "network")
      .map((r) =>
        window.CleanInspectPrivacyUtils.buildCurlCommand(
          {
            url: r.url,
            method: r.method,
            headers: r.requestHeaders,
            postData: r.postData,
          },
          $("redactSensitive").checked,
        ),
      );
    try {
      await navigator.clipboard.writeText(commands.join("\n"));
      setMessage(`${commands.length} cURL command(s) copied`);
    } catch {
      setMessage("Clipboard unavailable");
    }
  });
  $("copyScripts").addEventListener("click", () =>
    copyText(
      [...state.scripts.values()]
        .filter((x) => allowedResource(x.url))
        .map((x) => x.url)
        .join("\n"),
      "Script URLs copied",
    ),
  );
  $("copyEndpoints").addEventListener("click", () =>
    copyText(
      visibleEndpoints()
        .map(
          (x) =>
            `${x.method} ${x.origin}${x.path}${x.params.size ? " ?" + [...x.params].join("&") : ""}`,
        )
        .join("\n"),
      "Endpoints copied",
    ),
  );
  $("clear").addEventListener("click", () => {
    state.all = [];
    state.requestMap.clear();
    state.resourceKeys.clear();
    state.requestHashCache.clear();
    state.scripts.clear();
    state.endpoints.clear();
    state.secrets.clear();
    state.tech.clear();
    resetScanCounts();
    renderScripts();
    renderEndpoints();
    renderFindings();
    refresh();
  });
  $("savePreset").addEventListener("click", () =>
    chrome.storage.local.get(presetsKey, (d) => {
      const presets = d[presetsKey] || {};
      presets[state.host || "unknown"] = getPreset();
      const capped = window.CleanInspectPrivacyUtils.capStoredValue(
        presets,
        1000,
        131072,
      );
      chrome.storage.local.set({ [presetsKey]: capped }, () =>
        setMessage("Preset saved for " + (state.host || "this site")),
      );
    }),
  );
  state.observer = new IntersectionObserver((entries) => {
    if (entries.some((e) => e.isIntersecting)) renderMoreIfVisible();
  });
  state.observer.observe($("sentinel"));
  setTheme();
  init();
})();
