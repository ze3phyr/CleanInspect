(() => {
  const legacySensitiveQueryName = /(?:token|key|secret|auth|session)/i;
  const sensitiveNameSegments = new Set([
    "token",
    "key",
    "secret",
    "auth",
    "session",
    "code",
    "state",
    "sid",
    "jwt",
    "pass",
    "password",
    "passwd",
    "pwd",
    "signature",
    "sig",
    "ticket",
    "credential",
    "bearer",
    "otp",
    "nonce",
    "csrf",
    "xsrf",
  ]);
  const sensitiveHeaderName =
    /(?:authorization|proxy-authorization|cookie|set-cookie|(?:^|[-_])(?:api[-_]?key|token|secret|password|credential)(?:$|[-_]))/i;

  function isSensitiveName(name) {
    const normalized = String(name || "").toLowerCase();
    if (legacySensitiveQueryName.test(normalized)) return true;
    return normalized.split(/[_\-.]+/).some((part) =>
      sensitiveNameSegments.has(part),
    );
  }

  function requestSignature(request) {
    const url = new URL(request.url);
    const names = [...url.searchParams.keys()].sort();
    return `${String(request.method || "GET").toUpperCase()} ${url.origin}${url.pathname} ?${names.join("&")}`;
  }

  async function hashRequest(request) {
    const bytes = new TextEncoder().encode(requestSignature(request));
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return [...new Uint8Array(digest)]
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  function redactUrl(value) {
    try {
      const url = new URL(value);
      const pairs = [];
      for (const [name, queryValue] of url.searchParams) {
        pairs.push([
          name,
          isSensitiveName(name) ? "[REDACTED]" : queryValue,
        ]);
      }
      url.search = "";
      for (const [name, queryValue] of pairs)
        url.searchParams.append(name, queryValue);
      return url.href;
    } catch {
      return "[URL REDACTED]";
    }
  }

  function redactHeaders(headers) {
    return (headers || []).map((header) => ({
      ...header,
      value: sensitiveHeaderName.test(String(header.name || ""))
        ? "[REDACTED]"
        : header.value,
    }));
  }

  function shellQuote(value) {
    return "'" + String(value).replace(/'/g, "'\\''") + "'";
  }

  function buildCurlCommand(request, redact) {
    const headers = redact
      ? redactHeaders(request.headers).filter(
          (header) => !/(?:^|[-_])cookie(?:$|[-_])/i.test(header.name || ""),
        )
      : request.headers || [];
    const url = redact ? redactUrl(request.url || "") : request.url || "";
    const headerArgs = headers
      .map((header) => `-H ${shellQuote(`${header.name}: ${header.value}`)}`)
      .join(" ");
    const body = !redact && request.postData && request.postData.text
      ? ` --data-raw ${shellQuote(request.postData.text)}`
      : "";
    return `curl ${shellQuote(url)} -X ${shellQuote(request.method || "GET")}${headerArgs ? ` ${headerArgs}` : ""}${body}`;
  }

  function redactPostData(postData) {
    if (!postData) return postData;
    const result = { ...postData };
    if (Object.hasOwn(result, "text")) {
      const mimeType = String(result.mimeType || "")
        .split(";", 1)[0]
        .trim();
      if (/^[^/]+\/(?:json|[^/]+\+json)$/i.test(mimeType)) {
        try {
          const parsed = JSON.parse(result.text);
          const redactJson = (value) => {
            if (Array.isArray(value)) return value.map(redactJson);
            if (!value || typeof value !== "object") return value;
            const redacted = Object.create(null);
            for (const [key, child] of Object.entries(value)) {
              redacted[key] = isSensitiveName(key)
                ? "[REDACTED]"
                : redactJson(child);
            }
            return redacted;
          };
          result.text = JSON.stringify(redactJson(parsed));
        } catch {
          result.text = "[REDACTED]";
        }
      } else if (
        mimeType.toLowerCase() ===
        "application/x-www-form-urlencoded"
      ) {
        try {
          const params = new URLSearchParams(String(result.text));
          result.text = [...params]
            .map(([name, value]) =>
              `${encodeURIComponent(name)}=${encodeURIComponent(isSensitiveName(name) ? "[REDACTED]" : value)}`,
            )
            .join("&");
        } catch {
          result.text = "[REDACTED]";
        }
      } else {
        result.text = "[REDACTED]";
      }
    }
    if (Array.isArray(result.params)) {
      result.params = result.params.map((param) => ({
        ...param,
        value: "[REDACTED]",
      }));
    }
    return result;
  }

  function redactCookies(cookies) {
    return (cookies || []).map((cookie) => ({
      ...cookie,
      value: "[REDACTED]",
    }));
  }

  function redactUrlsInObject(value) {
    if (!value || typeof value !== "object") return;
    for (const [key, child] of Object.entries(value)) {
      if (
        typeof child === "string" &&
        /^(?:url|redirecturl)$/i.test(key)
      ) {
        value[key] = redactUrl(child);
      } else if (child && typeof child === "object") {
        redactUrlsInObject(child);
      }
    }
  }

  function redactHarEntry(entry) {
    const copy = JSON.parse(JSON.stringify(entry));
    redactUrlsInObject(copy);
    if (copy.request) {
      copy.request.headers = redactHeaders(copy.request.headers);
      copy.request.cookies = redactCookies(copy.request.cookies);
      copy.request.postData = redactPostData(copy.request.postData);
      if (Array.isArray(copy.request.queryString)) {
        copy.request.queryString = copy.request.queryString.map((item) => ({
          ...item,
          value: isSensitiveName(item.name)
            ? "[REDACTED]"
            : item.value,
        }));
      }
    }
    if (copy.response) {
      copy.response.headers = redactHeaders(copy.response.headers);
      copy.response.headers = copy.response.headers.map((header) =>
        String(header.name || "").toLowerCase() === "location"
          ? { ...header, value: redactUrl(header.value || "") }
          : header,
      );
      if (Array.isArray(copy.response.cookies)) {
        copy.response.cookies = redactCookies(copy.response.cookies);
      }
      if (
        copy.response.content &&
        Object.hasOwn(copy.response.content, "text")
      ) {
        copy.response.content.text = "[REDACTED]";
      }
    }
    return copy;
  }

  function capStoredValue(value, maxEntries, maxBytes) {
    const copy = Array.isArray(value) ? [...value] : { ...(value || {}) };
    const entries = () => (Array.isArray(copy) ? copy : Object.keys(copy));
    const encodedSize = () =>
      new TextEncoder().encode(JSON.stringify(copy)).length;
    while (entries().length > maxEntries || encodedSize() > maxBytes) {
      if (Array.isArray(copy)) copy.shift();
      else {
        const oldest = Object.keys(copy)[0];
        if (oldest === undefined) break;
        delete copy[oldest];
      }
    }
    return copy;
  }

  window.CleanInspectPrivacyUtils = {
    requestSignature,
    hashRequest,
    redactUrl,
    redactHeaders,
    redactHarEntry,
    buildCurlCommand,
    capStoredValue,
  };
})();
