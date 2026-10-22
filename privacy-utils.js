(() => {
  const sensitiveQueryName = /(?:token|key|secret|auth|session)/i;
  const sensitiveHeaderName =
    /(?:authorization|proxy-authorization|cookie|set-cookie|(?:^|[-_])(?:api[-_]?key|token|secret|password|credential)(?:$|[-_]))/i;

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
          sensitiveQueryName.test(name) ? "[REDACTED]" : queryValue,
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

  function redactHarEntry(entry) {
    const copy = JSON.parse(JSON.stringify(entry));
    if (copy.request) {
      copy.request.url = redactUrl(copy.request.url || "");
      copy.request.headers = redactHeaders(copy.request.headers);
      if (Array.isArray(copy.request.queryString)) {
        copy.request.queryString = copy.request.queryString.map((item) => ({
          ...item,
          value: sensitiveQueryName.test(String(item.name || ""))
            ? "[REDACTED]"
            : item.value,
        }));
      }
    }
    if (copy.response) {
      copy.response.headers = redactHeaders(copy.response.headers);
      if (Array.isArray(copy.response.cookies)) {
        copy.response.cookies = copy.response.cookies.map((cookie) => ({
          ...cookie,
          value: "[REDACTED]",
        }));
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
    capStoredValue,
  };
})();
