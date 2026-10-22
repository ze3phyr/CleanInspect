// Local detection rules. Keep expressions global and bounded; validators reject
// common placeholders and documented examples after a syntactic match.
(() => {
  const rules = [
    {
      name: "JWT",
      label: "JSON Web Token",
      severity: "high",
      regex:
        /\beyJ[A-Za-z0-9_-]{8,512}\.[A-Za-z0-9_-]{8,512}\.[A-Za-z0-9_-]{8,512}\b/g,
      validate(value) {
        const parts = value.split(".");
        if (parts.length !== 3) return false;
        try {
          const decode = (part) => {
            const base64 =
              part.replace(/-/g, "+").replace(/_/g, "/") +
              "=".repeat((4 - (part.length % 4)) % 4);
            return atob(base64);
          };
          const header = JSON.parse(decode(parts[0]));
          JSON.parse(decode(parts[1]));
          return (
            !!header && typeof header.alg === "string" && parts[2].length >= 8
          );
        } catch {
          return false;
        }
      },
    },
    {
      name: "Google API key",
      label: "Google API key (public by design)",
      severity: "low",
      note: "Usually not a vulnerability by itself; check API and referrer restrictions.",
      regex: /AIza[0-9A-Za-z_-]{35}/g,
      validate(value) {
        return value.length === 39;
      },
    },
    {
      name: "API credential assignment",
      label: "API key or credential assignment",
      severity: "high",
      regex:
        /\b(?:api[_-]?key|access[_-]?token|client[_-]?secret)\b[\t ]{0,8}[:=][\t ]{0,8}["']([A-Za-z0-9_./+=-]{12,256})["']/gi,
      capture: 1,
      validate(value) {
        const normalized = value.toLowerCase();
        return ![
          "your_api_key_here",
          "example",
          "placeholder",
          "changeme",
          "dummy",
          "redacted",
          "replace_me",
          "test_key",
        ].some((word) => normalized.includes(word));
      },
    },
    {
      name: "Bearer token",
      label: "Bearer token",
      severity: "medium",
      regex: /\bBearer[\t ]{1,16}([A-Za-z0-9._~-]{16,256})\b/gi,
      capture: 1,
      validate(value) {
        return ![
          "example",
          "placeholder",
          "changeme",
          "dummy",
          "redacted",
          "your_token",
        ].some((word) => value.toLowerCase().includes(word));
      },
    },
    {
      name: "AWS access key",
      label: "AWS access key ID",
      severity: "high",
      regex: /\bAKIA[0-9A-Z]{16}\b/g,
      validate(value) {
        return value !== "AKIAIOSFODNN7EXAMPLE";
      },
    },
    {
      name: "Private key",
      label: "Private key material",
      severity: "high",
      regex:
        /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\r\n]{1,2}([A-Za-z0-9+/=\r\n]{20,2048})[\r\n]{1,2}-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
      capture: 1,
      validate(value) {
        return value.replace(/[\r\n]/g, "").length >= 20;
      },
    },
    {
      name: "Internal hostname",
      label: "Internal hostname",
      severity: "info",
      note: "Reconnaissance hint only; this may be documentation or a non-routable example.",
      regex:
        /\b((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){2,8}(?:internal|intranet|corp|localhost))(?::[0-9]{1,5})?\b/gi,
      capture: 1,
      validate(value) {
        return !["this.internal", "internal", "localhost"].includes(
          value.toLowerCase(),
        );
      },
    },
  ];
  window.CLEANINSPECT_RULES = rules;
  // Preserve the earlier global name for any local customization that still reads it.
  window.CLEANINSPECT_PATTERNS = rules;
})();
