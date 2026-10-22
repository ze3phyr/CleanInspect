// Resolve overlapping detections into one finding per exact value.
(() => {
  const severityRank = { high: 0, medium: 1, low: 2, info: 3 };
  const specificityRank = {
    provider: 4,
    token: 3,
    generic: 2,
    password: 1,
    recon: 0,
  };
  const jwtPublicNote = "likely public client token";

  function decodeJwtPayload(value) {
    try {
      const parts = value.split(".");
      if (parts.length !== 3) return null;
      let encoded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
      while (encoded.length % 4) encoded += "=";
      const payload = JSON.parse(atob(encoded));
      return payload && typeof payload === "object" ? payload : null;
    } catch {
      return null;
    }
  }

  function isJwtRule(rule) {
    return /\bjwt\b/i.test(String(rule.label || rule.name || ""));
  }

  function resolveRule(rule, value) {
    let severity = severityRank[rule.severity] === undefined
      ? "info"
      : rule.severity;
    let note = rule.note || "";
    const label = String(rule.label || rule.name || "");
    const isPublicByDesign = /public by design/i.test(label);

    if (isJwtRule(rule)) {
      const payload = decodeJwtPayload(value);
      const role = String((payload && payload.role) || "").toLowerCase();
      const issuer = String((payload && payload.iss) || "");
      if (role === "service_role") {
        severity = "high";
      } else if (
        role === "anon" ||
        role === "public" ||
        /firebase|securetoken\.google\.com|supabase|public[ _-]?client|anon/i.test(
          issuer,
        )
      ) {
        severity = "low";
        note = jwtPublicNote;
      } else {
        severity = "medium";
      }
    }

    if (
      (rule.kind === "generic" || rule.kind === "password") &&
      severityRank[severity] < severityRank.medium
    ) {
      severity = "medium";
    }
    if (isPublicByDesign && severity === "high") severity = "medium";

    return { severity, note, isPublicByDesign };
  }

  function resolve(text, rules) {
    const grouped = new Map();
    for (const rule of rules || []) {
      if (!rule || !rule.regex) continue;
      try {
        const flags = rule.regex.flags.includes("g")
          ? rule.regex.flags
          : `${rule.regex.flags}g`;
        const expression = new RegExp(rule.regex.source, flags);
        for (const match of text.matchAll(expression)) {
          const value = rule.capture ? match[rule.capture] : match[0];
          if (
            !value ||
            (typeof rule.validate === "function" &&
              !rule.validate(value, match))
          ) {
            continue;
          }
          const label = rule.label || rule.name || "Unlabeled rule";
          const specificity = specificityRank[rule.kind] ?? 0;
          const resolved = resolveRule(rule, value);
          let item = grouped.get(value);
          if (!item) {
            item = {
              value,
              rule,
              label,
              severity: resolved.severity,
              note: resolved.note,
              specificity,
              publicByDesign: resolved.isPublicByDesign,
              matches: [],
            };
            grouped.set(value, item);
          } else if (specificity > item.specificity) {
            item.rule = rule;
            item.label = label;
            item.severity = resolved.severity;
            item.note = resolved.note;
            item.specificity = specificity;
            item.publicByDesign = resolved.isPublicByDesign;
          }
          item.matches.push({ match, rule });
        }
      } catch {
        // A malformed or throwing rule cannot interrupt scans for other rules.
      }
    }
    return [...grouped.values()];
  }

  window.CleanInspectFindingResolver = { resolve };
})();
