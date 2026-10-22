// Resolve overlapping detections into one finding per exact value.
(() => {
  const severityRank = { high: 0, medium: 1, low: 2, info: 3 };
  const providerPattern =
    /(?:aws|amazon|github|google|stripe|slack|square|twilio|sendgrid|npm|private key)/i;
  const authPattern = /(?:jwt|bearer|basic)/i;
  const genericPattern =
    /(?:assignment|credential|generic|api[_ -]?key|access[_ -]?token|client[_ -]?secret)/i;
  const passwordPattern = /(?:hardcoded[_ -]?password|password)/i;

  function specificity(rule) {
    const identity = `${rule.name || ""} ${rule.label || ""}`;
    if (providerPattern.test(identity)) return 4;
    if (authPattern.test(identity)) return 3;
    if (genericPattern.test(identity)) return 2;
    if (passwordPattern.test(identity)) return 1;
    return 0;
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
          )
            continue;
          const label = rule.label || rule.name || "Unlabeled rule";
          const rank = specificity(rule);
          let severity =
            severityRank[rule.severity] === undefined ? "info" : rule.severity;
          // Generic key-name assignments and public keys can never be reported as high.
          if (rank === 2 && severityRank[severity] < severityRank.medium)
            severity = "medium";
          if (/public by design/i.test(label) && severity === "high")
            severity = "medium";
          let item = grouped.get(value);
          if (!item) {
            item = {
              value,
              rule,
              label,
              severity,
              specificity: rank,
              publicByDesign: false,
              matches: [],
            };
            grouped.set(value, item);
          } else if (
            rank > item.specificity ||
            (rank === item.specificity &&
              severityRank[severity] < severityRank[item.severity])
          ) {
            item.rule = rule;
            item.label = label;
            item.severity = severity;
            item.specificity = rank;
          }
          if (/public by design/i.test(label)) item.publicByDesign = true;
          item.matches.push({ match, rule });
        }
      } catch {
        // A malformed or throwing rule cannot interrupt scans for other rules.
      }
    }
    for (const item of grouped.values()) {
      if (item.publicByDesign && item.severity === "high")
        item.severity = "medium";
    }
    return [...grouped.values()];
  }

  window.CleanInspectFindingResolver = { resolve };
})();
