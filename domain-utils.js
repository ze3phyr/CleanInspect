(() => {
  const rules = window.CLEANINSPECT_PSL || [];
  const exact = new Set();
  const wildcard = new Set();
  const exceptions = new Set();

  for (const rule of rules) {
    if (rule.startsWith("!")) exceptions.add(rule.slice(1));
    else if (rule.startsWith("*.")) wildcard.add(rule.slice(2));
    else exact.add(rule);
  }

  function isIpAddress(host) {
    const plain =
      host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
    if (plain.includes(":")) return true;
    const parts = plain.split(".");
    return (
      parts.length === 4 &&
      parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255)
    );
  }

  function registrableDomain(input) {
    const host = String(input || "")
      .toLowerCase()
      .replace(/\.$/, "");
    if (
      !host ||
      isIpAddress(host) ||
      host === "localhost" ||
      host.endsWith(".localhost")
    )
      return host;
    const labels = host.split(".");
    let publicSuffixLength = 1; // PSL's implicit * rule.
    let exceptionLength = 0;

    for (let i = 0; i < labels.length; i++) {
      const suffix = labels.slice(i).join(".");
      const length = labels.length - i;
      if (exact.has(suffix) && length > publicSuffixLength)
        publicSuffixLength = length;
      if (exceptions.has(suffix) && length > exceptionLength)
        exceptionLength = length;
      if (
        i > 0 &&
        wildcard.has(labels.slice(i).join(".")) &&
        length + 1 > publicSuffixLength
      ) {
        publicSuffixLength = length + 1;
      }
    }

    if (exceptionLength) publicSuffixLength = exceptionLength - 1;
    return labels
      .slice(-Math.min(labels.length, publicSuffixLength + 1))
      .join(".");
  }

  function sameParty(a, b) {
    return !!a && !!b && registrableDomain(a) === registrableDomain(b);
  }

  window.CleanInspectDomainUtils = {
    registrableDomain,
    sameParty,
    isIpAddress,
  };
})();
