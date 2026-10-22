const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { performance } = require("node:perf_hooks");
const { webcrypto } = require("node:crypto");

async function main() {
  const extensionDir = path.resolve(__dirname, "..");
  const source = fs.readFileSync(
    path.join(extensionDir, "patterns.js"),
    "utf8",
  );
  const sandbox = {
    window: {},
    crypto: webcrypto,
    TextEncoder,
    URL,
    atob(value) {
      return Buffer.from(value, "base64").toString("binary");
    },
  };
  vm.runInNewContext(source, sandbox, {
    filename: "patterns.js",
    timeout: 1000,
  });
  const pslSource = fs.readFileSync(
    path.join(extensionDir, "public-suffix-list.js"),
    "utf8",
  );
  vm.runInNewContext(pslSource, sandbox, {
    filename: "public-suffix-list.js",
    timeout: 1000,
  });
  const domainSource = fs.readFileSync(
    path.join(extensionDir, "domain-utils.js"),
    "utf8",
  );
  vm.runInNewContext(domainSource, sandbox, {
    filename: "domain-utils.js",
    timeout: 1000,
  });
  const viewSource = fs.readFileSync(
    path.join(extensionDir, "request-view.js"),
    "utf8",
  );
  vm.runInNewContext(viewSource, sandbox, {
    filename: "request-view.js",
    timeout: 1000,
  });
  const privacySource = fs.readFileSync(
    path.join(extensionDir, "privacy-utils.js"),
    "utf8",
  );
  vm.runInNewContext(privacySource, sandbox, {
    filename: "privacy-utils.js",
    timeout: 1000,
  });
  const privacyUtils = sandbox.window.CleanInspectPrivacyUtils;
  const resolverSource = fs.readFileSync(
    path.join(extensionDir, "finding-resolver.js"),
    "utf8",
  );
  vm.runInNewContext(resolverSource, sandbox, {
    filename: "finding-resolver.js",
    timeout: 1000,
  });
  const domainUtils = sandbox.window.CleanInspectDomainUtils;
  const requestView = sandbox.window.CleanInspectRequestView;
  const resolve = sandbox.window.CleanInspectFindingResolver.resolve;
  const rules = sandbox.window.CLEANINSPECT_RULES;
  assert.ok(
    Array.isArray(rules) && rules.length > 0,
    "patterns.js must expose CLEANINSPECT_RULES",
  );

  function acceptedMatches(text, rule) {
    const re = new RegExp(rule.regex.source, rule.regex.flags);
    const found = [];
    for (const match of text.matchAll(re)) {
      const value = rule.capture ? match[rule.capture] : match[0];
      if (value && (!rule.validate || rule.validate(value, match)))
        found.push({ rule, value, match });
    }
    return found;
  }

  function base64url(text) {
    return Buffer.from(text)
      .toString("base64")
      .replace(/=/g, "")
      .replace(/\+/g, "-")
      .replace(/\//g, "_");
  }
  const varied = "BCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const googleKey = "AIza" + varied.repeat(2).slice(0, 35);
  const apiValue = "sK8" + "qT5" + "vR2" + "mN7" + "pL4";
  const bearerValue = "bR8" + "tM5" + "qV2" + "xN7" + "zP4" + "hC6";
  const awsKey = "AKIA" + "Q7W8E9R0T1Y2U3I4";
  const pemBody = "QUJD".repeat(8);
  const jwtHeader = base64url(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const jwtPayload = base64url(
    JSON.stringify({ sub: "synthetic-user", exp: 2000000000 }),
  );
  const jwt = jwtHeader + "." + jwtPayload + "." + "s".repeat(24);
  const positives = new Map([
    ["JWT", jwt],
    ["Google API key", googleKey],
    ["API credential assignment", 'apiKey:"' + apiValue + '"'],
    ["Bearer token", "Bearer " + bearerValue],
    ["AWS access key", awsKey],
    [
      "Private key",
      "-----BEGIN " +
        "PRIVATE KEY-----\n" +
        pemBody +
        "\n-----END " +
        "PRIVATE KEY-----",
    ],
    ["Internal hostname", "https://" + "api.dev.internal" + "/status"],
  ]);

  for (const rule of rules) {
    assert.equal(
      Object.prototype.toString.call(rule.regex),
      "[object RegExp]",
      `${rule.name} needs a RegExp`,
    );
    assert.ok(rule.regex.global, `${rule.name} regex must be global`);
    const sample = positives.get(rule.name);
    assert.ok(sample, `missing synthetic positive sample for ${rule.name}`);
    const matches = acceptedMatches(sample, rule);
    assert.ok(
      matches.length > 0,
      `${rule.name} sample must match and pass validate`,
    );
  }

  const documentedAwsExample = "AKIA" + "IOSFODNN7" + "EXAMPLE";
  const negatives = [
    "The word internal appears in this prose.",
    "this.internal",
    'csrf_token="<random>"',
    'apiKey:"YOUR_API_KEY_HERE_xxxx"',
    'password:"Password"',
    "Basic subscription plan",
    documentedAwsExample,
    'Bearer " + token',
  ];
  for (const sample of negatives) {
    const findings = rules.flatMap((rule) => acceptedMatches(sample, rule));
    assert.equal(
      findings.length,
      0,
      `negative sample produced a finding: ${sample}`,
    );
  }

  const googleAssignment = 'apiKey:"' + googleKey + '"';
  const googleFindings = resolve(googleAssignment, rules);
  assert.equal(
    googleFindings.length,
    1,
    "Google API key assignment must produce exactly one finding",
  );
  assert.equal(googleFindings[0].severity, "low");
  assert.match(googleFindings[0].label, /Google API key/i);

  const clientSecret =
    "cS8" +
    "qT5" +
    "vR2" +
    "mN7" +
    "pL4" +
    "bX9" +
    "zK2" +
    "dW6" +
    "fJ3" +
    "hG" +
    "rV5";
  assert.equal(clientSecret.length, 32);
  const clientSecretFindings = resolve(
    'clientSecret:"' + clientSecret + '"',
    rules,
  );
  assert.equal(
    clientSecretFindings.length,
    1,
    "clientSecret assignment must produce exactly one finding",
  );
  assert.equal(
    clientSecretFindings[0].severity,
    "medium",
    "generic assignment severity must be capped at MEDIUM",
  );

  const overlapValue = "overlap-value-123456";
  const overlapFindings = resolve(overlapValue, [
    {
      name: "Generic assignment",
      label: "Generic assignment",
      severity: "high",
      regex: /overlap-value-123456/g,
    },
    {
      name: "Bearer token",
      label: "Bearer token",
      severity: "medium",
      regex: /overlap-value-123456/g,
    },
    {
      name: "AWS access key",
      label: "AWS access key",
      severity: "high",
      regex: /overlap-value-123456/g,
    },
  ]);
  assert.equal(
    overlapFindings.length,
    1,
    "overlapping specific rules must yield one finding per exact value",
  );
  assert.equal(
    overlapFindings[0].label,
    "AWS access key",
    "provider-specific rule must win over auth and generic rules",
  );
  assert.equal(overlapFindings[0].severity, "high");

  const publicOverlap = resolve(overlapValue, [
    {
      name: "AWS access key",
      label: "AWS access key",
      severity: "high",
      regex: /overlap-value-123456/g,
    },
    {
      name: "Google API key",
      label: "Google API key (public by design)",
      severity: "low",
      regex: /overlap-value-123456/g,
    },
  ]);
  assert.equal(publicOverlap.length, 1);

  assert.notEqual(
    publicOverlap[0].severity,
    "high",
    "values matched by public-by-design rules cannot be HIGH",
  );

  assert.equal(
    domainUtils.sameParty("192.168.1.5", "10.0.1.5"),
    false,
    "different IPv4 addresses are separate parties",
  );
  assert.equal(
    domainUtils.sameParty("a.github.io", "b.github.io"),
    false,
    "private suffix tenants stay separate",
  );
  assert.equal(
    domainUtils.sameParty("shop.example.co.uk", "example.co.uk"),
    true,
    "multi-label ICANN suffix is honored",
  );
  assert.equal(
    domainUtils.registrableDomain("foo.example.com.tr"),
    "example.com.tr",
    "com.tr stays inside the registrant domain",
  );
  assert.equal(
    domainUtils.registrableDomain("localhost"),
    "localhost",
    "localhost is its own host",
  );
  assert.equal(
    domainUtils.registrableDomain("2001:db8::1"),
    "2001:db8::1",
    "IPv6 is its own host",
  );
  assert.equal(requestView.dataUrlVisible(false), true);
  assert.equal(requestView.dataUrlVisible(true), false);

  const diffA = {
    method: "GET",
    url: "https://example.test/api?token=alpha&mode=full",
  };
  const diffB = {
    method: "GET",
    url: "https://example.test/api?mode=short&token=beta",
  };
  assert.equal(
    privacyUtils.requestSignature(diffA),
    privacyUtils.requestSignature(diffB),
    "diff signature omits values and sorts query names",
  );
  assert.ok(!privacyUtils.requestSignature(diffA).includes("alpha"));
  assert.equal(
    await privacyUtils.hashRequest(diffA),
    await privacyUtils.hashRequest(diffB),
    "diff hash ignores query values",
  );
  const querySecret = "secret" + "value";
  const redactedUrl = privacyUtils.redactUrl(
    `https://example.test/?token=${querySecret}&page=2`,
  );
  const redactedParams = new URL(redactedUrl).searchParams;
  assert.equal(redactedParams.get("token"), "[REDACTED]");
  assert.equal(redactedParams.get("page"), "2");
  const redactedHeaders = privacyUtils.redactHeaders([
    { name: "Authorization", value: querySecret },
    { name: "Cookie", value: querySecret },
    { name: "Set-Cookie", value: querySecret },
    { name: "X-API-Key", value: querySecret },
    { name: "Accept", value: "application/json" },
  ]);
  assert.ok(
    redactedHeaders
      .slice(0, 4)
      .every((header) => header.value === "[REDACTED]"),
  );
  assert.equal(redactedHeaders[4].value, "application/json");
  const redactedHar = privacyUtils.redactHarEntry({
    request: {
      url: `https://example.test/?api_key=${querySecret}`,
      headers: [{ name: "Authorization", value: querySecret }],
      queryString: [{ name: "api_key", value: querySecret }],
    },
    response: {
      headers: [{ name: "Set-Cookie", value: querySecret }],
      cookies: [{ name: "sid", value: querySecret }],
      content: { text: querySecret },
    },
  });
  assert.ok(
    !JSON.stringify(redactedHar).includes(querySecret),
    "redacted HAR contains no supplied sensitive marker",
  );
  const capped = privacyUtils.capStoredValue(
    { oldest: "1", middle: "2", newest: "3" },
    2,
    1000,
  );
  assert.deepEqual(
    Object.keys(capped),
    ["middle", "newest"],
    "storage cap drops oldest entries",
  );

  const twoThousandRequests = Array.from({ length: 2000 }, (_, index) => ({
    method: index % 3 ? "GET" : "POST",
    status: index % 2 ? 200 : 404,
    type: "xhr",
    url: `https://api.example.test/v${index % 20}/item/${index}`,
    time: index % 70,
    index,
  }));
  const refreshStart = performance.now();
  const refreshed = requestView.build(
    twoThousandRequests,
    () => true,
    "time",
    -1,
  );
  const refreshElapsed = performance.now() - refreshStart;
  assert.equal(refreshed.length, 2000);
  // The table's filter+sort path must handle 2,000 visible requests in under 100 ms on CI.
  assert.ok(
    refreshElapsed < 100,
    `2,000-request table refresh took ${refreshElapsed.toFixed(1)}ms (budget 100ms)`,
  );

  function assertBoundedQuantifiers(regex) {
    const text = regex.source;
    let inClass = false;
    for (let i = 0; i < text.length; i++) {
      if (text[i] === "\\") {
        i++;
        continue;
      }
      if (text[i] === "[") {
        inClass = true;
        continue;
      }
      if (text[i] === "]" && inClass) {
        inClass = false;
        continue;
      }
      if (inClass) continue;
      assert.notEqual(text[i], "*", `unbounded * in ${regex}`);
      assert.notEqual(text[i], "+", `unbounded + in ${regex}`);
      if (text[i] === "{") {
        const end = text.indexOf("}", i + 1);
        if (end !== -1) {
          const quantifier = text.slice(i + 1, end);
          assert.ok(
            !(
              quantifier.endsWith(",") &&
              quantifier
                .slice(0, -1)
                .split("")
                .every((char) => char >= "0" && char <= "9")
            ),
            `unbounded {n,} in ${regex}`,
          );
        }
      }
    }
  }
  for (const rule of rules) assertBoundedQuantifiers(rule.regex);

  const randomSeed = "aZ4!.,;:/?@[]{}()_-=+%~";
  const randomPrintable = randomSeed
    .repeat(Math.ceil(400000 / randomSeed.length))
    .slice(0, 400000);
  const adversarial = [
    ".".repeat(400000),
    "eyJ".repeat(Math.ceil(400000 / 3)).slice(0, 400000),
    "AKIA".repeat(100000),
    "Bearer ".repeat(Math.ceil(400000 / 7)).slice(0, 400000),
    'apiKey="'.repeat(50000),
    "-----BEGIN PRIVATE KEY-----".repeat(15000),
    randomPrintable,
  ];
  for (const rule of rules) {
    for (const input of adversarial) {
      const re = new RegExp(rule.regex.source, rule.regex.flags);
      const start = performance.now();
      let accepted = 0;
      for (const match of input.matchAll(re)) {
        const value = rule.capture ? match[rule.capture] : match[0];
        if (value && (!rule.validate || rule.validate(value, match)))
          accepted++;
        if (accepted >= 500) break;
      }
      const elapsed = performance.now() - start;
      assert.ok(
        elapsed <= 1000,
        `${rule.name} took ${elapsed.toFixed(1)}ms on a 400KB stress input`,
      );
    }
  }

  console.log(`CleanInspect scanner checks passed (${rules.length} rules).`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
