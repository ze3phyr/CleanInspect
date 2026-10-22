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
    URLSearchParams,
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
  const exportedPatterns = sandbox.window.CLEANINSPECT_PATTERNS;
  assert.ok(
    Array.isArray(rules) && rules.length === 48,
    "patterns.js must expose all 48 CLEANINSPECT_RULES",
  );
  assert.equal(exportedPatterns.length, rules.length);

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
  function varied(length, alphabet = "Q7w9Er2T5y8U3i6O1p4A") {
    return Array.from(
      { length },
      (_, index) => alphabet[(index * 7 + 3) % alphabet.length],
    ).join("");
  }
  const hex = (length) => varied(length, "a1c3e5b7d9f20468");
  const makeJwt = (payload) =>
    base64url(JSON.stringify({ alg: "HS256", typ: "JWT" })) +
    "." +
    base64url(JSON.stringify(payload)) +
    "." +
    varied(32);
  const samples = new Map([
    ["AWS access key ID", () => ["AKIA", "Q7W8E9R0T1Y2U3I4"].join("")],
    ["AWS secret access key", () => ['aws_secret_access_key="', varied(40), '"'].join("")],
    ["Private key (PEM block with body)", () => ["-----BEGIN ", "PRIVATE KEY-----\n", varied(80), "\n-----END PRIVATE KEY-----"].join("")],
    ["GitHub token", () => ["ghp_", varied(36, "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789")].join("")],
    ["GitLab personal access token", () => ["glpat-", varied(20)].join("")],
    ["Slack token", () => ["xoxb-", varied(24)].join("")],
    ["Slack webhook URL", () => ["https://hooks.slack.com/services/", varied(24)].join("")],
    ["Discord webhook URL", () => ["https://discord.com/api/webhooks/", "12345678901234567", "/", varied(60)].join("")],
    ["Stripe live secret / restricted key", () => ["sk_live_", varied(24)].join("")],
    ["SendGrid API key", () => ["SG.", varied(22), ".", varied(43)].join("")],
    ["Google OAuth client secret", () => ["GOCSPX-", varied(28)].join("")],
    ["Firebase Cloud Messaging server key (legacy)", () => ["AAAA", varied(7), ":", varied(140)].join("")],
    ["npm access token", () => ["npm_", varied(36)].join("")],
    ["PyPI upload token", () => ["pypi-AgEIcHlwaS5vcmc", varied(50)].join("")],
    ["Shopify access token", () => ["shpat_", hex(32)].join("")],
    ["Square access token", () => ["sq0atp-", varied(22)].join("")],
    ["DigitalOcean token", () => ["dop_v1_", hex(64)].join("")],
    ["Hugging Face token", () => ["hf_", varied(34)].join("")],
    ["OpenAI API key", () => ["sk-proj-", varied(40)].join("")],
    ["Anthropic API key", () => ["sk-ant-api01-", varied(80)].join("")],
    ["Mapbox secret token", () => ["sk.eyJ", varied(20), ".", varied(20)].join("")],
    ["Braintree / PayPal production token", () => ["access_token$production$", varied(16, "abcd1234efgh5678"), "$", hex(32)].join("")],
    ["Cloudinary URL with API secret", () => ["cloudinary://12345678:", varied(20), "@assets"].join("")],
    ["Azure storage connection string (AccountKey)", () => ["DefaultEndpointsProtocol=https;AccountKey=", varied(60, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"), "=="].join("")],
    ["Azure SAS token signature", () => ["?sv=2024-01-01&sp=read&sig=", varied(30)].join("")],
    ["Database / broker URL with password", () => ["postgres://user:", varied(20), "@database.example"].join("")],
    ["Supabase service_role JWT", () => makeJwt({ role: "service_role", iss: "synthetic" })],
    ["JWT", () => makeJwt({ role: "member", iss: "synthetic" })],
    ["Bearer token (literal)", () => ["Bearer ", varied(30)].join("")],
    ["Basic auth header (decodes to user:pass)", () => ["Basic ", Buffer.from("tester:" + varied(20)).toString("base64")].join("")],
    ["Credentials in URL (user:pass@host)", () => ["https://tester:", varied(20), "@host.example"].join("")],
    ["Generic secret assignment (key-name + high-entropy value)", () => ["serviceSecret=\"", varied(40), "\""].join("")],
    ["Hardcoded password", () => ["password=\"", varied(24), "\""].join("")],
    ["Facebook / Meta access token", () => ["EAA", varied(50)].join("")],
    ["Telegram bot token", () => ["12345678:AA", varied(33)].join("")],
    ["Mailgun API key", () => ["key-", hex(32)].join("")],
    ["Twilio API key SID", () => ["SK", hex(32)].join("")],
    ["Stripe test secret key", () => ["sk_test_", varied(24)].join("")],
    ["Google API key (public by design, check restrictions)", () => ["AIza", varied(35)].join("")],
    ["Stripe publishable key (public)", () => ["pk_live_", varied(24)].join("")],
    ["Mapbox public token (public)", () => ["pk.eyJ", varied(20), ".", varied(20)].join("")],
    ["Sentry DSN (public)", () => ["https://", hex(32), "@errors.example/", "123"].join("")],
    ["AWS S3 bucket reference", () => ["assets-bucket.s3.amazonaws.com"].join("")],
    ["Google Cloud Storage bucket reference", () => ["assets.storage.googleapis.com"].join("")],
    ["Azure Blob storage account", () => ["abc.blob.core.windows.net"].join("")],
    ["Firebase Realtime Database URL", () => ["demo-app.firebaseio.com"].join("")],
    ["Internal-looking URL (private TLD)", () => ["https://api.example.internal/v1"].join("")],
    ["Localhost / private-network URL", () => ["http://localhost:8080/api"].join("")],
  ]);
  const googleKey = samples.get(
    "Google API key (public by design, check restrictions)",
  )();

  for (const rule of rules) {
    assert.equal(
      Object.prototype.toString.call(rule.regex),
      "[object RegExp]",
      `${rule.label} needs a RegExp`,
    );
    assert.ok(rule.regex.global, `${rule.label} regex must be global`);
    assert.ok(
      ["provider", "token", "generic", "password", "recon"].includes(
        rule.kind,
      ),
      `${rule.label} must have a kind`,
    );
    const makeSample = samples.get(rule.label);
    assert.ok(makeSample, `missing synthetic positive sample for ${rule.label}`);
    const sample = makeSample();
    const matches = acceptedMatches(sample, rule);
    assert.ok(
      matches.length > 0,
      `${rule.label} sample must match and pass validate`,
    );
    const resolved = resolve(sample, [rule]);
    assert.equal(resolved.length, 1, `${rule.label} should resolve once`);
    assert.equal(
      resolved[0].severity,
      rule.severity,
      `${rule.label} should retain its declared severity`,
    );
    assert.equal(
      exportedPatterns.find((pattern) => pattern.label === rule.label).kind,
      rule.kind,
      `${rule.label} kind should be present in both exports`,
    );
  }

  const documentedAwsExample = "AKIA" + "IOSFODNN7" + "EXAMPLE";
  const negatives = [
    "internal",
    'apiKey:"abcdefghijklmnopqrst"',
    'apiKey:"aaaaaaaaaaaaaaaaaaaa"',
    'apiKey:"enter-your-key-here"',
    "Bearer abcdefghijklmnop12345",
    'password:"Password"',
    'csrf_token="' + "random".repeat(5) + '"',
    "this.internal",
    documentedAwsExample,
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
      kind: "generic",
      severity: "high",
      regex: /overlap-value-123456/g,
    },
    {
      name: "Bearer token",
      label: "Bearer token",
      kind: "token",
      severity: "medium",
      regex: /overlap-value-123456/g,
    },
    {
      name: "AWS access key",
      label: "AWS access key",
      kind: "provider",
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
      name: "Google API key",
      label: "Google API key (public by design)",
      kind: "provider",
      severity: "high",
      regex: /overlap-value-123456/g,
    },
  ]);
  assert.equal(publicOverlap.length, 1);
  assert.notEqual(
    publicOverlap[0].severity,
    "high",
    "values matched by public-by-design rules cannot be HIGH",
  );
  for (const kind of ["generic", "password"]) {
    const capped = resolve(overlapValue, [
      {
        label: `${kind} synthetic rule`,
        kind,
        severity: "high",
        regex: /overlap-value-123456/g,
      },
    ]);
    assert.equal(capped[0].severity, "medium");
  }

  const jwtRule = rules.find((rule) => rule.label === "JWT");
  const anonymousJwt = makeJwt({ role: "anon", iss: "synthetic" });
  const publicJwt = makeJwt({ role: "public", iss: "synthetic" });
  const firebaseJwt = makeJwt({
    iss: "https://securetoken.google.com/project",
  });
  const ordinaryJwt = makeJwt({ role: "member", iss: "synthetic" });
  const serviceJwt = makeJwt({ role: "service_role", iss: "synthetic" });
  for (const token of [anonymousJwt, publicJwt, firebaseJwt]) {
    const finding = resolve(token, [jwtRule])[0];
    assert.equal(finding.severity, "low");
    assert.equal(finding.note, "likely public client token");
  }
  assert.equal(resolve(ordinaryJwt, [jwtRule])[0].severity, "medium");
  assert.equal(resolve(serviceJwt, [jwtRule])[0].severity, "high");

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
  const newlySensitiveNames = [
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
    "login-code",
    "oauth.state",
    "reset_password",
  ];
  for (const [index, name] of newlySensitiveNames.entries()) {
    const url = privacyUtils.redactUrl(
      `https://example.test/?${encodeURIComponent(name)}=query-marker-${index}`,
    );
    assert.equal(
      new URL(url).searchParams.get(name),
      "[REDACTED]",
      `${name} query value should be redacted`,
    );
  }
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
  const markers = [
    "marker-url-701",
    "marker-cookie-702",
    "marker-cookie-header-703",
    "marker-auth-header-704",
    "marker-api-header-705",
    "marker-body-706",
    "marker-param-707",
    "marker-location-708",
    "marker-redirect-709",
    "marker-other-url-710",
    "marker-response-cookie-711",
    "marker-response-set-cookie-712",
    "marker-response-body-713",
    "marker-nested-url-714",
    "marker-location-code-715",
    "marker-location-state-716",
    "marker-redirect-code-717",
    "marker-redirect-state-718",
    "marker-query-code-719",
    "marker-query-state-720",
    "marker-json-nested-password-721",
  ];
  const markerEntry = {
    request: {
      method: "POST",
      url: `https://example.test/?token=${markers[0]}`,
      headers: [
        { name: "Cookie", value: `sid=${markers[2]}` },
        { name: "Authorization", value: markers[3] },
        { name: "X-API-Key", value: markers[4] },
      ],
      cookies: [{ name: "sid", value: markers[1] }],
      queryString: [
        { name: "code", value: markers[18] },
        { name: "state", value: markers[19] },
      ],
      postData: {
        mimeType: "application/json",
        text: JSON.stringify({
          password: markers[5],
          displayName: "safe-name-survives",
          profile: {
            passwd: markers[20],
            nickname: "safe-nickname-survives",
          },
        }),
        params: [{ name: "api_key", value: markers[6] }],
      },
    },
    response: {
      headers: [
        {
          name: "Location",
          value: `https://else.test/?code=${markers[14]}&state=${markers[15]}`,
        },
        { name: "Set-Cookie", value: `sid=${markers[11]}` },
      ],
      redirectURL: `https://else.test/?code=${markers[16]}&state=${markers[17]}`,
      cookies: [{ name: "sid", value: markers[10] }],
      content: { text: markers[12] },
      url: `https://else.test/?secret=${markers[9]}`,
    },
    metadata: { url: `https://metadata.test/?key=${markers[13]}` },
  };
  const markerHar = privacyUtils.redactHarEntry(markerEntry);
  const markerCurl = privacyUtils.buildCurlCommand(
    markerEntry.request,
    true,
  );
  for (const marker of markers) {
    assert.ok(
      !JSON.stringify(markerHar).includes(marker),
      `redacted HAR retained ${marker}`,
    );
    assert.ok(
      !markerCurl.includes(marker),
      `redacted cURL retained ${marker}`,
    );
  }
  const redactedBody = JSON.parse(markerHar.request.postData.text);
  assert.equal(redactedBody.password, "[REDACTED]");
  assert.equal(redactedBody.displayName, "safe-name-survives");
  assert.equal(redactedBody.profile.passwd, "[REDACTED]");
  assert.equal(redactedBody.profile.nickname, "safe-nickname-survives");
  assert.deepEqual(
    [...new URL(markerHar.response.headers[0].value).searchParams.values()],
    ["[REDACTED]", "[REDACTED]"],
  );
  assert.deepEqual(
    [...new URL(markerHar.response.redirectURL).searchParams.values()],
    ["[REDACTED]", "[REDACTED]"],
  );
  assert.equal(markerHar.request.postData.params[0].name, "api_key");
  assert.equal(markerHar.request.postData.params[0].value, "[REDACTED]");
  assert.deepEqual(
    Array.from(markerHar.request.queryString, (item) => item.value),
    ["[REDACTED]", "[REDACTED]"],
  );
  assert.ok(!markerCurl.includes("--data-raw"));
  assert.ok(!markerCurl.includes("Cookie:"));
  const redactedForm = privacyUtils.redactHarEntry({
    request: {
      postData: {
        mimeType: "application/x-www-form-urlencoded",
        text: "username=keep-this&state=form-secret",
      },
    },
  });
  assert.equal(
    new URLSearchParams(redactedForm.request.postData.text).get("username"),
    "keep-this",
  );
  assert.equal(
    new URLSearchParams(redactedForm.request.postData.text).get("state"),
    "[REDACTED]",
  );
  assert.equal(
    privacyUtils.redactHarEntry({
      request: {
        postData: { mimeType: "application/json", text: "{broken" },
      },
    }).request.postData.text,
    "[REDACTED]",
  );
  assert.equal(
    privacyUtils.redactHarEntry({
      request: { postData: { mimeType: "text/plain", text: "sensitive" } },
    }).request.postData.text,
    "[REDACTED]",
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
