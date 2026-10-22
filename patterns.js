/*
 * CleanInspect secret patterns, v2.
 *
 * Contract with panel.js (unchanged): window.CLEANINSPECT_PATTERNS is an array of
 *   { name, regex /…/g, capture? }
 * and the scanner reports `capture ? match[capture] : match[0]`.
 *
 * Extra fields (used once panel.js applies the small patch that calls validate()):
 *   validate(value, match) -> boolean   drop false positives (entropy, placeholders, decoding)
 *   severity: 'high' | 'medium' | 'low' | 'info'
 *   note: short triage hint
 *
 * Rules of the road for editing this file:
 *   1. Every regex must be global (g flag).
 *   2. Every quantifier must be BOUNDED ({1,64}, never + or * on a character class that can
 *      repeat across a whole bundle). Pages are untrusted input; an unbounded quantifier can
 *      turn a crafted or merely huge script into a frozen DevTools panel (ReDoS).
 *   3. Prefer a distinctive literal prefix (AKIA, ghp_, xoxb-, ...) over generic shapes.
 *   4. Everything here is a heuristic. Confirm a hit by reading the context before you report it.
 */
(function () {
  'use strict';

  // ---------- helpers ----------

  const PLACEHOLDER = new RegExp(
    '^(?:x{4,}|\\*{4,}|0{6,}|<.*>|\\$\\{.*\\}|\\{\\{.*\\}\\}|%\\w+%|your[_-]?|changeme|change[_-]me|' +
    'replace[_-]?me|placeholder|insert[_-]|dummy|sample|todo|redacted|null$|undefined$|' +
    'process\\.env|password$|passwd$|secret$|token$|apikey$|api[_-]key$)|example(?:key)?$',
    'i'
  );

  function entropy(s) {
    const f = Object.create(null);
    for (const c of s) f[c] = (f[c] || 0) + 1;
    let h = 0;
    for (const k in f) { const p = f[k] / s.length; h -= p * Math.log2(p); }
    return h;
  }

  // 8+ characters in a row that step by exactly one code point (abcdefgh, 12345678).
  function sequential(s) {
    let run = 1;
    for (let i = 1; i < s.length; i++) {
      run = s.charCodeAt(i) - s.charCodeAt(i - 1) === 1 ? run + 1 : 1;
      if (run >= 8) return true;
    }
    return false;
  }

  function looksFake(v) {
    return PLACEHOLDER.test(v) || /^(.)\1+$/.test(v) || sequential(v);
  }

  function b64urlJson(part) {
    try {
      let s = part.replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      const j = JSON.parse(atob(s));
      return j && typeof j === 'object' ? j : null;
    } catch (e) { return null; }
  }

  function jwtParts(v) {
    const p = v.split('.');
    return { header: b64urlJson(p[0]), payload: b64urlJson(p[1]) };
  }

  const RULES = [];
  function add(label, severity, regex, opts) {
    RULES.push(Object.assign({ label, severity, regex }, opts || {}));
  }

  const NOT_SECRET_KEY = /csrf|xsrf|nonce|captcha|site[_-]?key|public|publishable|pubkey|session[_-]?id/i;

  // ---------- HIGH: credentials that are secret by design ----------

  add('AWS access key ID', 'high', /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/g,
    { validate: v => !looksFake(v), note: 'ASIA = temporary STS key. Look for the matching secret key nearby.' });

  add('AWS secret access key', 'high',
    /\b(?:aws[_-]?secret[_-]?access[_-]?key|aws[_-]?secret[_-]?key|secret[_-]?access[_-]?key)["']?\s{0,3}[:=]\s{0,3}["']([A-Za-z0-9\/+=]{40})["']/gi,
    { capture: 1, validate: v => !looksFake(v) && entropy(v) >= 3.5 });

  add('Private key (PEM block with body)', 'high',
    /(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----)(?=(?:\\n|\\r|\s|[A-Za-z0-9+\/=:,.-]){60,6000}?-----END)/g,
    { capture: 1, note: 'Requires real key material after the header, so crypto libraries that only embed the header string are skipped.' });

  add('GitHub token', 'high',
    /\b(?:gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})(?![A-Za-z0-9_])/g);

  add('GitLab personal access token', 'high', /\bglpat-[A-Za-z0-9_-]{20}(?![A-Za-z0-9_-])/g);

  add('Slack token', 'high', /\bxox[abposr]-[A-Za-z0-9-]{10,72}(?![A-Za-z0-9-])/g);

  add('Slack webhook URL', 'high',
    /https:\/\/hooks\.slack\.com\/(?:services|workflows|triggers)\/[A-Za-z0-9\/_-]{16,120}/g,
    { note: 'Anyone with this URL can post into the channel.' });

  add('Discord webhook URL', 'high',
    /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,80}/g);

  add('Stripe live secret / restricted key', 'high', /\b[sr]k_live_[0-9A-Za-z]{24,99}\b/g);

  add('SendGrid API key', 'high', /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])/g);

  add('Google OAuth client secret', 'high', /\bGOCSPX-[A-Za-z0-9_-]{28}(?![A-Za-z0-9_-])/g);

  add('Firebase Cloud Messaging server key (legacy)', 'high',
    /\bAAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}(?![A-Za-z0-9_-])/g);

  add('npm access token', 'high', /\bnpm_[A-Za-z0-9]{36}\b/g);

  add('PyPI upload token', 'high', /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,200}(?![A-Za-z0-9_-])/g);

  add('Shopify access token', 'high', /\bshp(?:at|ca|pa|ss)_[a-f0-9]{32}\b/g);

  add('Square access token', 'high', /\bsq0(?:atp|csp)-[A-Za-z0-9_-]{22,43}(?![A-Za-z0-9_-])/g);

  add('DigitalOcean token', 'high', /\bdop_v1_[a-f0-9]{64}\b/g);

  add('Hugging Face token', 'high', /\bhf_[A-Za-z0-9]{34}\b/g);

  add('OpenAI API key', 'high',
    /\b(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,200}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})(?![A-Za-z0-9_-])/g);

  add('Anthropic API key', 'high', /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,120}(?![A-Za-z0-9_-])/g);

  add('Mapbox secret token', 'high',
    /\bsk\.eyJ[A-Za-z0-9_-]{20,500}\.[A-Za-z0-9_-]{20,100}(?![A-Za-z0-9_-])/g);

  add('Braintree / PayPal production token', 'high',
    /\baccess_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}\b/g);

  add('Cloudinary URL with API secret', 'high',
    /\bcloudinary:\/\/\d{8,20}:([A-Za-z0-9_-]{20,40})@[a-z0-9_-]{2,40}/gi,
    { capture: 1, validate: v => !looksFake(v) });

  add('Azure storage connection string (AccountKey)', 'high',
    /DefaultEndpointsProtocol=https?;[^"'\s]{0,200}?AccountKey=([A-Za-z0-9+\/=]{60,100})/gi,
    { capture: 1, validate: v => !looksFake(v) });

  add('Azure SAS token signature', 'medium',
    /[?&]sv=\d{4}-\d{2}-\d{2}&[^"'\s<>]{0,400}?\bsig=([A-Za-z0-9%+\/=]{30,100})/g,
    { capture: 1, note: 'Check the se= (expiry) and sp= (permissions) fields in the surrounding URL.' });

  add('Database / broker URL with password', 'high',
    /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql|sqlserver):\/\/[^\s"'`<>:@\/]{1,64}:([^\s"'`<>@\/]{3,100})@[^\s"'`<>\/]{3,200}/gi,
    { capture: 1, validate: v => !looksFake(v) && !/^(?:pass(?:word)?|pwd|user)$/i.test(v) });

  add('Supabase service_role JWT', 'high',
    /\beyJ[A-Za-z0-9_-]{10,100}\.eyJ[A-Za-z0-9_-]{10,2000}\.[A-Za-z0-9_-]{10,1000}(?![A-Za-z0-9_-])/g,
    { validate: v => { const p = jwtParts(v); return !!(p.header && p.payload && p.payload.role === 'service_role'); },
      note: 'service_role bypasses Row Level Security. Distinct from the public anon key.' });

  // ---------- MEDIUM: credentials whose impact depends on context ----------

  add('JWT', 'medium',
    /\beyJ[A-Za-z0-9_-]{10,100}\.eyJ[A-Za-z0-9_-]{10,2000}\.[A-Za-z0-9_-]{10,1000}(?![A-Za-z0-9_-])/g,
    { validate: v => { const p = jwtParts(v); return !!(p.header && p.payload); },
      note: 'Decode it: check exp, role/scope, sub. Anon/public-role JWTs are usually intentional.' });

  add('Bearer token (literal)', 'medium', /\bBearer\s{1,5}([A-Za-z0-9_.~+\/-]{20,512}={0,2})/gi,
    { capture: 1, validate: v => !looksFake(v) && entropy(v) >= 3.2 });

  add('Basic auth header (decodes to user:pass)', 'medium',
    /\bBasic\s{1,5}([A-Za-z0-9+\/]{16,512}={0,2})(?![A-Za-z0-9+\/=])/g,
    { capture: 1,
      validate: v => { try { const d = atob(v); return d.length >= 5 && d.indexOf(':') > 0 && /^[\x20-\x7e]+$/.test(d); } catch (e) { return false; } } });

  add('Credentials in URL (user:pass@host)', 'medium',
    /\bhttps?:\/\/[A-Za-z0-9._~%!$&'()*+,;=-]{1,64}:([A-Za-z0-9._~%!$&'()*+,;=-]{3,64})@[A-Za-z0-9.-]{3,100}/gi,
    { capture: 1, validate: v => !looksFake(v) && !/^\d+$/.test(v) });

  add('Generic secret assignment (key-name + high-entropy value)', 'medium',
    /\b([A-Za-z0-9_.-]{0,30}(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|app[_-]?secret|access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?key|secret|token)[A-Za-z0-9_.-]{0,30})["']?\s{0,3}[:=]\s{0,3}["'`]([A-Za-z0-9_\/+=.~-]{16,200})["'`]/gi,
    { capture: 2,
      validate: (v, m) =>
        !NOT_SECRET_KEY.test(m[1]) && !looksFake(v) && entropy(v) >= 3.3 &&
        !/\/\//.test(v) && v[0] !== '/' &&
        !/^[a-z]+(?:[A-Z][a-z]+){2,}$/.test(v) &&          // camelCase identifier
        !/^[A-Za-z]+(?:[_.-][A-Za-z]+){1,}$/.test(v) &&    // word-word-word label
        !/^[A-Z_]+$/.test(v),
      note: 'Rename-proof catch-all. Expect some noise; read the context.' });

  add('Hardcoded password', 'low',
    /\b(?:password|passwd|pwd)["']?\s{0,3}[:=]\s{0,3}["']([^"'\s\\]{8,64})["']/gi,
    { capture: 1,
      validate: v => !looksFake(v) && !/^[A-Za-z]+$/.test(v) && entropy(v) >= 2.5,
      note: 'Pure-letter values are skipped (i18n labels like password:"Password").' });

  add('Facebook / Meta access token', 'medium', /\bEAA[A-Za-z0-9]{50,300}(?![A-Za-z0-9])/g,
    { validate: v => entropy(v) >= 4.0 });

  add('Telegram bot token', 'medium', /\b\d{8,10}:AA[A-Za-z0-9_-]{33}(?![A-Za-z0-9_-])/g);

  add('Mailgun API key', 'medium', /\bkey-[0-9a-f]{32}\b/g, { validate: v => !looksFake(v) });

  add('Twilio API key SID', 'medium', /\bSK[0-9a-f]{32}\b/g, { validate: v => !looksFake(v) });

  add('Stripe test secret key', 'low', /\b[sr]k_test_[0-9A-Za-z]{24,99}\b/g,
    { note: 'Test mode only, but shows the integration and key hygiene.' });

  // ---------- LOW / INFO: public by design, but worth a look ----------

  add('Google API key (public by design, check restrictions)', 'low',
    /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g,
    { note: 'Often a restricted browser key (Maps, Firebase). Only reportable if it works for unrestricted/expensive APIs, and only test within program rules.' });

  add('Stripe publishable key (public)', 'info', /\bpk_live_[0-9A-Za-z]{24,99}\b/g);

  add('Mapbox public token (public)', 'info',
    /\bpk\.eyJ[A-Za-z0-9_-]{20,500}\.[A-Za-z0-9_-]{20,100}(?![A-Za-z0-9_-])/g);

  add('Sentry DSN (public)', 'info',
    /\bhttps:\/\/[0-9a-f]{32}(?::[0-9a-f]{32})?@[a-z0-9.-]{3,100}\/\d{1,12}\b/g);

  // ---------- INFO: recon (assets and internal endpoints) ----------

  add('AWS S3 bucket reference', 'info',
    /\b(?:[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:[.-](?:[a-z]{2}-[a-z]+-\d|external-1|accelerate|dualstack))?\.amazonaws\.com|s3(?:[.-][a-z0-9-]{2,30})?\.amazonaws\.com\/[a-z0-9][a-z0-9.-]{2,62})\b/g,
    { note: 'Check listing/write permissions and subdomain-takeover only within program scope.' });

  add('Google Cloud Storage bucket reference', 'info',
    /\b(?:storage\.googleapis\.com\/[a-z0-9][a-z0-9._-]{2,62}|[a-z0-9][a-z0-9._-]{2,62}\.storage\.googleapis\.com)(?![a-z0-9._-])/g);

  add('Azure Blob storage account', 'info', /\b[a-z0-9]{3,24}\.blob\.core\.windows\.net\b/g);

  add('Firebase Realtime Database URL', 'info',
    /\b[a-z0-9-]{3,60}\.(?:firebaseio\.com|firebasedatabase\.app)\b/g,
    { note: 'Misconfigured rules can expose data; only probe within program scope.' });

  add('Internal-looking URL (private TLD)', 'info',
    /\b(?:https?|wss?):\/\/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.){1,6}(?:internal|intranet|corp|lan|local|localdomain|home\.arpa)(?::\d{2,5})?(?:\/[^\s"'<>`\\]{0,200})?/gi,
    { note: 'Scheme is required on purpose, so property chains like this.internal are not flagged.' });

  add('Localhost / private-network URL', 'info',
    /\b(?:https?|wss?):\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0|10(?:\.\d{1,3}){3}|192\.168(?:\.\d{1,3}){2}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2})(?::\d{2,5})?(?:\/[^\s"'<>`\\]{0,200})?/gi,
    { note: 'Dev leftovers; sometimes SSRF/DNS-rebinding leads.' });

  // ---------- export ----------

  const TAG = { high: 'HIGH', medium: 'MED', low: 'LOW', info: 'INFO' };
  window.CLEANINSPECT_RULES = RULES;
  window.CLEANINSPECT_PATTERNS = RULES.map(r => ({
    name: TAG[r.severity] + ' · ' + r.label,   // severity shows even without the panel.js patch
    regex: r.regex,
    capture: r.capture,
    validate: r.validate,
    severity: r.severity,
    note: r.note
  }));
})();
