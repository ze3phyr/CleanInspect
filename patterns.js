// Edit these expressions to customize local secret scanning. Keep each regex global.
// Findings are heuristics: validate every match before treating it as a real secret.
window.CLEANINSPECT_PATTERNS = [
  { name: 'JWT', regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { name: 'API key / token assignment', regex: /\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|token|secret)\b\s*[:=]\s*["']([A-Za-z0-9_./+=-]{12,})["']/gi, capture: 1 },
  { name: 'Bearer token', regex: /\bBearer\s+([A-Za-z0-9_./+=-]{12,})/gi, capture: 1 },
  { name: 'AWS access key', regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'Private key header', regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'Internal hostname', regex: /\b(?:[\w-]+\.)*(?:internal|intranet|corp|localhost)(?::\d+)?\b/gi }
];
