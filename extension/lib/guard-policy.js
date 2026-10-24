// Pure validation/decision helpers for the fail-closed per-tab network guard.
// Kept free of chrome.* dependencies so the contract can be regression-tested
// with Node's built-in test runner.

const GUARD_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{15,127}$/;
const SHA256 = /^[0-9a-f]{64}$/;
const ALLOWED_METHODS = new Set(["GET", "HEAD", "OPTIONS", "POST"]);

function isIpv4(value) {
  const parts = String(value).split(".");
  return parts.length === 4 && parts.every((part) => {
    if (!/^\d{1,3}$/.test(part)) return false;
    if (part.length > 1 && part.startsWith("0")) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

export function isIpLiteral(value) {
  const host = String(value || "").replace(/^\[|\]$/g, "");
  if (isIpv4(host)) return true;
  if (!host.includes(":") || !/^[0-9a-f:.]+$/i.test(host)) return false;
  try {
    return new URL(`http://[${host}]/`).hostname.length > 0;
  } catch {
    return false;
  }
}

export function normalizeOrigin(value) {
  let parsed;
  try {
    parsed = new URL(String(value || ""));
  } catch {
    throw new Error("guard origin is not a valid URL");
  }
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("guard origins are limited to HTTP(S)");
  }
  if (parsed.username || parsed.password || !isIpLiteral(parsed.hostname)) {
    throw new Error("guard origins require an IP-literal host without userinfo");
  }
  if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
    throw new Error("guard allowlist entries must be exact origins");
  }
  return parsed.origin;
}

export function normalizePolicy(raw, now = Date.now()) {
  const guardId = String(raw?.guardId || "");
  if (!GUARD_ID.test(guardId)) throw new Error("invalid guard id");
  const expiresAt = Number(raw?.expiresAt);
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= now || expiresAt > now + 3_600_000) {
    throw new Error("guard expiry must be within the next hour");
  }
  if (!Array.isArray(raw?.allowedOrigins) || raw.allowedOrigins.length < 1 || raw.allowedOrigins.length > 16) {
    throw new Error("guard requires between 1 and 16 exact origins");
  }
  const allowedOrigins = [...new Set(raw.allowedOrigins.map(normalizeOrigin))].sort();
  if (!Array.isArray(raw?.allowedMethods) || raw.allowedMethods.length < 1) {
    throw new Error("guard requires an HTTP method allowlist");
  }
  const allowedMethods = [...new Set(raw.allowedMethods.map((value) => String(value).toUpperCase()))].sort();
  if (allowedMethods.some((method) => !ALLOWED_METHODS.has(method))) {
    throw new Error("guard method is outside the bounded owned-lab set");
  }
  const maxRequests = Number(raw?.maxRequests);
  if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > 1000) {
    throw new Error("guard request budget must be between 1 and 1000");
  }
  const scopeSha256 = String(raw?.scopeSha256 || "");
  const egressPolicySha256 = String(raw?.egressPolicySha256 || "");
  if (!SHA256.test(scopeSha256) || !SHA256.test(egressPolicySha256)) {
    throw new Error("guard scope and egress bindings must be SHA-256 digests");
  }
  return {
    version: 1,
    guardId,
    expiresAt,
    allowedOrigins,
    allowedMethods,
    maxRequests,
    scopeSha256,
    egressPolicySha256,
    requestsUsed: 0,
    blockedRequests: 0,
    lastBlockCode: null,
    configuredAt: now,
  };
}

export function decideRequest(policy, request, now = Date.now()) {
  if (!policy || policy.version !== 1) return { allow: false, code: "GUARD_MISSING" };
  if (now >= policy.expiresAt) return { allow: false, code: "GUARD_EXPIRED" };
  if (policy.requestsUsed >= policy.maxRequests) return { allow: false, code: "GUARD_BUDGET_EXHAUSTED" };
  let parsed;
  try {
    parsed = new URL(String(request?.url || ""));
  } catch {
    return { allow: false, code: "GUARD_URL_INVALID" };
  }
  if (!["http:", "https:"].includes(parsed.protocol) || parsed.username || parsed.password) {
    return { allow: false, code: "GUARD_SCHEME_DENIED" };
  }
  if (!policy.allowedOrigins.includes(parsed.origin)) {
    return { allow: false, code: "GUARD_ORIGIN_DENIED" };
  }
  const method = String(request?.method || "GET").toUpperCase();
  if (!policy.allowedMethods.includes(method)) {
    return { allow: false, code: "GUARD_METHOD_DENIED" };
  }
  return { allow: true, code: "GUARD_ALLOW" };
}

export function isAttachment(headers) {
  return (headers || []).some((header) =>
    String(header?.name || "").toLowerCase() === "content-disposition" &&
    /^\s*attachment(?:;|$)/i.test(String(header?.value || ""))
  );
}

const DNR_RESOURCE_TYPES = [
  "main_frame", "sub_frame", "stylesheet", "script", "image", "font", "object",
  "xmlhttprequest", "ping", "csp_report", "media", "websocket", "other",
];

function regexEscape(value) {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function dnrRules(tabId, policy) {
  const id = Number(tabId);
  if (!Number.isSafeInteger(id) || id < 1 || id > 100_000_000) {
    throw new Error("tab id is outside the guarded DNR range");
  }
  const base = id * 20;
  const block = {
    id: base + 1,
    priority: 1,
    action: { type: "block" },
    condition: {
      regexFilter: "^https?://",
      tabIds: [id],
      resourceTypes: DNR_RESOURCE_TYPES,
    },
  };
  const allow = policy.allowedOrigins.map((origin, index) => {
    const parsed = new URL(origin);
    const defaultPort = parsed.protocol === "https:" ? "443" : "80";
    const authority = regexEscape(parsed.host);
    const optionalDefault = parsed.port ? "" : `(?::${defaultPort})?`;
    return {
      id: base + 2 + index,
      priority: 2,
      action: { type: "allow" },
      condition: {
        regexFilter: `^${regexEscape(parsed.protocol)}//${authority}${optionalDefault}(?:/|$)`,
        requestMethods: policy.allowedMethods.map((method) => method.toLowerCase()),
        tabIds: [id],
        resourceTypes: DNR_RESOURCE_TYPES,
      },
    };
  });
  return [block, ...allow];
}
