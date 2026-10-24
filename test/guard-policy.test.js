import test from "node:test";
import assert from "node:assert/strict";

import {
  decideRequest,
  dnrRules,
  isAttachment,
  isIpLiteral,
  normalizeOrigin,
  normalizePolicy,
} from "../extension/lib/guard-policy.js";

const NOW = 2_000_000_000_000;
const DIGEST = "a".repeat(64);

function policy(overrides = {}) {
  return normalizePolicy({
    guardId: "guard-0123456789abcdef",
    expiresAt: NOW + 60_000,
    allowedOrigins: ["http://10.77.0.20:8080"],
    allowedMethods: ["GET", "POST"],
    maxRequests: 10,
    scopeSha256: DIGEST,
    egressPolicySha256: DIGEST,
    ...overrides,
  }, NOW);
}

test("only exact IP-literal HTTP origins are accepted", () => {
  assert.equal(normalizeOrigin("http://10.77.0.20:8080"), "http://10.77.0.20:8080");
  assert.equal(normalizeOrigin("https://[2001:db8::7]"), "https://[2001:db8::7]");
  assert.equal(isIpLiteral("10.77.0.20"), true);
  assert.equal(isIpLiteral("target.example"), false);
  assert.throws(() => normalizeOrigin("https://target.example"), /IP-literal/);
  assert.throws(() => normalizeOrigin("http://10.77.0.20/path"), /exact origins/);
});

test("policy is bounded and rejects dangerous methods", () => {
  assert.throws(() => policy({ allowedMethods: ["DELETE"] }), /bounded/);
  assert.throws(() => policy({ maxRequests: 1001 }), /between 1 and 1000/);
  assert.throws(() => policy({ expiresAt: NOW + 3_600_001 }), /within the next hour/);
});

test("request decision enforces origin method expiry and durable budget state", () => {
  const value = policy();
  assert.deepEqual(
    decideRequest(value, { url: "http://10.77.0.20:8080/path?q=1", method: "POST" }, NOW),
    { allow: true, code: "GUARD_ALLOW" }
  );
  assert.equal(decideRequest(value, { url: "http://10.77.0.21:8080/", method: "GET" }, NOW).code, "GUARD_ORIGIN_DENIED");
  assert.equal(decideRequest(value, { url: "http://10.77.0.20:8080/", method: "PUT" }, NOW).code, "GUARD_METHOD_DENIED");
  assert.equal(decideRequest(value, { url: "http://10.77.0.20:8080/", method: "GET" }, value.expiresAt).code, "GUARD_EXPIRED");
  value.requestsUsed = value.maxRequests;
  assert.equal(decideRequest(value, { url: "http://10.77.0.20:8080/", method: "GET" }, NOW).code, "GUARD_BUDGET_EXHAUSTED");
});

test("attachment responses are identified without exposing header values", () => {
  assert.equal(isAttachment([{ name: "Content-Disposition", value: "attachment; filename=x" }]), true);
  assert.equal(isAttachment([{ name: "content-type", value: "text/html" }]), false);
});

test("DNR defense in depth blocks all HTTP then allows only exact guarded origins and methods", () => {
  const rules = dnrRules(42, policy());
  assert.equal(rules[0].action.type, "block");
  assert.equal(rules[0].condition.regexFilter, "^https?://");
  assert.deepEqual(rules[0].condition.tabIds, [42]);
  assert.equal(rules[1].action.type, "allow");
  assert.match("http://10.77.0.20:8080/path", new RegExp(rules[1].condition.regexFilter));
  assert.doesNotMatch("http://10.77.0.201:8080/path", new RegExp(rules[1].condition.regexFilter));
  assert.deepEqual(rules[1].condition.requestMethods, ["get", "post"]);
});
