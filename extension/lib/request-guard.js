// Per-tab, pre-request HTTP(S) enforcement using the CDP Fetch domain.

import { attachedTabIds, cdp, ensureAttached, ensureDomain } from "./cdp.js";
import { decideRequest, dnrRules, isAttachment, normalizePolicy } from "./guard-policy.js";

const PREFIX = "network-guard:";
const queues = new Map();

const key = (tabId) => `${PREFIX}${tabId}`;

async function load(tabId) {
  const result = await chrome.storage.session.get(key(tabId));
  return result[key(tabId)] || null;
}

async function save(tabId, policy) {
  await chrome.storage.session.set({ [key(tabId)]: policy });
}

async function clear(tabId) {
  const policy = await load(tabId);
  queues.delete(tabId);
  if (policy?.dnrRuleIds?.length) {
    try { await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: policy.dnrRuleIds }); } catch {}
  }
  await chrome.storage.session.remove(key(tabId));
}

async function installDnr(tabId, policy) {
  const rules = dnrRules(tabId, policy);
  const ids = rules.map((rule) => rule.id);
  await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: ids, addRules: rules });
  policy.dnrRuleIds = ids;
  policy.dnrBlockRuleId = ids[0];
  await save(tabId, policy);
}

async function lockdownDnr(policy) {
  const allowIds = (policy?.dnrRuleIds || []).filter((id) => id !== policy.dnrBlockRuleId);
  if (!allowIds.length) return;
  try { await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: allowIds }); } catch {}
}

async function hardenSession(tabId, sessionId) {
  await cdp(tabId, "Network.enable", {}, sessionId);
  await cdp(tabId, "Network.setBypassServiceWorker", { bypass: true }, sessionId);
  await cdp(
    tabId,
    "Fetch.enable",
    {
      handleAuthRequests: true,
      patterns: [
        { urlPattern: "http://*/*", requestStage: "Request" },
        { urlPattern: "https://*/*", requestStage: "Request" },
      ],
    },
    sessionId
  );
  await cdp(
    tabId,
    "Target.setAutoAttach",
    { autoAttach: true, flatten: true, waitForDebuggerOnStart: true },
    sessionId
  );
  // Defense in depth for channels outside ordinary HTTP fetches. The CDP Fetch
  // gate remains authoritative for network traffic.
  try {
    await cdp(
      tabId,
      "Page.addScriptToEvaluateOnNewDocument",
      {
        source: `(() => {
          const deny = () => { throw new DOMException('Blocked by owned-lab network guard', 'SecurityError'); };
          for (const name of ['RTCPeerConnection','webkitRTCPeerConnection','WebTransport']) {
            try { Object.defineProperty(globalThis, name, { value: deny, configurable: false, writable: false }); } catch {}
          }
          try { Object.defineProperty(globalThis, 'open', { value: deny, configurable: false, writable: false }); } catch {}
          try { if (navigator.sendBeacon) Object.defineProperty(navigator, 'sendBeacon', { value: () => false, configurable: false }); } catch {}
        })();`,
      },
      sessionId
    );
  } catch {}
  try {
    await cdp(tabId, "Page.setDownloadBehavior", { behavior: "deny" }, sessionId);
  } catch {}
}

export async function configure(tabId, rawPolicy) {
  const tab = await chrome.tabs.get(tabId);
  if (!tab || tab.url !== "about:blank") {
    throw new Error("network guard can only be installed on a new about:blank tab");
  }
  if (await load(tabId)) throw new Error("network guard is immutable after installation");
  const policy = normalizePolicy(rawPolicy);
  await save(tabId, policy);
  try {
    await installDnr(tabId, policy);
    await ensureAttached(tabId);
    await ensureDomain(tabId, "Network");
    await ensureDomain(tabId, "Page");
    await hardenSession(tabId);
  } catch (error) {
    await clear(tabId);
    try { await chrome.tabs.remove(tabId); } catch {}
    throw error;
  }
  return publicStatus(policy, true);
}

function publicStatus(policy, attached = false) {
  if (!policy) return { configured: false, attached: false };
  return {
    configured: true,
    attached,
    dnrEnforced: !!policy.dnrBlockRuleId,
    version: policy.version,
    guardId: policy.guardId,
    expiresAt: policy.expiresAt,
    allowedOrigins: policy.allowedOrigins,
    allowedMethods: policy.allowedMethods,
    maxRequests: policy.maxRequests,
    requestsUsed: policy.requestsUsed,
    blockedRequests: policy.blockedRequests,
    lastBlockCode: policy.lastBlockCode,
    scopeSha256: policy.scopeSha256,
    egressPolicySha256: policy.egressPolicySha256,
  };
}

export async function status(tabId) {
  const policy = await load(tabId);
  if (!policy) return publicStatus(null, false);
  let dnrEnforced = false;
  try {
    const rules = await chrome.declarativeNetRequest.getSessionRules();
    const live = new Set(rules.map((rule) => rule.id));
    dnrEnforced = policy.dnrRuleIds.every((id) => live.has(id));
  } catch {}
  const result = publicStatus(policy, attachedTabIds().includes(tabId));
  result.dnrEnforced = dnrEnforced;
  return result;
}

export async function isGuardedTab(tabId) {
  return !!(await load(tabId));
}

async function block(tabId, sessionId, requestId, policy, code) {
  if (policy) {
    policy.blockedRequests += 1;
    policy.lastBlockCode = code;
    await save(tabId, policy);
  }
  try {
    await cdp(tabId, "Fetch.failRequest", { requestId, errorReason: "BlockedByClient" }, sessionId);
  } catch {}
}

async function handlePaused(tabId, sessionId, params) {
  const policy = await load(tabId);
  if (!policy) return block(tabId, sessionId, params.requestId, null, "GUARD_MISSING");
  if (params.responseStatusCode || params.responseErrorReason) {
    if (isAttachment(params.responseHeaders)) {
      return block(tabId, sessionId, params.requestId, policy, "GUARD_DOWNLOAD_DENIED");
    }
    try {
      await cdp(tabId, "Fetch.continueRequest", { requestId: params.requestId }, sessionId);
    } catch {
      await block(tabId, sessionId, params.requestId, policy, "GUARD_CONTINUE_FAILED");
    }
    return;
  }
  const decision = decideRequest(policy, params.request);
  if (!decision.allow) return block(tabId, sessionId, params.requestId, policy, decision.code);
  policy.requestsUsed += 1;
  await save(tabId, policy);
  try {
    await cdp(
      tabId,
      "Fetch.continueRequest",
      { requestId: params.requestId, interceptResponse: true },
      sessionId
    );
  } catch {
    await block(tabId, sessionId, params.requestId, policy, "GUARD_CONTINUE_FAILED");
  }
}

function serialize(tabId, task) {
  const previous = queues.get(tabId) || Promise.resolve();
  const next = previous.then(task, task).finally(() => {
    if (queues.get(tabId) === next) queues.delete(tabId);
  });
  queues.set(tabId, next);
  return next;
}

export async function onCdpEvent(tabId, method, params, sessionId) {
  if (method === "Fetch.requestPaused") {
    return serialize(tabId, () => handlePaused(tabId, sessionId, params));
  }
  if (method === "Fetch.authRequired") {
    return serialize(tabId, async () => {
      const policy = await load(tabId);
      if (policy) {
        policy.blockedRequests += 1;
        policy.lastBlockCode = "GUARD_AUTH_CHALLENGE_DENIED";
        await save(tabId, policy);
      }
      try {
        await cdp(
          tabId,
          "Fetch.continueWithAuth",
          { requestId: params.requestId, authChallengeResponse: { response: "CancelAuth" } },
          sessionId
        );
      } catch {}
    });
  }
  if (method === "Target.attachedToTarget" && params?.sessionId && await load(tabId)) {
    return serialize(tabId, async () => {
      try {
        await hardenSession(tabId, params.sessionId);
        await cdp(tabId, "Runtime.runIfWaitingForDebugger", {}, params.sessionId);
      } catch {
        // A child target that cannot inherit the guard must never resume.
        await clear(tabId);
        try { await chrome.tabs.remove(tabId); } catch {}
      }
    });
  }
}

export async function onTabCreated(tab) {
  if (tab?.openerTabId == null || !(await load(tab.openerTabId))) return;
  try { await chrome.tabs.remove(tab.id); } catch {}
}

export async function onTabRemoved(tabId) {
  await clear(tabId);
}

export async function onDebuggerDetach(tabId) {
  const policy = await load(tabId);
  if (!policy) return;
  // Remove allow rules first but retain block-all until the tab is gone.
  await lockdownDnr(policy);
  try { await chrome.tabs.remove(tabId); } catch {}
}
