"use strict";
importScripts(
  "core.js",
  "safebrowsing.js",
  "vulnerability-scanner.js",
  "email-security.js",
  "directory-checker.js",
  "security-headers.js",
  "ssl-checker.js",
  "page-checks.js",
);
const C = ScannerCore;
const running = new Map();
let defaults, config;
// Storage mutations are serialized so scans from different tabs cannot lose history.
let writes = Promise.resolve(),
  commands = Promise.resolve();
function write(fn) {
  const operation = writes.then(fn);
  writes = operation.catch(() => {});
  return operation;
}
const configReady = (async () => {
  defaults = await (await fetch(chrome.runtime.getURL("config.json"))).json();
  const saved = await chrome.storage.local.get("securityScannerConfig");
  config = C.normalizeConfig(defaults, saved.securityScannerConfig);
  await chrome.storage.local.set({ securityScannerConfig: config });
})();
chrome.runtime.onInstalled.addListener(() => {
  configReady.catch(console.error);
});
async function fingerprint(value) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return Array.from(new Uint8Array(bytes), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("");
}
async function tabForScan(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0)
    throw new Error("Open this extension on the website you want to scan.");
  const tab = await chrome.tabs.get(tabId);
  C.sanitizeUrl(tab.url);
  const url = new URL(tab.url);
  if (["chromewebstore.google.com", "chrome.google.com"].includes(url.hostname))
    throw new Error(
      "Chrome does not allow scanning the Web Store. Open a regular website.",
    );
  return tab;
}
async function persistJob(job) {
  const snapshot = structuredClone(job);
  await write(async () => {
    const { scanJobs = {} } = await chrome.storage.session.get("scanJobs");
    scanJobs[job.tabId] = snapshot;
    await chrome.storage.session.set({ scanJobs });
  });
}
async function badge(tabId, report) {
  try {
    const enabled = config.settings.showBadge && report?.overallScore !== null;
    const text = enabled && report ? String(report.overallScore) : "";
    await chrome.action.setBadgeText({ tabId, text });
    if (text)
      await chrome.action.setBadgeBackgroundColor({
        tabId,
        color:
          Object.values(report.checks).some(
            (check) => check.status === "failed",
          ) ||
          report.threatDetected ||
          report.overallScore < 50
            ? "#b12c3e"
            : report.coverage < 75 || report.overallScore < 80
              ? "#895600"
              : "#14664e",
      });
    await chrome.action.setTitle({
      tabId,
      title: text
        ? `Website Security Scanner: ${text}/100, ${report.coverage}% coverage. Limited assessment.`
        : "Website Security Scanner",
    });
  } catch {
    /* A tab can close while its scan completes. */
  }
}
async function stopScan(tabId, reason = "Scan cancelled.") {
  const run = running.get(tabId);
  if (!run) return;
  run.reason = reason;
  run.controller.abort();
  // Await completion before starting another scan or deleting its data.
  await run.done;
}
async function startScan(tabId, force = false) {
  await configReady;
  const tab = await tabForScan(tabId);
  if (running.has(tabId))
    return { job: structuredClone(running.get(tabId).job) };
  const pageKey = await fingerprint(tab.url);
  const profile = await fingerprint(JSON.stringify(config));
  const cacheKey = pageKey + ":" + profile;
  const { scanCache = {} } = await chrome.storage.session.get("scanCache");
  const cached = scanCache[cacheKey];
  if (
    !force &&
    config.settings.cacheMinutes > 0 &&
    cached &&
    Date.now() - Date.parse(cached.timestamp) <
      config.settings.cacheMinutes * 60000
  ) {
    const job = {
      tabId,
      id: crypto.randomUUID(),
      status: "complete",
      cached: true,
      completed: 9,
      total: 9,
      report: cached,
      startedAt: Date.now(),
    };
    await persistJob(job);
    await badge(tabId, cached);
    return { job };
  }
  const job = {
    tabId,
    id: crypto.randomUUID(),
    status: "running",
    cached: false,
    completed: 0,
    total: 9,
    startedAt: Date.now(),
    checks: {},
  };
  const run = { controller: new AbortController(), job, reason: null };
  running.set(tabId, run);
  try {
    await persistJob(job);
  } catch (error) {
    running.delete(tabId);
    throw error;
  }
  run.done = executeScan(
    run,
    tab,
    structuredClone(config),
    pageKey,
    profile,
    cacheKey,
  );
  return { job: structuredClone(job) };
}
async function executeScan(
  run,
  tab,
  settingsConfig,
  pageKey,
  profile,
  cacheKey,
) {
  const { job, controller } = run;
  const { signal } = controller;
  const { settings, apiKeys } = settingsConfig;
  const url = new URL(tab.url),
    externalAllowed = settings.externalServices && C.isPublicHost(url.hostname);
  const timeout = setTimeout(() => {
    run.reason =
      "Scan timed out after 60 seconds. Completed checks are shown; try again.";
    controller.abort();
  }, 60000);
  let heartbeat;
  try {
    // Short, bounded jobs call an extension API periodically to survive the worker idle timeout.
    heartbeat = setInterval(() => {
      chrome.storage.session.get("scanJobs").catch(() => {});
    }, 15000);
    const pagePromise =
      settings.checks.mixedContent || settings.checks.forms
        ? C.withAbort(
            chrome.scripting.executeScript({
              target: { tabId: tab.id },
              func: inspectPage,
              args: [tab.url],
              injectImmediately: true,
            }),
            signal,
          ).then((results) => {
            if (!results[0]?.result)
              throw new Error("The page could not be inspected.");
            return pageResults(results[0].result);
          })
        : Promise.resolve({});
    // Attach a rejection handler immediately; both page checks consume the same inspection.
    pagePromise.catch(() => {});
    const tasks = {
      https: async () =>
        C.result(
          url.protocol === "https:" ? "passed" : "failed",
          url.protocol === "https:" ? 20 : 0,
          url.protocol === "https:"
            ? "This page URL uses HTTPS."
            : "This page uses unencrypted HTTP.",
        ),
      ssl: () =>
        url.protocol !== "https:"
          ? C.result("failed", 0, "TLS is unavailable on this HTTP page.")
          : new SslChecker().check(url.hostname, signal),
      safeBrowsing: () =>
        new SafeBrowsingClient(apiKeys.googleSafeBrowsing).checkUrl(
          url.origin,
          signal,
        ),
      vulnerabilities: () =>
        new VulnerabilityScanner(apiKeys.virusTotal).checkDomain(
          url.hostname,
          signal,
        ),
      emailSecurity: () =>
        new EmailSecurityChecker().checkDomain(url.hostname, signal),
      exposedDirectories: () =>
        new DirectoryChecker(settings).checkExposedDirectories(
          url.origin,
          signal,
        ),
      securityHeaders: async () => {
        const headers = await C.request(
          C.sanitizeUrl(tab.url),
          { method: "HEAD", redirect: "error" },
          { signal, format: "response" },
        );
        // Never render or persist unrelated headers (for example Set-Cookie).
        return new SecurityHeadersChecker().checkSecurityHeaders(
          headers.headers,
        );
      },
      mixedContent: async () => (await pagePromise).mixedContent,
      forms: async () => (await pagePromise).forms,
    };
    await Promise.all(
      Object.entries(tasks).map(async ([key, fn]) => {
        let value;
        try {
          if (!settings.checks[key]) value = C.skipped("Disabled in Settings.");
          else if (
            [
              "ssl",
              "safeBrowsing",
              "vulnerabilities",
              "emailSecurity",
            ].includes(key) &&
            !externalAllowed
          )
            value = C.skipped(
              settings.externalServices
                ? "External lookups are disabled for local/private hostnames and IP ranges."
                : "Enable external security services in Settings to run this check.",
            );
          else if (key === "exposedDirectories" && !settings.directoryConsent)
            value = C.skipped(
              "Enable directory probing in Settings only for sites you are authorized to test.",
            );
          else value = await fn();
        } catch (error) {
          value = C.errorResult(error);
        }
        job.checks[key] = value;
        job.completed += 1;
        await persistJob(job);
      }),
    );
    const stillCurrent = await chrome.tabs.get(tab.id);
    if (stillCurrent.url !== tab.url) {
      run.reason =
        "The page changed during the scan. Scan the current page again.";
      controller.abort();
    }
    const report = {
      id: job.id,
      version: "1.0.5",
      url: url.origin,
      timestamp: new Date().toISOString(),
      partial: signal.aborted,
      pageKey,
      profile,
      checks: job.checks,
      ...C.scoreReport(job.checks),
      recommendations: C.recommendations(job.checks),
    };
    if (signal.aborted) {
      job.status = "cancelled";
      job.message = run.reason || "Scan cancelled.";
      job.report = report;
      // Partial results remain visible in the popup, but never enter history/cache or the badge.
      await persistJob(job);
      return;
    }
    await write(async () => {
      const { scanHistory = [] } =
        await chrome.storage.local.get("scanHistory");
      report.comparison = C.compareReports(
        report,
        scanHistory.find((previous) => previous.url === report.url),
      );
      if (settings.saveHistory)
        await chrome.storage.local.set({
          scanHistory: [report, ...scanHistory].slice(0, 50),
        });
      const { scanCache = {} } = await chrome.storage.session.get("scanCache");
      const freshEntries = Object.entries(scanCache)
        .filter(
          ([, value]) =>
            Date.now() - Date.parse(value.timestamp) < 300000 &&
            value.pageKey !== pageKey,
        )
        .sort((a, b) => Date.parse(b[1].timestamp) - Date.parse(a[1].timestamp))
        .slice(0, 19);
      if (settings.cacheMinutes > 0) freshEntries.unshift([cacheKey, report]);
      await chrome.storage.session.set({
        scanCache: Object.fromEntries(freshEntries),
      });
    });
    job.status = "complete";
    job.report = report;
    await persistJob(job);
    await badge(tab.id, report);
  } catch (error) {
    job.status = "error";
    job.message = error.message;
    await persistJob(job).catch(console.error);
  } finally {
    clearTimeout(timeout);
    clearInterval(heartbeat);
    if (running.get(tab.id) === run) running.delete(tab.id);
  }
}
async function getState(tabId) {
  await configReady;
  await writes;
  const { scanJobs = {} } = await chrome.storage.session.get("scanJobs");
  let job = scanJobs[tabId];
  if (job?.status === "running" && !running.has(tabId)) {
    job.status = "error";
    job.message = "Chrome interrupted the previous scan. Run a fresh scan.";
    await persistJob(job);
  }
  return { config, job: job || null };
}
async function clearReports(id) {
  if (!id)
    for (const tabId of [...running.keys()])
      await stopScan(tabId, "Scan stopped while clearing data.");
  await write(async () => {
    const { scanHistory = [] } = await chrome.storage.local.get("scanHistory");
    await chrome.storage.local.set({
      scanHistory: id ? scanHistory.filter((report) => report.id !== id) : [],
    });
    const { scanCache = {}, scanJobs = {} } = await chrome.storage.session.get([
      "scanCache",
      "scanJobs",
    ]);
    await chrome.storage.session.set({
      scanCache: id
        ? Object.fromEntries(
            Object.entries(scanCache).filter(([, report]) => report.id !== id),
          )
        : {},
      scanJobs: id
        ? Object.fromEntries(
            Object.entries(scanJobs).filter(([, job]) => job.report?.id !== id),
          )
        : {},
    });
  });
  for (const tab of await chrome.tabs.query({})) await badge(tab.id, null);
  return { success: true };
}
async function handle(message) {
  await configReady;
  if (message.action === "getState") return getState(message.tabId);
  if (message.action === "startScan")
    return startScan(message.tabId, message.force === true);
  if (message.action === "cancelScan") {
    await stopScan(message.tabId);
    return getState(message.tabId);
  }
  if (message.action === "getHistory") {
    await writes;
    const { scanHistory = [] } = await chrome.storage.local.get("scanHistory");
    return { history: scanHistory };
  }
  if (message.action === "deleteReport")
    return clearReports(String(message.id));
  if (message.action === "clearHistory") return clearReports();
  if (message.action === "saveConfig") {
    for (const tabId of [...running.keys()])
      await stopScan(tabId, "Settings changed. Start a fresh scan.");
    config = C.normalizeConfig(defaults, message.config || {});
    await write(async () => {
      await chrome.storage.local.set({ securityScannerConfig: config });
      if (!config.settings.saveHistory)
        await chrome.storage.local.set({ scanHistory: [] });
      await chrome.storage.session.set({ scanCache: {}, scanJobs: {} });
    });
    for (const tab of await chrome.tabs.query({})) await badge(tab.id, null);
    return { success: true, config };
  }
  throw new Error("Unknown extension request.");
}
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only our own extension pages may access settings, keys, history, or scans.
  if (
    sender.id !== chrome.runtime.id ||
    !sender.url?.startsWith(chrome.runtime.getURL(""))
  )
    return false;
  const readOnly = ["getState", "getHistory"].includes(message?.action);
  const response = readOnly
    ? handle(message)
    : commands.then(() => handle(message));
  if (!readOnly) commands = response.catch(() => {});
  response.then(sendResponse, (error) =>
    sendResponse({ error: String(error.message || error).slice(0, 300) }),
  );
  return true;
});
chrome.tabs.onRemoved.addListener((tabId) => {
  const operation = commands.then(async () => {
    await stopScan(tabId, "Tab closed.");
    await write(async () => {
      const { scanJobs = {} } = await chrome.storage.session.get("scanJobs");
      delete scanJobs[tabId];
      await chrome.storage.session.set({ scanJobs });
    });
  });
  commands = operation.catch(console.error);
});
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status !== "loading" && !changeInfo.url) return;
  const operation = commands.then(async () => {
    await configReady;
    await stopScan(tabId, "The page changed during the scan.");
    await write(async () => {
      const { scanJobs = {} } = await chrome.storage.session.get("scanJobs");
      delete scanJobs[tabId];
      await chrome.storage.session.set({ scanJobs });
    });
    await badge(tabId, null);
  });
  commands = operation.catch(console.error);
});
