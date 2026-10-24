const test = require("node:test"),
  assert = require("node:assert/strict"),
  harness = require("./background-harness.cjs");
const defaults = require("../config.json");
const settings = (extra) => ({ ...structuredClone(defaults), ...extra });
async function setup(t, options) {
  const h = await harness(options);
  t.after(() => h.close());
  return h;
}
test("extension update preserves keys and does not grant external-service consent", async (t) => {
  const saved = {
    apiKeys: { googleSafeBrowsing: "saved-google", virusTotal: "saved-virus" },
    settings: { checkTimeout: 120000 },
  };
  const h = await setup(t, { saved });
  h.listeners.install({ reason: "update" });
  const state = await h.send({ action: "getState", tabId: 1 });
  assert.equal(state.config.apiKeys.googleSafeBrowsing, "saved-google");
  assert.equal(state.config.apiKeys.virusTotal, "saved-virus");
  assert.equal(state.config.settings.externalServices, false);
});
test("default scan records real check outcomes, coverage and badge without external requests", async (t) => {
  const h = await setup(t);
  await h.send({ action: "startScan", tabId: 1 });
  const job = await h.wait();
  assert.equal(job.status, "complete");
  assert.equal(job.report.checks.https.status, "passed");
  assert.equal(job.report.checks.ssl.status, "skipped");
  assert.equal(job.report.checks.securityHeaders.score, 15);
  assert.equal(job.report.coverage, 46);
  assert.equal(h.badges[1], "100");
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0].url, "https://scanner.org/private");
  assert.doesNotMatch(
    JSON.stringify(h.local.scanHistory),
    /token=secret|fragment/,
  );
});
test("cache reuses reports without duplicating history and fresh scans compare", async (t) => {
  const h = await setup(t);
  await h.send({ action: "startScan", tabId: 1 });
  const first = await h.wait();
  await h.send({ action: "startScan", tabId: 1 });
  const cached = await h.wait();
  assert.equal(cached.cached, true);
  assert.equal(cached.report.id, first.report.id);
  assert.equal(h.calls.length, 1);
  assert.equal(h.local.scanHistory.length, 1);
  await h.send({ action: "startScan", tabId: 1, force: true });
  const fresh = await h.wait();
  assert.equal(fresh.cached, false);
  assert.notEqual(fresh.report.id, first.report.id);
  assert.equal(fresh.report.comparison.scoreDelta, 0);
  assert.equal(h.local.scanHistory.length, 2);
});
test("cache is page-specific and expires after its configured lifetime", async (t) => {
  const h = await setup(t);
  await h.send({ action: "startScan", tabId: 1 });
  await h.wait();
  h.tabs.get(1).url = "https://scanner.org/another";
  await h.send({ action: "startScan", tabId: 1 });
  assert.equal((await h.wait()).cached, false);
  for (const r of Object.values(h.session.scanCache))
    r.timestamp = new Date(Date.now() - 310000).toISOString();
  await h.send({ action: "startScan", tabId: 1 });
  assert.equal((await h.wait()).cached, false);
});
test("all disabled checks produce no assessment instead of a false score", async (t) => {
  const c = settings();
  for (const key of Object.keys(c.settings.checks))
    c.settings.checks[key] = false;
  const h = await setup(t, { saved: c });
  await h.send({ action: "startScan", tabId: 1 });
  const j = await h.wait();
  assert.equal(j.report.overallScore, null);
  assert.equal(j.report.coverage, 0);
  assert.equal(h.badges[1], "");
  assert.equal(h.calls.length, 0);
});
test("cancellation stops network/body waits and does not save partial reports", async (t) => {
  const h = await setup(t, { request: () => new Promise(() => {}) });
  await h.send({ action: "startScan", tabId: 1 });
  const result = await h.send({ action: "cancelScan", tabId: 1 });
  assert.equal(result.job.status, "cancelled");
  assert.equal(h.local.scanHistory, undefined);
  assert.equal(h.session.scanCache, undefined);
});
test("whole scan deadline settles even when script injection never responds", async (t) => {
  const h = await setup(t, {
    inspect: () => new Promise(() => {}),
    clockScale: 0.0005,
  });
  await h.send({ action: "startScan", tabId: 1 });
  const j = await h.wait();
  assert.equal(j.status, "cancelled");
  assert.match(j.message, /60 seconds/);
  assert.equal(h.local.scanHistory, undefined);
});
test("history is capped at 50 reports without losing concurrent tab results", async (t) => {
  const h = await setup(t);
  h.local.scanHistory = Array.from({ length: 49 }, (_, i) => ({
    id: "old-" + i,
    url: "https://old.org",
    checks: {},
    timestamp: new Date().toISOString(),
  }));
  await Promise.all([
    h.send({ action: "startScan", tabId: 1 }),
    h.send({ action: "startScan", tabId: 2 }),
  ]);
  await Promise.all([h.wait(1), h.wait(2)]);
  assert.equal(h.local.scanHistory.length, 50);
  assert.ok(h.local.scanHistory.some((r) => r.url === "https://scanner.org"));
  assert.ok(h.local.scanHistory.some((r) => r.url === "https://second.org"));
});
test("clear-all removes history, cached reports, session jobs and badges but preserves keys", async (t) => {
  const c = settings();
  c.apiKeys.googleSafeBrowsing = "keep-me";
  const h = await setup(t, { saved: c });
  await h.send({ action: "startScan", tabId: 1 });
  await h.wait();
  await h.send({ action: "clearHistory" });
  assert.equal(h.local.scanHistory.length, 0);
  assert.deepEqual(h.session.scanCache, {});
  assert.deepEqual(h.session.scanJobs, {});
  assert.equal(
    h.local.securityScannerConfig.apiKeys.googleSafeBrowsing,
    "keep-me",
  );
  assert.equal(h.badges[1], "");
});
test("individual report deletion also removes matching cache and session data", async (t) => {
  const h = await setup(t);
  await h.send({ action: "startScan", tabId: 1 });
  const j = await h.wait();
  await h.send({ action: "deleteReport", id: j.report.id });
  assert.equal(h.local.scanHistory.length, 0);
  assert.equal(Object.keys(h.session.scanCache).length, 0);
  assert.equal((await h.send({ action: "getState", tabId: 1 })).job, null);
});
test("disabling history deletes old reports and invalidates cached settings", async (t) => {
  const h = await setup(t);
  await h.send({ action: "startScan", tabId: 1 });
  await h.wait();
  const c = (await h.send({ action: "getState", tabId: 1 })).config;
  c.settings.saveHistory = false;
  c.settings.showBadge = false;
  await h.send({ action: "saveConfig", config: c });
  await h.send({ action: "startScan", tabId: 1, force: true });
  await h.wait();
  assert.equal(h.local.scanHistory.length, 0);
  assert.equal(h.badges[1], "");
});
test("navigation and tab close cancel and remove stale jobs and badges", async (t) => {
  const h = await setup(t);
  await h.send({ action: "startScan", tabId: 1 });
  await h.wait();
  h.tabs.get(1).url = "https://changed.org";
  h.listeners.updated(1, { status: "loading" });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal((await h.send({ action: "getState", tabId: 1 })).job, null);
  assert.equal(h.badges[1], "");
});
test("worker restart surfaces interrupted scans instead of leaving progress stuck", async (t) => {
  const h = await setup(t, {
    session: {
      scanJobs: { 1: { id: "interrupted", tabId: 1, status: "running" } },
    },
  });
  const state = await h.send({ action: "getState", tabId: 1 });
  assert.equal(state.job.status, "error");
  assert.match(state.job.message, /interrupted/);
});
test("external pages and content scripts cannot read keys or initiate scans", async (t) => {
  const h = await setup(t);
  for (const sender of [
    { id: "other", url: "https://scanner.org" },
    { id: "fixture", url: "https://scanner.org", tab: { id: 1 } },
    { id: "fixture", url: "chrome-extension://different/popup.html" },
  ])
    assert.equal(await h.send({ action: "getState" }, sender), undefined);
});
test("invalid tabs and browser-internal pages return useful errors", async (t) => {
  const h = await setup(t);
  assert.match(
    (await h.send({ action: "startScan", tabId: -1 })).error,
    /Open this extension/,
  );
  h.tabs.get(1).url = "chrome://extensions/";
  assert.match((await h.send({ action: "startScan", tabId: 1 })).error, /HTTP/);
});
