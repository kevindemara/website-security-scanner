const test = require("node:test");
const assert = require("node:assert/strict");
const C = require("../core.js");
const defaults = require("../config.json");
const ssl = require("../ssl-checker.js");
const HeadersChecker = require("../security-headers.js");
const { ssl: fixture, headers } = require("./fixtures.cjs");
const pass = (key) => C.result("passed", C.CHECKS[key].max, "Fixture pass");
function report() {
  const checks = Object.fromEntries(
    Object.keys(C.CHECKS).map((key) => [key, pass(key)]),
  );
  return {
    id: "report-id",
    version: "1.0.5",
    url: "https://scanner.test",
    timestamp: new Date().toISOString(),
    pageKey: "page",
    profile: "settings",
    checks,
    ...C.scoreReport(checks),
    recommendations: [],
  };
}
test("migration preserves real keys, merges new defaults, and resets legacy placeholders", () => {
  const config = C.normalizeConfig(defaults, {
    apiKeys: {
      googleSafeBrowsing: " real-key ",
      virusTotal: "YOUR_VIRUSTOTAL_API_KEY",
    },
    settings: { maxDirectoriesToCheck: 10, checkTimeout: 120000 },
  });
  assert.equal(config.apiKeys.googleSafeBrowsing, "real-key");
  assert.equal(config.apiKeys.virusTotal, "");
  assert.equal(config.settings.checks.forms, true);
  assert.equal(config.settings.externalServices, false);
  assert.equal(config.settings.checkTimeout, 60000);
});
test("normalization bounds settings and prevents truthy strings granting consent", () => {
  const c = C.normalizeConfig(defaults, {
    settings: {
      externalServices: "true",
      directoryConsent: 1,
      cacheMinutes: 999,
      maxDirectoriesToCheck: -1,
    },
  });
  assert.equal(c.settings.externalServices, false);
  assert.equal(c.settings.directoryConsent, false);
  assert.equal(c.settings.cacheMinutes, 5);
  assert.equal(c.settings.maxDirectoriesToCheck, 1);
});
test("URL sanitization strips tokens, credentials and fragments", () => {
  assert.equal(
    C.sanitizeUrl("https://user:secret@scanner.test/page?token=secret#private"),
    "https://scanner.test/page",
  );
  assert.equal(
    C.sanitizeUrl("https://scanner.test/page", true),
    "https://scanner.test",
  );
  assert.throws(() => C.sanitizeUrl("file:///private"));
});
test("private hostnames and address forms never go to external providers", () => {
  for (const host of [
    "localhost",
    "localhost.",
    "foo.local",
    "foo.local.",
    "foo.internal",
    "scanner.test",
    "127.0.0.1",
    "10.0.0.1",
    "192.168.0.1",
    "172.20.1.1",
    "169.254.1.2",
    "100.64.0.1",
    "[::1]",
    "[fd00::1]",
  ])
    assert.equal(C.isPublicHost(host), false, host);
  assert.equal(C.isPublicHost("example.org"), true);
  assert.equal(C.isPublicHost("8.8.8.8"), true);
});
test("unknown checks have no score and visibly reduce coverage", () => {
  const r = C.scoreReport({
    https: pass("https"),
    ssl: C.errorResult(new Error("Offline")),
    safeBrowsing: C.skipped("No consent"),
  });
  assert.equal(r.overallScore, 100);
  assert.equal(r.coverage, 17);
  assert.equal(r.assessedWeight, 20);
  assert.equal(
    C.scoreReport({ https: C.skipped("Disabled") }).overallScore,
    null,
  );
});
test("full coverage reaches 100 and scores are bounded", () => {
  assert.equal(report().coverage, 100);
  assert.equal(report().overallScore, 100);
  assert.equal(
    C.scoreReport({ https: C.result("passed", 999, "Invalid") }).overallScore,
    100,
  );
});
test("a detected reputation threat caps the overall score", () => {
  const r = report();
  r.checks.safeBrowsing = C.result("failed", 0, "Threat");
  assert.equal(C.scoreReport(r.checks).overallScore, 20);
  assert.equal(C.scoreReport(r.checks).threatDetected, true);
});
test("comparison calculates changes only for matching pages, settings and coverage", () => {
  const previous = report(),
    current = report();
  current.checks.https = C.result("failed", 0, "HTTP");
  Object.assign(current, C.scoreReport(current.checks));
  const diff = C.compareReports(current, previous);
  assert.equal(diff.comparable, true);
  assert.equal(diff.scoreDelta, -17);
  assert.equal(diff.changes[0].check, "https");
  current.pageKey = "different";
  assert.equal(C.compareReports(current, previous).scoreDelta, null);
  current.pageKey = previous.pageKey;
  current.checks.ssl = C.skipped("Disabled");
  assert.equal(C.compareReports(current, previous).comparable, false);
  assert.equal(
    C.compareReports(current, { ...previous, url: "https://else.test" }),
    null,
  );
});
test("exports remove internal fingerprints and settings and escape hostile HTML", () => {
  const r = report();
  r.apiKeys = { secret: "do-not-export" };
  r.checks.forms.details.message = "<img src=x onerror=alert(1)>";
  const json = JSON.stringify(C.publicReport(r));
  assert.doesNotMatch(json, /do-not-export|pageKey|profile/);
  const html = C.reportHtml(r);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /&lt;img/);
  assert.doesNotMatch(html, /<script/i);
});
test("recommendations prioritize failures and include check-specific advice", () => {
  const items = C.recommendations({
    https: C.result("warning", 10, "Weak"),
    forms: C.result("failed", 0, "Unsafe", { recommendations: ["Use POST."] }),
  });
  assert.equal(items[0].check, "forms");
  assert.equal(items[0].priority, "high");
  assert.ok(items.some((i) => i.advice === "Use POST."));
});
for (const grade of ["F", "T", "M"])
  test("SSL grade " + grade + " never earns a pass", () => {
    const r = ssl.analyze(fixture(grade));
    assert.equal(r.status, "failed");
    assert.equal(r.score, 0);
  });
test("SSL uses worst endpoint and validates certificate times", () => {
  const f = fixture("A");
  f.endpoints.push({ ...structuredClone(f.endpoints[0]), grade: "C" });
  assert.equal(ssl.analyze(f).score, 5);
  assert.equal(ssl.analyze(fixture("A", -1)).status, "failed");
  assert.equal(ssl.analyze(fixture("A", 10)).status, "warning");
  assert.equal(ssl.analyze(fixture("A", 90)).status, "passed");
});
test("SSL refuses missing or incomplete endpoints, grades and leaf certs", () => {
  for (const change of [
    (f) => (f.endpoints = []),
    (f) => delete f.endpoints[0].grade,
    (f) => (f.endpoints[0].statusMessage = "In progress"),
    (f) => (f.certs = []),
    (f) => (f.certs[0].notBefore = "invalid"),
    (f) => (f.status = "ERROR"),
    (f) => (f.status = "IN_PROGRESS"),
  ]) {
    const f = fixture();
    change(f);
    assert.throws(() => ssl.analyze(f));
  }
});
test("header values are assessed rather than presence alone", () => {
  const checker = new HeadersChecker();
  assert.equal(checker.checkSecurityHeaders(headers).score, 15);
  const weak = checker.checkSecurityHeaders({
    ...headers,
    "Content-Security-Policy": "default-src *; script-src 'unsafe-inline'",
    "Strict-Transport-Security": "max-age=0",
    "X-Content-Type-Options": "wrong",
  });
  assert.equal(weak.status, "failed");
  assert.ok(weak.details.recommendations.length >= 3);
});
test("frame-ancestors replaces X-Frame-Options and obsolete X-XSS-Protection is not rewarded", () => {
  const checker = new HeadersChecker();
  assert.equal(checker.checkSecurityHeaders(headers).score, 15);
  assert.equal(
    checker.checkSecurityHeaders({ "X-XSS-Protection": "1; mode=block" }).score,
    0,
  );
});
test("request timeout aborts an unresponsive fetch", async (t) => {
  t.mock.method(global, "fetch", () => new Promise(() => {}));
  await assert.rejects(C.request("https://scanner.test", {}, { timeout: 10 }), {
    name: "AbortError",
  });
});
test("cancellation interrupts pending work and delays", async () => {
  const controller = new AbortController();
  const pending = C.withAbort(new Promise(() => {}), controller.signal);
  const waiting = C.delay(60000, controller.signal);
  controller.abort();
  await assert.rejects(pending, { name: "AbortError" });
  await assert.rejects(waiting, { name: "AbortError" });
});
test("requests bound bodies and omit credentials", async (t) => {
  let options;
  t.mock.method(global, "fetch", async (url, opts) => {
    options = opts;
    return new Response("123456");
  });
  await assert.rejects(
    C.request("https://scanner.test", {}, { format: "text", maxBytes: 5 }),
    /too large/,
  );
  assert.equal(options.credentials, "omit");
  assert.equal(options.referrerPolicy, "no-referrer");
});
test("request timeout includes body streaming", async (t) => {
  t.mock.method(
    global,
    "fetch",
    async () => new Response(new ReadableStream({ start() {} })),
  );
  await assert.rejects(C.request("https://scanner.test", {}, { timeout: 10 }), {
    name: "AbortError",
  });
});
test("HTTP 429 yields an actionable rate-limit error", async (t) => {
  t.mock.method(
    global,
    "fetch",
    async () => new Response("{}", { status: 429 }),
  );
  await assert.rejects(C.request("https://scanner.test"), /rate limit/);
});

test("CSP duplicate directives and element overrides cannot hide an unsafe script policy", () => {
  const checker = new HeadersChecker();
  for (const csp of [
    "script-src *; script-src 'self'",
    "script-src 'self'; script-src-elem *",
    "script-src 'self'; script-src-attr 'unsafe-inline'",
  ]) {
    const r = checker.checkSecurityHeaders({
      ...headers,
      "Content-Security-Policy": csp,
    });
    assert.ok(
      r.details.headerDetails.find((h) => h.name === "Content-Security-Policy")
        .status === "warning",
    );
  }
});
test("error messages redact query credentials in referenced URLs", () => {
  assert.doesNotMatch(
    C.errorResult(
      new Error("Cannot access https://scanner.test/path?key=secret#token"),
    ).details.message,
    /secret|token/,
  );
});

test("truncated form details cannot hide a failure later in the page", () => {
  const { pageResults } = require("../page-checks.js");
  const r = pageResults({
    protocol: "https:",
    mixed: [],
    mixedCount: 0,
    forms: Array.from({ length: 20 }, () => ({ severity: "warning" })),
    failedForms: 1,
    formCount: 21,
    inspectedForms: 21,
  });
  assert.equal(r.forms.status, "failed");
  assert.equal(r.forms.score, 0);
});
test("every graded TLS endpoint must include a referenced leaf certificate", () => {
  const f = fixture();
  f.endpoints.push({ grade: "A", statusMessage: "Ready" });
  assert.throws(
    () => ssl.analyze(f),
    /certificate validity information is incomplete/,
  );
});
