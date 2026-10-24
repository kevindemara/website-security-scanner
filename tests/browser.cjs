const fs = require("node:fs"),
  path = require("node:path"),
  http = require("node:http"),
  assert = require("node:assert/strict");
const { expect } = require("@playwright/test"),
  launch = require("./browser-launch.cjs"),
  { ssl, headers } = require("./fixtures.cjs");
const output = path.resolve("test-results");
fs.mkdirSync(output, { recursive: true });
const profileDirectory = fs.mkdtempSync(path.join(output, "browser-profile-"));
let context, server;
const results = [],
  requests = [],
  errors = [];
let popup, worker, site, cdp, extensionId;
const fixtureHtml = (https = false) =>
  `<!doctype html><html><head><title>Security scanner test fixture</title></head><body><h1>Controlled test website</h1>${https ? '<img src="http://insecure.invalid/pixel?private=secret">' : ""}<form action="${https ? "http://insecure.invalid/login?private=secret" : "/login"}" method="get"><input type="password" value="never-read-this-password"><button>Sign in</button></form></body></html>`;
async function check(name, fn) {
  await fn();
  results.push(name);
  console.log("PASS " + name);
}
async function grantAction() {
  const targets = (await cdp.send("Target.getTargets", { filter: [{}] }))
    .targetInfos;
  const target = targets.find((t) => t.type === "tab" && t.url === site.url());
  assert.ok(target, "Expected site tab target");
  await cdp.send("Extensions.triggerAction", {
    id: extensionId,
    targetId: target.targetId,
  });
}
async function openPopup() {
  const next = context.waitForEvent("page");
  await worker.evaluate(() =>
    chrome.tabs.create({
      url: chrome.runtime.getURL("popup.html"),
      active: false,
    }),
  );
  const page = await next;
  page.on("pageerror", (e) => errors.push(e.message));
  await page.waitForLoadState();
  await expect(page.locator("#check-settings input")).toHaveCount(9);
  return page;
}
async function finished() {
  await expect(popup.locator("#report-source")).toHaveText("Latest scan", {
    timeout: 15000,
  });
  await expect(popup.locator("#scan-progress")).toBeHidden();
}
async function fresh() {
  await popup.locator("#fresh-button").click();
  await finished();
}
async function selectPanel(name) {
  await popup.locator("#tab-" + name).click();
}
async function report() {
  return popup.evaluate(() => C.publicReport(currentReport));
}
(async () => {
  server = http.createServer((req, res) => {
    requests.push({
      url: req.url,
      method: req.method,
      cookie: req.headers.cookie,
    });
    res.setHeader("Content-Type", "text/html");
    for (const [key, value] of Object.entries(headers))
      res.setHeader(key, value);
    res.setHeader("Set-Cookie", "fixture=private; SameSite=Lax");
    res.end(
      req.url.startsWith("/backup/")
        ? "<title>Index of /backup/</title>"
        : fixtureHtml(),
    );
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const origin = "http://127.0.0.1:" + server.address().port;
  context = await launch(path.resolve("."), profileDirectory);
  worker =
    context.serviceWorkers()[0] ||
    (await context.waitForEvent("serviceworker"));
  extensionId = worker.url().split("/")[2];
  cdp = await context.browser().newBrowserCDPSession();
  site = context.pages()[0];
  await site.goto(origin + "/page?token=secret#hidden");
  await grantAction();
  popup = await openPopup();
  await check(
    "real extension loads with temporary activeTab access and no startup errors",
    async () => {
      assert.equal(
        await worker.evaluate(() => chrome.runtime.getManifest().version),
        "1.0.5",
      );
      await expect(popup.locator("#current-url")).toHaveText(origin);
      assert.equal(
        await worker.evaluate(() =>
          chrome.permissions.contains({
            origins: ["http://*/*", "https://*/*"],
          }),
        ),
        false,
      );
    },
  );
  await check(
    "actual HTTP scan reaches page, unauthenticated HEAD response and report UI",
    async () => {
      await popup.locator("#scan-button").click();
      await finished();
      const r = await report();
      assert.equal(r.checks.https.status, "failed");
      assert.equal(r.checks.forms.status, "failed");
      assert.equal(r.checks.securityHeaders.score, 15);
      assert.equal(r.checks.ssl.status, "skipped");
      assert.ok(
        requests.some(
          (r) => r.method === "HEAD" && r.url === "/page" && !r.cookie,
        ),
      );
      assert.doesNotMatch(
        JSON.stringify(r),
        /never-read-this-password|token=secret|#hidden/,
      );
    },
  );
  await check(
    "score badge and recommendations reflect completed scan",
    async () => {
      const badge = await worker.evaluate(async () => {
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });
        return chrome.action.getBadgeText({ tabId: tab.id });
      });
      assert.equal(badge, String((await report()).overallScore));
      await expect(popup.locator("#advice-list li").first()).toContainText(
        "HTTPS",
      );
    },
  );
  await check(
    "cache reuse avoids network and history duplication",
    async () => {
      const before = requests.length;
      await popup.locator("#scan-button").click();
      await expect(popup.locator("#report-source")).toContainText(
        "Cached scan",
      );
      assert.equal(requests.length, before);
      assert.equal(
        await worker.evaluate(
          async () =>
            (await chrome.storage.local.get("scanHistory")).scanHistory.length,
        ),
        1,
      );
    },
  );
  await check("fresh scan compares the previous matching page", async () => {
    await fresh();
    await expect(popup.locator("#comparison")).toContainText("0 points since");
    assert.equal(
      await worker.evaluate(
        async () =>
          (await chrome.storage.local.get("scanHistory")).scanHistory.length,
      ),
      2,
    );
  });
  await check(
    "JSON and standalone HTML downloads are safe and contain report evidence",
    async () => {
      for (const format of ["json", "html"]) {
        const pending = popup.waitForEvent("download");
        await popup.locator("#export-" + format).click();
        const d = await pending;
        const target = path.join(output, "browser-export." + format);
        await d.saveAs(target);
        const data = fs.readFileSync(target, "utf8");
        assert.match(data, /Website Security Scanner|"version": "1.0.5"/);
        assert.doesNotMatch(
          data,
          /never-read-this-password|token=secret|apiKeys|pageKey|profile/,
        );
        if (format === "html") assert.doesNotMatch(data, /<script/i);
      }
    },
  );
  await check(
    "history supports search, viewing and individual deletion",
    async () => {
      await selectPanel("history");
      await expect(popup.locator(".history-row")).toHaveCount(2);
      await popup.locator("#history-search").fill("no-match");
      await expect(popup.locator(".history-row")).toHaveCount(0);
      await popup.locator("#history-search").fill("127.0.0.1");
      await popup.locator(".history-open").first().click();
      await expect(popup.locator("#report-source")).toHaveText("Saved report");
      await selectPanel("history");
      await popup.locator(".history-delete").first().click();
      await expect(popup.locator(".history-row")).toHaveCount(1);
    },
  );
  await check(
    "settings save check controls, masked keys and badge preference",
    async () => {
      await selectPanel("settings");
      await popup.locator("#google-api-key").fill("synthetic-google-key");
      await popup.locator("#virustotal-api-key").fill("synthetic-virus-key");
      await expect(popup.locator("#google-api-key")).toHaveAttribute(
        "type",
        "password",
      );
      await popup.locator("#show-keys").check();
      await expect(popup.locator("#google-api-key")).toHaveAttribute(
        "type",
        "text",
      );
      await popup.locator("#show-keys").uncheck();
      await popup.locator("#show-badge").uncheck();
      await popup.locator("#enable-forms").uncheck();
      await popup
        .getByRole("button", { name: "Save settings", exact: true })
        .click();
      await expect(popup.locator("#notice")).toContainText("Settings saved");
      await selectPanel("scan");
      await fresh();
      assert.equal((await report()).checks.forms.status, "skipped");
      const badge = await worker.evaluate(async () => {
        const [tab] = await chrome.tabs.query({
          active: true,
          currentWindow: true,
        });
        return chrome.action.getBadgeText({ tabId: tab.id });
      });
      assert.equal(badge, "");
    },
  );
  await check(
    "directory probing requires consent and finds a real directory index",
    async () => {
      await selectPanel("settings");
      await popup.locator("#enable-exposedDirectories").check();
      await popup
        .getByRole("button", { name: "Save settings", exact: true })
        .click();
      await expect(popup.locator("#notice")).toContainText("Settings saved");
      await selectPanel("scan");
      await fresh();
      const r = await report();
      assert.equal(r.checks.exposedDirectories.status, "failed");
      assert.ok(
        r.checks.exposedDirectories.details.exposedDirectories.includes(
          "/backup/",
        ),
      );
      assert.ok(requests.some((r) => r.url === "/backup/" && !r.cookie));
    },
  );
  // Deterministic external-service responses; all extension logic and browser APIs remain real.
  await worker.evaluate(
    ({ ssl, headers }) => {
      const original = globalThis.fetch;
      globalThis.fixtureRequests = [];
      globalThis.fixtureSlow = false;
      globalThis.fetch = async (input, options = {}) => {
        const url = new URL(String(input));
        if (globalThis.fixtureSlow && options.method === "HEAD")
          return new Promise(() => {});
        if (url.hostname === "scanner-fixture.org") {
          fixtureRequests.push({
            url: url.href,
            body: options.body,
            headers: options.headers,
          });
          return new Response("", { headers });
        }
        if (
          [
            "api.ssllabs.com",
            "dns.google",
            "safebrowsing.googleapis.com",
            "www.virustotal.com",
          ].includes(url.hostname)
        ) {
          fixtureRequests.push({
            url: url.href,
            body: options.body,
            headers: options.headers,
          });
          let data = {};
          if (url.hostname === "api.ssllabs.com") data = ssl;
          if (url.hostname === "dns.google")
            data = {
              Status: 0,
              Answer: [
                {
                  type: 16,
                  data: url.searchParams.get("name").startsWith("_dmarc.")
                    ? "v=DMARC1; p=reject;"
                    : "v=spf1 -all",
                },
              ],
            };
          if (url.hostname === "www.virustotal.com")
            data = {
              data: {
                attributes: {
                  last_analysis_stats: {
                    harmless: 90,
                    malicious: 0,
                    suspicious: 0,
                  },
                  last_analysis_date: 1700000000,
                },
              },
            };
          return new Response(JSON.stringify(data));
        }
        return original(input, options);
      };
    },
    { ssl: ssl(), headers },
  );
  await context.route("https://scanner-fixture.org/**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/html",
      body: fixtureHtml(true),
    }),
  );
  await context.route("http://insecure.invalid/**", (route) => route.abort());
  await site.goto("https://scanner-fixture.org/page?token=secret#hidden");
  await grantAction();
  await popup.close();
  popup = await openPopup();
  await check(
    "HTTPS DOM inspection detects mixed resources and insecure forms",
    async () => {
      await selectPanel("settings");
      await popup.locator("#enable-exposedDirectories").uncheck();
      await popup.locator("#enable-forms").check();
      await popup.locator("#show-badge").check();
      await popup.locator("#external-services").check();
      await popup
        .getByRole("button", { name: "Save settings", exact: true })
        .click();
      await expect(popup.locator("#notice")).toContainText("Settings saved");
      await selectPanel("scan");
      await fresh();
      const r = await report();
      assert.equal(r.checks.mixedContent.status, "failed");
      assert.equal(r.checks.forms.status, "failed");
      assert.equal(r.checks.ssl.status, "passed");
      assert.equal(r.checks.safeBrowsing.status, "passed");
      assert.equal(r.checks.vulnerabilities.status, "passed");
      assert.equal(r.checks.emailSecurity.status, "passed");
      assert.doesNotMatch(
        JSON.stringify(r),
        /private=secret|token=secret|never-read-this-password|synthetic-google-key|synthetic-virus-key/,
      );
      await popup.screenshot({
        path: path.join(output, "popup-scan.png"),
        fullPage: true,
      });
    },
  );
  await check(
    "HTTPS forms distinguish secure POST, external sign-in and passwordless pages",
    async () => {
      const inspect = async () =>
        worker.evaluate(async () => {
          const [tab] = await chrome.tabs.query({
            active: true,
            currentWindow: true,
          });
          return (
            await chrome.scripting.executeScript({
              target: { tabId: tab.id },
              func: inspectPage,
              args: [tab.url],
            })
          )[0].result;
        });
      await site.evaluate(() => {
        document.body.innerHTML =
          '<form method="post" action="/login"><input type="password" value="secret-form-value"></form>';
      });
      let data = await inspect();
      assert.equal(data.formCount, 0);
      assert.doesNotMatch(JSON.stringify(data), /secret-form-value/);
      await site.evaluate(() => {
        document
          .querySelector("form")
          .insertAdjacentHTML(
            "beforeend",
            '<button formaction="http://insecure.invalid/login">Unsafe submit</button>',
          );
      });
      assert.ok((await inspect()).failedForms > 0);
      await site.evaluate(() => document.querySelector("button").remove());
      await site.evaluate(() => {
        document.querySelector("form").action =
          "https://identity-provider.invalid/login";
      });
      data = await inspect();
      assert.equal(data.forms[0].severity, "warning");
      await site.evaluate(() => {
        document.body.innerHTML = "<p>No forms here</p>";
      });
      assert.equal((await inspect()).formCount, 0);
    },
  );
  await check(
    "external lookup payloads omit the page path, tokens and fragment",
    async () => {
      const calls = await worker.evaluate(() => fixtureRequests);
      const safe = calls.find((c) =>
        c.url.includes("safebrowsing.googleapis.com"),
      );
      assert.ok(safe);
      assert.equal(
        JSON.parse(safe.body).threatInfo.threatEntries[0].url,
        "https://scanner-fixture.org/",
      );
      for (const call of calls.filter(
        (c) => !c.url.includes("scanner-fixture.org/page"),
      ))
        assert.doesNotMatch(
          call.url + (call.body || ""),
          /token=secret|#hidden|\/page/,
        );
    },
  );
  await check(
    "progress survives closing and reopening the popup and cancellation stops work",
    async () => {
      await worker.evaluate(() => (globalThis.fixtureSlow = true));
      await popup.locator("#fresh-button").click();
      await expect(popup.locator("#cancel-button")).toBeVisible();
      await expect(popup.locator("#progress-label")).not.toHaveText("0 / 9");
      await popup.close();
      popup = await openPopup();
      await expect(popup.locator("#cancel-button")).toBeVisible();
      await popup.locator("#cancel-button").click();
      await expect(popup.locator("#report-source")).toHaveText(
        "Partial scan · not saved",
      );
      await expect(popup.locator("#notice")).toContainText("cancelled");
      await worker.evaluate(() => (globalThis.fixtureSlow = false));
    },
  );
  await check(
    "clear all removes saved and cached reports while retaining configured keys",
    async () => {
      await selectPanel("history");
      popup.once("dialog", (dialog) => dialog.accept());
      await popup.locator("#clear-history").click();
      await expect(popup.locator(".history-row")).toHaveCount(0);
      const data = await worker.evaluate(async () => ({
        local: await chrome.storage.local.get(null),
        session: await chrome.storage.session.get(null),
      }));
      assert.equal(data.local.scanHistory.length, 0);
      assert.equal(Object.keys(data.session.scanCache).length, 0);
      assert.equal(Object.keys(data.session.scanJobs).length, 0);
      assert.equal(
        data.local.securityScannerConfig.apiKeys.googleSafeBrowsing,
        "synthetic-google-key",
      );
    },
  );
  await check(
    "keyboard tab navigation and responsive layout avoid horizontal overflow",
    async () => {
      await popup.locator("#tab-scan").focus();
      await popup.keyboard.press("ArrowRight");
      await expect(popup.locator("#tab-history")).toHaveAttribute(
        "aria-selected",
        "true",
      );
      await popup.setViewportSize({ width: 360, height: 800 });
      assert.equal(
        await popup.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        true,
      );
      await selectPanel("settings");
      await popup.screenshot({
        path: path.join(output, "popup-settings.png"),
        fullPage: true,
      });
    },
  );
  await check(
    "internal browser pages are rejected without breaking settings/history",
    async () => {
      await site.goto("chrome://version/");
      await popup.close();
      const next = context.waitForEvent("page");
      await worker.evaluate(() =>
        chrome.tabs.create({
          url: chrome.runtime.getURL("popup.html"),
          active: false,
        }),
      );
      popup = await next;
      await popup.waitForLoadState();
      await expect(popup.locator("#scan-button")).toBeDisabled();
      await selectPanel("settings");
      await expect(popup.locator("#settings-form")).toBeVisible();
    },
  );
  await check(
    "real browser restart migrates legacy saved keys and keeps external services opt-in",
    async () => {
      await worker.evaluate(() =>
        chrome.storage.local.set({
          securityScannerConfig: {
            apiKeys: {
              googleSafeBrowsing: "legacy-key",
              virusTotal: "legacy-virus",
            },
            settings: { checkTimeout: 120000 },
          },
        }),
      );
      await context.close();
      context = await launch(path.resolve("."), profileDirectory);
      worker =
        context.serviceWorkers()[0] ||
        (await context.waitForEvent("serviceworker"));
      extensionId = worker.url().split("/")[2];
      cdp = await context.browser().newBrowserCDPSession();
      site = context.pages()[0];
      await site.goto(origin + "/restart");
      await grantAction();
      popup = await openPopup();
      const config = await popup.evaluate(() => currentConfig);
      assert.equal(config.apiKeys.googleSafeBrowsing, "legacy-key");
      assert.equal(config.apiKeys.virusTotal, "legacy-virus");
      assert.equal(config.settings.externalServices, false);
      assert.equal(config.settings.checkTimeout, 60000);
    },
  );
  assert.deepEqual(errors, [], "Unexpected popup errors");
  const summary = {
    browser: context.browser().version(),
    extensionVersion: "1.0.5",
    passed: results.length,
    tests: results,
    externalServices:
      "Deterministic provider fixtures; no live API credentials were supplied.",
    screenshots: ["popup-scan.png", "popup-settings.png"],
  };
  fs.writeFileSync(
    path.join(output, "browser-results.json"),
    JSON.stringify(summary, null, 2),
  );
  console.log(JSON.stringify(summary, null, 2));
})()
  .catch(async (error) => {
    console.error(error);
    if (popup)
      await popup
        .screenshot({
          path: path.join(output, "browser-failure.png"),
          fullPage: true,
        })
        .catch(() => {});
    process.exitCode = 1;
  })
  .finally(async () => {
    if (context) await context.close();
    if (server) await new Promise((resolve) => server.close(resolve));
  });
