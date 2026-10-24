const test = require("node:test"),
  assert = require("node:assert/strict");
const C = require("../core.js"),
  Safe = require("../safebrowsing.js"),
  Virus = require("../vulnerability-scanner.js"),
  Email = require("../email-security.js"),
  Directory = require("../directory-checker.js"),
  Ssl = require("../ssl-checker.js");
const { ssl: fixture } = require("./fixtures.cjs");
const json = (data) =>
  new Response(JSON.stringify(data), {
    headers: { "Content-Type": "application/json" },
  });
test("Safe Browsing skips missing keys without a request", async (t) => {
  t.mock.method(global, "fetch", () => {
    throw Error("Unexpected request");
  });
  assert.equal(
    (await new Safe("").checkUrl("https://scanner.test")).status,
    "skipped",
  );
});
test("Safe Browsing sends only the origin and current client version", async (t) => {
  let sent, options;
  t.mock.method(global, "fetch", async (u, o) => {
    sent = u;
    options = o;
    return json({ matches: [{ threatType: "MALWARE" }] });
  });
  const r = await new Safe("key with spaces").checkUrl(
    "https://scanner.test/private?token=secret#hidden",
  );
  assert.equal(r.status, "failed");
  assert.match(sent, /key%20with%20spaces/);
  const body = JSON.parse(options.body);
  assert.equal(body.client.clientVersion, "1.0.5");
  assert.equal(body.threatInfo.threatEntries[0].url, "https://scanner.test/");
  assert.doesNotMatch(options.body, /secret|private|hidden/);
});
test("Safe Browsing handles clean and malformed responses conservatively", async (t) => {
  t.mock.method(global, "fetch", async () => json({}));
  assert.equal(
    (await new Safe("fixture").checkUrl("https://scanner.test")).status,
    "passed",
  );
  global.fetch = async () => json({ matches: "invalid" });
  await assert.rejects(
    new Safe("fixture").checkUrl("https://scanner.test"),
    /Invalid/,
  );
});
test("VirusTotal treats malicious reputation as failure", async (t) => {
  let opts;
  t.mock.method(global, "fetch", async (u, o) => {
    opts = o;
    return json({
      data: {
        attributes: {
          last_analysis_stats: { malicious: 1, harmless: 90 },
          last_analysis_date: 1700000000,
        },
      },
    });
  });
  const r = await new Virus("fixture-key").checkDomain("scanner.test");
  assert.equal(r.status, "failed");
  assert.equal(r.score, 0);
  assert.equal(opts.headers["x-apikey"], "fixture-key");
  assert.doesNotMatch(JSON.stringify(r), /fixture-key/);
});
test("VirusTotal does not turn absent analyses into a clean bill of health", async (t) => {
  t.mock.method(global, "fetch", async () =>
    json({ data: { attributes: { last_analysis_stats: {} } } }),
  );
  await assert.rejects(
    new Virus("fixture-key").checkDomain("scanner.test"),
    /no usable/,
  );
  assert.equal(
    (await new Virus("").checkDomain("scanner.test")).status,
    "skipped",
  );
});
test("DNS errors are unknown rather than missing email records", async (t) => {
  t.mock.method(global, "fetch", async () => json({ Status: 2 }));
  await assert.rejects(
    new Email().checkDomain("scanner.test"),
    /DNS lookup failed/,
  );
});
test("email checks join split TXT strings and distinguish enforcing DMARC", async (t) => {
  t.mock.method(global, "fetch", async (url) =>
    json({
      Status: 0,
      Answer: [
        {
          type: 16,
          data: url.includes("_dmarc")
            ? '"v=DMARC1; " "p=reject;"'
            : '"v=spf1 " "-all"',
        },
      ],
    }),
  );
  const r = await new Email().checkDomain("scanner.test");
  assert.equal(r.status, "passed");
  assert.equal(r.details.spfRecords[0], "v=spf1 -all");
});
test("monitor-only DMARC yields actionable warning", async (t) => {
  t.mock.method(global, "fetch", async (url) =>
    json({
      Status: 0,
      Answer: [
        {
          type: 16,
          data: url.includes("_dmarc") ? "v=DMARC1; p=none" : "v=spf1 -all",
        },
      ],
    }),
  );
  const r = await new Email().checkDomain("scanner.test");
  assert.equal(r.status, "warning");
  assert.ok(r.details.recommendations.some((x) => x.includes("monitoring")));
});
test("an accessible normal page is not a directory exposure", async (t) => {
  t.mock.method(global, "fetch", async () => new Response("<h1>Welcome</h1>"));
  assert.equal(
    (
      await new Directory({ maxDirectoriesToCheck: 1 }).checkExposedDirectories(
        "https://scanner.test",
      )
    ).status,
    "passed",
  );
});
test("directory indexes are detected and queries are not probed", async (t) => {
  let request;
  t.mock.method(global, "fetch", async (u) => {
    request = u;
    return new Response("<title>Index of /backup/</title>");
  });
  const r = await new Directory({
    maxDirectoriesToCheck: 1,
  }).checkExposedDirectories("https://scanner.test/private?token=secret");
  assert.equal(r.status, "failed");
  assert.equal(request, "https://scanner.test/backup/");
});
test("directory network failures are not scored as safe", async (t) => {
  t.mock.method(global, "fetch", async () => {
    throw new TypeError("Offline");
  });
  assert.equal(
    (
      await new Directory({ maxDirectoriesToCheck: 1 }).checkExposedDirectories(
        "https://scanner.test",
      )
    ).status,
    "error",
  );
});
test("directory 403 and 404 responses are recognized as unavailable to public requests", async (t) => {
  for (const status of [403, 404]) {
    t.mock.method(global, "fetch", async () => new Response("", { status }));
    assert.equal(
      (
        await new Directory({
          maxDirectoriesToCheck: 1,
        }).checkExposedDirectories("https://scanner.test")
      ).status,
      "passed",
    );
  }
});
test("SSL consumes an immediately READY response without unnecessary polling", async (t) => {
  let calls = 0;
  t.mock.method(global, "fetch", async () => {
    calls++;
    return json(fixture("A"));
  });
  assert.equal((await new Ssl().check("scanner.test")).status, "passed");
  assert.equal(calls, 1);
});
test("SSL polling obeys cancellation", async (t) => {
  t.mock.method(global, "fetch", async () => json({ status: "IN_PROGRESS" }));
  const controller = new AbortController();
  const promise = new Ssl().check("scanner.test", controller.signal);
  setTimeout(() => controller.abort(), 10);
  await assert.rejects(promise, { name: "AbortError" });
});
