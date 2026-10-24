// Optional, credential-free smoke checks against provider-owned public domains.
// Never include real API keys in this script, command-line arguments, or output.
const fs = require("node:fs");
require("../core.js");
const Email = require("../email-security.js"),
  Ssl = require("../ssl-checker.js");
(async () => {
  const checks = await Promise.allSettled([
    new Email().checkDomain("google.com"),
    new Ssl().check("www.ssllabs.com"),
  ]);
  const summary = checks.map((entry, index) => ({
    service:
      index === 0
        ? "Google Public DNS (google.com)"
        : "SSL Labs (www.ssllabs.com)",
    ...(entry.status === "fulfilled"
      ? { status: "response-validated", checkStatus: entry.value.status }
      : { status: "unavailable", reason: entry.reason.message }),
  }));
  fs.mkdirSync("test-results", { recursive: true });
  fs.writeFileSync(
    "test-results/live-results.json",
    JSON.stringify(
      { checkedAt: new Date().toISOString(), checks: summary },
      null,
      2,
    ),
  );
  console.log(JSON.stringify(summary, null, 2));
  if (summary.some((entry) => entry.status === "unavailable"))
    process.exitCode = 1;
})().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
