/* Shared, dependency-free scan and report utilities. */
(function (root) {
  "use strict";
  const CHECKS = Object.freeze({
    https: {
      label: "HTTPS",
      max: 20,
      advice: "Serve the site over HTTPS and redirect HTTP visitors to HTTPS.",
    },
    ssl: {
      label: "TLS certificate",
      max: 15,
      advice:
        "Renew expired certificates, fix certificate trust/name errors, and disable obsolete TLS protocols.",
    },
    safeBrowsing: {
      label: "Safe Browsing",
      max: 15,
      advice:
        "Investigate the reported threat and request a review through Google Search Console after remediation.",
    },
    vulnerabilities: {
      label: "Domain reputation",
      max: 15,
      advice:
        "Review VirusTotal detections and investigate suspicious content. Reputation is not a vulnerability audit.",
    },
    emailSecurity: {
      label: "Email authentication",
      max: 10,
      advice:
        "Publish valid SPF and DMARC records. Validate legitimate senders before enforcing a DMARC policy.",
    },
    exposedDirectories: {
      label: "Directory listings",
      max: 10,
      advice:
        "Disable directory indexing and remove sensitive files from publicly reachable directories.",
    },
    securityHeaders: {
      label: "Security headers",
      max: 15,
      advice:
        "Configure the missing or weak response headers; test your policy with your application before deployment.",
    },
    mixedContent: {
      label: "Mixed content",
      max: 10,
      advice:
        "Replace HTTP resource URLs with HTTPS URLs and verify that every resource supports HTTPS.",
    },
    forms: {
      label: "Form security",
      max: 10,
      advice:
        "Use HTTPS for the page and form destination. Submit passwords with POST and verify external sign-in destinations.",
    },
  });
  function result(status, score, message, extra = {}) {
    return { status, score, details: { message, ...extra } };
  }
  const skipped = (message) => result("skipped", null, message);
  const errorResult = (error) =>
    result(
      "error",
      null,
      error.name === "AbortError"
        ? "Check cancelled or timed out."
        : String(error.message || error)
            .replace(/https?:\/\/[^\s"'<>]+/g, (value) => {
              try {
                return sanitizeUrl(value);
              } catch {
                return "[URL]";
              }
            })
            .slice(0, 300),
    );
  function sanitizeUrl(value, originOnly = false) {
    const url = new URL(value);
    if (!["https:", "http:"].includes(url.protocol))
      throw new Error("Only HTTP and HTTPS websites can be scanned.");
    url.username = "";
    url.password = "";
    url.search = "";
    url.hash = "";
    return originOnly ? url.origin : url.href;
  }
  function isPublicHost(host) {
    host = host
      .toLowerCase()
      .replace(/^\[|\]$/g, "")
      .replace(/\.$/, "");
    if (
      !host.includes(".") ||
      /(?:^|\.)(localhost|local|internal|test|invalid|example)$/.test(host)
    )
      return false;
    if (host.includes(":")) return false; // Never send IPv6 literals to external providers.
    if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
      const p = host.split(".").map(Number);
      return !(
        p[0] === 0 ||
        p[0] === 10 ||
        p[0] === 127 ||
        p[0] >= 224 ||
        (p[0] === 169 && p[1] === 254) ||
        (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
        (p[0] === 192 && (p[1] === 168 || p[1] === 0)) ||
        (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
        (p[0] === 198 && [18, 19, 51].includes(p[1])) ||
        (p[0] === 203 && p[1] === 0)
      );
    }
    return true;
  }
  function normalizeConfig(defaults, saved = {}) {
    const bounded = (value, min, max, fallback) =>
      Number.isFinite(Number(value))
        ? Math.min(max, Math.max(min, Number(value)))
        : fallback;
    const s = saved.settings || {};
    const settings = {
      ...defaults.settings,
      ...s,
      checks: { ...defaults.settings.checks, ...(s.checks || {}) },
    };
    for (const key of [
      "saveHistory",
      "showBadge",
      "externalServices",
      "directoryConsent",
    ])
      settings[key] =
        s[key] === undefined ? defaults.settings[key] : s[key] === true;
    for (const key of Object.keys(CHECKS))
      settings.checks[key] = settings.checks[key] !== false;
    settings.checkTimeout = 60000;
    settings.cacheMinutes = bounded(settings.cacheMinutes, 0, 5, 5);
    settings.maxDirectoriesToCheck = Math.floor(
      bounded(settings.maxDirectoriesToCheck, 1, 10, 5),
    );
    settings.maxRequestsPerMinute = bounded(
      settings.maxRequestsPerMinute,
      30,
      60,
      60,
    );
    const apiKeys = {};
    for (const key of ["googleSafeBrowsing", "virusTotal"]) {
      const value = saved.apiKeys?.[key];
      apiKeys[key] =
        typeof value === "string" && !value.startsWith("YOUR_")
          ? value.trim().slice(0, 256)
          : "";
    }
    return { apiKeys, settings };
  }
  function scoreReport(checks) {
    let earned = 0,
      assessed = 0;
    for (const [key, value] of Object.entries(checks)) {
      if (
        CHECKS[key] &&
        ["passed", "warning", "failed"].includes(value.status) &&
        Number.isFinite(value.score)
      ) {
        assessed += CHECKS[key].max;
        earned += Math.max(0, Math.min(CHECKS[key].max, value.score));
      }
    }
    const total = Object.values(CHECKS).reduce(
      (sum, check) => sum + check.max,
      0,
    );
    let score = assessed ? Math.round((100 * earned) / assessed) : null;
    const threatDetected = ["safeBrowsing", "vulnerabilities"].some(
      (key) => checks[key]?.status === "failed",
    );
    if (threatDetected && score !== null) score = Math.min(20, score);
    return {
      overallScore: score,
      coverage: Math.round((100 * assessed) / total),
      assessedWeight: assessed,
      totalWeight: total,
      threatDetected,
    };
  }
  function recommendations(checks) {
    const items = [];
    for (const [key, check] of Object.entries(checks)) {
      if (!CHECKS[key] || !["warning", "failed"].includes(check.status))
        continue;
      items.push({
        check: key,
        priority: check.status === "failed" ? "high" : "medium",
        title: CHECKS[key].label,
        advice: CHECKS[key].advice,
      });
      for (const advice of check.details.recommendations || [])
        items.push({
          check: key,
          priority: "medium",
          title: CHECKS[key].label,
          advice,
        });
    }
    return items.sort(
      (a, b) =>
        (a.priority === "high" ? 0 : 1) - (b.priority === "high" ? 0 : 1),
    );
  }
  function compareReports(current, previous) {
    if (!previous || previous.url !== current.url) return null;
    const known = (check) =>
      check && ["passed", "warning", "failed"].includes(check.status);
    const sameCoverage = Object.keys(CHECKS).every(
      (key) => !!known(current.checks[key]) === !!known(previous.checks[key]),
    );
    const comparable =
      sameCoverage &&
      current.pageKey === previous.pageKey &&
      current.profile === previous.profile;
    const changes = Object.keys(CHECKS)
      .filter(
        (key) =>
          current.checks[key]?.status !== previous.checks[key]?.status ||
          current.checks[key]?.score !== previous.checks[key]?.score,
      )
      .map((key) => ({
        check: key,
        before: previous.checks[key]?.status || "unknown",
        after: current.checks[key]?.status || "unknown",
        beforeScore: previous.checks[key]?.score ?? null,
        afterScore: current.checks[key]?.score ?? null,
      }));
    return {
      previousTimestamp: previous.timestamp,
      comparable,
      scoreDelta:
        comparable &&
        current.overallScore !== null &&
        previous.overallScore !== null
          ? current.overallScore - previous.overallScore
          : null,
      changes,
    };
  }
  function escapeHtml(text) {
    return String(text).replace(
      /[&<>"']/g,
      (c) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          '"': "&quot;",
          "'": "&#39;",
        })[c],
    );
  }
  function publicReport(report) {
    const {
      id,
      version,
      url,
      timestamp,
      partial = false,
      overallScore,
      coverage,
      assessedWeight,
      totalWeight,
      threatDetected,
      checks,
      recommendations: advice,
      comparison,
    } = report;
    return {
      id,
      version,
      url,
      timestamp,
      partial,
      overallScore,
      coverage,
      assessedWeight,
      totalWeight,
      threatDetected,
      checks,
      recommendations: advice,
      comparison,
    };
  }
  function reportHtml(report) {
    const r = publicReport(report),
      e = escapeHtml;
    return (
      '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Security report</title><style>body{font:16px system-ui;max-width:850px;margin:40px auto;padding:20px;color:#182b44}article{padding:16px 0;border-bottom:1px solid #ccd5dd}pre{white-space:pre-wrap;overflow-wrap:anywhere}h1,h2{color:#164f74}</style><h1>Website Security Scanner</h1><p>' +
      e(r.url) +
      "</p><p>" +
      e(r.timestamp) +
      " · Version " +
      e(r.version) +
      "</p>" +
      (r.partial
        ? "<p><strong>Partial scan: cancelled or timed out. This report was not saved to history.</strong></p>"
        : "") +
      "<h2>Score: " +
      e(r.overallScore ?? "Unavailable") +
      "/100 · Coverage: " +
      e(r.coverage) +
      "%</h2><p>This is a limited assessment, not a guarantee of safety. Unknown checks earn no points and are excluded from the score. Coverage shows how much was assessed.</p>" +
      Object.entries(r.checks)
        .map(
          ([key, check]) =>
            "<article><h2>" +
            e(CHECKS[key]?.label || key) +
            " — " +
            e(check.status) +
            "</h2><p>" +
            e(check.details.message) +
            "</p><pre>" +
            e(JSON.stringify(check.details, null, 2)) +
            "</pre></article>",
        )
        .join("") +
      "<h2>Recommendations</h2><ul>" +
      (r.recommendations || [])
        .map((item) => "<li>" + e(item.priority + ": " + item.advice) + "</li>")
        .join("") +
      "</ul></html>"
    );
  }
  function abortError() {
    return new DOMException("Cancelled or timed out", "AbortError");
  }
  function withAbort(promise, signal) {
    return new Promise((resolve, reject) => {
      const cancel = () => reject(abortError());
      if (signal?.aborted) {
        Promise.resolve(promise).catch(() => {});
        reject(abortError());
        return;
      }
      signal?.addEventListener("abort", cancel, { once: true });
      Promise.resolve(promise)
        .then(resolve, reject)
        .finally(() => signal?.removeEventListener("abort", cancel));
    });
  }
  function delay(ms, signal) {
    return new Promise((resolve, reject) => {
      if (signal?.aborted) return reject(abortError());
      const cleanup = () => signal?.removeEventListener("abort", cancel);
      const timer = setTimeout(() => {
        cleanup();
        resolve();
      }, ms);
      const cancel = () => {
        clearTimeout(timer);
        cleanup();
        reject(abortError());
      };
      signal?.addEventListener("abort", cancel, { once: true });
    });
  }
  async function request(
    url,
    options = {},
    { signal, timeout = 8000, format = "json", maxBytes = 500000 } = {},
  ) {
    const controller = new AbortController();
    const abort = () => controller.abort();
    if (signal?.aborted) throw abortError();
    signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(abort, timeout);
    try {
      const response = await withAbort(
        fetch(url, {
          cache: "no-store",
          credentials: "omit",
          referrerPolicy: "no-referrer",
          redirect: "error",
          ...options,
          signal: controller.signal,
        }),
        controller.signal,
      );
      if (!response.ok)
        throw new Error(
          response.status === 429
            ? "Service rate limit reached. Try again later."
            : `Request failed (HTTP ${response.status}).`,
        );
      if (format === "response") return response;
      // The timer also bounds response body decoding, not just receipt of headers.
      const reader = response.body?.getReader();
      if (!reader) throw new Error("The service returned an empty response.");
      let size = 0;
      const chunks = [];
      try {
        while (true) {
          const part = await withAbort(reader.read(), controller.signal);
          if (part.done) break;
          size += part.value.byteLength;
          if (size > maxBytes)
            throw new Error("The response is too large to assess safely.");
          chunks.push(part.value);
        }
      } catch (error) {
        reader.cancel().catch(() => {});
        throw error;
      }
      const bytes = new Uint8Array(size);
      let offset = 0;
      for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
      }
      const text = new TextDecoder().decode(bytes);
      return format === "text" ? text : JSON.parse(text);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }
  const api = {
    CHECKS,
    result,
    skipped,
    errorResult,
    sanitizeUrl,
    isPublicHost,
    normalizeConfig,
    scoreReport,
    recommendations,
    compareReports,
    escapeHtml,
    publicReport,
    reportHtml,
    delay,
    request,
    abortError,
    withAbort,
  };
  root.ScannerCore = api;
  if (typeof module !== "undefined") module.exports = api;
})(globalThis);
