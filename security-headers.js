class SecurityHeadersChecker {
  checkSecurityHeaders(headers) {
    const C = globalThis.ScannerCore;
    const h = {};
    if (headers instanceof Headers)
      headers.forEach((value, key) => {
        h[key.toLowerCase()] = value;
      });
    else
      for (const [key, value] of Object.entries(headers))
        h[key.toLowerCase()] = String(value);
    const recommendations = [],
      headerDetails = [];
    const csp = h["content-security-policy"] || "";
    const directives = {};
    for (const part of csp.split(";")) {
      const [key, ...values] = part.trim().split(/\s+/);
      if (key && !Object.hasOwn(directives, key.toLowerCase()))
        directives[key.toLowerCase()] = values;
    }
    const scriptSources =
      directives["script-src"] || directives["default-src"] || [];
    const safeScripts = [
      scriptSources,
      directives["script-src-elem"] || scriptSources,
      directives["script-src-attr"] || scriptSources,
    ].every(
      (sources) =>
        sources.length > 0 &&
        !sources.some((value) =>
          [
            "'unsafe-inline'",
            "'unsafe-eval'",
            "*",
            "http:",
            "https:",
            "data:",
          ].includes(value),
        ),
    );
    const frameAncestors = directives["frame-ancestors"];
    const frameSafe =
      frameAncestors?.length > 0 &&
      !frameAncestors.includes("*") &&
      !frameAncestors.some((value) => ["http:", "https:"].includes(value));
    const maxAge = h["strict-transport-security"]?.match(
      /(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i,
    );
    const rules = [
      [
        "Content-Security-Policy",
        4,
        safeScripts,
        "Define script-src or default-src with narrow trusted sources; avoid unsafe-inline, unsafe-eval, and wildcards.",
      ],
      [
        "Strict-Transport-Security",
        4,
        !!maxAge && Number(maxAge[1]) >= 31536000,
        "Set HSTS max-age to at least 31536000 after confirming HTTPS works for your site.",
      ],
      [
        "X-Content-Type-Options",
        2,
        h["x-content-type-options"]?.toLowerCase() === "nosniff",
        "Set X-Content-Type-Options: nosniff.",
      ],
      [
        "Frame protection",
        2,
        frameSafe || /^(DENY|SAMEORIGIN)$/i.test(h["x-frame-options"] || ""),
        "Restrict embedding with CSP frame-ancestors 'self' or 'none', or X-Frame-Options.",
      ],
      [
        "Referrer-Policy",
        2,
        [
          "no-referrer",
          "same-origin",
          "strict-origin",
          "strict-origin-when-cross-origin",
        ].includes(h["referrer-policy"]?.toLowerCase()),
        "Use a restrictive Referrer-Policy, such as strict-origin-when-cross-origin.",
      ],
      [
        "Permissions-Policy",
        1,
        /\w+\s*=\s*\(/.test(h["permissions-policy"] || ""),
        "Define a Permissions-Policy for sensitive browser features your application does not need.",
      ],
    ];
    let score = 0;
    for (const [name, weight, valid, advice] of rules) {
      if (valid) score += weight;
      else recommendations.push(advice);
      headerDetails.push({
        name,
        status: valid ? "passed" : "warning",
        value: (name === "Frame protection"
          ? h["content-security-policy"] || h["x-frame-options"] || "Missing"
          : h[name.toLowerCase()] || "Missing"
        ).slice(0, 2000),
      });
    }
    return C.result(
      score === 15 ? "passed" : score >= 7 ? "warning" : "failed",
      score,
      score === 15
        ? "Core security headers are present with useful values."
        : "Security headers are missing or have weak values.",
      {
        headerDetails,
        recommendations,
        limitation:
          "Heuristic review of a new unauthenticated HEAD response. This may differ from the loaded page; it does not fully validate CSP syntax. Deprecated X-XSS-Protection is not required.",
      },
    );
  }
}
if (typeof module !== "undefined") module.exports = SecurityHeadersChecker;
