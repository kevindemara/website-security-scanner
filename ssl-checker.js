class SslChecker {
  static analyze(data, now = Date.now()) {
    const C = globalThis.ScannerCore;
    if (data.status !== "READY")
      throw new Error(
        data.status === "ERROR"
          ? "SSL Labs could not assess this host."
          : "SSL assessment is not ready. Try a fresh scan later.",
      );
    const endpoints = data.endpoints || [];
    const grades = {
      "A+": 15,
      A: 15,
      "A-": 13,
      B: 10,
      C: 5,
      D: 3,
      E: 1,
      F: 0,
      T: 0,
      M: 0,
    };
    if (
      !endpoints.length ||
      endpoints.some(
        (e) => !Object.hasOwn(grades, e.grade) || e.statusMessage !== "Ready",
      )
    )
      throw new Error(
        "SSL Labs did not return a complete grade for every endpoint.",
      );
    if (
      endpoints.some(
        (endpoint) =>
          !Array.isArray(endpoint.details?.certChains) ||
          !endpoint.details.certChains.length ||
          endpoint.details.certChains.some((chain) => !chain.certIds?.[0]),
      )
    )
      throw new Error(
        "Endpoint certificate validity information is incomplete.",
      );
    const leafIds = new Set(
      endpoints.flatMap(
        (e) =>
          e.details?.certChains
            ?.map((chain) => chain.certIds?.[0])
            .filter(Boolean) || [],
      ),
    );
    // Never assume the first certificate is the site's leaf certificate.
    const certs = (data.certs || []).filter((cert) => leafIds.has(cert.id));
    if (
      !leafIds.size ||
      certs.length !== leafIds.size ||
      certs.some(
        (cert) =>
          !Number.isFinite(cert.notAfter) || !Number.isFinite(cert.notBefore),
      )
    )
      throw new Error(
        "Endpoint certificate validity information is incomplete.",
      );
    let score = Math.min(...endpoints.map((e) => grades[e.grade]));
    const daysToExpiry = Math.floor(
      (Math.min(...certs.map((c) => c.notAfter)) - now) / 86400000,
    );
    if (daysToExpiry < 0 || certs.some((c) => c.notBefore > now)) score = 0;
    else if (daysToExpiry < 30) score = Math.min(score, 10);
    const status = score === 0 ? "failed" : score < 13 ? "warning" : "passed";
    return C.result(
      status,
      score,
      status === "failed"
        ? "TLS has certificate or configuration failures."
        : daysToExpiry < 30
          ? "A certificate expires in less than 30 days."
          : "TLS assessment available for every endpoint.",
      {
        daysToExpiry,
        endpointCount: endpoints.length,
        endpoints: endpoints.slice(0, 32).map((e) => ({
          ipAddress: String(e.ipAddress || "").slice(0, 100),
          grade: e.grade,
        })),
        certificates: certs.slice(0, 32).map((c) => ({
          subject: String(c.subject || "").slice(0, 300),
          issuer: String(c.issuerSubject || "").slice(0, 300),
          validFrom: new Date(c.notBefore).toISOString(),
          validTo: new Date(c.notAfter).toISOString(),
        })),
        assessedAt: data.testTime
          ? new Date(data.testTime).toISOString()
          : "Not provided",
      },
    );
  }
  async check(domain, signal) {
    const C = globalThis.ScannerCore,
      deadline = Date.now() + 40000;
    const url =
      "https://api.ssllabs.com/api/v3/analyze?host=" +
      encodeURIComponent(domain) +
      "&publish=off&fromCache=on&all=done";
    while (true) {
      const data = await C.request(
        url,
        {},
        { signal, timeout: Math.max(1, Math.min(8000, deadline - Date.now())) },
      );
      if (data.errors)
        throw new Error("SSL Labs rejected the assessment request.");
      if (["READY", "ERROR"].includes(data.status))
        return SslChecker.analyze(data);
      if (Date.now() + 5000 >= deadline)
        throw new Error(
          "SSL Labs is still assessing this host. Try a fresh scan later.",
        );
      await C.delay(5000, signal);
    }
  }
}
if (typeof module !== "undefined") module.exports = SslChecker;
