exports.ssl = (grade = "A", expiresInDays = 90) => {
  const now = Date.now();
  return {
    status: "READY",
    testTime: now,
    endpoints: [
      {
        grade,
        statusMessage: "Ready",
        ipAddress: "93.184.216.34",
        details: { certChains: [{ certIds: ["leaf"] }] },
      },
    ],
    certs: [
      {
        id: "leaf",
        notBefore: now - 86400000,
        notAfter: now + expiresInDays * 86400000,
        subject: "CN=scanner.test",
        issuerSubject: "Fixture CA",
      },
    ],
  };
};
exports.headers = {
  "Content-Security-Policy":
    "default-src 'self'; script-src 'self'; frame-ancestors 'none'",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=()",
};
