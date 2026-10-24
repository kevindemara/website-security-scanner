class SafeBrowsingClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
  }
  async checkUrl(url, signal) {
    const C = globalThis.ScannerCore;
    if (!this.apiKey)
      return C.skipped("Add a Google Safe Browsing API key in Settings.");
    // Only the site origin is submitted; paths, queries, and fragments stay private.
    const data = await C.request(
      "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=" +
        encodeURIComponent(this.apiKey),
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: {
            clientId: "website-security-scanner",
            clientVersion: "1.0.5",
          },
          threatInfo: {
            threatTypes: [
              "MALWARE",
              "SOCIAL_ENGINEERING",
              "UNWANTED_SOFTWARE",
              "POTENTIALLY_HARMFUL_APPLICATION",
            ],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url: new URL(url).origin + "/" }],
          },
        }),
      },
      { signal },
    );
    if (
      !data ||
      typeof data !== "object" ||
      Array.isArray(data) ||
      (data.matches !== undefined && !Array.isArray(data.matches))
    )
      throw new Error("Invalid Safe Browsing response.");
    const threats = (data.matches || []).map((match) =>
      String(match.threatType || "Unknown threat").slice(0, 100),
    );
    return C.result(
      threats.length ? "failed" : "passed",
      threats.length ? 0 : 15,
      threats.length
        ? "Google Safe Browsing flagged this site origin."
        : "No listed threats found for this site origin. Individual pages were not checked.",
      { threatTypes: threats.slice(0, 20) },
    );
  }
}
if (typeof module !== "undefined") module.exports = SafeBrowsingClient;
