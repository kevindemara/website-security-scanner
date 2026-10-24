class DirectoryChecker {
  constructor(settings = {}) {
    this.limit = Math.min(10, Math.max(1, settings.maxDirectoriesToCheck || 5));
    this.delayMs =
      60000 / Math.min(60, Math.max(30, settings.maxRequestsPerMinute || 60));
    this.paths = [
      "/backup/",
      "/logs/",
      "/config/",
      "/files/",
      "/uploads/",
      "/old/",
      "/temp/",
      "/test/",
      "/database/",
      "/private/",
    ];
  }
  isDirectoryListing(html) {
    return /<(?:title|h1)[^>]*>\s*(?:Index of\s*\/|Directory listing for\s*\/)/i.test(
      html,
    );
  }
  async checkExposedDirectories(url, signal) {
    const C = globalThis.ScannerCore,
      checkedDirectories = [],
      exposedDirectories = [],
      errors = [];
    const origin = new URL(url).origin;
    for (const path of this.paths.slice(0, this.limit)) {
      if (checkedDirectories.length) await C.delay(this.delayMs, signal);
      checkedDirectories.push(path);
      try {
        // No cookies, no cross-origin redirects, and no arbitrary file downloads.
        const response = await C.request(
          origin + path,
          { redirect: "manual" },
          { signal, format: "text" },
        );
        if (this.isDirectoryListing(response.slice(0, 200000)))
          exposedDirectories.push(path);
      } catch (error) {
        if (signal?.aborted) throw error;
        // 401/403/404 are expected access controls, not failed networking.
        if (!/HTTP (?:401|403|404)/.test(error.message)) errors.push(path);
      }
    }
    if (!exposedDirectories.length && errors.length)
      return C.result(
        "error",
        null,
        "Some directory requests could not be assessed.",
        { checkedDirectories, errors },
      );
    return C.result(
      exposedDirectories.length ? "failed" : "passed",
      exposedDirectories.length ? 0 : 10,
      exposedDirectories.length
        ? "Public directory indexes detected."
        : "No directory indexes detected in the checked paths.",
      {
        checkedDirectories,
        exposedDirectories,
        errors,
        limitation:
          "Accessible pages are not treated as exposed directories. Only recognizable directory indexes are flagged.",
      },
    );
  }
}
if (typeof module !== "undefined") module.exports = DirectoryChecker;
