# Troubleshooting 1.0.5

- **Cannot scan this page:** use a regular HTTP or HTTPS site. Chrome internal pages and the Chrome Web Store are restricted. Click the extension icon on the site to grant temporary access.
- **Unavailable headers:** the site may not support HEAD, may redirect, or may not serve an unauthenticated response without its URL query. The result is unknown; the extension does not silently award points or retry authenticated requests.
- **Skipped external checks:** enable external security lookups in Settings and add keys for Safe Browsing and VirusTotal. Local/private names and literal private IP ranges are excluded. SSL Labs applies only to HTTPS sites.
- **SSL Labs is still assessing:** other checks finish independently. Retry with Scan fresh later. The extension never waits indefinitely and never interprets missing grades or certificates as a pass.
- **Request failed or rate limited:** verify your key and provider access; retry later. Keys and provider request URLs are not logged.
- **Low coverage:** some checks are disabled, unavailable, inapplicable, or missing keys. Coverage explains the extent of the assessment. A high score does not mean every check passed.
- **Outdated results:** choose Scan fresh. SSL Labs and VirusTotal may still return their own earlier assessments; review the result dates.
- **Progress after reopening:** running jobs are stored in session storage. If Chrome terminates the worker unexpectedly, the extension prompts you to retry. Closing or navigating the scanned tab cancels its job.
- **Delete data:** History > Clear all scan data stops active scans and clears history, session jobs, and cache. Keys remain in Settings until you clear them and save. Exported files must be deleted separately.

For extension errors, open `chrome://extensions`, enable Developer mode, and inspect the extension's service worker or right-click its popup and choose Inspect. Report reproducible steps and the Chrome version through [GitHub issues](https://github.com/kevindemara/website-security-scanner/issues). Do not share your API keys or private website URLs.
