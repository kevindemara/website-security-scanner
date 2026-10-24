# Website Security Scanner

Chrome extension version **1.0.5**. Run a visible, on-demand assessment of the current website, with evidence, coverage, and recommendations. A score is not a guarantee of safety or a vulnerability audit.

## Load locally

1. Open `chrome://extensions` in Chrome 120 or newer.
2. Turn on Developer mode, select **Load unpacked**, and choose this repository folder.
3. Open an HTTP or HTTPS website, click the extension icon, then **Scan site**.
4. Use **Settings** to select checks. External security services and directory probing are off by default.

There is no production build step or runtime dependency. Node and npm are only needed for development, tests, and release packaging.

## Ten additions in 1.0.5

1. **Local history:** retain up to 50 reports, search by hostname, open reports, delete one, or clear all scan data.
2. **Comparison:** compare the previous report for the same origin, including changes to individual check statuses and points. Score deltas require the same page, settings, and assessed checks.
3. **Export:** download JSON or a standalone HTML report. Keys, settings, page fingerprints, URL credentials, and scanned URL query strings are excluded.
4. **Progress and cancellation:** see completed checks, cancel work, and reopen the popup during a scan. Interrupted worker jobs surface a retry message. Cancelled reports are not saved to history or cache.
5. **Check controls:** select checks individually. External services require opt-in; directory probing requires its own authorization confirmation.
6. **Cache:** reuse matching page/settings reports for up to five minutes, or select **Scan fresh**. Cache is limited to 20 reports in browser session storage.
7. **Mixed content:** inspect HTTP resource references and recorded requests on an HTTPS page.
8. **Form security:** detect HTTP submissions, passwords on HTTP pages, passwords submitted without POST, unsafe destinations, and cross-origin password forms requiring review.
9. **Recommendations:** prioritize fixes and evaluate useful header values, including CSP, HSTS, frame protection, MIME sniffing, referrer policy, and permissions policy. No points are awarded for obsolete X-XSS-Protection.
10. **Toolbar badge:** optional per-tab score, with a red badge for failed checks and amber for limited coverage. Navigation clears the badge.

## What the checks mean

| Check                | Data source                                           | Maximum weight |
| -------------------- | ----------------------------------------------------- | -------------: |
| HTTPS                | Current page URL                                      |             20 |
| TLS certificate      | SSL Labs, optional                                    |             15 |
| Safe Browsing        | Google Safe Browsing, optional key                    |             15 |
| Domain reputation    | VirusTotal, optional key                              |             15 |
| Email authentication | Google Public DNS, optional                           |             10 |
| Directory listings   | Up to 10 unauthenticated common-path requests, opt-in |             10 |
| Security headers     | A new unauthenticated HEAD request                    |             15 |
| Mixed content        | Current top-level page                                |             10 |
| Form security        | Current top-level page                                |             10 |

The score is normalized over assessed checks. Skipped, unavailable, or cancelled checks do not earn points and do not count toward assessed weight. **Coverage** is assessed weight divided by all 120 possible points. Reputation threat detections cap the score at 20. A high score at low coverage is incomplete.

Scans have a 60-second overall deadline. Individual network requests include an eight-second body/read deadline. SSL Labs polling is bounded to approximately 40 seconds and consumes an immediately completed response without an unnecessary wait. Scans run checks concurrently.

## Privacy

Read [privacy.html](privacy.html) for the full policy. The extension uses temporary `activeTab` access rather than permanent access to every website. External provider host permissions are restricted to SSL Labs, Google DNS, Google Safe Browsing, and VirusTotal. No analytics, account, developer backend, remote scripts, or advertising is included.

Keys are preserved when upgrading from 1.0.4. External lookups remain disabled until you explicitly enable them. History stays on your device, can be disabled, and has deletion controls. The scanned page's path, query, and fragment are not sent to external providers: Safe Browsing checks only the origin; the other providers receive hostnames. Sanitized resource and form destination paths may be stored in local reports. Page/header checks contact the site itself. Requests omit cookies and referrers.

## Development and verification

```powershell
npm ci
npx playwright install chromium
npm run check
npm test
npm run test:browser
npm run format:check
npm run package
```

Node 22 or newer is recommended. The browser suite loads the actual Manifest V3 extension in Chromium, triggers its action to grant temporary host access, exercises a controlled HTTP server, and inspects real page DOM. External provider responses use deterministic fixtures, not live API keys. Browser artifacts are written to `test-results/`.

On Windows environments with Chromium's version-assembly startup failure, the test launcher creates an isolated sibling copy of the downloaded **test browser**, removes only its redundant version assembly lookup, and leaves the original executable and installed browsers unchanged. This workaround is not included in the extension ZIP. Set `SCANNER_CHROMIUM_EXECUTABLE` to test with another compatible Chromium binary.

The ZIP is created from the explicit allowlist in `scripts/release-files.cjs`. Tests, source-control files, Node dependencies, developer documentation, and credentials are excluded. The manifest is at the ZIP root.

See [RELEASE-1.0.5.md](RELEASE-1.0.5.md) for upload instructions and [STORE-LISTING.md](STORE-LISTING.md) for replacement listing/privacy text.

## Limits

Checks inspect the top-level page at one moment, not future behavior, shadow DOM, or cross-origin frame contents. Form values are never inspected. Header checks use a fresh unauthenticated response with URL queries removed, which may differ from the original navigation. Redirects are not followed for header checks or directory probes. Network errors are unknown, not a pass. A directory URL returning 200 alone is not a finding; recognizable index HTML is required. Email checks inspect the exact hostname, not public-suffix organizational-domain inheritance or full SPF policy evaluation. Private-name/IP filtering does not resolve DNS, and public-looking names can route privately. SSL Labs and reputation reports can be historical even when selecting Scan fresh.
