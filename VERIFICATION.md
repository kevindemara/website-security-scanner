# Verification — Website Security Scanner 1.0.5

Date: October 23, 2026 (America/Toronto).

**Story:** a user selects a site, runs the extension, reviews real check evidence and coverage, controls optional providers, and manages local scan reports without exposing API keys or form values.

## Final results

| Check                                                                              | Result                      |
| ---------------------------------------------------------------------------------- | --------------------------- |
| Production manifest, JSON, JavaScript syntax, asset references and icon dimensions | Passed                      |
| Automated regression tests against production modules                              | 55 passed; 0 failed/skipped |
| Chromium integration scenarios with the actual MV3 extension                       | 17 passed; 0 failed         |
| Live Google Public DNS response parsing                                            | Passed                      |
| Live SSL Labs response/endpoint/certificate parsing                                | Passed                      |
| Formatting and Git whitespace validation                                           | Passed                      |
| Independent ZIP CRC, file list, root manifest and source-byte comparison           | Passed                      |

Runtime: Node 24.19.0; Chromium 156.0.8078.4; Playwright 1.64.1 on Windows. Browser startup required an isolated test-executable copy to work around the host's private assembly resolution failure. The original downloaded executable and installed browsers were not modified. The workaround is part of the development test launcher only.

## Regression boundaries

The 55 Node tests cover migration and legacy placeholders; conservative consent defaults; private hostname/IP filters; sanitization; scores/coverage/threat caps; comparison matching; export escaping and excluded fields; recommendations; SSL worst endpoint grades, expiry and incomplete certificates; useful header values and duplicate/overridden CSP directives; bounded requests/body streaming; cancellation; rate-limit errors; Safe Browsing payloads; VirusTotal empty-result handling; DNS failures and split TXT strings; directory-index detection versus ordinary pages; storage concurrency; history/cache limits; cache expiry; cancelled jobs; worker interruption; navigation; deletion; message sender checks; and browser-internal pages.

## Browser boundaries

The Chromium suite uses a real loaded extension, real Chrome storage/tabs/action/scripting APIs, and a controlled local HTTP server. It triggers the extension action through Chrome DevTools Protocol so tests genuinely use temporary activeTab access. Popup interactions run in the extension's own page, without replacing Chrome APIs.

- real extension loads with temporary activeTab access and no startup errors.
- actual HTTP scan reaches page, unauthenticated HEAD response and report UI.
- score badge and recommendations reflect completed scan.
- cache reuse avoids network and history duplication.
- fresh scan compares the previous matching page.
- JSON and standalone HTML downloads are safe and contain report evidence.
- history supports search, viewing and individual deletion.
- settings save check controls, masked keys and badge preference.
- directory probing requires consent and finds a real directory index.
- HTTPS DOM inspection detects mixed resources and insecure forms.
- HTTPS forms distinguish secure POST, external sign-in and passwordless pages.
- external lookup payloads omit the page path, tokens and fragment.
- progress survives closing and reopening the popup and cancellation stops work.
- clear all removes saved and cached reports while retaining configured keys.
- keyboard tab navigation and responsive layout avoid horizontal overflow.
- internal browser pages are rejected without breaking settings/history.
- real browser restart migrates legacy saved keys and keeps external services opt-in.

Actual HTTP requests verified that same-origin header and directory requests omit cookies and scanned URL query strings. Real HTTPS DOM fixtures verified mixed-resource findings, secure/insecure form configurations, form-button submission overrides, safe text rendering, and absence of password values. Browser screenshots are `test-results/popup-scan.png` and `test-results/popup-settings.png`. JSON and HTML exports were downloaded and inspected.

## External services and limits

Browser tests replace external provider network responses with deterministic fixtures while exercising the production request, parsing, scoring, settings, and rendering code. No real Safe Browsing or VirusTotal keys were supplied, so their account authentication, subscription permissions, quotas, and live reputation results were **not** verified. Users must verify their own eligible keys in Settings.

The credential-free live smoke checks used provider-owned public domains. Google Public DNS returned a valid response for google.com; the email policy check reported a warning, which is an assessed outcome rather than a test failure. SSL Labs returned a complete, parseable assessment for www.ssllabs.com. Machine-readable results are in `test-results/live-results.json`.

This is engineering validation, not Chrome Web Store approval or an exhaustive security audit. The hosted privacy policy and dashboard declarations still require the publisher's update using the supplied files. Developer-account access and Verified CRX Uploads settings were not checked.

## Artifact

`dist/website-security-scanner-1.0.5.zip` — 64,424 bytes; 18 allowlisted extension files. ZIP entries were independently checked with Python zipfile, including CRCs, blank API keys, version 1.0.5, root manifest, and exact equality to the tested source files.

SHA-256: `49bb13b9631707f1bed478b3603823c5eb0203118d41a8e9f6d8c127d74e82f4`

Reproduce with `npm ci`, `npx playwright install chromium`, `npm run check`, `npm test`, `npm run test:browser`, `npm run test:live`, `npm run format:check`, and `npm run package`.

## UI refresh

Refreshed the unpublished 1.0.5 popup with pill tabs, clearer cards and status labels, improved spacing and typography, sticky navigation, and larger interaction targets. All runtime JavaScript, manifest, permissions, and configuration files were confirmed byte-for-byte unchanged. The 55 regression tests and 17 Chromium integration scenarios pass with the refresh. Additional visual review covers Scan, History, and Settings at 320, 360, and 460 pixels, text/status contrast, keyboard focus, forced colors, and reduced motion. Visual review evidence is in test-results/ui-refresh-review.json; the illustrative preview is test-results/ui-refresh-preview.png.

## Backed-up evidence

Copies of the browser, live-provider, and UI review summaries, along with the UI preview and settings screenshot, are included in `release-assets/1.0.5/`. The generated release ZIP and SHA-256 file are also tracked under `dist/`. Temporary profiles and other test artifacts remain excluded.
