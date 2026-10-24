# Website Security Scanner 1.0.5

Remove the hourly reminder `finish-website-security-scanner-1-0-5` when this release is complete.

## Release fixes

- Preserve saved configuration during installation and updates.
- Interpret SSL Labs endpoint grades and certificate dates conservatively.
- Bound requests and the entire scan; cancel actual work on timeout.
- Update privacy documentation and show explicit external-service consent.
- Replace simulated tests with regression and browser coverage.

## Ten features

1. Local history (50 reports), search, individual deletion and clear-all.
2. Comparison with the previous report for the same origin.
3. JSON and standalone HTML exports, without API keys or URL queries.
4. Live progress, cancellation, and reopening an in-progress scan.
5. Individual check controls; external services and directory probing opt in.
6. Bounded five-minute cache and a fresh-scan override.
7. Mixed-content inspection of the active page.
8. Insecure form and password submission checks.
9. Prioritized, actionable recommendations and header value analysis.
10. Optional, tab-specific toolbar score badges.

## Validation and delivery

- Node regression tests exercise production modules with deterministic network fixtures.
- Chromium loads the real Manifest V3 extension for browser integration tests.
- Release ZIP uses an explicit allowlist; manifest at root; no tests, keys, or dependencies.
- Deliver release notes, store/privacy text and exact verification results.

## Progress

- Complete: all release fixes and ten features implemented in version 1.0.5.
- Complete: 55 regression tests and 17 actual-extension Chromium scenarios pass.
- Complete: live Google DNS and SSL Labs responses validated.
- Complete: release ZIP independently verified; details in VERIFICATION.md.
- Complete: release, store listing, privacy policy and upload instructions prepared.
- Remaining publisher actions: host the replacement privacy policy, update dashboard declarations, and upload/submit the ZIP. These are described in RELEASE-1.0.5.md.
- The hourly fallback reminder was removed after all implementation and validation work completed. No Chrome Web Store update or hosted privacy-policy change has been published.
