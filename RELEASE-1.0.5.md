# Release 1.0.5

## Upload artifact

`dist/website-security-scanner-1.0.5.zip`

Upload this ZIP to the **existing** Website Security Scanner item, ID `pdiemljmfgdabpogapllfdabcnnleffd`, rather than creating a new item. The ZIP contains only the extension's 18 runtime/assets files, with `manifest.json` at the root. No private signing key is required for a normal ZIP upload; if your account has enabled Verified CRX Uploads, use its configured signing procedure instead.

## Fixed

- Saved API keys/settings survive an update. New defaults are merged without replacing user keys.
- SSL scoring uses the worst endpoint grade and each endpoint's referenced leaf certificate. Expired/not-yet-valid certificates fail; missing/unknown data stays unavailable.
- Checks run concurrently. A 60-second whole-scan deadline, bounded network/body reads, bounded SSL polling, and actual cancellation prevent indefinite waiting.
- Errors and skipped checks never receive invented points. Coverage and assessment limits are visible. Reputation threats cap the score.
- Untrusted result text is rendered safely. HTML exports escape all result text. No remotely hosted scripts or evaluated code are used.
- API configuration is no longer web-accessible. Permanent HTTP/HTTPS access was replaced by activeTab and four specific provider origins.
- External lookups require explicit opt-in, including after a 1.0.4 migration. Privacy documentation covers SSL Labs, DNS, local reports, form/resource metadata, and deletion.

## Visual refresh

Updated the popup styling with modern cards, pill tabs, clearer status labels, improved spacing, and sticky navigation. All controls and scan behavior are preserved. This is included in the same unpublished 1.0.5 ZIP.

## Ten implemented features

See the numbered feature list in [README.md](README.md): history; comparisons; JSON/HTML export; progress/cancel/reopen; check/service controls; cache/fresh scan; mixed content; form security; recommendations; toolbar badges.

## Before submitting

1. Publish the replacement content in `privacy.html` at the privacy-policy URL already used by the store listing. The bundled policy is complete, but cannot replace the hosted page by itself.
2. Update the listing and privacy practices using [STORE-LISTING.md](STORE-LISTING.md). The new release stores optional local reports and makes disclosed, optional third-party transfers.
3. Review the unpacked extension locally if desired. Use Chrome 120 or newer. No keys are needed for local checks. Add your own eligible keys in Settings to verify your specific Safe Browsing and VirusTotal accounts.
4. Sign into the developer account that owns the listing. In its Package tab, upload the ZIP, update changed metadata, and submit for review. Store approval and developer-account settings cannot be established from this repository.

All features are included in 1.0.5. Source code and the upload ZIP are backed up in this repository. The Chrome Web Store update, listing changes, and hosted privacy policy still require the publisher's submission.

## Verification

The final verification counts and environment are recorded in [VERIFICATION.md](VERIFICATION.md). Browser screenshots, exports, and machine-readable summaries are under `test-results/`. The ZIP has a sibling SHA-256 file.

## Backed-up release evidence

UI previews and machine-readable browser, live-provider, and layout verification summaries are saved in `release-assets/1.0.5/`. Temporary browser profiles, dependencies, and test traces are excluded from version control.
