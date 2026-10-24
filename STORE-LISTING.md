# Chrome Web Store copy for 1.0.5

## Suggested description

Website Security Scanner gives you an on-demand assessment of the website in your current tab. Review the evidence behind each finding, the overall assessment score, and how much of the scan was completed.

Checks include HTTPS, TLS certificates through SSL Labs, Google Safe Browsing origin checks, VirusTotal domain reputation, SPF/DMARC email authentication, security header values, directory indexes, mixed content, and unsafe form configurations.

New in 1.0.5:

- Save up to 50 reports locally, search history, and delete individual reports or all scan data.
- Compare the previous scan, including changes to individual checks.
- Export JSON and standalone HTML reports.
- See progress, cancel scans, and reopen the popup while a scan runs.
- Select checks and choose whether to use external services.
- Reuse recent results or run a fresh scan.
- Detect mixed HTTP resources on HTTPS pages.
- Identify unsafe password and form submission configurations.
- Get prioritized recommendations for the findings.
- Show an optional per-tab score badge.

External services are off by default. Enabling them sends the site hostname to SSL Labs, Google Public DNS, and VirusTotal, and the site origin to Google Safe Browsing. Paths, queries, and fragments of the scanned page URL are not sent to these providers. Google Safe Browsing and VirusTotal require your own eligible API keys; the remaining checks work without those keys. Directory probing is separately opt-in and should only be used on sites you are authorized to test.

API keys, settings, and optional report history stay in local extension storage. There is no developer-operated collection server, advertising, or analytics. Clear history and cached scan data from the History tab, or turn history off in Settings.

This extension provides limited, heuristic checks. It does not guarantee a website is safe and is not a vulnerability audit. Scores include completed checks only; coverage shows the extent of the assessment. Historical provider results may be outdated. See the privacy policy for details and limits.

## Single purpose

Provide an on-demand security assessment of the website the user selects, with visible evidence, coverage, recommendations, and user-controlled local reports.

## Permission justifications

| Permission                  | Reason                                                                                                                     |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| activeTab                   | Temporarily access the URL and origin of the website selected by clicking the extension.                                   |
| scripting                   | Inspect current top-level resource URLs and form attributes for mixed content and insecure forms. No form values are read. |
| storage                     | Preserve user API keys/settings, optional local report history, and bounded session scan/cache data.                       |
| api.ssllabs.com             | Optional TLS certificate and endpoint configuration assessments after explicit opt-in.                                     |
| dns.google                  | Optional SPF/DMARC TXT lookups after explicit opt-in.                                                                      |
| safebrowsing.googleapis.com | Optional Safe Browsing origin lookup using the user's key, after explicit opt-in.                                          |
| www.virustotal.com          | Optional domain reputation lookup using the user's key, after explicit opt-in.                                             |

No remote code is used. All executable JavaScript is packaged with the extension. External APIs return data only.

## Privacy practices to update in the dashboard

Replace the old blanket statement that no data is handled. The extension reads the selected website, keeps optional local scan reports, processes top-level resource/form metadata, and stores user-supplied API keys. External lookup transfers happen only after explicit opt-in.

Review the dashboard's current category definitions for **Web history** (selected URLs and reports), **Website content** (resource URLs and form attributes), and **Authentication information** (user-supplied API credentials). Local storage alone does not exempt handled data from disclosure. No password/form values, payments, health information, advertising profiles, or analytics are collected. Final selections should describe the actual data handling above rather than copying the old listing's declarations.

Use the policy content in `privacy.html` to replace the hosted policy at:
https://mobilestudios.ca/privacy-policy-website-security-scanner-chrome-extension/

A policy bundled inside the ZIP does not update that website. The hosted policy must be published before submitting the update. No hosting/account changes have been made by this project.

Chrome references: [Update an existing item](https://developer.chrome.com/docs/webstore/update), [User data policy FAQ](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq).
