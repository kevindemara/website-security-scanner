# Optional external services

Version 1.0.5 ships with no API keys. Never put developer-wide secret keys into `config.json`: extension packages are readable by their users.

Open the extension, choose **Settings**, and review the external-services disclosure before enabling **Allow external security lookups**. Select the checks you want. Add your own Google Safe Browsing and/or VirusTotal keys, then **Save settings**. Keys are masked by default, stored in Chrome local extension storage, preserved on upgrade, and excluded from exports. Clear a field and save to remove a key.

- **Google Safe Browsing:** requires a key enabled for the Safe Browsing v4 API. Only the site origin is checked; paths, queries, and fragments are not sent. See the [official API guide](https://developers.google.com/safe-browsing/v4/get-started).
- **VirusTotal:** requires a key with access to the domain reputation API. This is historical reputation, not an active vulnerability audit. See the [official domain reference](https://docs.virustotal.com/reference/domain-info).
- **SSL Labs:** no extension-configured key. An assessment may take longer than the scan's bounded waiting period; the result is then unavailable, with a retry instruction. See the [API documentation](https://github.com/ssllabs/ssllabs-scan/blob/master/ssllabs-api-docs-v3.md).
- **Google Public DNS:** no extension-configured key. TXT queries inspect SPF and DMARC for the exact hostname. See the [JSON API documentation](https://developers.google.com/speed/public-dns/docs/doh/json).

Provider quotas, access requirements, and terms can change. Use your own eligible credentials and consult the provider's current terms. Rate-limit, authentication, timeout, and unavailable-result errors do not earn score points. Missing keys skip the affected check.

Directory probing has a separate checkbox confirming authorization. It sends unauthenticated GET requests to the current site and does not involve a third-party scanning service.

Read [privacy.html](privacy.html) for data transfers and retention.
