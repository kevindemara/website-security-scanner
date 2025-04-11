# Website Security Scanner - Production Version

## API Configuration Instructions

This production version of the Website Security Scanner Chrome extension uses real API integrations for more accurate security checks. Follow these instructions to configure the necessary API keys.

### Required API Keys

1. **Google Safe Browsing API Key**
   - Used for checking if websites are flagged as malicious
   - [Get a Google Safe Browsing API key](https://developers.google.com/safe-browsing/v4/get-started)

2. **VirusTotal API Key**
   - Used for vulnerability scanning and reputation checks
   - [Get a VirusTotal API key](https://developers.virustotal.com/reference)

### Configuration Steps

1. **Open the extension directory**
   - After extracting the extension files, locate the `config.json` file in the root directory

2. **Edit the config.json file**
   - Replace the placeholder values with your actual API keys:

```json
{
  "apiKeys": {
    "googleSafeBrowsing": "YOUR_GOOGLE_SAFE_BROWSING_API_KEY",
    "virusTotal": "YOUR_VIRUSTOTAL_API_KEY"
  },
  "settings": {
    "checkTimeout": 10000,
    "maxDirectoriesToCheck": 10,
    "maxRequestsPerMinute": 30
  }
}
```

3. **Save the file**
   - Make sure to save the changes to `config.json`

4. **Load or reload the extension**
   - If you're installing for the first time, follow the installation instructions
   - If you're updating an existing installation, go to `chrome://extensions/`, find the Website Security Scanner, and click the refresh icon

### API Usage Notes

#### Google Safe Browsing API
- Free tier allows up to 100,000 URLs per day
- Requires a Google Cloud Platform account
- API documentation: [Safe Browsing API v4](https://developers.google.com/safe-browsing/v4/reference/rest)

#### VirusTotal API
- Free tier allows up to 4 requests per minute
- Public API has a daily quota
- API documentation: [VirusTotal API v3](https://developers.virustotal.com/reference)

### Fallback Behavior

If API keys are not configured:
- The extension will still function but with reduced capabilities
- Security checks that require API keys will show warnings
- The overall security score will be calculated based on available checks only

### Troubleshooting

If you encounter issues with the API integrations:

1. **Verify API keys**
   - Double-check that your API keys are entered correctly
   - Ensure there are no extra spaces or characters

2. **Check API quotas**
   - If you're getting errors, you may have exceeded your API quota
   - VirusTotal has strict rate limits on the free tier

3. **Network issues**
   - Make sure your browser has internet access
   - Some corporate networks may block API requests

4. **Console errors**
   - Open Chrome DevTools (F12) and check the console for error messages
   - Look for specific API error responses

### Privacy Notice

- All API requests are made directly from your browser
- Your API keys are stored locally in the extension and are not sent to any servers other than the respective API providers
- Website URLs are sent to the configured APIs for security checking
- No browsing history or personal data is collected or transmitted
