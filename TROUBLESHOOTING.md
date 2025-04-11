# Troubleshooting Guide for Website Security Scanner

This guide will help you resolve common issues with the Website Security Scanner Chrome extension.

## Common Issues and Solutions

### 1. Extension Not Loading or Crashing

**Symptoms:**
- Extension icon appears grayed out
- Clicking the extension icon does nothing
- Extension crashes immediately after opening

**Solutions:**
- Ensure you're using a supported Chrome version (version 88 or higher)
- Try reloading the extension:
  1. Go to `chrome://extensions/`
  2. Find Website Security Scanner
  3. Click the refresh icon
- If the issue persists, try reinstalling the extension:
  1. Go to `chrome://extensions/`
  2. Remove the Website Security Scanner
  3. Load it again using "Load unpacked"

### 2. "Cannot read properties of undefined" Error

**Symptoms:**
- Error in console: "Cannot read properties of undefined (reading 'url')"
- Scan fails to start or times out

**Solutions:**
- This error typically occurs when trying to scan browser internal pages or when tab information is not accessible
- Make sure you're on a regular web page (http:// or https://) and not a browser internal page (chrome://, edge://, etc.)
- Try refreshing the page before scanning
- If using the extension in incognito mode, make sure it has permission to run in incognito

### 3. Scan Timeout or Failure

**Symptoms:**
- Scan never completes
- "Scan timed out" error message
- "Error communicating with background script" message

**Solutions:**
- Check your internet connection
- Try scanning a different website
- Reload the extension
- Ensure the website you're scanning is accessible
- If scanning HTTPS sites, check if your browser has any certificate warnings
- Try disabling other extensions temporarily to check for conflicts

### 4. API Key Configuration Issues

**Symptoms:**
- Warning messages about unconfigured APIs
- Some security checks show "Error" status
- Reduced overall security score

**Solutions:**
- Verify your API keys are entered correctly in the settings
- Ensure there are no extra spaces before or after the API keys
- Check if your API keys are still valid by testing them directly with the API providers
- If using Google Safe Browsing API, ensure your API key has the Safe Browsing API enabled in the Google Cloud Console

### 5. Browser Internal Page Errors

**Symptoms:**
- Error message: "Cannot scan browser internal pages"
- Error message: "Cannot access tab URL"

**Solutions:**
- The extension cannot scan browser internal pages like chrome://extensions, chrome://settings, etc.
- Navigate to a regular website (http:// or https://) before using the extension
- The extension also cannot scan local files (file://), data URLs, or JavaScript URLs

### 6. Permission Issues

**Symptoms:**
- Some security checks don't run
- "Error performing check" messages

**Solutions:**
- Make sure you've granted all required permissions to the extension
- When prompted for permissions, click "Allow"
- If using a managed Chrome installation (e.g., corporate environment), check with your administrator about extension permissions

## Checking for Errors in the Console

To view detailed error messages:

1. Right-click on the extension popup
2. Select "Inspect" or "Inspect Element"
3. Go to the "Console" tab
4. Look for any red error messages

## Reporting Issues

If you continue to experience issues after trying these troubleshooting steps, please report the problem with the following information:

1. Chrome version
2. Extension version
3. Exact error messages from the console
4. Steps to reproduce the issue
5. Type of website where the issue occurs

## API Rate Limits

Note that the free tier of the APIs used by this extension have rate limits:

- Google Safe Browsing API: 100,000 URLs per day
- VirusTotal API: 4 requests per minute, 1,000 per day

If you exceed these limits, some security checks may fail until the rate limits reset.
