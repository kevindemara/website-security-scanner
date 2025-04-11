# Website Security Scanner - Chrome Extension

## Installation Instructions

### Method 1: Install from ZIP file

1. **Download the extension ZIP file**
   - Save the attached `website-security-scanner.zip` file to your computer

2. **Extract the ZIP file**
   - Right-click the ZIP file and select "Extract All..." or use your preferred extraction tool
   - Remember the location where you extracted the files

3. **Open Chrome Extensions page**
   - Open Google Chrome
   - Type `chrome://extensions/` in the address bar and press Enter
   - Or navigate through: Chrome menu (three dots) > More Tools > Extensions

4. **Enable Developer Mode**
   - Toggle on "Developer mode" in the top-right corner of the Extensions page

5. **Load the extension**
   - Click the "Load unpacked" button that appears after enabling Developer mode
   - Navigate to the folder where you extracted the extension files
   - Select the `website-security-scanner` folder (not the zip file)
   - Click "Select Folder" or "Open"

6. **Verify installation**
   - The Website Security Scanner extension should now appear in your extensions list
   - You should see the extension icon in your Chrome toolbar

### Using the Extension

1. **Navigate to any website** you want to analyze

2. **Click the extension icon** in the Chrome toolbar
   - The extension popup will open and automatically begin scanning the current website

3. **View the security report**
   - The overall trust score (0-100) is displayed at the top
   - Individual security checks are listed below
   - Hover over or click on each security check to see detailed information

4. **Rescan the website**
   - Click the "Scan Now" button to perform a new scan of the current page

## Features

- **SSL Certificate Check**: Validates the SSL certificate and shows days to expiry
- **HTTPS Status**: Verifies if the site is using secure HTTPS protocol
- **Safe Browsing Check**: Checks if the site is flagged by Google Safe Browsing
- **Vulnerability Check**: Scans for known vulnerabilities
- **Email Security**: Checks domain email security (SPF/DMARC records)
- **Exposed Directories**: Checks for exposed directory listings
- **Security Headers**: Scans for important security headers like CSP, HSTS, etc.

## Limitations of the Prototype

- Some security checks use simulated data in this prototype version
- For a production version, actual API integrations would be needed:
  - Google Safe Browsing API
  - VirusTotal or Sucuri API
  - Actual DNS lookups for email security
  - Real HTTP requests for directory checks

## Future Enhancements

- History of previous scans
- Exportable security reports
- More detailed security checks
- Custom scoring weights
- Scheduled automatic scans
