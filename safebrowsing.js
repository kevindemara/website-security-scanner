// Google Safe Browsing API client for Website Security Scanner

class SafeBrowsingClient {
  constructor(apiKey) {
    this.apiKey = apiKey;
    this.apiUrl = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';
    this.clientId = 'website-security-scanner';
    this.clientVersion = '1.0.0';
  }

  /**
   * Check if a URL is safe according to Google Safe Browsing
   * @param {string} url - The URL to check
   * @returns {Promise<Object>} - The check result
   */
  async checkUrl(url) {
    try {
      // If API key is not set, return a warning
      if (!this.apiKey || this.apiKey === 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY') {
        console.warn('Google Safe Browsing API key not configured');
        return {
          status: 'warning',
          score: 7, // Reduced score due to unconfigured API
          details: {
            message: 'Google Safe Browsing check skipped (API key not configured)',
            threatTypes: [],
            apiConfigured: false
          }
        };
      }

      const requestBody = {
        client: {
          clientId: this.clientId,
          clientVersion: this.clientVersion
        },
        threatInfo: {
          threatTypes: [
            'MALWARE',
            'SOCIAL_ENGINEERING',
            'UNWANTED_SOFTWARE',
            'POTENTIALLY_HARMFUL_APPLICATION'
          ],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: url }]
        }
      };

      const response = await fetch(`${this.apiUrl}?key=${this.apiKey}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestBody)
      });

      if (!response.ok) {
        throw new Error(`API request failed with status ${response.status}`);
      }

      const data = await response.json();
      
      // If matches are found, the site is unsafe
      if (data.matches && data.matches.length > 0) {
        const threatTypes = data.matches.map(match => match.threatType);
        return {
          status: 'failed',
          score: 0,
          details: {
            message: 'Site flagged by Google Safe Browsing',
            threatTypes: threatTypes,
            apiConfigured: true
          }
        };
      }
      
      // No matches means the site is safe
      return {
        status: 'passed',
        score: 15,
        details: {
          message: 'No threats detected by Google Safe Browsing',
          threatTypes: [],
          apiConfigured: true
        }
      };
    } catch (error) {
      console.error('Error checking Google Safe Browsing:', error);
      return {
        status: 'error',
        score: 5, // Partial score due to API error
        details: {
          message: `Error checking Google Safe Browsing: ${error.message}`,
          error: error.message,
          apiConfigured: this.apiKey !== 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY'
        }
      };
    }
  }
}

// Export the client
if (typeof module !== 'undefined') {
  module.exports = SafeBrowsingClient;
}
