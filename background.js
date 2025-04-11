// Main background script for Website Security Scanner
// Integrates all security check modules

// Import security check modules
importScripts(
  'safebrowsing.js',
  'vulnerability-scanner.js',
  'email-security.js',
  'directory-checker.js',
  'security-headers.js'
);

// Import configuration
let config = {
  apiKeys: {
    googleSafeBrowsing: "YOUR_GOOGLE_SAFE_BROWSING_API_KEY",
    virusTotal: "YOUR_VIRUSTOTAL_API_KEY"
  },
  settings: {
    checkTimeout: 10000,
    maxDirectoriesToCheck: 10,
    maxRequestsPerMinute: 30
  }
};

// Load configuration from storage
chrome.storage.local.get(['securityScannerConfig'], function(result) {
  if (result.securityScannerConfig) {
    config = result.securityScannerConfig;
    console.log('Configuration loaded from storage');
  } else {
    // Save default config to storage
    chrome.storage.local.set({securityScannerConfig: config}, function() {
      console.log('Default configuration saved to storage');
    });
  }
});

// Initialize when extension is installed or updated
chrome.runtime.onInstalled.addListener(() => {
  console.log('Website Security Scanner extension installed');
  
  // Load default configuration file
  fetch(chrome.runtime.getURL('config.json'))
    .then(response => response.json())
    .then(data => {
      config = data;
      // Save to storage
      chrome.storage.local.set({securityScannerConfig: config}, function() {
        console.log('Configuration loaded from file and saved to storage');
      });
    })
    .catch(error => {
      console.error('Error loading configuration:', error);
    });
});

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'scanWebsite') {
    // Get the current tab URL
    chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
      try {
        // Check if tabs array is empty or undefined
        if (!tabs || tabs.length === 0) {
          console.error('No active tabs found');
          sendResponse({
            error: 'No active tab found. Please try again.',
            timestamp: new Date().toISOString(),
            overallScore: 0
          });
          return;
        }
        
        // Check if URL is accessible
        if (!tabs[0].url) {
          console.error('Cannot access tab URL. This might be a chrome:// or edge:// page.');
          sendResponse({
            error: 'Cannot scan this page. The extension cannot access URLs for browser internal pages.',
            timestamp: new Date().toISOString(),
            overallScore: 0
          });
          return;
        }
        
        const currentUrl = tabs[0].url;
        const tabId = tabs[0].id;
        
        // Check if this is a browser internal page
        if (currentUrl.startsWith('chrome://') || 
            currentUrl.startsWith('edge://') || 
            currentUrl.startsWith('about:') ||
            currentUrl.startsWith('chrome-extension://')) {
          console.error('Cannot scan browser internal page:', currentUrl);
          sendResponse({
            error: 'Cannot scan browser internal pages. Please navigate to a website.',
            timestamp: new Date().toISOString(),
            overallScore: 0
          });
          return;
        }
        
        // Perform security checks
        const securityReport = await performSecurityChecks(currentUrl, tabId);
        
        // Send results back to popup
        sendResponse(securityReport);
      } catch (error) {
        console.error('Error in tab query or security check:', error);
        sendResponse({
          error: `An unexpected error occurred: ${error.message}`,
          timestamp: new Date().toISOString(),
          overallScore: 0
        });
      }
    });
    
    // Return true to indicate we will send a response asynchronously
    return true;
  } else if (message.action === 'saveConfig') {
    // Save updated configuration
    config = message.config;
    chrome.storage.local.set({securityScannerConfig: config}, function() {
      console.log('Configuration updated');
      sendResponse({success: true});
    });
    return true;
  }
});

// Main function to perform all security checks
async function performSecurityChecks(url, tabId) {
  try {
    // Validate inputs
    if (!url) {
      throw new Error('URL is required for security checks');
    }
    
    if (!tabId) {
      throw new Error('Tab ID is required for security checks');
    }
    
    // Parse the URL to get domain information
    const urlObj = new URL(url);
    const domain = urlObj.hostname;
    const protocol = urlObj.protocol;
    
    // Initialize security report
    const securityReport = {
      url: url,
      timestamp: new Date().toISOString(),
      overallScore: 0,
      checks: {
        ssl: { status: 'pending', score: 0, details: {} },
        https: { status: 'pending', score: 0, details: {} },
        safeBrowsing: { status: 'pending', score: 0, details: {} },
        vulnerabilities: { status: 'pending', score: 0, details: {} },
        emailSecurity: { status: 'pending', score: 0, details: {} },
        exposedDirectories: { status: 'pending', score: 0, details: {} },
        securityHeaders: { status: 'pending', score: 0, details: {} }
      }
    };
    
    // Check HTTPS status
    securityReport.checks.https = await checkHttpsStatus(url, protocol);
    
    // Check SSL certificate (if HTTPS)
    if (protocol === 'https:') {
      securityReport.checks.ssl = await checkSSLCertificate(domain, tabId);
    } else {
      securityReport.checks.ssl = {
        status: 'failed',
        score: 0,
        details: { message: 'Site is not using HTTPS' }
      };
    }
    
    // Check Google Safe Browsing
    try {
      const safeBrowsingClient = new SafeBrowsingClient(config.apiKeys.googleSafeBrowsing);
      securityReport.checks.safeBrowsing = await safeBrowsingClient.checkUrl(url);
    } catch (error) {
      console.error('Error in Safe Browsing check:', error);
      securityReport.checks.safeBrowsing = {
        status: 'error',
        score: 5,
        details: { 
          message: 'Error checking Google Safe Browsing',
          error: error.message
        }
      };
    }
    
    // Check for known vulnerabilities
    try {
      const vulnerabilityScanner = new VulnerabilityScanner(config.apiKeys.virusTotal);
      securityReport.checks.vulnerabilities = await vulnerabilityScanner.checkDomain(domain);
    } catch (error) {
      console.error('Error in vulnerability check:', error);
      securityReport.checks.vulnerabilities = {
        status: 'error',
        score: 5,
        details: { 
          message: 'Error checking vulnerabilities',
          error: error.message
        }
      };
    }
    
    // Check email security (SPF/DMARC)
    try {
      const emailSecurityChecker = new EmailSecurityChecker();
      securityReport.checks.emailSecurity = await emailSecurityChecker.checkDomain(domain);
    } catch (error) {
      console.error('Error in email security check:', error);
      securityReport.checks.emailSecurity = {
        status: 'error',
        score: 3,
        details: { 
          message: 'Error checking email security',
          error: error.message
        }
      };
    }
    
    // Check for exposed directories
    try {
      const directoryChecker = new DirectoryChecker(config.settings);
      securityReport.checks.exposedDirectories = await directoryChecker.checkExposedDirectories(url);
    } catch (error) {
      console.error('Error in directory check:', error);
      securityReport.checks.exposedDirectories = {
        status: 'error',
        score: 5,
        details: { 
          message: 'Error checking for exposed directories',
          error: error.message
        }
      };
    }
    
    // Check security headers
    try {
      securityReport.checks.securityHeaders = await checkSecurityHeaders(url, tabId);
    } catch (error) {
      console.error('Error in security headers check:', error);
      securityReport.checks.securityHeaders = {
        status: 'error',
        score: 5,
        details: { 
          message: 'Error checking security headers',
          error: error.message
        }
      };
    }
    
    // Calculate overall score
    securityReport.overallScore = calculateOverallScore(securityReport.checks);
    
    return securityReport;
  } catch (error) {
    console.error('Error performing security checks:', error);
    return {
      url: url || 'unknown',
      timestamp: new Date().toISOString(),
      overallScore: 0,
      error: error.message,
      checks: {
        ssl: { status: 'error', score: 0, details: { message: 'Error performing check' } },
        https: { status: 'error', score: 0, details: { message: 'Error performing check' } },
        safeBrowsing: { status: 'error', score: 0, details: { message: 'Error performing check' } },
        vulnerabilities: { status: 'error', score: 0, details: { message: 'Error performing check' } },
        emailSecurity: { status: 'error', score: 0, details: { message: 'Error performing check' } },
        exposedDirectories: { status: 'error', score: 0, details: { message: 'Error performing check' } },
        securityHeaders: { status: 'error', score: 0, details: { message: 'Error performing check' } }
      }
    };
  }
}

// Check HTTPS status
async function checkHttpsStatus(url, protocol) {
  try {
    if (protocol === 'https:') {
      return {
        status: 'passed',
        score: 20,
        details: { message: 'Site is using HTTPS' }
      };
    } else {
      return {
        status: 'failed',
        score: 0,
        details: { message: 'Site is not using HTTPS' }
      };
    }
  } catch (error) {
    console.error('Error checking HTTPS status:', error);
    return {
      status: 'error',
      score: 0,
      details: { message: 'Error checking HTTPS status' }
    };
  }
}

// Check SSL certificate
// @@@SNIPPET background.js (Modified checkSSLCertificate function)
async function checkSSLCertificate(domain, tabId) {
  try {
    const apiUrl = 'https://api.ssllabs.com/api/v3/analyze?host=' + domain;

    // Initiate the SSL Labs scan
    const analyzeResponse = await fetch(apiUrl);
    if (!analyzeResponse.ok) {
      throw new Error(`SSL Labs API error: ${analyzeResponse.statusText}`);
    }
    const analyzeData = await analyzeResponse.json();

    // Poll the API until the analysis is complete
    let attempts = 0;
    const maxAttempts = 30;
    let ready = false;
    let sslLabsResult = null;

    while (!ready && attempts < maxAttempts) {
      await new Promise(resolve => setTimeout(resolve, 5000));

      const resultResponse = await fetch(apiUrl + '&fromCache=on&all=on');
      if (!resultResponse.ok) {
        throw new Error(`SSL Labs API error: ${resultResponse.statusText}`);
      }
      sslLabsResult = await resultResponse.json();

      if (sslLabsResult.status === 'READY' || sslLabsResult.status === 'ERROR') {
        ready = true;
      }
      attempts++;
    }

    if (!ready) {
      throw new Error('SSL Labs API timed out');
    }

    if (sslLabsResult.status === 'ERROR') {
      throw new Error(`SSL Labs API returned an error: ${sslLabsResult.statusMessage}`);
    }

    // Extract relevant certificate information
    let certDetails = {};
    if (sslLabsResult.certs && sslLabsResult.certs.length > 0) {
      const cert = sslLabsResult.certs[0]; // Use the first certificate (usually the site cert)
      certDetails = {
        subject: cert.subject,
        issuer: cert.issuerSubject,
        validFrom: new Date(cert.notBefore).toISOString(),
        validTo: new Date(cert.notAfter).toISOString(),
        signatureAlgorithm: cert.sigAlg,
        // Expiry (calculated from validTo)
        daysToExpiry: Math.round((new Date(cert.notAfter) - new Date()) / (1000 * 60 * 60 * 24)),
      };
    }

    // Extract endpoint information (IP, server name, grade)
    let endpointDetails = [];
    if (sslLabsResult.endpoints && sslLabsResult.endpoints.length > 0) {
      endpointDetails = sslLabsResult.endpoints.map(endpoint => ({
        ipAddress: endpoint.ipAddress,
        serverName: endpoint.serverName,
        grade: endpoint.grade,
        statusMessage: endpoint.statusMessage
      }));
    }

    // Calculate a score and status based on SSL Labs results
    let score = 15;
    let status = 'passed';
    let message = 'SSL certificate is valid and well-configured';

    if (sslLabsResult.overallRating === 'F') {
      score = 0;
      status = 'failed';
      message = 'Poor SSL/TLS configuration';
    } else if (sslLabsResult.overallRating === 'C') {
      score = 5;
      status = 'warning';
      message = 'SSL/TLS configuration has issues';
    }

    return {
      status: status,
      score: score,
      details: {
        message: message,
        sslLabs: sslLabsResult, // Include the full SSL Labs result if needed
        ...certDetails,
        endpoints: endpointDetails // Add endpoint details
      }
    };
  } catch (error) {
    console.error('Error checking SSL certificate:', error);
    return {
      status: 'error',
      score: 0,
      details: { message: `Error checking SSL certificate: ${error.message}` }
    };
  }
}

// Check security headers
async function checkSecurityHeaders(url, tabId) {
  try {
    // We'll use the chrome.scripting API to execute a script in the page context
    // to get header information
    const results = await chrome.scripting.executeScript({
      target: { tabId: tabId },
      func: () => {
        // This function runs in the context of the page
        // In a real implementation, we would use fetch to get headers
        
        // Create a function to get response headers
        const getResponseHeaders = async () => {
          try {
            const response = await fetch(window.location.href, {
              method: 'HEAD',
              cache: 'no-store'
            });
            
            const headers = {};
            response.headers.forEach((value, key) => {
              headers[key] = value;
            });
            
            return headers;
          } catch (error) {
            console.error('Error fetching headers:', error);
            return {};
          }
        };
        
        // Return a promise to get headers
        return getResponseHeaders();
      }
    });
    
    // Get headers from the result
    const headers = results[0].result;
    
    // Use the SecurityHeadersChecker to analyze headers
    const securityHeadersChecker = new SecurityHeadersChecker();
    return securityHeadersChecker.checkSecurityHeaders(headers);
  } catch (error) {
    console.error('Error checking security headers:', error);
    return {
      status: 'error',
      score: 5, // Partial score due to error
      details: { message: 'Error checking security headers' }
    };
  }
}

// Calculate overall score based on individual check scores
function calculateOverallScore(checks) {
  const scores = Object.values(checks).map(check => check.score);
  const totalScore = scores.reduce((sum, score) => sum + score, 0);
  
  // Maximum possible score is the sum of maximum scores for each check
  // SSL: 15, HTTPS: 20, Safe Browsing: 15, Vulnerabilities: 15, 
  // Email Security: 10, Exposed Directories: 10, Security Headers: 15
  // Total: 100
  
  return Math.min(100, totalScore);
}
