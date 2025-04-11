// @@@SNIPPET popup.js
// Popup script for Website Security Scanner
// Handles UI updates and communication with background service worker

document.addEventListener('DOMContentLoaded', function() {
  // Get DOM elements
  const scanButton = document.getElementById('scan-button');
  const scanProgress = document.getElementById('scan-progress');
  const currentUrlElement = document.getElementById('current-url');
  const overallScoreElement = document.getElementById('overall-score');
  const scanTimeElement = document.getElementById('scan-time');
  const settingsLink = document.getElementById('settings-link');
  const settingsModal = document.getElementById('settings-modal');
  const closeModalBtn = document.querySelector('.close');
  const saveSettingsBtn = document.getElementById('save-settings');
  const googleApiKeyInput = document.getElementById('google-api-key');
  const virusTotalApiKeyInput = document.getElementById('virustotal-api-key');
  
  // Scan timeout variables
  let scanTimeoutId = null;
  const SCAN_TIMEOUT_MS = 120000; // 20 seconds timeout
  const SCAN_CHECK_INTERVAL_MS = 1000; // Check every second
  let scanProgressInterval = null;
  let scanStartTime = null;
  
  // Hide scan progress initially
  scanProgress.style.display = 'none';
  
  // Error handling utilities - inline implementation instead of importScripts
  // URL validation function
  function validateScanUrl(url) {
    if (!url) {
      return {
        valid: false,
        message: 'Cannot access tab URL. This might be a browser internal page.'
      };
    }
    
    // Check if this is a browser internal page
    if (url.startsWith('chrome://') || 
        url.startsWith('edge://') || 
        url.startsWith('about:') ||
        url.startsWith('chrome-extension://') ||
        url.startsWith('file://')) {
      return {
        valid: false,
        message: 'Cannot scan browser internal pages. Please navigate to a website.'
      };
    }
    
    // Check if URL has a valid protocol
    try {
      const urlObj = new URL(url);
      if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
        return {
          valid: false,
          message: `Cannot scan URLs with protocol "${urlObj.protocol}". Only HTTP and HTTPS are supported.`
        };
      }
    } catch (error) {
      return {
        valid: false,
        message: `Invalid URL: ${error.message}`
      };
    }
    
    return {
      valid: true,
      message: ''
    };
  }
  
  // Load saved API keys
  loadApiKeys();
  
  // Get current tab URL and display it
  chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
    if (chrome.runtime.lastError) {
      showError(`Error accessing tab: ${chrome.runtime.lastError.message}`);
      return;
    }
    
    if (!tabs || tabs.length === 0) {
      showError('No active tab found');
      return;
    }
    
    // Check if URL is accessible
    if (!tabs[0].url) {
      showError('Cannot access tab URL. This might be a chrome:// or edge:// page.');
      return;
    }
    
    const currentUrl = tabs[0].url;
    
    // Validate the URL
    const urlValidation = validateScanUrl(currentUrl);
    if (!urlValidation.valid) {
      showError(urlValidation.message);
      return;
    }
    
    currentUrlElement.textContent = currentUrl;
    
    // Auto-scan when popup opens
    performScan();
  });
  
  // Add click event listener to scan button
  scanButton.addEventListener('click', performScan);
  
  // Settings modal functionality
  settingsLink.addEventListener('click', function(e) {
    e.preventDefault();
    settingsModal.style.display = 'block';
  });
  
  closeModalBtn.addEventListener('click', function() {
    settingsModal.style.display = 'none';
  });
  
  window.addEventListener('click', function(event) {
    if (event.target == settingsModal) {
      settingsModal.style.display = 'none';
    }
  });
  
  saveSettingsBtn.addEventListener('click', saveApiKeys);
  
  // Function to load API keys from storage
  function loadApiKeys() {
    chrome.storage.local.get(['securityScannerConfig'], function(result) {
      if (chrome.runtime.lastError) {
        console.error(`Error loading API keys: ${chrome.runtime.lastError.message}`);
        return;
      }
      
      if (result.securityScannerConfig && result.securityScannerConfig.apiKeys) {
        const apiKeys = result.securityScannerConfig.apiKeys;
        
        // Only fill if not the placeholder values
        if (apiKeys.googleSafeBrowsing && apiKeys.googleSafeBrowsing !== 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY') {
          googleApiKeyInput.value = apiKeys.googleSafeBrowsing;
        }
        
        if (apiKeys.virusTotal && apiKeys.virusTotal !== 'YOUR_VIRUSTOTAL_API_KEY') {
          virusTotalApiKeyInput.value = apiKeys.virusTotal;
        }
      }
    });
  }
  
  // Function to save API keys to storage
  function saveApiKeys() {
    chrome.storage.local.get(['securityScannerConfig'], function(result) {
      if (chrome.runtime.lastError) {
        alert(`Error saving API keys: ${chrome.runtime.lastError.message}`);
        return;
      }
      
      let config = result.securityScannerConfig || {
        apiKeys: {},
        settings: {
          checkTimeout: 120000,
          maxDirectoriesToCheck: 10,
          maxRequestsPerMinute: 30
        }
      };
      
      // Update API keys
      config.apiKeys.googleSafeBrowsing = googleApiKeyInput.value || 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY';
      config.apiKeys.virusTotal = virusTotalApiKeyInput.value || 'YOUR_VIRUSTOTAL_API_KEY';
      
      // Save to storage
      chrome.storage.local.set({securityScannerConfig: config}, function() {
        if (chrome.runtime.lastError) {
          alert(`Error saving settings: ${chrome.runtime.lastError.message}`);
          return;
        }
        
        console.log('API keys saved');
        
        // Send message to background script to update config
        chrome.runtime.sendMessage(
          { action: 'saveConfig', config: config },
          function(response) {
            if (chrome.runtime.lastError) {
              alert(`Error updating background script: ${chrome.runtime.lastError.message}`);
              return;
            }
            
            if (response && response.success) {
              // Show success message
              alert('Settings saved successfully!');
              settingsModal.style.display = 'none';
            } else {
              alert('Error saving settings. Please try again.');
            }
          }
        );
      });
    });
  }
  
  // Function to perform security scan
  function performScan() {
    // First check if we can access the current tab
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
      if (chrome.runtime.lastError) {
        showError(`Error accessing tab: ${chrome.runtime.lastError.message}`);
        return;
      }
      
      if (!tabs || tabs.length === 0) {
        showError('No active tab found');
        return;
      }
      
      // Check if URL is accessible
      if (!tabs[0].url) {
        showError('Cannot access tab URL. This might be a chrome:// or edge:// page.');
        return;
      }
      
      const currentUrl = tabs[0].url;
      
      // Validate the URL
      const urlValidation = validateScanUrl(currentUrl);
      if (!urlValidation.valid) {
        showError(urlValidation.message);
        return;
      }
      
      // If we get here, we can proceed with the scan
      startScan();
    });
  }
  
  // Function to start the actual scan
  function startScan() {
    // Show scanning in progress
    scanButton.style.display = 'none';
    scanProgress.style.display = 'flex';
    resetResults();
    
    // Clear any previous error messages
    currentUrlElement.classList.remove('error');
    
    // Remove any previous API warnings
    const previousWarnings = document.querySelectorAll('.api-warning');
    previousWarnings.forEach(warning => warning.remove());
    
    // Remove any previous error notifications
    const previousErrors = document.querySelectorAll('.error-notification');
    previousErrors.forEach(error => error.remove());
    
    // Record scan start time
    scanStartTime = Date.now();
    
    // Set up progress indicator
    updateScanProgressIndicator();
    
    // Set a timeout for the scan
    clearScanTimeout(); // Clear any existing timeout
    scanTimeoutId = setTimeout(function() {
      handleScanTimeout();
    }, SCAN_TIMEOUT_MS);
    
    // Set up interval to update progress indicator
    scanProgressInterval = setInterval(updateScanProgressIndicator, SCAN_CHECK_INTERVAL_MS);
    
    // Send message to background script to start scan
    chrome.runtime.sendMessage(
      { action: 'scanWebsite' },
      function(response) {
        // Clear the timeout and interval since we got a response
        clearScanTimeout();
        
        // Check for runtime errors
        if (chrome.runtime.lastError) {
          showError(`Error communicating with background script: ${chrome.runtime.lastError.message}`);
          scanButton.style.display = 'block';
          scanProgress.style.display = 'none';
          return;
        }
        
        // Hide scanning progress
        scanButton.style.display = 'block';
        scanProgress.style.display = 'none';
        
        // Check if response contains an error
        if (response && response.error) {
          showErrorNotification(response.error);
          return;
        }
        
        // Update UI with results
        if (response) {
          updateResultsUI(response);
        } else {
          showError('Scan failed. Please try again.');
        }
      }
    );
  }
  
  // Function to update scan progress indicator
  function updateScanProgressIndicator() {
    if (!scanStartTime) return;
    
    const elapsedTime = Date.now() - scanStartTime;
    const progressPercent = Math.min(100, (elapsedTime / SCAN_TIMEOUT_MS) * 100);
    
    // Update progress text
    const progressText = scanProgress.querySelector('span');
    if (progressText) {
      if (elapsedTime > SCAN_TIMEOUT_MS * 0.7) {
        progressText.textContent = 'Still scanning... (this may take a moment)';
      } else {
        progressText.textContent = 'Scanning...';
      }
    }
  }
  
  // Function to clear scan timeout and interval
  function clearScanTimeout() {
    if (scanTimeoutId) {
      clearTimeout(scanTimeoutId);
      scanTimeoutId = null;
    }
    
    if (scanProgressInterval) {
      clearInterval(scanProgressInterval);
      scanProgressInterval = null;
    }
    
    scanStartTime = null;
  }
  
  // Function to handle scan timeout
  function handleScanTimeout() {
    // Clear the interval
    if (scanProgressInterval) {
      clearInterval(scanProgressInterval);
      scanProgressInterval = null;
    }
    
    // Reset UI
    scanButton.style.display = 'block';
    scanProgress.style.display = 'none';
    
    // Show timeout error
    showErrorNotification('The scan timed out. This could be due to slow network connection or the website being unresponsive. Please try again or try scanning a different website.');
  }
  
  // Function to show an error notification
  function showErrorNotification(errorMessage) {
    // Create error notification element
    const errorElement = document.createElement('div');
    errorElement.className = 'error-notification';
    errorElement.innerHTML = `
      <div class="error-title">Error Scanning Website</div>
      <div class="error-message">${errorMessage}</div>
      <div class="error-help">Please try scanning a different website or check the troubleshooting guide.</div>
    `;
    
    // Insert after URL container
    const urlContainer = document.querySelector('.url-container');
    urlContainer.parentNode.insertBefore(errorElement, urlContainer.nextSibling);
    
    // Reset scan button
    scanButton.style.display = 'block';
    scanProgress.style.display = 'none';
  }
  
  // Function to reset all result displays
  function resetResults() {
    overallScoreElement.textContent = '--';
    overallScoreElement.className = 'score-value';
    document.querySelectorAll('.check-score').forEach(element => {
      element.textContent = '--';
      element.className = 'check-score';
    });
    document.querySelectorAll('.check-details').forEach(element => {
      element.innerHTML = '';
    });
    
    // Reset score circle
    const scoreCircle = document.querySelector('.score-circle');
    if (scoreCircle) {
      scoreCircle.classList.remove('good-score-bg', 'medium-score-bg', 'bad-score-bg');
    }
  }
  
  // Function to update UI with scan results
  function updateResultsUI(report) {
    // Check if report has an error
    if (report.error) {
      showErrorNotification(report.error);
      return;
    }
    
    // Update overall score
    overallScoreElement.textContent = report.overallScore;
    
    // Update scan time
    const scanTime = new Date(report.timestamp);
    scanTimeElement.textContent = scanTime.toLocaleTimeString();
    
    // Update each security check section
    updateCheckSection('ssl-check', report.checks.ssl);
    updateCheckSection('https-check', report.checks.https);
    updateCheckSection('safebrowsing-check', report.checks.safeBrowsing);
    updateCheckSection('vulnerabilities-check', report.checks.vulnerabilities);
    updateCheckSection('email-security-check', report.checks.emailSecurity);
    updateCheckSection('directories-check', report.checks.exposedDirectories);
    updateCheckSection('headers-check', report.checks.securityHeaders);
    
    // Set color of overall score based on value
    setScoreColor(overallScoreElement, report.overallScore);
    
    // Update score circle color
    updateScoreCircleColor(report.overallScore);
    
    // Check if any API keys are missing and show warning
    checkApiKeyStatus(report);
  }
  
  // Function to check API key status and show warnings
  function checkApiKeyStatus(report) {
    let missingApis = [];
    
    // Check Safe Browsing API
    if (report.checks.safeBrowsing.details && report.checks.safeBrowsing.details.apiConfigured === false) {
      missingApis.push('Google Safe Browsing');
    }
    
    // Check VirusTotal API
    if (report.checks.vulnerabilities.details && report.checks.vulnerabilities.details.apiConfigured === false) {
      missingApis.push('VirusTotal');
    }
    
    // Show warning if APIs are missing
    if (missingApis.length > 0) {
      const warningElement = document.createElement('div');
      warningElement.className = 'api-warning';
      warningElement.innerHTML = `
        <p>⚠️ Some API keys are not configured: ${missingApis.join(', ')}</p>
        <p><a href="#" id="configure-apis-link">Configure APIs</a> for more accurate results.</p>
      `;
      
      // Insert after URL container
      const urlContainer = document.querySelector('.url-container');
      if (urlContainer) {
        urlContainer.parentNode.insertBefore(warningElement, urlContainer.nextSibling);
        
        // Add click event to the configure link
        const configureLink = document.getElementById('configure-apis-link');
        if (configureLink) {
          configureLink.addEventListener('click', function(e) {
            e.preventDefault();
            settingsModal.style.display = 'block';
          });
        }
      }
    }
  }
  
  // Function to update individual check section
  function updateCheckSection(sectionId, checkData) {
    if (!checkData) {
      console.error(`Missing check data for section: ${sectionId}`);
      return;
    }
    
    const section = document.getElementById(sectionId);
    if (!section) {
      console.error(`Section not found: ${sectionId}`);
      return;
    }
    
    const scoreElement = section.querySelector('.check-score');
    const detailsElement = section.querySelector('.check-details');
    
    if (!scoreElement || !detailsElement) {
      console.error(`Required elements not found in section: ${sectionId}`);
      return;
    }
    
    // Update score
    scoreElement.textContent = checkData.score;
    setScoreColor(scoreElement, checkData.score);
    
    // Update status icon based on status
    const statusIcon = getStatusIcon(checkData.status);
    
    // Get message from details or use a default
    const message = checkData.details && checkData.details.message 
      ? checkData.details.message 
      : 'No details available';
    
    // Start building the details HTML
    let detailsHtml = `<div class="status-row">
      <span class="status-icon">${statusIcon}</span>
      <span class="status-message">${message}</span>
    </div>`;
    
    // Add error message if present
    if (checkData.details && checkData.details.error) {
      detailsHtml += `<div class="error-row">
        <span class="error-message">Error: ${checkData.details.error}</span>
      </div>`;
    }
    
    // Add SSL Labs details (customize this section)
    if (sectionId === 'ssl-check' && checkData.details && checkData.details.sslLabs) {
      detailsHtml += '<div class="details-list">';
    
      if (checkData.details.endpoints && checkData.details.endpoints.length > 0) {
        checkData.details.endpoints.forEach(endpoint => {
          detailsHtml += `<div class="detail-row">
            <span class="detail-key">IP Address:</span>
            <span class="detail-value">${endpoint.ipAddress}</span>
          </div>`;
          detailsHtml += `<div class="detail-row">
            <span class="detail-key">Server Name:</span>
            <span class="detail-value">${endpoint.serverName}</span>
          </div>`;
          detailsHtml += `<div class="detail-row">
            <span class="detail-key">SSL Labs Grade:</span>
            <span class="detail-value">${endpoint.grade} (${endpoint.statusMessage})</span>
          </div>`;
        });
      }
    
      if (checkData.details.subject) {
        detailsHtml += `<div class="detail-row">
          <span class="detail-key">Subject:</span>
          <span class="detail-value">${checkData.details.subject}</span>
        </div>`;
      }
      if (checkData.details.issuer) {
        detailsHtml += `<div class="detail-row">
          <span class="detail-key">Issuer:</span>
          <span class="detail-value">${checkData.details.issuer}</span>
        </div>`;
      }
      if (checkData.details.validFrom) {
        detailsHtml += `<div class="detail-row">
          <span class="detail-key">Valid From:</span>
          <span class="detail-value">${new Date(checkData.details.validFrom).toLocaleDateString()}</span>
        </div>`;
      }
      if (checkData.details.validTo) {
        detailsHtml += `<div class="detail-row">
          <span class="detail-key">Valid To:</span>
          <span class="detail-value">${new Date(checkData.details.validTo).toLocaleDateString()}</span>
        </div>`;
      }
      if (checkData.details.daysToExpiry !== undefined) {
        detailsHtml += `<div class="detail-row">
          <span class="detail-key">Days To Expiry:</span>
          <span class="detail-value">${checkData.details.daysToExpiry}</span>
        </div>`;
      }
    
      detailsHtml += '</div>'; // Close details-list
      
      // REMOVE the line that was adding the full sslLabs data
      //detailsElement.innerHTML += `<pre>${JSON.stringify(checkData.details.sslLabs, null, 2)}</pre>`;
    }
    
    // Add other details if available (but NOT the full sslLabs)
    if (checkData.details && Object.keys(checkData.details).length > 0) {
      detailsHtml += '<div class="details-list">';
      for (const [key, value] of Object.entries(checkData.details)) {
        // Skip certain keys (including sslLabs)
        if (key === 'message' || key === 'apiConfigured' || key === 'error' || key === 'sslLabs') continue;
        
        // Skip empty arrays
        if (Array.isArray(value) && value.length === 0) continue;
        
        // Format arrays and objects nicely
        let displayValue = formatValue(value);
        
        // Format the key for display
        const displayKey = formatKey(key);
        
        detailsHtml += `<div class="detail-row">
          <span class="detail-key">${displayKey}:</span>
          <span class="detail-value">${displayValue}</span>
        </div>`;
      }
      detailsHtml += '</div>';
    }
    
    // Finally, set the innerHTML
    detailsElement.innerHTML = detailsHtml;
    detailsElement.style.display = 'block';
  }
  
  // Function to format a value for display
  function formatValue(value) {
    if (value === null || value === undefined) {
      return 'None';
    }

    if (typeof value === 'object' && value !== null) {
      try {
        if (Array.isArray(value)) {
          // Handle arrays of objects
          let formattedArray = '<div class="details-grid">'; // Use a grid container
          for (const item of value) {
            if (typeof item === 'object' && item !== null) {
              for (const [key, val] of Object.entries(item)) {
                formattedArray += `<div class="detail-key">${formatKey(key)}:</div>
                  <div class="detail-value">${formatValue(val)}</div>`;
              }
            } else {
              formattedArray += `<div class="detail-value">${formatValue(item)}</div>`; // Simple value
            }
          }
          formattedArray += '</div>'; // Close grid container
          return formattedArray;
        } else {
          // Handle single objects
          let formattedString = '<div class="details-grid">'; // Use a grid container
          for (const [key, val] of Object.entries(value)) {
            formattedString += `<div class="detail-key">${formatKey(key)}:</div>
              <div class="detail-value">${formatValue(val)}</div>`;
          }
          formattedString += '</div>'; // Close grid container
          return formattedString;
        }
      } catch (e) {
        return String(value);
      }
    }

    return String(value);
  }
  
  // Function to format a key for display
  function formatKey(key) {
    return key
      .replace(/([A-Z])/g, ' $1')
      .replace(/^./, str => str.toUpperCase())
      .replace(/([a-z])([A-Z])/g, '$1 $2');
  }
  
  // Function to get status icon based on status
  function getStatusIcon(status) {
    switch (status) {
      case 'passed':
        return '✅';
      case 'warning':
        return '⚠️';
      case 'failed':
        return '❌';
      case 'error':
        return '⚠️';
      case 'pending':
        return '⏳';
      default:
        return '❓';
    }
  }
  
  // Function to set color based on score
  function setScoreColor(element, score) {
    if (!element) return;
    
    // Remove existing color classes
    element.classList.remove('good-score', 'medium-score', 'bad-score');
    
    if (score >= 70) {
      element.classList.add('good-score');
    } else if (score >= 40) {
      element.classList.add('medium-score');
    } else {
      element.classList.add('bad-score');
    }
  }
  
  // Function to update score circle color
  function updateScoreCircleColor(score) {
    const scoreCircle = document.querySelector('.score-circle');
    if (!scoreCircle) {
      console.error('Score circle element not found');
      return;
    }
    
    // Remove existing color classes
    scoreCircle.classList.remove('good-score-bg', 'medium-score-bg', 'bad-score-bg');
    
    if (score >= 70) {
      scoreCircle.classList.add('good-score-bg');
    } else if (score >= 40) {
      scoreCircle.classList.add('medium-score-bg');
    } else {
      scoreCircle.classList.add('bad-score-bg');
    }
  }
  
  // Function to show error message
  function showError(message) {
    console.error(message);
    if (currentUrlElement) {
      currentUrlElement.textContent = message;
      currentUrlElement.classList.add('error');
    }
    
    // Reset scan button and progress
    if (scanButton) scanButton.style.display = 'block';
    if (scanProgress) scanProgress.style.display = 'none';
  }
});