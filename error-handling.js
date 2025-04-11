// Error handling utilities for Website Security Scanner

/**
 * Handles tab query errors and provides appropriate error messages
 * @param {Error} error - The error object
 * @param {Function} callback - Callback function to handle the error
 * @returns {string} - Error message
 */
function handleTabQueryError(error, callback) {
  let errorMessage = 'An unknown error occurred while accessing the tab';
  
  if (error && error.message) {
    errorMessage = `Error accessing tab: ${error.message}`;
  }
  
  if (callback && typeof callback === 'function') {
    callback(errorMessage);
  }
  
  return errorMessage;
}

/**
 * Validates if a URL can be scanned by the extension
 * @param {string} url - The URL to validate
 * @returns {Object} - Validation result with status and message
 */
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

/**
 * Handles API errors and provides appropriate error messages
 * @param {Error} error - The error object
 * @param {string} apiName - Name of the API that failed
 * @returns {Object} - Error details object
 */
function handleApiError(error, apiName) {
  let errorMessage = `Error in ${apiName} API`;
  let errorCode = 'UNKNOWN_ERROR';
  
  if (error && error.message) {
    errorMessage = `${errorMessage}: ${error.message}`;
    
    // Try to extract error code if available
    if (error.code) {
      errorCode = error.code;
    } else if (error.name) {
      errorCode = error.name;
    }
  }
  
  return {
    status: 'error',
    score: 5, // Partial score for API errors
    details: {
      message: errorMessage,
      error: error ? error.message : 'Unknown error',
      errorCode: errorCode,
      apiName: apiName
    }
  };
}

/**
 * Creates a standardized error response for security checks
 * @param {string} checkName - Name of the security check
 * @param {Error} error - The error object
 * @returns {Object} - Standardized error response
 */
function createErrorResponse(checkName, error) {
  return {
    timestamp: new Date().toISOString(),
    overallScore: 0,
    error: error ? error.message : `Error in ${checkName} check`,
    errorDetails: {
      checkName: checkName,
      errorMessage: error ? error.message : 'Unknown error',
      errorStack: error ? error.stack : null,
      timestamp: new Date().toISOString()
    }
  };
}

// Export the utilities
if (typeof module !== 'undefined') {
  module.exports = {
    handleTabQueryError,
    validateScanUrl,
    handleApiError,
    createErrorResponse
  };
}
