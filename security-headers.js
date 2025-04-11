// Security Headers Checker for Website Security Scanner
// Performs comprehensive security header analysis

class SecurityHeadersChecker {
  constructor() {
    // Define security headers to check with descriptions and importance levels
    this.securityHeaders = {
      'Content-Security-Policy': {
        description: 'Helps prevent XSS attacks by specifying which dynamic resources are allowed to load',
        importance: 'high',
        weight: 3,
        example: "default-src 'self'; script-src 'self' trusted-scripts.com"
      },
      'Strict-Transport-Security': {
        description: 'Forces browsers to use HTTPS for the specified domain',
        importance: 'high',
        weight: 3,
        example: 'max-age=31536000; includeSubDomains'
      },
      'X-Content-Type-Options': {
        description: 'Prevents browsers from MIME-sniffing a response from the declared content-type',
        importance: 'medium',
        weight: 2,
        example: 'nosniff'
      },
      'X-Frame-Options': {
        description: 'Protects against clickjacking attacks by preventing the page from being embedded in a frame',
        importance: 'medium',
        weight: 2,
        example: 'DENY'
      },
      'X-XSS-Protection': {
        description: 'Enables the cross-site scripting (XSS) filter in browsers',
        importance: 'medium',
        weight: 2,
        example: '1; mode=block'
      },
      'Referrer-Policy': {
        description: 'Controls how much referrer information should be included with requests',
        importance: 'medium',
        weight: 2,
        example: 'strict-origin-when-cross-origin'
      },
      'Permissions-Policy': {
        description: 'Controls which browser features and APIs can be used in the page',
        importance: 'medium',
        weight: 2,
        example: 'camera=(), microphone=(), geolocation=()'
      },
      'Cache-Control': {
        description: 'Directives for caching mechanisms in requests and responses',
        importance: 'low',
        weight: 1,
        example: 'no-store, max-age=0'
      },
      'Clear-Site-Data': {
        description: 'Clears browsing data (cookies, storage, cache) associated with the requesting website',
        importance: 'low',
        weight: 1,
        example: '"cache", "cookies", "storage"'
      },
      'Cross-Origin-Embedder-Policy': {
        description: 'Prevents a document from loading any cross-origin resources that don\'t explicitly grant the document permission',
        importance: 'low',
        weight: 1,
        example: 'require-corp'
      },
      'Cross-Origin-Opener-Policy': {
        description: 'Prevents other domains from opening/controlling a window',
        importance: 'low',
        weight: 1,
        example: 'same-origin'
      },
      'Cross-Origin-Resource-Policy': {
        description: 'Prevents other domains from reading the response of the resources to which this header is applied',
        importance: 'low',
        weight: 1,
        example: 'same-origin'
      }
    };
    
    // Maximum possible score (sum of all weights)
    this.maxScore = Object.values(this.securityHeaders).reduce((sum, header) => sum + header.weight, 0);
  }

  /**
   * Check security headers for a given URL
   * @param {Object} headers - The response headers object
   * @returns {Object} - The check result
   */
  checkSecurityHeaders(headers) {
    try {
      // Convert headers object to lowercase keys for case-insensitive matching
      const normalizedHeaders = this.normalizeHeaders(headers);
      
      // Track present and missing headers
      const presentHeaders = [];
      const missingHeaders = [];
      const headerDetails = [];
      
      // Calculate score based on present headers
      let score = 0;
      
      // Check each security header
      for (const [headerName, headerInfo] of Object.entries(this.securityHeaders)) {
        const normalizedName = headerName.toLowerCase();
        
        if (normalizedHeaders[normalizedName]) {
          // Header is present
          presentHeaders.push(headerName);
          score += headerInfo.weight;
          
          // Add header details
          headerDetails.push({
            name: headerName,
            value: normalizedHeaders[normalizedName],
            status: 'present',
            importance: headerInfo.importance,
            description: headerInfo.description
          });
        } else {
          // Header is missing
          missingHeaders.push(headerName);
          
          // Add header details
          headerDetails.push({
            name: headerName,
            status: 'missing',
            importance: headerInfo.importance,
            description: headerInfo.description,
            example: headerInfo.example
          });
        }
      }
      
      // Calculate percentage score (0-15 scale)
      const percentageScore = (score / this.maxScore);
      const scaledScore = Math.round(percentageScore * 15);
      
      // Determine status based on score
      let status, message;
      
      if (percentageScore >= 0.7) {
        status = 'passed';
        message = 'Good security header implementation';
      } else if (percentageScore >= 0.4) {
        status = 'warning';
        message = 'Some important security headers are missing';
      } else {
        status = 'failed';
        message = 'Most security headers are missing';
      }
      
      return {
        status: status,
        score: scaledScore,
        details: {
          message: message,
          presentHeaders: presentHeaders,
          missingHeaders: missingHeaders,
          headerDetails: headerDetails,
          totalScore: score,
          maxScore: this.maxScore
        }
      };
    } catch (error) {
      console.error('Error checking security headers:', error);
      return {
        status: 'error',
        score: 5, // Partial score due to error
        details: {
          message: `Error checking security headers: ${error.message}`,
          error: error.message
        }
      };
    }
  }
  
  /**
   * Normalize headers object to lowercase keys
   * @param {Object} headers - The headers object
   * @returns {Object} - Normalized headers object
   */
  normalizeHeaders(headers) {
    const normalized = {};
    
    // Handle different header formats
    if (headers instanceof Headers) {
      // Web API Headers object
      headers.forEach((value, key) => {
        normalized[key.toLowerCase()] = value;
      });
    } else if (typeof headers === 'object') {
      // Plain object
      for (const [key, value] of Object.entries(headers)) {
        normalized[key.toLowerCase()] = value;
      }
    }
    
    return normalized;
  }
  
  /**
   * Analyze a specific security header value
   * @param {string} headerName - The header name
   * @param {string} headerValue - The header value
   * @returns {Object} - Analysis result
   */
  analyzeHeaderValue(headerName, headerValue) {
    // This could be expanded to provide more detailed analysis of header values
    switch (headerName.toLowerCase()) {
      case 'content-security-policy':
        return this.analyzeCSP(headerValue);
      case 'strict-transport-security':
        return this.analyzeHSTS(headerValue);
      default:
        return {
          valid: true,
          recommendations: []
        };
    }
  }
  
  /**
   * Analyze Content-Security-Policy header value
   * @param {string} cspValue - The CSP header value
   * @returns {Object} - Analysis result
   */
  analyzeCSP(cspValue) {
    const recommendations = [];
    
    // Check for unsafe-inline in script-src
    if (cspValue.includes("script-src") && cspValue.includes("'unsafe-inline'")) {
      recommendations.push("Avoid using 'unsafe-inline' in script-src as it defeats the purpose of CSP");
    }
    
    // Check for unsafe-eval in script-src
    if (cspValue.includes("script-src") && cspValue.includes("'unsafe-eval'")) {
      recommendations.push("Avoid using 'unsafe-eval' in script-src as it allows potentially dangerous code execution");
    }
    
    // Check if default-src is defined
    if (!cspValue.includes("default-src")) {
      recommendations.push("Consider adding default-src directive as a fallback for other resource types");
    }
    
    return {
      valid: true,
      recommendations: recommendations
    };
  }
  
  /**
   * Analyze Strict-Transport-Security header value
   * @param {string} hstsValue - The HSTS header value
   * @returns {Object} - Analysis result
   */
  analyzeHSTS(hstsValue) {
    const recommendations = [];
    
    // Check max-age value
    const maxAgeMatch = hstsValue.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge < 31536000) { // Less than 1 year
        recommendations.push("Consider increasing max-age to at least 31536000 (1 year)");
      }
    } else {
      recommendations.push("max-age directive is missing");
    }
    
    // Check for includeSubDomains
    if (!hstsValue.includes("includeSubDomains")) {
      recommendations.push("Consider adding includeSubDomains directive for better security");
    }
    
    // Check for preload
    if (!hstsValue.includes("preload")) {
      recommendations.push("Consider adding preload directive for maximum security");
    }
    
    return {
      valid: true,
      recommendations: recommendations
    };
  }
}

// Export the checker
if (typeof module !== 'undefined') {
  module.exports = SecurityHeadersChecker;
}
