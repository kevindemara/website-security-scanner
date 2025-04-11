// Directory Exposure Checker for Website Security Scanner
// Performs HTTP requests to check for exposed directories

class DirectoryChecker {
  constructor(settings = {}) {
    this.maxDirectoriesToCheck = settings.maxDirectoriesToCheck || 10;
    this.requestTimeout = 5000; // 5 seconds timeout
    this.maxRequestsPerMinute = settings.maxRequestsPerMinute || 30;
    
    // Common directories that might be exposed
    this.commonDirectories = [
      '/admin/',
      '/backup/',
      '/wp-admin/',
      '/config/',
      '/database/',
      '/db/',
      '/logs/',
      '/old/',
      '/temp/',
      '/test/',
      '/upload/',
      '/uploads/',
      '/files/',
      '/private/',
      '/dev/',
      '/.git/',
      '/.svn/',
      '/phpmyadmin/',
      '/server-status/',
      '/wp-content/'
    ];
  }

  /**
   * Check for exposed directories on a website
   * @param {string} url - The base URL to check
   * @returns {Promise<Object>} - The check result
   */
  async checkExposedDirectories(url) {
    try {
      // Parse the URL to get the base
      const baseUrl = new URL(url);
      const origin = baseUrl.origin;
      
      // Select directories to check (limit to max)
      const directoriesToCheck = this.commonDirectories.slice(0, this.maxDirectoriesToCheck);
      
      // Track exposed directories
      const exposedDirectories = [];
      const checkedDirectories = [];
      
      // Use Promise.all with rate limiting
      const results = await this.rateLimit(
        directoriesToCheck.map(dir => () => this.checkDirectory(origin + dir))
      );
      
      // Process results
      results.forEach((result, index) => {
        const directory = directoriesToCheck[index];
        checkedDirectories.push(directory);
        
        if (result.exposed) {
          exposedDirectories.push({
            path: directory,
            status: result.status,
            indexingEnabled: result.indexingEnabled
          });
        }
      });
      
      // Determine status and score based on exposed directories
      let status, score, message;
      
      if (exposedDirectories.length === 0) {
        status = 'passed';
        score = 10;
        message = 'No exposed directories detected';
      } else if (exposedDirectories.length <= 2) {
        status = 'warning';
        score = 5;
        message = `${exposedDirectories.length} exposed ${exposedDirectories.length === 1 ? 'directory' : 'directories'} detected`;
      } else {
        status = 'failed';
        score = 0;
        message = `${exposedDirectories.length} exposed directories detected`;
      }
      
      return {
        status: status,
        score: score,
        details: {
          message: message,
          exposedDirectories: exposedDirectories,
          checkedDirectories: checkedDirectories,
          totalChecked: checkedDirectories.length
        }
      };
    } catch (error) {
      console.error('Error checking exposed directories:', error);
      return {
        status: 'error',
        score: 5, // Partial score due to error
        details: {
          message: `Error checking for exposed directories: ${error.message}`,
          error: error.message,
          checkedDirectories: []
        }
      };
    }
  }
  
  /**
   * Check if a specific directory is exposed
   * @param {string} url - The directory URL to check
   * @returns {Promise<Object>} - The check result
   */
  async checkDirectory(url) {
    try {
      // Create AbortController for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.requestTimeout);
      
      try {
        const response = await fetch(url, {
          method: 'GET',
          headers: {
            'User-Agent': 'Mozilla/5.0 Website Security Scanner'
          },
          redirect: 'follow',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        // Check if directory is accessible
        if (response.ok) {
          // Get response text to check for directory listing
          const text = await response.text();
          
          // Check if it's a directory listing
          const isDirectoryListing = this.isDirectoryListing(text);
          
          return {
            exposed: true,
            status: response.status,
            indexingEnabled: isDirectoryListing
          };
        }
        
        return {
          exposed: false,
          status: response.status
        };
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      // Handle timeout specifically
      if (error.name === 'AbortError') {
        return {
          exposed: false,
          error: 'Request timed out'
        };
      }
      
      // For network errors, the directory might exist but be inaccessible
      return {
        exposed: false,
        error: error.message
      };
    }
  }
  
  /**
   * Check if HTML content represents a directory listing
   * @param {string} html - The HTML content to check
   * @returns {boolean} - True if it's a directory listing
   */
  isDirectoryListing(html) {
    // Common patterns in directory listings
    const patterns = [
      'Index of /',
      'Directory Listing For',
      '<title>Index of',
      '<h1>Index of',
      'Parent Directory</a>',
      'Directory listing for',
      'Last modified</a>',
      'Name</a></th><th>Size</a>',
      '[To Parent Directory]'
    ];
    
    return patterns.some(pattern => html.includes(pattern));
  }
  
  /**
   * Rate limit a series of async functions
   * @param {Array<Function>} functions - Array of functions to execute
   * @returns {Promise<Array>} - Array of results
   */
  async rateLimit(functions) {
    const results = [];
    const delay = (60 * 1000) / this.maxRequestsPerMinute;
    
    for (let i = 0; i < functions.length; i++) {
      // Add delay between requests to respect rate limit
      if (i > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }
      
      try {
        const result = await functions[i]();
        results.push(result);
      } catch (error) {
        results.push({ exposed: false, error: error.message });
      }
    }
    
    return results;
  }
}

// Export the checker
if (typeof module !== 'undefined') {
  module.exports = DirectoryChecker;
}
