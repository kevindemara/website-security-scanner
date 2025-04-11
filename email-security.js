// Email Security Checker for Website Security Scanner
// Performs DNS lookups for SPF and DMARC records

class EmailSecurityChecker {
  constructor() {
    this.dnsApiUrl = 'https://dns.google/resolve';
    this.requestTimeout = 5000; // 5 seconds timeout
  }

  /**
   * Check domain email security (SPF and DMARC records)
   * @param {string} domain - The domain to check
   * @returns {Promise<Object>} - The check result
   */
  async checkDomain(domain) {
    try {
      // Check SPF record
      const spfResult = await this.checkSpfRecord(domain);
      
      // Check DMARC record
      const dmarcResult = await this.checkDmarcRecord(domain);
      
      // Determine overall status and score
      let status, score, message;
      
      if (spfResult.exists && dmarcResult.exists) {
        status = 'passed';
        score = 10;
        message = 'Domain has both SPF and DMARC records';
      } else if (spfResult.exists) {
        status = 'warning';
        score = 5;
        message = 'Domain has SPF but no DMARC record';
      } else if (dmarcResult.exists) {
        status = 'warning';
        score = 3;
        message = 'Domain has DMARC but no SPF record';
      } else {
        status = 'failed';
        score = 0;
        message = 'Domain has neither SPF nor DMARC records';
      }
      
      return {
        status: status,
        score: score,
        details: {
          message: message,
          spf: spfResult.exists ? 'Found' : 'Not found',
          spfRecord: spfResult.record,
          dmarc: dmarcResult.exists ? 'Found' : 'Not found',
          dmarcRecord: dmarcResult.record
        }
      };
    } catch (error) {
      console.error('Error checking email security:', error);
      return {
        status: 'error',
        score: 3, // Partial score due to error
        details: {
          message: `Error checking email security: ${error.message}`,
          error: error.message
        }
      };
    }
  }
  
  /**
   * Check if domain has an SPF record
   * @param {string} domain - The domain to check
   * @returns {Promise<Object>} - The check result
   */
  async checkSpfRecord(domain) {
    try {
      const txtRecords = await this.queryDns(domain, 'TXT');
      
      // Look for SPF record in TXT records
      const spfRecord = txtRecords.find(record => 
        record.toLowerCase().includes('v=spf1')
      );
      
      return {
        exists: !!spfRecord,
        record: spfRecord || 'No SPF record found'
      };
    } catch (error) {
      console.error('Error checking SPF record:', error);
      return {
        exists: false,
        record: `Error: ${error.message}`
      };
    }
  }
  
  /**
   * Check if domain has a DMARC record
   * @param {string} domain - The domain to check
   * @returns {Promise<Object>} - The check result
   */
  async checkDmarcRecord(domain) {
    try {
      const dmarcDomain = `_dmarc.${domain}`;
      const txtRecords = await this.queryDns(dmarcDomain, 'TXT');
      
      // Look for DMARC record in TXT records
      const dmarcRecord = txtRecords.find(record => 
        record.toLowerCase().includes('v=dmarc1')
      );
      
      return {
        exists: !!dmarcRecord,
        record: dmarcRecord || 'No DMARC record found'
      };
    } catch (error) {
      console.error('Error checking DMARC record:', error);
      return {
        exists: false,
        record: `Error: ${error.message}`
      };
    }
  }
  
  /**
   * Query DNS records using Google's public DNS API
   * @param {string} domain - The domain to query
   * @param {string} type - The DNS record type (e.g., 'TXT')
   * @returns {Promise<Array<string>>} - Array of record values
   */
  async queryDns(domain, type) {
    try {
      // Create AbortController for timeout
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.requestTimeout);
      
      try {
        const url = `${this.dnsApiUrl}?name=${encodeURIComponent(domain)}&type=${type}`;
        const response = await fetch(url, {
          method: 'GET',
          signal: controller.signal
        });
        
        clearTimeout(timeoutId);
        
        if (!response.ok) {
          throw new Error(`DNS query failed with status ${response.status}`);
        }
        
        const data = await response.json();
        
        // Extract record data from response
        const records = [];
        if (data.Answer && Array.isArray(data.Answer)) {
          data.Answer.forEach(answer => {
            if (answer.data) {
              // Clean up the record data (remove quotes)
              const cleanRecord = answer.data.replace(/^"|"$/g, '');
              records.push(cleanRecord);
            }
          });
        }
        
        return records;
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      // Handle timeout specifically
      if (error.name === 'AbortError') {
        throw new Error('DNS query timed out');
      }
      
      throw error;
    }
  }
}

// Export the checker
if (typeof module !== 'undefined') {
  module.exports = EmailSecurityChecker;
}
