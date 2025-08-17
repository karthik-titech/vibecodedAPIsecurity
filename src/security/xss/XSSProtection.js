const crypto = require('crypto');

/**
 * XSS Protection for Vibe-Coded Applications
 * Prevents Cross-Site Scripting vulnerabilities
 * 
 * @description This class provides comprehensive XSS protection through
 * output encoding, Content Security Policy headers, and input sanitization.
 */
class XSSProtection {
  constructor(options = {}) {
    this.cspConfig = options.csp || this.getDefaultCSP();
    this.encodingOptions = options.encoding || {};
  }

  /**
   * Get default Content Security Policy configuration
   */
  getDefaultCSP() {
    return {
      'default-src': ["'self'"],
      'script-src': ["'self'", "'unsafe-inline'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:'],
      'connect-src': ["'self'"],
      'font-src': ["'self'"],
      'object-src': ["'none'"],
      'media-src': ["'self'"],
      'frame-src': ["'none'"],
      'base-uri': ["'self'"],
      'form-action': ["'self'"]
    };
  }

  /**
   * Encode HTML to prevent XSS
   * @param {string} input - Input to encode
   * @returns {string} Encoded HTML
   */
  encodeHTML(input) {
    if (typeof input !== 'string') return input;
    
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  }

  /**
   * Encode JavaScript to prevent XSS
   * @param {string} input - Input to encode
   * @returns {string} Encoded JavaScript
   */
  encodeJavaScript(input) {
    if (typeof input !== 'string') return input;
    
    return input
      .replace(/\\/g, '\\\\')
      .replace(/'/g, "\\'")
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  }

  /**
   * Encode URL parameters to prevent XSS
   * @param {string} input - Input to encode
   * @returns {string} Encoded URL
   */
  encodeURL(input) {
    if (typeof input !== 'string') return input;
    return encodeURIComponent(input);
  }

  /**
   * Sanitize HTML input by removing dangerous tags and attributes
   * @param {string} input - HTML input to sanitize
   * @returns {string} Sanitized HTML
   */
  sanitizeHTML(input) {
    if (typeof input !== 'string') return input;
    
    // Remove script tags and event handlers
    return input
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/<iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe>/gi, '')
      .replace(/<object\b[^<]*(?:(?!<\/object>)<[^<]*)*<\/object>/gi, '')
      .replace(/<embed\b[^<]*(?:(?!<\/embed>)<[^<]*)*<\/embed>/gi, '')
      .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
      .replace(/javascript:/gi, '')
      .replace(/vbscript:/gi, '')
      .replace(/data:/gi, '');
  }

  /**
   * Generate Content Security Policy header
   * @returns {string} CSP header value
   */
  generateCSPHeader() {
    const directives = [];
    
    for (const [directive, sources] of Object.entries(this.cspConfig)) {
      directives.push(`${directive} ${sources.join(' ')}`);
    }
    
    return directives.join('; ');
  }

  /**
   * Apply security headers to Express response
   * @param {Object} res - Express response object
   */
  applySecurityHeaders(res) {
    res.setHeader('Content-Security-Policy', this.generateCSPHeader());
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  }

  /**
   * Create a safe HTML template with automatic encoding
   * @param {string} template - HTML template
   * @param {Object} data - Data to interpolate
   * @returns {string} Safe HTML
   */
  createSafeTemplate(template, data = {}) {
    let result = template;
    
    for (const [key, value] of Object.entries(data)) {
      const placeholder = new RegExp(`{{\\s*${key}\\s*}}`, 'g');
      result = result.replace(placeholder, this.encodeHTML(String(value)));
    }
    
    return result;
  }

  /**
   * Validate and sanitize user input
   * @param {Object} input - User input object
   * @param {Object} schema - Validation schema
   * @returns {Object} Sanitized input
   */
  validateAndSanitize(input, schema) {
    const sanitized = {};
    
    for (const [field, rules] of Object.entries(schema)) {
      const value = input[field];
      
      if (value === undefined || value === null) {
        if (rules.required) {
          throw new Error(`Field ${field} is required`);
        }
        continue;
      }
      
      let sanitizedValue = String(value);
      
      // Apply sanitization rules
      if (rules.sanitizeHTML) {
        sanitizedValue = this.sanitizeHTML(sanitizedValue);
      }
      
      if (rules.maxLength && sanitizedValue.length > rules.maxLength) {
        throw new Error(`Field ${field} exceeds maximum length`);
      }
      
      if (rules.pattern && !rules.pattern.test(sanitizedValue)) {
        throw new Error(`Field ${field} does not match required pattern`);
      }
      
      sanitized[field] = sanitizedValue;
    }
    
    return sanitized;
  }

  /**
   * Generate nonce for CSP inline scripts
   * @returns {string} Nonce value
   */
  generateNonce() {
    return crypto.randomBytes(16).toString('base64');
  }

  /**
   * Create middleware for Express.js
   * @returns {Function} Express middleware
   */
  middleware() {
    return (req, res, next) => {
      this.applySecurityHeaders(res);
      
      // Add nonce to res.locals for template engines
      res.locals.nonce = this.generateNonce();
      
      next();
    };
  }
}

module.exports = XSSProtection;
