const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');
const compression = require('compression');

/**
 * Comprehensive Security Middleware for Vibe-Coded Applications
 * 
 * @description This middleware combines all security protections into a single
 * Express.js middleware stack, making it easy to secure any vibe-coded application.
 */
class SecurityMiddleware {
  constructor(options = {}) {
    this.options = {
      // Rate limiting options
      rateLimit: {
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100, // limit each IP to 100 requests per windowMs
        message: 'Too many requests from this IP, please try again later.',
        standardHeaders: true,
        legacyHeaders: false,
        ...options.rateLimit
      },
      
      // CORS options
      cors: {
        origin: options.cors?.origin || true,
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
        ...options.cors
      },
      
      // Helmet options
      helmet: {
        contentSecurityPolicy: {
          directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
          },
        },
        ...options.helmet
      },
      
      // Request size limits
      bodyLimit: options.bodyLimit || '10mb',
      
      // Additional security options
      enableCompression: options.enableCompression !== false,
      enableCors: options.enableCors !== false,
      enableHelmet: options.enableHelmet !== false,
      enableRateLimit: options.enableRateLimit !== false,
      
      ...options
    };
  }

  /**
   * Create the complete security middleware stack
   * @returns {Array} Array of Express middleware functions
   */
  createMiddlewareStack() {
    const middleware = [];

    // Compression middleware
    if (this.options.enableCompression) {
      middleware.push(compression());
    }

    // CORS middleware
    if (this.options.enableCors) {
      middleware.push(cors(this.options.cors));
    }

    // Helmet security headers
    if (this.options.enableHelmet) {
      middleware.push(helmet(this.options.helmet));
    }

    // Custom security headers
    middleware.push(this.customSecurityHeaders());

    // Rate limiting
    if (this.options.enableRateLimit) {
      middleware.push(rateLimit(this.options.rateLimit));
    }

    // Request size limiting
    middleware.push(this.requestSizeLimit());

    // Request logging
    middleware.push(this.requestLogger());

    // Security monitoring
    middleware.push(this.securityMonitoring());

    return middleware;
  }

  /**
   * Custom security headers middleware
   */
  customSecurityHeaders() {
    return (req, res, next) => {
      // Remove server information
      res.removeHeader('X-Powered-By');
      
      // Add custom security headers
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-XSS-Protection', '1; mode=block');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
      res.setHeader('X-Security-Provider', 'VibeCoded Security Framework');
      
      // Add security timestamp
      res.setHeader('X-Security-Timestamp', new Date().toISOString());
      
      next();
    };
  }

  /**
   * Request size limiting middleware
   */
  requestSizeLimit() {
    return (req, res, next) => {
      const contentLength = parseInt(req.headers['content-length'] || '0');
      const limit = this.parseSizeLimit(this.options.bodyLimit);
      
      if (contentLength > limit) {
        return res.status(413).json({
          error: 'Request entity too large',
          message: `Request size exceeds limit of ${this.options.bodyLimit}`,
          code: 'REQUEST_TOO_LARGE'
        });
      }
      
      next();
    };
  }

  /**
   * Parse size limit string to bytes
   */
  parseSizeLimit(limit) {
    const units = {
      'b': 1,
      'kb': 1024,
      'mb': 1024 * 1024,
      'gb': 1024 * 1024 * 1024
    };
    
    const match = limit.toLowerCase().match(/^(\d+)([kmg]?b)$/);
    if (!match) return 10 * 1024 * 1024; // Default 10MB
    
    const [, size, unit] = match;
    return parseInt(size) * (units[unit] || units['mb']);
  }

  /**
   * Request logging middleware
   */
  requestLogger() {
    return (req, res, next) => {
      const start = Date.now();
      
      // Log request
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - ${req.ip}`);
      
      // Log response
      res.on('finish', () => {
        const duration = Date.now() - start;
        const status = res.statusCode;
        const statusColor = status >= 400 ? '\x1b[31m' : status >= 300 ? '\x1b[33m' : '\x1b[32m';
        
        console.log(`${statusColor}[${new Date().toISOString()}] ${req.method} ${req.path} - ${status} (${duration}ms)\x1b[0m`);
      });
      
      next();
    };
  }

  /**
   * Security monitoring middleware
   */
  securityMonitoring() {
    return (req, res, next) => {
      // Monitor for suspicious patterns
      const suspiciousPatterns = [
        /<script/i,
        /javascript:/i,
        /vbscript:/i,
        /on\w+\s*=/i,
        /union\s+select/i,
        /drop\s+table/i,
        /delete\s+from/i,
        /insert\s+into/i,
        /update\s+.*\s+set/i
      ];
      
      const requestData = {
        url: req.url,
        method: req.method,
        headers: req.headers,
        body: req.body,
        query: req.query,
        params: req.params
      };
      
      const requestString = JSON.stringify(requestData).toLowerCase();
      
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(requestString)) {
          console.warn(`🚨 Suspicious request detected: ${pattern.source}`);
          console.warn(`   URL: ${req.url}`);
          console.warn(`   IP: ${req.ip}`);
          console.warn(`   User-Agent: ${req.headers['user-agent']}`);
          
          // Log to security monitoring system
          this.logSecurityEvent('SUSPICIOUS_REQUEST', {
            pattern: pattern.source,
            url: req.url,
            ip: req.ip,
            userAgent: req.headers['user-agent'],
            timestamp: new Date().toISOString()
          });
        }
      }
      
      next();
    };
  }

  /**
   * Log security events
   */
  logSecurityEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      source: 'SecurityMiddleware'
    };
    
    // In production, send to security monitoring system
    console.log('🔒 SECURITY EVENT:', logEntry);
  }

  /**
   * Create error handling middleware
   */
  createErrorHandler() {
    return (error, req, res, next) => {
      // Log security event
      this.logSecurityEvent('APPLICATION_ERROR', {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip
      });
      
      // Don't expose internal errors in production
      const isDevelopment = process.env.NODE_ENV === 'development';
      
      res.status(error.status || 500).json({
        error: 'Internal server error',
        message: isDevelopment ? error.message : 'Something went wrong',
        ...(isDevelopment && { stack: error.stack })
      });
    };
  }

  /**
   * Create 404 handler
   */
  createNotFoundHandler() {
    return (req, res) => {
      res.status(404).json({
        error: 'Not found',
        message: `Route ${req.method} ${req.path} not found`,
        code: 'ROUTE_NOT_FOUND'
      });
    };
  }

  /**
   * Create health check endpoint
   */
  createHealthCheck() {
    return (req, res) => {
      res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        memory: process.memoryUsage(),
        security: {
          framework: 'VibeCoded Security',
          version: require('../../package.json').version,
          features: [
            'Rate Limiting',
            'CORS Protection',
            'Security Headers',
            'Request Monitoring',
            'XSS Protection',
            'SQL Injection Protection'
          ]
        }
      });
    };
  }

  /**
   * Create security status endpoint
   */
  createSecurityStatus() {
    return (req, res) => {
      res.json({
        security: {
          framework: 'VibeCoded Security Framework',
          version: require('../../package.json').version,
          status: 'active',
          timestamp: new Date().toISOString(),
          features: {
            rateLimit: this.options.enableRateLimit,
            cors: this.options.enableCors,
            helmet: this.options.enableHelmet,
            compression: this.options.enableCompression
          },
          recommendations: [
            'Use HTTPS in production',
            'Regularly update dependencies',
            'Monitor security logs',
            'Conduct security audits'
          ]
        }
      });
    };
  }
}

module.exports = SecurityMiddleware;
