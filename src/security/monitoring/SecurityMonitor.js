const fs = require('fs').promises;
const path = require('path');

/**
 * Security Monitor for Vibe-Coded Applications
 * 
 * @description This class provides comprehensive security monitoring, threat detection,
 * and real-time alerting for vibe-coded applications to prevent security breaches.
 */
class SecurityMonitor {
  constructor(options = {}) {
    this.options = {
      // Monitoring options
      logFile: options.logFile || 'security-events.log',
      maxLogSize: options.maxLogSize || 10 * 1024 * 1024, // 10MB
      maxLogFiles: options.maxLogFiles || 5,
      
      // Alert thresholds
      alertThresholds: {
        failedLogins: options.alertThresholds?.failedLogins || 5,
        suspiciousRequests: options.alertThresholds?.suspiciousRequests || 10,
        sqlInjectionAttempts: options.alertThresholds?.sqlInjectionAttempts || 3,
        xssAttempts: options.alertThresholds?.xssAttempts || 3,
        rateLimitViolations: options.alertThresholds?.rateLimitViolations || 20,
        ...options.alertThresholds
      },
      
      // Monitoring intervals
      monitoringInterval: options.monitoringInterval || 60000, // 1 minute
      
      // Alert channels
      alertChannels: {
        console: options.alertChannels?.console !== false,
        file: options.alertChannels?.file !== false,
        webhook: options.alertChannels?.webhook || null,
        email: options.alertChannels?.email || null,
        ...options.alertChannels
      },
      
      ...options
    };
    
    // Event counters
    this.eventCounters = {
      failedLogins: 0,
      suspiciousRequests: 0,
      sqlInjectionAttempts: 0,
      xssAttempts: 0,
      rateLimitViolations: 0,
      authenticationFailures: 0,
      authorizationFailures: 0,
      inputValidationFailures: 0,
      databaseErrors: 0,
      applicationErrors: 0
    };
    
    // Event history
    this.eventHistory = [];
    this.maxHistorySize = 1000;
    
    // Alert history
    this.alertHistory = [];
    this.maxAlertHistory = 100;
    
    // Monitoring state
    this.isMonitoring = false;
    this.monitoringInterval = null;
    
    // Threat patterns
    this.threatPatterns = {
      sqlInjection: [
        /union\s+select/i,
        /drop\s+table/i,
        /delete\s+from/i,
        /insert\s+into/i,
        /update\s+.*\s+set/i,
        /exec\s*\(/i,
        /xp_cmdshell/i,
        /';?\s*drop\s+table/i,
        /';?\s*delete\s+from/i
      ],
      xss: [
        /<script[^>]*>/i,
        /javascript:/i,
        /vbscript:/i,
        /on\w+\s*=/i,
        /<iframe[^>]*>/i,
        /<object[^>]*>/i,
        /<embed[^>]*>/i,
        /data:text\/html/i
      ],
      pathTraversal: [
        /\.\.\//,
        /\.\.\\/,
        /%2e%2e%2f/i,
        /%2e%2e%5c/i
      ],
      commandInjection: [
        /[;&|`$()]/,
        /exec\s*\(/i,
        /system\s*\(/i,
        /eval\s*\(/i
      ]
    };
  }

  /**
   * Start security monitoring
   */
  async startMonitoring() {
    if (this.isMonitoring) {
      console.log('⚠️ Security monitoring is already running');
      return;
    }
    
    try {
      // Initialize log file
      await this.initializeLogFile();
      
      // Start monitoring interval
      this.monitoringInterval = setInterval(() => {
        this.checkThresholds();
      }, this.options.monitoringInterval);
      
      this.isMonitoring = true;
      
      this.logSecurityEvent('MONITORING_STARTED', {
        timestamp: new Date().toISOString(),
        configuration: this.options
      });
      
      console.log('🔒 Security monitoring started');
    } catch (error) {
      console.error('❌ Failed to start security monitoring:', error.message);
      throw error;
    }
  }

  /**
   * Stop security monitoring
   */
  stopMonitoring() {
    if (!this.isMonitoring) {
      console.log('⚠️ Security monitoring is not running');
      return;
    }
    
    if (this.monitoringInterval) {
      clearInterval(this.monitoringInterval);
      this.monitoringInterval = null;
    }
    
    this.isMonitoring = false;
    
    this.logSecurityEvent('MONITORING_STOPPED', {
      timestamp: new Date().toISOString()
    });
    
    console.log('🔒 Security monitoring stopped');
  }

  /**
   * Log security event
   * @param {string} eventType - Type of security event
   * @param {Object} eventData - Event data
   * @param {string} severity - Event severity (low, medium, high, critical)
   */
  async logSecurityEvent(eventType, eventData, severity = 'medium') {
    const event = {
      id: this.generateEventId(),
      type: eventType,
      severity: severity,
      timestamp: new Date().toISOString(),
      data: eventData,
      source: eventData.source || 'application'
    };
    
    // Add to history
    this.eventHistory.push(event);
    if (this.eventHistory.length > this.maxHistorySize) {
      this.eventHistory.shift();
    }
    
    // Update counters
    this.updateEventCounters(eventType);
    
    // Check for threats
    const threatLevel = this.detectThreats(event);
    if (threatLevel > 0) {
      event.threatLevel = threatLevel;
      await this.handleThreat(event);
    }
    
    // Write to log file
    await this.writeToLogFile(event);
    
    // Send alerts if needed
    if (severity === 'high' || severity === 'critical') {
      await this.sendAlert(event);
    }
    
    return event;
  }

  /**
   * Generate unique event ID
   */
  generateEventId() {
    return `evt_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Update event counters
   */
  updateEventCounters(eventType) {
    const counterMap = {
      'LOGIN_FAILED': 'failedLogins',
      'SUSPICIOUS_REQUEST': 'suspiciousRequests',
      'SQL_INJECTION_ATTEMPT': 'sqlInjectionAttempts',
      'XSS_ATTEMPT': 'xssAttempts',
      'RATE_LIMIT_VIOLATION': 'rateLimitViolations',
      'AUTHENTICATION_FAILURE': 'authenticationFailures',
      'AUTHORIZATION_FAILURE': 'authorizationFailures',
      'INPUT_VALIDATION_FAILURE': 'inputValidationFailures',
      'DATABASE_ERROR': 'databaseErrors',
      'APPLICATION_ERROR': 'applicationErrors'
    };
    
    const counter = counterMap[eventType];
    if (counter) {
      this.eventCounters[counter]++;
    }
  }

  /**
   * Detect threats in security events
   */
  detectThreats(event) {
    let threatLevel = 0;
    const eventString = JSON.stringify(event).toLowerCase();
    
    // Check for SQL injection patterns
    for (const pattern of this.threatPatterns.sqlInjection) {
      if (pattern.test(eventString)) {
        threatLevel = Math.max(threatLevel, 3);
        break;
      }
    }
    
    // Check for XSS patterns
    for (const pattern of this.threatPatterns.xss) {
      if (pattern.test(eventString)) {
        threatLevel = Math.max(threatLevel, 3);
        break;
      }
    }
    
    // Check for path traversal
    for (const pattern of this.threatPatterns.pathTraversal) {
      if (pattern.test(eventString)) {
        threatLevel = Math.max(threatLevel, 2);
        break;
      }
    }
    
    // Check for command injection
    for (const pattern of this.threatPatterns.commandInjection) {
      if (pattern.test(eventString)) {
        threatLevel = Math.max(threatLevel, 4);
        break;
      }
    }
    
    // Check for brute force attempts
    if (event.type === 'LOGIN_FAILED' && this.eventCounters.failedLogins > 10) {
      threatLevel = Math.max(threatLevel, 2);
    }
    
    // Check for rapid requests
    if (event.type === 'RATE_LIMIT_VIOLATION' && this.eventCounters.rateLimitViolations > 50) {
      threatLevel = Math.max(threatLevel, 2);
    }
    
    return threatLevel;
  }

  /**
   * Handle detected threats
   */
  async handleThreat(event) {
    const threatActions = {
      1: 'Monitor closely',
      2: 'Increase logging',
      3: 'Block IP temporarily',
      4: 'Block IP permanently',
      5: 'Emergency response'
    };
    
    const action = threatActions[event.threatLevel] || 'Monitor';
    
    const threatEvent = {
      ...event,
      threatAction: action,
      handled: true
    };
    
    // Log threat
    await this.logSecurityEvent('THREAT_DETECTED', {
      originalEvent: event,
      threatLevel: event.threatLevel,
      action: action,
      timestamp: new Date().toISOString()
    }, 'high');
    
    // Send immediate alert
    await this.sendAlert(threatEvent, 'threat');
    
    console.log(`🚨 Threat detected (Level ${event.threatLevel}): ${action}`);
  }

  /**
   * Check alert thresholds
   */
  checkThresholds() {
    const alerts = [];
    
    // Check failed logins
    if (this.eventCounters.failedLogins >= this.options.alertThresholds.failedLogins) {
      alerts.push({
        type: 'FAILED_LOGINS_THRESHOLD',
        message: `High number of failed login attempts: ${this.eventCounters.failedLogins}`,
        severity: 'medium'
      });
    }
    
    // Check suspicious requests
    if (this.eventCounters.suspiciousRequests >= this.options.alertThresholds.suspiciousRequests) {
      alerts.push({
        type: 'SUSPICIOUS_REQUESTS_THRESHOLD',
        message: `High number of suspicious requests: ${this.eventCounters.suspiciousRequests}`,
        severity: 'high'
      });
    }
    
    // Check SQL injection attempts
    if (this.eventCounters.sqlInjectionAttempts >= this.options.alertThresholds.sqlInjectionAttempts) {
      alerts.push({
        type: 'SQL_INJECTION_THRESHOLD',
        message: `SQL injection attempts detected: ${this.eventCounters.sqlInjectionAttempts}`,
        severity: 'critical'
      });
    }
    
    // Check XSS attempts
    if (this.eventCounters.xssAttempts >= this.options.alertThresholds.xssAttempts) {
      alerts.push({
        type: 'XSS_THRESHOLD',
        message: `XSS attempts detected: ${this.eventCounters.xssAttempts}`,
        severity: 'critical'
      });
    }
    
    // Send alerts
    alerts.forEach(alert => {
      this.sendAlert(alert, 'threshold');
    });
    
    // Reset counters if alerts were sent
    if (alerts.length > 0) {
      this.resetCounters();
    }
  }

  /**
   * Reset event counters
   */
  resetCounters() {
    Object.keys(this.eventCounters).forEach(key => {
      this.eventCounters[key] = 0;
    });
  }

  /**
   * Send security alert
   */
  async sendAlert(alert, type = 'event') {
    const alertData = {
      id: this.generateEventId(),
      type: type,
      timestamp: new Date().toISOString(),
      data: alert,
      source: 'SecurityMonitor'
    };
    
    // Add to alert history
    this.alertHistory.push(alertData);
    if (this.alertHistory.length > this.maxAlertHistory) {
      this.alertHistory.shift();
    }
    
    // Console alert
    if (this.options.alertChannels.console) {
      this.sendConsoleAlert(alertData);
    }
    
    // File alert
    if (this.options.alertChannels.file) {
      await this.sendFileAlert(alertData);
    }
    
    // Webhook alert
    if (this.options.alertChannels.webhook) {
      await this.sendWebhookAlert(alertData);
    }
    
    // Email alert
    if (this.options.alertChannels.email) {
      await this.sendEmailAlert(alertData);
    }
  }

  /**
   * Send console alert
   */
  sendConsoleAlert(alert) {
    const colors = {
      low: '\x1b[36m',    // Cyan
      medium: '\x1b[33m', // Yellow
      high: '\x1b[31m',   // Red
      critical: '\x1b[35m' // Magenta
    };
    
    const color = colors[alert.data.severity] || '\x1b[0m';
    const reset = '\x1b[0m';
    
    console.log(`${color}🚨 SECURITY ALERT [${alert.data.severity?.toUpperCase()}]${reset}`);
    console.log(`${color}Type: ${alert.type}${reset}`);
    console.log(`${color}Message: ${alert.data.message || alert.data.type}${reset}`);
    console.log(`${color}Timestamp: ${alert.timestamp}${reset}`);
    console.log(`${color}ID: ${alert.id}${reset}`);
    console.log('');
  }

  /**
   * Send file alert
   */
  async sendFileAlert(alert) {
    try {
      const alertFile = path.join(process.cwd(), 'security-alerts.log');
      const alertLine = `${alert.timestamp} - ${alert.type} - ${alert.data.severity} - ${alert.data.message || alert.data.type}\n`;
      
      await fs.appendFile(alertFile, alertLine);
    } catch (error) {
      console.error('Failed to write alert to file:', error.message);
    }
  }

  /**
   * Send webhook alert
   */
  async sendWebhookAlert(alert) {
    try {
      const https = require('https');
      const url = require('url');
      
      const webhookUrl = url.parse(this.options.alertChannels.webhook);
      const postData = JSON.stringify(alert);
      
      const options = {
        hostname: webhookUrl.hostname,
        port: webhookUrl.port || 443,
        path: webhookUrl.path,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(postData)
        }
      };
      
      const req = https.request(options, (res) => {
        // Handle response
      });
      
      req.on('error', (error) => {
        console.error('Webhook alert failed:', error.message);
      });
      
      req.write(postData);
      req.end();
    } catch (error) {
      console.error('Failed to send webhook alert:', error.message);
    }
  }

  /**
   * Send email alert
   */
  async sendEmailAlert(alert) {
    // Email implementation would go here
    // This is a placeholder for email alert functionality
    console.log(`📧 Email alert would be sent for: ${alert.data.message || alert.data.type}`);
  }

  /**
   * Initialize log file
   */
  async initializeLogFile() {
    try {
      const logPath = path.join(process.cwd(), this.options.logFile);
      
      // Check if log file exists and rotate if needed
      try {
        const stats = await fs.stat(logPath);
        if (stats.size > this.options.maxLogSize) {
          await this.rotateLogFile();
        }
      } catch (error) {
        // File doesn't exist, create it
        await fs.writeFile(logPath, '');
      }
    } catch (error) {
      console.error('Failed to initialize log file:', error.message);
    }
  }

  /**
   * Rotate log file
   */
  async rotateLogFile() {
    try {
      const logPath = path.join(process.cwd(), this.options.logFile);
      
      for (let i = this.options.maxLogFiles - 1; i > 0; i--) {
        const oldFile = `${logPath}.${i}`;
        const newFile = `${logPath}.${i + 1}`;
        
        try {
          await fs.rename(oldFile, newFile);
        } catch (error) {
          // File doesn't exist, continue
        }
      }
      
      await fs.rename(logPath, `${logPath}.1`);
      await fs.writeFile(logPath, '');
    } catch (error) {
      console.error('Failed to rotate log file:', error.message);
    }
  }

  /**
   * Write event to log file
   */
  async writeToLogFile(event) {
    try {
      const logPath = path.join(process.cwd(), this.options.logFile);
      const logLine = `${event.timestamp} - ${event.type} - ${event.severity} - ${JSON.stringify(event.data)}\n`;
      
      await fs.appendFile(logPath, logLine);
    } catch (error) {
      console.error('Failed to write to log file:', error.message);
    }
  }

  /**
   * Get security statistics
   */
  getSecurityStats() {
    return {
      monitoring: {
        isActive: this.isMonitoring,
        startTime: this.isMonitoring ? new Date().toISOString() : null
      },
      events: {
        total: this.eventHistory.length,
        counters: this.eventCounters,
        recent: this.eventHistory.slice(-10)
      },
      alerts: {
        total: this.alertHistory.length,
        recent: this.alertHistory.slice(-5)
      },
      threats: {
        detected: this.eventHistory.filter(e => e.threatLevel > 0).length,
        levels: {
          low: this.eventHistory.filter(e => e.threatLevel === 1).length,
          medium: this.eventHistory.filter(e => e.threatLevel === 2).length,
          high: this.eventHistory.filter(e => e.threatLevel === 3).length,
          critical: this.eventHistory.filter(e => e.threatLevel >= 4).length
        }
      }
    };
  }

  /**
   * Get security recommendations
   */
  getSecurityRecommendations() {
    const recommendations = [];
    
    if (this.eventCounters.failedLogins > 5) {
      recommendations.push('Implement account lockout after failed login attempts');
    }
    
    if (this.eventCounters.sqlInjectionAttempts > 0) {
      recommendations.push('Review and strengthen SQL injection protection');
    }
    
    if (this.eventCounters.xssAttempts > 0) {
      recommendations.push('Review and strengthen XSS protection');
    }
    
    if (this.eventCounters.rateLimitViolations > 10) {
      recommendations.push('Consider implementing stricter rate limiting');
    }
    
    if (this.eventCounters.inputValidationFailures > 5) {
      recommendations.push('Review input validation rules');
    }
    
    return recommendations;
  }

  /**
   * Create Express middleware for security monitoring
   */
  createMonitoringMiddleware() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      // Monitor request
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        
        // Log suspicious patterns
        this.monitorRequest(req, res, duration);
      });
      
      next();
    };
  }

  /**
   * Monitor individual request
   */
  monitorRequest(req, res, duration) {
    const requestData = {
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      duration: duration,
      statusCode: res.statusCode
    };
    
    // Check for suspicious patterns
    const requestString = JSON.stringify(requestData).toLowerCase();
    
    // Check for SQL injection
    for (const pattern of this.threatPatterns.sqlInjection) {
      if (pattern.test(requestString)) {
        this.logSecurityEvent('SQL_INJECTION_ATTEMPT', requestData, 'high');
        break;
      }
    }
    
    // Check for XSS
    for (const pattern of this.threatPatterns.xss) {
      if (pattern.test(requestString)) {
        this.logSecurityEvent('XSS_ATTEMPT', requestData, 'high');
        break;
      }
    }
    
    // Check for path traversal
    for (const pattern of this.threatPatterns.pathTraversal) {
      if (pattern.test(requestString)) {
        this.logSecurityEvent('PATH_TRAVERSAL_ATTEMPT', requestData, 'medium');
        break;
      }
    }
    
    // Log failed requests
    if (res.statusCode >= 400) {
      this.logSecurityEvent('REQUEST_FAILED', requestData, 'low');
    }
  }
}

module.exports = SecurityMonitor;
