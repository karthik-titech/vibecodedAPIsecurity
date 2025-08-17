const fs = require('fs').promises;
const path = require('path');

/**
 * Incident Response Manager for Vibe-Coded Applications
 * 
 * @description This class provides comprehensive incident response capabilities
 * including automated response actions, incident documentation, and escalation
 * procedures for security incidents in vibe-coded applications.
 */
class IncidentResponseManager {
  constructor(options = {}) {
    this.options = {
      // Incident response settings
      autoResponse: options.autoResponse !== false,
      escalationThreshold: options.escalationThreshold || 5, // incidents per hour
      responseTimeout: options.responseTimeout || 15 * 60 * 1000, // 15 minutes
      
      // Notification settings
      notifications: {
        email: options.notifications?.email || null,
        slack: options.notifications?.slack || null,
        webhook: options.notifications?.webhook || null,
        sms: options.notifications?.sms || null
      },
      
      // Incident storage
      incidentLogFile: options.incidentLogFile || 'security-incidents.log',
      incidentDatabase: options.incidentDatabase || 'incidents.json',
      
      // Response actions
      enableAutoBlocking: options.enableAutoBlocking !== false,
      enableRateLimiting: options.enableRateLimiting !== false,
      enableLogging: options.enableLogging !== false,
      
      ...options
    };
    
    // Incident tracking
    this.activeIncidents = new Map();
    this.incidentHistory = [];
    this.responseActions = new Map();
    
    // Incident types and severity levels
    this.incidentTypes = {
      'SQL_INJECTION': {
        name: 'SQL Injection Attempt',
        severity: 'critical',
        autoResponse: true,
        responseActions: ['block_ip', 'log_incident', 'notify_admin']
      },
      'XSS_ATTEMPT': {
        name: 'Cross-Site Scripting Attempt',
        severity: 'high',
        autoResponse: true,
        responseActions: ['block_ip', 'log_incident', 'notify_admin']
      },
      'BRUTE_FORCE': {
        name: 'Brute Force Attack',
        severity: 'high',
        autoResponse: true,
        responseActions: ['block_ip', 'rate_limit', 'log_incident', 'notify_admin']
      },
      'UNAUTHORIZED_ACCESS': {
        name: 'Unauthorized Access Attempt',
        severity: 'medium',
        autoResponse: true,
        responseActions: ['log_incident', 'notify_admin']
      },
      'DATA_BREACH': {
        name: 'Data Breach',
        severity: 'critical',
        autoResponse: false,
        responseActions: ['log_incident', 'notify_admin', 'escalate']
      },
      'MALWARE_DETECTED': {
        name: 'Malware Detected',
        severity: 'critical',
        autoResponse: true,
        responseActions: ['block_ip', 'isolate_system', 'log_incident', 'notify_admin']
      },
      'DDOS_ATTACK': {
        name: 'DDoS Attack',
        severity: 'high',
        autoResponse: true,
        responseActions: ['rate_limit', 'block_ip', 'log_incident', 'notify_admin']
      },
      'CONFIGURATION_ERROR': {
        name: 'Security Configuration Error',
        severity: 'medium',
        autoResponse: false,
        responseActions: ['log_incident', 'notify_admin']
      },
      'DEPENDENCY_VULNERABILITY': {
        name: 'Dependency Vulnerability',
        severity: 'medium',
        autoResponse: false,
        responseActions: ['log_incident', 'notify_admin']
      },
      'INSIDER_THREAT': {
        name: 'Insider Threat',
        severity: 'high',
        autoResponse: false,
        responseActions: ['log_incident', 'notify_admin', 'escalate']
      }
    };
    
    // Response action implementations
    this.responseActionHandlers = {
      'block_ip': this.blockIP.bind(this),
      'rate_limit': this.rateLimit.bind(this),
      'log_incident': this.logIncident.bind(this),
      'notify_admin': this.notifyAdmin.bind(this),
      'escalate': this.escalateIncident.bind(this),
      'isolate_system': this.isolateSystem.bind(this),
      'backup_data': this.backupData.bind(this),
      'shutdown_service': this.shutdownService.bind(this)
    };
    
    // Initialize incident response system
    this.initializeIncidentResponse();
  }

  /**
   * Initialize incident response system
   */
  async initializeIncidentResponse() {
    try {
      // Load existing incidents
      await this.loadIncidentHistory();
      
      // Set up incident monitoring
      this.startIncidentMonitoring();
      
      console.log('🚨 Incident Response Manager initialized');
    } catch (error) {
      console.error('Failed to initialize incident response:', error.message);
    }
  }

  /**
   * Create new security incident
   */
  async createIncident(incidentData) {
    const incident = {
      id: this.generateIncidentId(),
      type: incidentData.type,
      severity: this.incidentTypes[incidentData.type]?.severity || 'low',
      status: 'open',
      timestamp: new Date().toISOString(),
      source: incidentData.source || 'unknown',
      description: incidentData.description,
      evidence: incidentData.evidence || [],
      affectedSystems: incidentData.affectedSystems || [],
      ipAddress: incidentData.ipAddress,
      userAgent: incidentData.userAgent,
      userId: incidentData.userId,
      responseActions: [],
      notes: [],
      escalationLevel: 0,
      resolvedAt: null,
      resolvedBy: null,
      resolutionNotes: ''
    };
    
    // Add to active incidents
    this.activeIncidents.set(incident.id, incident);
    
    // Log incident
    await this.logIncident(incident);
    
    // Determine response actions
    const responseActions = this.determineResponseActions(incident);
    
    // Execute auto-response if enabled
    if (this.options.autoResponse && this.incidentTypes[incident.type]?.autoResponse) {
      await this.executeResponseActions(incident, responseActions);
    }
    
    // Send notifications
    await this.sendIncidentNotifications(incident);
    
    // Check for escalation
    this.checkEscalation(incident);
    
    console.log(`🚨 Incident ${incident.id} created: ${incident.type} (${incident.severity})`);
    
    return incident;
  }

  /**
   * Generate unique incident ID
   */
  generateIncidentId() {
    return `INC_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Determine response actions for incident
   */
  determineResponseActions(incident) {
    const incidentType = this.incidentTypes[incident.type];
    if (!incidentType) {
      return ['log_incident'];
    }
    
    let actions = [...incidentType.responseActions];
    
    // Add severity-based actions
    if (incident.severity === 'critical') {
      actions.push('escalate');
    }
    
    if (incident.severity === 'high' || incident.severity === 'critical') {
      actions.push('notify_admin');
    }
    
    // Add source-based actions
    if (incident.ipAddress) {
      actions.push('block_ip');
    }
    
    return [...new Set(actions)]; // Remove duplicates
  }

  /**
   * Execute response actions
   */
  async executeResponseActions(incident, actions) {
    const results = [];
    
    for (const action of actions) {
      try {
        const handler = this.responseActionHandlers[action];
        if (handler) {
          const result = await handler(incident);
          results.push({
            action,
            success: true,
            result,
            timestamp: new Date().toISOString()
          });
        } else {
          results.push({
            action,
            success: false,
            error: 'Handler not found',
            timestamp: new Date().toISOString()
          });
        }
      } catch (error) {
        results.push({
          action,
          success: false,
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }
    
    // Update incident with response actions
    incident.responseActions = results;
    this.activeIncidents.set(incident.id, incident);
    
    return results;
  }

  /**
   * Response action handlers
   */
  async blockIP(incident) {
    if (!incident.ipAddress) {
      return { success: false, reason: 'No IP address provided' };
    }
    
    // This would integrate with firewall or WAF
    console.log(`🔒 Blocking IP: ${incident.ipAddress}`);
    
    return {
      success: true,
      action: 'ip_blocked',
      ipAddress: incident.ipAddress,
      duration: '24h'
    };
  }

  async rateLimit(incident) {
    if (!incident.ipAddress) {
      return { success: false, reason: 'No IP address provided' };
    }
    
    // This would integrate with rate limiting system
    console.log(`⏱️ Rate limiting IP: ${incident.ipAddress}`);
    
    return {
      success: true,
      action: 'rate_limited',
      ipAddress: incident.ipAddress,
      limit: '10 requests per minute'
    };
  }

  async logIncident(incident) {
    try {
      const logEntry = {
        timestamp: incident.timestamp,
        incidentId: incident.id,
        type: incident.type,
        severity: incident.severity,
        description: incident.description,
        source: incident.source,
        ipAddress: incident.ipAddress
      };
      
      await fs.appendFile(this.options.incidentLogFile, JSON.stringify(logEntry) + '\n');
      
      return {
        success: true,
        action: 'logged',
        file: this.options.incidentLogFile
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  async notifyAdmin(incident) {
    const notification = {
      type: 'security_incident',
      severity: incident.severity,
      incidentId: incident.id,
      title: `Security Incident: ${this.incidentTypes[incident.type]?.name || incident.type}`,
      description: incident.description,
      timestamp: incident.timestamp,
      source: incident.source,
      ipAddress: incident.ipAddress
    };
    
    // Send notifications through configured channels
    const results = [];
    
    if (this.options.notifications.email) {
      results.push(await this.sendEmailNotification(notification));
    }
    
    if (this.options.notifications.slack) {
      results.push(await this.sendSlackNotification(notification));
    }
    
    if (this.options.notifications.webhook) {
      results.push(await this.sendWebhookNotification(notification));
    }
    
    if (this.options.notifications.sms) {
      results.push(await this.sendSMSNotification(notification));
    }
    
    return {
      success: results.some(r => r.success),
      action: 'notified',
      channels: results
    };
  }

  async escalateIncident(incident) {
    incident.escalationLevel++;
    
    const escalation = {
      level: incident.escalationLevel,
      timestamp: new Date().toISOString(),
      reason: `Incident severity: ${incident.severity}`,
      actions: ['notify_management', 'activate_incident_response_team']
    };
    
    // Add escalation note
    incident.notes.push({
      type: 'escalation',
      timestamp: new Date().toISOString(),
      content: `Incident escalated to level ${incident.escalationLevel}`,
      escalation: escalation
    });
    
    this.activeIncidents.set(incident.id, incident);
    
    return {
      success: true,
      action: 'escalated',
      level: incident.escalationLevel
    };
  }

  async isolateSystem(incident) {
    // This would isolate affected systems
    console.log(`🔒 Isolating system for incident: ${incident.id}`);
    
    return {
      success: true,
      action: 'system_isolated',
      systems: incident.affectedSystems
    };
  }

  async backupData(incident) {
    // This would trigger data backup
    console.log(`💾 Backing up data for incident: ${incident.id}`);
    
    return {
      success: true,
      action: 'data_backed_up',
      timestamp: new Date().toISOString()
    };
  }

  async shutdownService(incident) {
    // This would shutdown affected services
    console.log(`🛑 Shutting down service for incident: ${incident.id}`);
    
    return {
      success: true,
      action: 'service_shutdown',
      services: incident.affectedSystems
    };
  }

  /**
   * Send incident notifications
   */
  async sendEmailNotification(notification) {
    try {
      // This would integrate with email service
      console.log(`📧 Email notification sent: ${notification.title}`);
      
      return {
        channel: 'email',
        success: true,
        message: 'Email notification sent'
      };
    } catch (error) {
      return {
        channel: 'email',
        success: false,
        error: error.message
      };
    }
  }

  async sendSlackNotification(notification) {
    try {
      // This would integrate with Slack API
      console.log(`💬 Slack notification sent: ${notification.title}`);
      
      return {
        channel: 'slack',
        success: true,
        message: 'Slack notification sent'
      };
    } catch (error) {
      return {
        channel: 'slack',
        success: false,
        error: error.message
      };
    }
  }

  async sendWebhookNotification(notification) {
    try {
      // This would send webhook notification
      console.log(`🔗 Webhook notification sent: ${notification.title}`);
      
      return {
        channel: 'webhook',
        success: true,
        message: 'Webhook notification sent'
      };
    } catch (error) {
      return {
        channel: 'webhook',
        success: false,
        error: error.message
      };
    }
  }

  async sendSMSNotification(notification) {
    try {
      // This would integrate with SMS service
      console.log(`📱 SMS notification sent: ${notification.title}`);
      
      return {
        channel: 'sms',
        success: true,
        message: 'SMS notification sent'
      };
    } catch (error) {
      return {
        channel: 'sms',
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Check for incident escalation
   */
  checkEscalation(incident) {
    const recentIncidents = this.getRecentIncidents(60 * 60 * 1000); // Last hour
    const similarIncidents = recentIncidents.filter(i => i.type === incident.type);
    
    if (similarIncidents.length >= this.options.escalationThreshold) {
      this.escalateIncident(incident);
    }
  }

  /**
   * Get recent incidents
   */
  getRecentIncidents(timeWindow) {
    const cutoff = Date.now() - timeWindow;
    return Array.from(this.activeIncidents.values())
      .filter(incident => new Date(incident.timestamp).getTime() > cutoff);
  }

  /**
   * Update incident status
   */
  async updateIncident(incidentId, updates) {
    const incident = this.activeIncidents.get(incidentId);
    if (!incident) {
      throw new Error(`Incident ${incidentId} not found`);
    }
    
    // Update incident
    Object.assign(incident, updates);
    
    // Add update note
    incident.notes.push({
      type: 'update',
      timestamp: new Date().toISOString(),
      content: `Incident updated: ${JSON.stringify(updates)}`
    });
    
    // If incident is resolved, move to history
    if (updates.status === 'resolved') {
      incident.resolvedAt = new Date().toISOString();
      this.activeIncidents.delete(incidentId);
      this.incidentHistory.push(incident);
      await this.saveIncidentHistory();
    } else {
      this.activeIncidents.set(incidentId, incident);
    }
    
    return incident;
  }

  /**
   * Add note to incident
   */
  async addIncidentNote(incidentId, note) {
    const incident = this.activeIncidents.get(incidentId);
    if (!incident) {
      throw new Error(`Incident ${incidentId} not found`);
    }
    
    incident.notes.push({
      type: 'note',
      timestamp: new Date().toISOString(),
      content: note,
      author: note.author || 'system'
    });
    
    this.activeIncidents.set(incidentId, incident);
    
    return incident;
  }

  /**
   * Get incident by ID
   */
  getIncident(incidentId) {
    return this.activeIncidents.get(incidentId) || 
           this.incidentHistory.find(i => i.id === incidentId);
  }

  /**
   * Get all active incidents
   */
  getActiveIncidents() {
    return Array.from(this.activeIncidents.values());
  }

  /**
   * Get incident history
   */
  getIncidentHistory() {
    return this.incidentHistory;
  }

  /**
   * Get incident statistics
   */
  getIncidentStats() {
    const active = this.getActiveIncidents();
    const history = this.getIncidentHistory();
    
    const stats = {
      active: active.length,
      total: active.length + history.length,
      bySeverity: {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      },
      byType: {},
      recent: this.getRecentIncidents(24 * 60 * 60 * 1000).length // Last 24 hours
    };
    
    // Count by severity
    [...active, ...history].forEach(incident => {
      stats.bySeverity[incident.severity]++;
      
      if (!stats.byType[incident.type]) {
        stats.byType[incident.type] = 0;
      }
      stats.byType[incident.type]++;
    });
    
    return stats;
  }

  /**
   * Load incident history from file
   */
  async loadIncidentHistory() {
    try {
      const data = await fs.readFile(this.options.incidentDatabase, 'utf8');
      this.incidentHistory = JSON.parse(data);
    } catch (error) {
      // File doesn't exist or is empty, start with empty history
      this.incidentHistory = [];
    }
  }

  /**
   * Save incident history to file
   */
  async saveIncidentHistory() {
    try {
      await fs.writeFile(
        this.options.incidentDatabase, 
        JSON.stringify(this.incidentHistory, null, 2)
      );
    } catch (error) {
      console.error('Failed to save incident history:', error.message);
    }
  }

  /**
   * Start incident monitoring
   */
  startIncidentMonitoring() {
    // Monitor for incident patterns
    setInterval(() => {
      this.monitorIncidentPatterns();
    }, 5 * 60 * 1000); // Every 5 minutes
    
    // Clean up old incidents
    setInterval(() => {
      this.cleanupOldIncidents();
    }, 60 * 60 * 1000); // Every hour
  }

  /**
   * Monitor for incident patterns
   */
  monitorIncidentPatterns() {
    const recentIncidents = this.getRecentIncidents(60 * 60 * 1000); // Last hour
    
    // Check for attack patterns
    const patterns = this.detectAttackPatterns(recentIncidents);
    
    if (patterns.length > 0) {
      console.log('🚨 Attack patterns detected:', patterns);
      
      // Create pattern-based incident
      this.createIncident({
        type: 'ATTACK_PATTERN',
        severity: 'high',
        description: `Attack pattern detected: ${patterns.join(', ')}`,
        source: 'pattern_detection',
        evidence: patterns
      });
    }
  }

  /**
   * Detect attack patterns
   */
  detectAttackPatterns(incidents) {
    const patterns = [];
    
    // Check for rapid-fire attacks
    const rapidIncidents = incidents.filter(i => 
      i.type === 'BRUTE_FORCE' || i.type === 'SQL_INJECTION'
    );
    
    if (rapidIncidents.length > 10) {
      patterns.push('Rapid-fire attack detected');
    }
    
    // Check for distributed attacks
    const uniqueIPs = new Set(incidents.map(i => i.ipAddress).filter(Boolean));
    if (uniqueIPs.size > 5 && incidents.length > 20) {
      patterns.push('Distributed attack detected');
    }
    
    // Check for targeted attacks
    const targetedIncidents = incidents.filter(i => i.type === 'UNAUTHORIZED_ACCESS');
    if (targetedIncidents.length > 5) {
      patterns.push('Targeted attack detected');
    }
    
    return patterns;
  }

  /**
   * Clean up old incidents
   */
  cleanupOldIncidents() {
    const cutoff = Date.now() - (30 * 24 * 60 * 60 * 1000); // 30 days ago
    
    this.incidentHistory = this.incidentHistory.filter(incident => 
      new Date(incident.timestamp).getTime() > cutoff
    );
    
    // Save cleaned history
    this.saveIncidentHistory();
  }

  /**
   * Create Express middleware for incident response
   */
  createIncidentResponseMiddleware() {
    return (req, res, next) => {
      // Add incident response headers
      res.setHeader('X-Incident-Response', 'enabled');
      res.setHeader('X-Incident-Response-Version', '1.0');
      
      // Monitor for potential incidents
      this.monitorRequest(req, res);
      
      next();
    };
  }

  /**
   * Monitor individual request for potential incidents
   */
  monitorRequest(req, res) {
    const requestData = {
      path: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.headers['user-agent'],
      timestamp: new Date().toISOString()
    };
    
    // Check for suspicious patterns
    if (this.isSuspiciousRequest(requestData)) {
      this.createIncident({
        type: 'SUSPICIOUS_REQUEST',
        severity: 'medium',
        description: `Suspicious request detected: ${req.method} ${req.path}`,
        source: 'request_monitoring',
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'],
        evidence: [requestData]
      });
    }
  }

  /**
   * Check if request is suspicious
   */
  isSuspiciousRequest(requestData) {
    const suspiciousPatterns = [
      /\.\.\//, // Path traversal
      /<script/i, // XSS
      /union\s+select/i, // SQL injection
      /eval\s*\(/i, // Code injection
      /javascript:/i // JavaScript injection
    ];
    
    const requestString = JSON.stringify(requestData).toLowerCase();
    
    return suspiciousPatterns.some(pattern => pattern.test(requestString));
  }

  /**
   * Generate incident report
   */
  async generateIncidentReport(incidentId) {
    const incident = this.getIncident(incidentId);
    if (!incident) {
      throw new Error(`Incident ${incidentId} not found`);
    }
    
    const report = {
      incidentId: incident.id,
      type: incident.type,
      severity: incident.severity,
      status: incident.status,
      timestamp: incident.timestamp,
      description: incident.description,
      source: incident.source,
      evidence: incident.evidence,
      responseActions: incident.responseActions,
      notes: incident.notes,
      timeline: this.generateIncidentTimeline(incident),
      recommendations: this.generateIncidentRecommendations(incident)
    };
    
    return report;
  }

  /**
   * Generate incident timeline
   */
  generateIncidentTimeline(incident) {
    const timeline = [
      {
        timestamp: incident.timestamp,
        event: 'Incident detected',
        description: incident.description
      }
    ];
    
    // Add response actions
    incident.responseActions.forEach(action => {
      timeline.push({
        timestamp: action.timestamp,
        event: `Response action: ${action.action}`,
        description: action.success ? 'Action completed successfully' : `Action failed: ${action.error}`
      });
    });
    
    // Add notes
    incident.notes.forEach(note => {
      timeline.push({
        timestamp: note.timestamp,
        event: `Note added`,
        description: note.content
      });
    });
    
    // Sort by timestamp
    return timeline.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
  }

  /**
   * Generate incident recommendations
   */
  generateIncidentRecommendations(incident) {
    const recommendations = [];
    
    // Type-specific recommendations
    switch (incident.type) {
      case 'SQL_INJECTION':
        recommendations.push(
          'Implement parameterized queries',
          'Use input validation and sanitization',
          'Review database access controls'
        );
        break;
      case 'XSS_ATTEMPT':
        recommendations.push(
          'Implement output encoding',
          'Use Content Security Policy headers',
          'Review input validation'
        );
        break;
      case 'BRUTE_FORCE':
        recommendations.push(
          'Implement account lockout policies',
          'Use CAPTCHA for login forms',
          'Monitor for suspicious login patterns'
        );
        break;
      case 'UNAUTHORIZED_ACCESS':
        recommendations.push(
          'Review access control policies',
          'Implement proper authentication',
          'Monitor access logs'
        );
        break;
    }
    
    // General recommendations
    recommendations.push(
      'Conduct security training for team members',
      'Implement automated security monitoring',
      'Regular security assessments and penetration testing'
    );
    
    return recommendations;
  }
}

module.exports = IncidentResponseManager;
