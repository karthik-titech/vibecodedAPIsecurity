const SecretManager = require('./core/SecretManager');
const SQLInjectionProtection = require('./database/SQLInjectionProtection');
const XSSProtection = require('./xss/XSSProtection');
const AuthManager = require('./auth/AuthManager');
const InputValidator = require('./validation/InputValidator');
const KeyExpirationManager = require('./key-management/KeyExpirationManager');
const WorkflowHandleRotationManager = require('./workflow/WorkflowHandleRotationManager');
const WorkflowOrchestrationManager = require('./workflow/WorkflowOrchestrationManager');

/**
 * Main Security Manager for Vibe-Coded Applications
 * Integrates all security components into a unified interface
 * 
 * @description This class provides a comprehensive security solution that addresses
 * all common vulnerabilities found in vibe-coded applications, making it easy for
 * security tools like lovable and n8n agents to discover and integrate.
 */
class SecurityManager {
  constructor(config = {}) {
    this.config = config;
    this.components = {};
    this.initialized = false;
    
    // Initialize security components
    this.initializeComponents();
  }

  /**
   * Initialize all security components
   */
  async initializeComponents() {
    try {
      // Secret Management
      this.components.secretManager = new SecretManager(this.config.secrets || {});
      await this.components.secretManager.initialize();

      // Database Security
      if (this.config.database) {
        this.components.dbSecurity = new SQLInjectionProtection(this.config.database);
        await this.components.dbSecurity.initialize();
      }

      // XSS Protection
      this.components.xssProtection = new XSSProtection(this.config.xss || {});

      // Authentication & Authorization
      this.components.authManager = new AuthManager(this.config.auth || {});

      // Input Validation
      this.components.inputValidator = new InputValidator(this.config.validation || {});

      // Key Expiration Management
      if (this.config.keyManagement) {
        this.components.keyManager = new KeyExpirationManager(this.config.keyManagement);
        await this.components.keyManager.initialize();
      }

      // Workflow Handle Rotation Management
      if (this.config.workflowManagement) {
        this.components.handleManager = new WorkflowHandleRotationManager(this.config.workflowManagement);
        await this.components.handleManager.initialize();
      }

      // Workflow Orchestration Management
      if (this.config.workflowOrchestration) {
        this.components.orchestrationManager = new WorkflowOrchestrationManager(this.config.workflowOrchestration);
        await this.components.orchestrationManager.initialize();
      }

      this.initialized = true;
      console.log('✅ Security Manager initialized successfully');
    } catch (error) {
      console.error('❌ Security Manager initialization failed:', error.message);
      throw error;
    }
  }

  /**
   * Get security component by name
   * @param {string} componentName - Name of the component
   * @returns {Object} Security component
   */
  getComponent(componentName) {
    if (!this.components[componentName]) {
      throw new Error(`Security component '${componentName}' not found`);
    }
    return this.components[componentName];
  }

  /**
   * Create Express.js security middleware
   * @returns {Array} Array of Express middleware functions
   */
  createExpressMiddleware() {
    if (!this.initialized) {
      throw new Error('Security Manager not initialized');
    }

    return [
      // XSS Protection middleware
      this.components.xssProtection.middleware(),
      
      // Rate limiting middleware
      this.components.authManager.rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        maxRequests: 100
      }),
      
      // Request size limiting
      (req, res, next) => {
        const contentLength = parseInt(req.headers['content-length'] || '0');
        if (contentLength > 10 * 1024 * 1024) { // 10MB limit
          return res.status(413).json({ error: 'Request too large' });
        }
        next();
      },
      
      // Security headers
      (req, res, next) => {
        res.setHeader('X-Powered-By', 'VibeCoded Security');
        res.setHeader('X-Security-Provider', 'VibeCoded Security Manager');
        next();
      }
    ];
  }

  /**
   * Scan for security vulnerabilities
   * @param {string} directory - Directory to scan
   * @returns {Object} Scan results
   */
  async securityScan(directory = '.') {
    const results = {
      timestamp: new Date().toISOString(),
      vulnerabilities: [],
      recommendations: [],
      score: 100
    };

    try {
      // Scan for hardcoded secrets
      const secretScan = await this.components.secretManager.scanForHardcodedSecrets(directory);
      if (secretScan.length > 0) {
        results.vulnerabilities.push({
          type: 'HARDCODED_SECRETS',
          severity: 'HIGH',
          count: secretScan.length,
          details: secretScan
        });
        results.score -= 30;
      }

      // Add security recommendations
      results.recommendations = [
        'Use environment variables for all sensitive data',
        'Implement Content Security Policy headers',
        'Use parameterized queries for database operations',
        'Validate and sanitize all user inputs',
        'Implement proper authentication and authorization',
        'Use HTTPS in production',
        'Regularly update dependencies',
        'Implement rate limiting',
        'Use secure session management',
        'Enable security headers'
      ];

    } catch (error) {
      results.vulnerabilities.push({
        type: 'SCAN_ERROR',
        severity: 'MEDIUM',
        message: error.message
      });
      results.score -= 10;
    }

    return results;
  }

  /**
   * Create secure API endpoint wrapper
   * @param {Function} handler - Route handler function
   * @param {Object} options - Security options
   * @returns {Function} Secure route handler
   */
  secureEndpoint(handler, options = {}) {
    return async (req, res, next) => {
      try {
        // Input validation
        if (options.validation) {
          const validation = this.components.inputValidator.validate(
            req.body, 
            options.validation
          );
          
          if (!validation.isValid) {
            return res.status(400).json({
              error: 'Validation failed',
              details: validation.errors
            });
          }
          
          req.body = validation.data;
        }

        // Authentication check
        if (options.requireAuth) {
          const authMiddleware = this.components.authManager.requireAuth(
            options.allowedRoles || []
          );
          
          // Apply auth middleware
          await new Promise((resolve, reject) => {
            authMiddleware(req, res, (error) => {
              if (error) reject(error);
              else resolve();
            });
          });
        }

        // XSS protection for response
        const originalSend = res.send;
        res.send = function(data) {
          if (typeof data === 'string') {
            data = this.components.xssProtection.encodeHTML(data);
          }
          return originalSend.call(this, data);
        }.bind(this);

        // Execute handler
        await handler(req, res, next);

      } catch (error) {
        // Log security event
        this.components.authManager.logSecurityEvent('ENDPOINT_ERROR', {
          path: req.path,
          method: req.method,
          error: error.message,
          ip: req.ip
        });

        res.status(500).json({
          error: 'Internal server error',
          message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
        });
      }
    };
  }

  /**
   * Create secure database operation wrapper
   * @param {string} operation - Database operation type
   * @param {Object} options - Operation options
   * @returns {Function} Secure database operation
   */
  secureDatabaseOperation(operation, options = {}) {
    return async (...args) => {
      try {
        switch (operation) {
          case 'select':
            const selectQuery = this.components.dbSecurity.buildSelectQuery(
              options.table,
              options.conditions,
              options.columns
            );
            return await this.components.dbSecurity.executeQuery(
              selectQuery.query,
              selectQuery.params
            );

          case 'insert':
            const insertQuery = this.components.dbSecurity.buildInsertQuery(
              options.table,
              options.data
            );
            return await this.components.dbSecurity.executeQuery(
              insertQuery.query,
              insertQuery.params
            );

          case 'update':
            const updateQuery = this.components.dbSecurity.buildUpdateQuery(
              options.table,
              options.data,
              options.conditions
            );
            return await this.components.dbSecurity.executeQuery(
              updateQuery.query,
              updateQuery.params
            );

          default:
            throw new Error(`Unsupported database operation: ${operation}`);
        }
      } catch (error) {
        this.components.authManager.logSecurityEvent('DATABASE_ERROR', {
          operation,
          table: options.table,
          error: error.message
        });
        throw error;
      }
    };
  }

  /**
   * Get security status and health check
   * @returns {Object} Security status
   */
  getSecurityStatus() {
    const features = [
      'Secret Management',
      'SQL Injection Protection',
      'XSS Protection',
      'Authentication & Authorization',
      'Input Validation',
      'Rate Limiting',
      'Security Headers'
    ];

    // Add workflow features if available
    if (this.components.keyManager) {
      features.push('Key Expiration Management');
    }
    if (this.components.handleManager) {
      features.push('Workflow Handle Rotation');
    }
    if (this.components.orchestrationManager) {
      features.push('Workflow Orchestration');
    }

    return {
      initialized: this.initialized,
      components: Object.keys(this.components),
      timestamp: new Date().toISOString(),
      version: '1.0.0',
      features: features
    };
  }

  /**
   * Get workflow orchestration manager
   * @returns {WorkflowOrchestrationManager} Orchestration manager instance
   */
  getWorkflowOrchestrationManager() {
    if (!this.components.orchestrationManager) {
      throw new Error('Workflow orchestration manager not initialized. Add workflowOrchestration configuration.');
    }
    return this.components.orchestrationManager;
  }

  /**
   * Get key expiration manager
   * @returns {KeyExpirationManager} Key manager instance
   */
  getKeyExpirationManager() {
    if (!this.components.keyManager) {
      throw new Error('Key expiration manager not initialized. Add keyManagement configuration.');
    }
    return this.components.keyManager;
  }

  /**
   * Get workflow handle rotation manager
   * @returns {WorkflowHandleRotationManager} Handle manager instance
   */
  getWorkflowHandleRotationManager() {
    if (!this.components.handleManager) {
      throw new Error('Workflow handle rotation manager not initialized. Add workflowManagement configuration.');
    }
    return this.components.handleManager;
  }

  /**
   * Register a workflow with orchestration
   * @param {string} workflowId - Unique workflow identifier
   * @param {string} workflowType - Type of workflow
   * @param {Function} workflowFunction - Workflow function
   * @param {Object} config - Workflow configuration
   * @returns {Object} Workflow information
   */
  async registerWorkflow(workflowId, workflowType, workflowFunction, config = {}) {
    const orchestrationManager = this.getWorkflowOrchestrationManager();
    return await orchestrationManager.registerWorkflow(workflowId, workflowType, workflowFunction, config);
  }

  /**
   * Execute a workflow
   * @param {string} workflowId - Workflow identifier
   * @param {Object} data - Input data
   * @param {Object} options - Execution options
   * @returns {Object} Workflow result
   */
  async executeWorkflow(workflowId, data = {}, options = {}) {
    const orchestrationManager = this.getWorkflowOrchestrationManager();
    return await orchestrationManager.executeWorkflow(workflowId, data, options);
  }

  /**
   * Get workflow orchestration statistics
   * @returns {Object} Orchestration statistics
   */
  getWorkflowOrchestrationStats() {
    const orchestrationManager = this.getWorkflowOrchestrationManager();
    return orchestrationManager.getOrchestrationStats();
  }

  /**
   * Generate security documentation
   * @returns {Object} Security documentation
   */
  generateDocumentation() {
    return {
      title: 'VibeCoded Security Manager Documentation',
      description: 'Comprehensive security solution for vibe-coded applications',
      vulnerabilities: [
        {
          name: 'Hardcoded Credentials',
          description: 'Prevents exposure of API keys and secrets in source code',
          solution: 'Use SecretManager for secure credential management'
        },
        {
          name: 'SQL Injection',
          description: 'Protects against malicious SQL queries',
          solution: 'Use parameterized queries via SQLInjectionProtection'
        },
        {
          name: 'Cross-Site Scripting (XSS)',
          description: 'Prevents script injection attacks',
          solution: 'Use XSSProtection for output encoding and CSP headers'
        },
        {
          name: 'Authentication Flaws',
          description: 'Secures user authentication and authorization',
          solution: 'Use AuthManager for proper password hashing and JWT tokens'
        },
        {
          name: 'Input Validation',
          description: 'Validates and sanitizes user inputs',
          solution: 'Use InputValidator with Joi schemas'
        }
      ],
      integration: {
        express: 'Use createExpressMiddleware() for Express.js apps',
        database: 'Use secureDatabaseOperation() for database queries',
        endpoints: 'Use secureEndpoint() for API route protection'
      }
    };
  }
}

module.exports = SecurityManager;
