/**
 * VibeCoded API Security Framework
 * 
 * Comprehensive security solution for vibe-coded applications
 * 
 * @description This framework addresses common security vulnerabilities found in
 * AI-generated applications, providing easy-to-use components for secure development.
 * 
 * @example
 * const { SecurityManager, SecretManager, AuthManager } = require('vibecoded-api-security');
 * 
 * const securityManager = new SecurityManager({
 *   secrets: { vaultPath: '.vault' },
 *   auth: { secretKey: process.env.JWT_SECRET }
 * });
 */

// Main security manager
const SecurityManager = require('./src/security/SecurityManager');

// Individual security components
const SecretManager = require('./src/security/core/SecretManager');
const SQLInjectionProtection = require('./src/security/database/SQLInjectionProtection');
const XSSProtection = require('./src/security/xss/XSSProtection');
const AuthManager = require('./src/security/auth/AuthManager');
const InputValidator = require('./src/security/validation/InputValidator');

// Additional security components
const CryptoManager = require('./src/security/crypto/CryptoManager');
const SecurityMonitor = require('./src/security/monitoring/SecurityMonitor');
const SecurityMiddleware = require('./src/security/middleware/SecurityMiddleware');
const ComplianceManager = require('./src/security/compliance/ComplianceManager');
const IncidentResponseManager = require('./src/security/incident/IncidentResponseManager');
const PerformanceSecurityManager = require('./src/security/performance/PerformanceSecurityManager');

// Security scanner
const SecurityScanner = require('./src/security/scan');

// Export all components
module.exports = {
  // Main security manager
  SecurityManager,
  
  // Individual components
  SecretManager,
  SQLInjectionProtection,
  XSSProtection,
  AuthManager,
  InputValidator,
  
  // Additional components
  CryptoManager,
  SecurityMonitor,
  SecurityMiddleware,
  ComplianceManager,
  IncidentResponseManager,
  PerformanceSecurityManager,
  
  // Security scanner
  SecurityScanner,
  
  // Version information
  version: require('./package.json').version,
  
  // Quick setup function
  createSecurityManager: (config) => new SecurityManager(config),
  
  // Utility functions
  utils: {
    // Generate a secure encryption key
    generateEncryptionKey: () => require('crypto').randomBytes(32).toString('hex'),
    
    // Generate a secure JWT secret
    generateJWTSecret: () => require('crypto').randomBytes(64).toString('hex'),
    
    // Validate environment variables
    validateEnvironment: () => {
      const required = ['JWT_SECRET', 'ENCRYPTION_KEY'];
      const missing = required.filter(key => !process.env[key]);
      
      if (missing.length > 0) {
        console.warn(`⚠️ Missing environment variables: ${missing.join(', ')}`);
        console.warn('💡 Use utils.generateEncryptionKey() and utils.generateJWTSecret() to generate secure keys');
        return false;
      }
      
      return true;
    }
  }
};

// Export individual components for direct access
module.exports.SecretManager = SecretManager;
module.exports.SQLInjectionProtection = SQLInjectionProtection;
module.exports.XSSProtection = XSSProtection;
module.exports.AuthManager = AuthManager;
module.exports.InputValidator = InputValidator;
module.exports.CryptoManager = CryptoManager;
module.exports.SecurityMonitor = SecurityMonitor;
module.exports.SecurityMiddleware = SecurityMiddleware;
module.exports.ComplianceManager = ComplianceManager;
module.exports.IncidentResponseManager = IncidentResponseManager;
module.exports.PerformanceSecurityManager = PerformanceSecurityManager;
module.exports.SecurityScanner = SecurityScanner;
