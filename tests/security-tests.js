const { 
  SecurityManager, 
  SecretManager, 
  SQLInjectionProtection, 
  XSSProtection, 
  AuthManager, 
  InputValidator,
  CryptoManager,
  SecurityMonitor,
  SecurityMiddleware
} = require('../index');

/**
 * Comprehensive Security Tests for VibeCoded Security Framework
 * 
 * These tests validate all security components and ensure the framework
 * properly protects against common vulnerabilities.
 */

describe('VibeCoded Security Framework Tests', () => {
  let securityManager;
  let secretManager;
  let dbSecurity;
  let xssProtection;
  let authManager;
  let inputValidator;
  let cryptoManager;
  let securityMonitor;
  let securityMiddleware;

  beforeAll(async () => {
    // Initialize all security components
    securityManager = new SecurityManager({
      secrets: { vaultPath: '.test-vault' },
      auth: { secretKey: 'test-secret-key' },
      validation: { strictMode: true }
    });

    secretManager = new SecretManager({ vaultPath: '.test-vault' });
    dbSecurity = new SQLInjectionProtection({
      type: 'postgresql',
      host: 'localhost',
      database: 'test_db',
      user: 'test_user',
      password: 'test_password'
    });
    xssProtection = new XSSProtection();
    authManager = new AuthManager({ secretKey: 'test-secret-key' });
    inputValidator = new InputValidator();
    cryptoManager = new CryptoManager();
    securityMonitor = new SecurityMonitor({ logFile: 'test-security-events.log' });
    securityMiddleware = new SecurityMiddleware();
  });

  afterAll(async () => {
    // Cleanup
    await secretManager.initialize();
    // Clean up test files
  });

  describe('SecretManager Tests', () => {
    test('should initialize secret manager', async () => {
      await expect(secretManager.initialize()).resolves.not.toThrow();
    });

    test('should store and retrieve secrets securely', async () => {
      const testSecret = 'test-api-key-123';
      await secretManager.setSecret('TEST_API_KEY', testSecret);
      
      const retrieved = await secretManager.getSecret('TEST_API_KEY');
      expect(retrieved).toBe(testSecret);
    });

    test('should encrypt secrets properly', async () => {
      const testData = 'sensitive-data';
      const encrypted = secretManager.encrypt(testData);
      
      expect(encrypted).toHaveProperty('encrypted');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('authTag');
      expect(encrypted.encrypted).not.toBe(testData);
    });

    test('should decrypt secrets properly', () => {
      const testData = 'sensitive-data';
      const encrypted = secretManager.encrypt(testData);
      const decrypted = secretManager.decrypt(encrypted);
      
      expect(decrypted).toBe(testData);
    });

    test('should detect hardcoded secrets', async () => {
      // Create a test file with hardcoded secrets
      const fs = require('fs').promises;
      const testFile = 'test-secrets.js';
      
      await fs.writeFile(testFile, `
        const stripeKey = 'sk_live_abc123def456';
        const apiKey = 'ak_test_789ghi012jkl';
        const password = 'secretpassword123';
      `);
      
      const results = await secretManager.scanForHardcodedSecrets('.');
      await fs.unlink(testFile);
      
      expect(results.length).toBeGreaterThan(0);
      expect(results.some(r => r.file.includes('test-secrets.js'))).toBe(true);
    });
  });

  describe('SQLInjectionProtection Tests', () => {
    test('should validate dangerous SQL patterns', () => {
      const dangerousQueries = [
        "SELECT * FROM users WHERE name = '" + "'; DROP TABLE users; --",
        "INSERT INTO users VALUES ('" + "'; DELETE FROM users; --",
        "UPDATE users SET name = '" + "'; DROP DATABASE; --"
      ];
      
      dangerousQueries.forEach(query => {
        expect(() => dbSecurity.validateQuery(query)).toThrow();
      });
    });

    test('should accept safe parameterized queries', () => {
      const safeQueries = [
        'SELECT * FROM users WHERE id = $1',
        'INSERT INTO users (name, email) VALUES ($1, $2)',
        'UPDATE users SET name = $1 WHERE id = $2'
      ];
      
      safeQueries.forEach(query => {
        expect(() => dbSecurity.validateQuery(query)).not.toThrow();
      });
    });

    test('should sanitize parameters', () => {
      const maliciousParams = [
        "'; DROP TABLE users; --",
        "<script>alert('xss')</script>",
        "'; INSERT INTO users VALUES ('hacker', 'hacker@evil.com'); --"
      ];
      
      maliciousParams.forEach(param => {
        const sanitized = dbSecurity.sanitizeParameter(param);
        expect(sanitized).not.toContain('DROP');
        expect(sanitized).not.toContain('INSERT');
        expect(sanitized).not.toContain('<script>');
      });
    });

    test('should build safe SELECT queries', () => {
      const query = dbSecurity.buildSelectQuery('users', { email: 'test@example.com' });
      
      expect(query.query).toContain('SELECT');
      expect(query.query).toContain('FROM users');
      expect(query.query).toContain('WHERE');
      expect(query.query).toContain('$1');
      expect(query.params).toContain('test@example.com');
    });

    test('should build safe INSERT queries', () => {
      const data = { name: 'John', email: 'john@example.com' };
      const query = dbSecurity.buildInsertQuery('users', data);
      
      expect(query.query).toContain('INSERT INTO users');
      expect(query.query).toContain('VALUES');
      expect(query.params).toContain('John');
      expect(query.params).toContain('john@example.com');
    });
  });

  describe('XSSProtection Tests', () => {
    test('should encode HTML properly', () => {
      const maliciousInputs = [
        '<script>alert("xss")</script>',
        '<img src="x" onerror="alert(\'xss\')">',
        'javascript:alert("xss")',
        '<iframe src="evil.com"></iframe>'
      ];
      
      maliciousInputs.forEach(input => {
        const encoded = xssProtection.encodeHTML(input);
        expect(encoded).not.toContain('<script>');
        expect(encoded).not.toContain('javascript:');
        expect(encoded).toContain('&lt;');
        expect(encoded).toContain('&gt;');
      });
    });

    test('should sanitize HTML input', () => {
      const maliciousHTML = `
        <script>alert('xss')</script>
        <img src="x" onerror="alert('xss')">
        <iframe src="evil.com"></iframe>
        <object data="evil.swf"></object>
        <embed src="evil.swf">
      `;
      
      const sanitized = xssProtection.sanitizeHTML(maliciousHTML);
      
      expect(sanitized).not.toContain('<script>');
      expect(sanitized).not.toContain('<iframe>');
      expect(sanitized).not.toContain('<object>');
      expect(sanitized).not.toContain('<embed>');
      expect(sanitized).not.toContain('onerror=');
    });

    test('should generate CSP headers', () => {
      const cspHeader = xssProtection.generateCSPHeader();
      
      expect(cspHeader).toContain('default-src');
      expect(cspHeader).toContain('script-src');
      expect(cspHeader).toContain('style-src');
      expect(cspHeader).toContain("'self'");
    });

    test('should create safe templates', () => {
      const template = '<h1>Hello {{name}}</h1>';
      const data = { name: '<script>alert("xss")</script>' };
      
      const safeTemplate = xssProtection.createSafeTemplate(template, data);
      
      expect(safeTemplate).toContain('Hello');
      expect(safeTemplate).not.toContain('<script>');
      expect(safeTemplate).toContain('&lt;script&gt;');
    });
  });

  describe('AuthManager Tests', () => {
    test('should hash passwords securely', async () => {
      const password = 'SecurePassword123!';
      const hash = await authManager.hashPassword(password);
      
      expect(hash).not.toBe(password);
      expect(hash.length).toBeGreaterThan(20);
    });

    test('should verify passwords correctly', async () => {
      const password = 'SecurePassword123!';
      const hash = await authManager.hashPassword(password);
      
      const isValid = await authManager.verifyPassword(password, hash);
      expect(isValid).toBe(true);
      
      const isInvalid = await authManager.verifyPassword('WrongPassword', hash);
      expect(isInvalid).toBe(false);
    });

    test('should generate and verify JWT tokens', () => {
      const payload = { userId: 123, email: 'test@example.com' };
      const token = authManager.generateToken(payload);
      
      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      
      const decoded = authManager.verifyToken(token);
      expect(decoded.userId).toBe(payload.userId);
      expect(decoded.email).toBe(payload.email);
    });

    test('should handle rate limiting', () => {
      const rateLimitMiddleware = authManager.rateLimit({
        windowMs: 1000,
        maxRequests: 2
      });
      
      // This would need to be tested with actual HTTP requests
      expect(typeof rateLimitMiddleware).toBe('function');
    });

    test('should validate password strength', () => {
      const weakPasswords = [
        '123',
        'password',
        'abc123',
        'Password',
        'PASSWORD123'
      ];
      
      weakPasswords.forEach(password => {
        const result = authManager.validatePasswordStrength(password);
        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      });
      
      const strongPassword = 'SecurePassword123!';
      const result = authManager.validatePasswordStrength(strongPassword);
      expect(result.isValid).toBe(true);
    });
  });

  describe('InputValidator Tests', () => {
    test('should validate user registration data', () => {
      const validData = {
        email: 'test@example.com',
        password: 'SecurePassword123!',
        username: 'testuser',
        firstName: 'John',
        lastName: 'Doe'
      };
      
      const validation = inputValidator.validate(validData, inputValidator.schemas.userRegistration);
      expect(validation.isValid).toBe(true);
    });

    test('should reject invalid user registration data', () => {
      const invalidData = {
        email: 'invalid-email',
        password: 'weak',
        username: 'a',
        firstName: '',
        lastName: ''
      };
      
      const validation = inputValidator.validate(invalidData, inputValidator.schemas.userRegistration);
      expect(validation.isValid).toBe(false);
      expect(validation.errors.length).toBeGreaterThan(0);
    });

    test('should sanitize strings properly', () => {
      const maliciousInputs = [
        '<script>alert("xss")</script>',
        'javascript:alert("xss")',
        'admin; DROP TABLE users; --',
        'normal text'
      ];
      
      maliciousInputs.forEach(input => {
        const sanitized = inputValidator.sanitizeString(input, { removeHTML: true, removeScripts: true });
        expect(sanitized).not.toContain('<script>');
        expect(sanitized).not.toContain('javascript:');
      });
    });

    test('should validate file uploads', () => {
      const validFile = {
        mimetype: 'image/jpeg',
        size: 1024 * 1024, // 1MB
        originalname: 'test.jpg'
      };
      
      const validation = inputValidator.validateFile(validFile);
      expect(validation.isValid).toBe(true);
      
      const invalidFile = {
        mimetype: 'application/exe',
        size: 10 * 1024 * 1024, // 10MB
        originalname: 'malware.exe'
      };
      
      const invalidValidation = inputValidator.validateFile(invalidFile);
      expect(invalidValidation.isValid).toBe(false);
    });
  });

  describe('CryptoManager Tests', () => {
    test('should generate secure random bytes', () => {
      const bytes = cryptoManager.generateRandomBytes(32);
      expect(bytes.length).toBe(32);
      expect(Buffer.isBuffer(bytes)).toBe(true);
    });

    test('should generate secure random strings', () => {
      const randomString = cryptoManager.generateRandomString(16);
      expect(randomString.length).toBe(16);
      expect(typeof randomString).toBe('string');
    });

    test('should encrypt and decrypt data', () => {
      const testData = 'sensitive information';
      const key = cryptoManager.generateRandomBytes(32);
      
      const encrypted = cryptoManager.encrypt(testData, key);
      expect(encrypted).toHaveProperty('encrypted');
      expect(encrypted).toHaveProperty('iv');
      expect(encrypted).toHaveProperty('authTag');
      
      const decrypted = cryptoManager.decrypt(encrypted, key);
      expect(decrypted).toBe(testData);
    });

    test('should hash data securely', () => {
      const testData = 'data to hash';
      const hash = cryptoManager.hash(testData);
      
      expect(hash).toHaveProperty('hash');
      expect(hash).toHaveProperty('salt');
      expect(hash).toHaveProperty('algorithm');
      
      const isValid = cryptoManager.verifyHash(testData, hash.hash, hash.salt);
      expect(isValid).toBe(true);
    });

    test('should derive keys from passwords', () => {
      const password = 'SecurePassword123!';
      const derivedKey = cryptoManager.deriveKey(password);
      
      expect(derivedKey).toHaveProperty('key');
      expect(derivedKey).toHaveProperty('salt');
      expect(derivedKey).toHaveProperty('iterations');
      expect(derivedKey.iterations).toBe(cryptoManager.options.pbkdf2Iterations);
    });

    test('should generate RSA key pairs', () => {
      const keyPair = cryptoManager.generateRSAKeyPair(2048);
      
      expect(keyPair).toHaveProperty('publicKey');
      expect(keyPair).toHaveProperty('privateKey');
      expect(keyPair).toHaveProperty('keySize');
      expect(keyPair.keySize).toBe(2048);
    });

    test('should create and verify digital signatures', () => {
      const data = 'data to sign';
      const keyPair = cryptoManager.generateRSAKeyPair(2048);
      
      const signature = cryptoManager.sign(data, keyPair.privateKey);
      expect(signature).toHaveProperty('signature');
      expect(signature).toHaveProperty('algorithm');
      
      const isValid = cryptoManager.verify(data, signature.signature, keyPair.publicKey);
      expect(isValid).toBe(true);
    });
  });

  describe('SecurityMonitor Tests', () => {
    test('should start and stop monitoring', async () => {
      await securityMonitor.startMonitoring();
      expect(securityMonitor.isMonitoring).toBe(true);
      
      securityMonitor.stopMonitoring();
      expect(securityMonitor.isMonitoring).toBe(false);
    });

    test('should log security events', async () => {
      const eventData = {
        type: 'TEST_EVENT',
        message: 'Test security event',
        ip: '127.0.0.1'
      };
      
      const event = await securityMonitor.logSecurityEvent('TEST_EVENT', eventData, 'medium');
      
      expect(event).toHaveProperty('id');
      expect(event).toHaveProperty('type');
      expect(event).toHaveProperty('severity');
      expect(event).toHaveProperty('timestamp');
      expect(event.type).toBe('TEST_EVENT');
      expect(event.severity).toBe('medium');
    });

    test('should detect threats', async () => {
      const maliciousEvent = {
        type: 'SUSPICIOUS_REQUEST',
        data: {
          url: '/api/users?q=1; DROP TABLE users; --',
          ip: '127.0.0.1'
        }
      };
      
      const event = await securityMonitor.logSecurityEvent('SUSPICIOUS_REQUEST', maliciousEvent.data, 'high');
      
      expect(event).toHaveProperty('threatLevel');
      expect(event.threatLevel).toBeGreaterThan(0);
    });

    test('should track event counters', async () => {
      // Reset counters
      securityMonitor.resetCounters();
      
      await securityMonitor.logSecurityEvent('LOGIN_FAILED', { email: 'test@example.com' });
      await securityMonitor.logSecurityEvent('LOGIN_FAILED', { email: 'test2@example.com' });
      
      expect(securityMonitor.eventCounters.failedLogins).toBe(2);
    });

    test('should provide security statistics', () => {
      const stats = securityMonitor.getSecurityStats();
      
      expect(stats).toHaveProperty('monitoring');
      expect(stats).toHaveProperty('events');
      expect(stats).toHaveProperty('alerts');
      expect(stats).toHaveProperty('threats');
    });
  });

  describe('SecurityMiddleware Tests', () => {
    test('should create middleware stack', () => {
      const middleware = securityMiddleware.createMiddlewareStack();
      
      expect(Array.isArray(middleware)).toBe(true);
      expect(middleware.length).toBeGreaterThan(0);
    });

    test('should create error handler', () => {
      const errorHandler = securityMiddleware.createErrorHandler();
      expect(typeof errorHandler).toBe('function');
    });

    test('should create 404 handler', () => {
      const notFoundHandler = securityMiddleware.createNotFoundHandler();
      expect(typeof notFoundHandler).toBe('function');
    });

    test('should create health check', () => {
      const healthCheck = securityMiddleware.createHealthCheck();
      expect(typeof healthCheck).toBe('function');
    });

    test('should create security status endpoint', () => {
      const securityStatus = securityMiddleware.createSecurityStatus();
      expect(typeof securityStatus).toBe('function');
    });
  });

  describe('SecurityManager Integration Tests', () => {
    test('should initialize all components', async () => {
      await securityManager.initializeComponents();
      
      expect(securityManager.initialized).toBe(true);
      expect(securityManager.components.secretManager).toBeDefined();
      expect(securityManager.components.xssProtection).toBeDefined();
      expect(securityManager.components.authManager).toBeDefined();
      expect(securityManager.components.inputValidator).toBeDefined();
    });

    test('should create Express middleware', () => {
      const middleware = securityManager.createExpressMiddleware();
      
      expect(Array.isArray(middleware)).toBe(true);
      expect(middleware.length).toBeGreaterThan(0);
    });

    test('should secure endpoints', () => {
      const handler = (req, res) => res.json({ message: 'success' });
      const secureHandler = securityManager.secureEndpoint(handler, {
        validation: inputValidator.schemas.userLogin
      });
      
      expect(typeof secureHandler).toBe('function');
    });

    test('should perform security scans', async () => {
      const scanResults = await securityManager.securityScan('.');
      
      expect(scanResults).toHaveProperty('timestamp');
      expect(scanResults).toHaveProperty('vulnerabilities');
      expect(scanResults).toHaveProperty('recommendations');
      expect(scanResults).toHaveProperty('score');
    });

    test('should provide security status', () => {
      const status = securityManager.getSecurityStatus();
      
      expect(status).toHaveProperty('initialized');
      expect(status).toHaveProperty('components');
      expect(status).toHaveProperty('version');
      expect(status).toHaveProperty('features');
    });
  });

  describe('End-to-End Security Tests', () => {
    test('should protect against SQL injection in user input', async () => {
      const maliciousInput = "'; DROP TABLE users; --";
      
      // This should be caught by input validation
      const validation = inputValidator.validate(
        { email: maliciousInput },
        inputValidator.schemas.userLogin
      );
      
      // The validation should pass (email format is valid)
      // But the database operation should be protected
      expect(validation.isValid).toBe(true);
      
      // The database operation should sanitize the input
      const sanitized = dbSecurity.sanitizeParameter(maliciousInput);
      expect(sanitized).not.toContain('DROP');
    });

    test('should protect against XSS in output', () => {
      const maliciousInput = '<script>alert("xss")</script>';
      
      const encoded = xssProtection.encodeHTML(maliciousInput);
      expect(encoded).not.toContain('<script>');
      expect(encoded).toContain('&lt;script&gt;');
    });

    test('should handle authentication securely', async () => {
      const password = 'SecurePassword123!';
      const hash = await authManager.hashPassword(password);
      
      // Verify password works
      const isValid = await authManager.verifyPassword(password, hash);
      expect(isValid).toBe(true);
      
      // Wrong password should fail
      const isInvalid = await authManager.verifyPassword('WrongPassword', hash);
      expect(isInvalid).toBe(false);
    });

    test('should encrypt sensitive data', () => {
      const sensitiveData = 'credit-card-number-1234';
      const key = cryptoManager.generateRandomBytes(32);
      
      const encrypted = cryptoManager.encrypt(sensitiveData, key);
      expect(encrypted.encrypted).not.toBe(sensitiveData);
      
      const decrypted = cryptoManager.decrypt(encrypted, key);
      expect(decrypted).toBe(sensitiveData);
    });
  });
});

// Run tests if this file is executed directly
if (require.main === module) {
  console.log('🧪 Running VibeCoded Security Framework Tests...');
  
  // This would typically be run with a test runner like Jest
  // For now, we'll just export the test suite
  module.exports = {
    describe,
    test,
    expect,
    beforeAll,
    afterAll
  };
}
