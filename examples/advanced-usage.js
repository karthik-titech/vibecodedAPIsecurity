const express = require('express');
const { 
  SecurityManager, 
  SecurityMiddleware, 
  CryptoManager, 
  SecurityMonitor 
} = require('../index');

/**
 * Advanced Usage Example for VibeCoded Security Framework
 * 
 * This example demonstrates a comprehensive security setup for a vibe-coded
 * application with all security components integrated.
 */

// Initialize all security components
const cryptoManager = new CryptoManager({
  encryptionAlgorithm: 'aes-256-gcm',
  hashAlgorithm: 'sha256',
  pbkdf2Iterations: 100000
});

const securityMonitor = new SecurityMonitor({
  logFile: 'security-events.log',
  alertThresholds: {
    failedLogins: 3,
    suspiciousRequests: 5,
    sqlInjectionAttempts: 2,
    xssAttempts: 2
  },
  alertChannels: {
    console: true,
    file: true,
    webhook: process.env.SECURITY_WEBHOOK_URL
  }
});

const securityMiddleware = new SecurityMiddleware({
  rateLimit: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
  },
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000'],
    credentials: true
  },
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
    }
  },
  bodyLimit: '10mb'
});

const securityManager = new SecurityManager({
  secrets: {
    vaultPath: '.vault',
    encryptionKey: process.env.ENCRYPTION_KEY || cryptoManager.generateRandomBytes(32).toString('hex')
  },
  database: {
    type: 'postgresql',
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'vibecoded_app',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password'
  },
  auth: {
    secretKey: process.env.JWT_SECRET || cryptoManager.generateRandomString(64),
    tokenExpiry: '24h',
    maxLoginAttempts: 5,
    lockoutDuration: 15 * 60 * 1000
  },
  validation: {
    strictMode: true,
    maxInputLength: 10000,
    allowedFileTypes: ['jpg', 'jpeg', 'png', 'gif', 'pdf'],
    maxFileSize: 5 * 1024 * 1024
  }
});

// Create Express app
const app = express();
app.use(express.json());

// Apply comprehensive security middleware
const middlewareStack = securityMiddleware.createMiddlewareStack();
app.use(middlewareStack);

// Start security monitoring
securityMonitor.startMonitoring();

// Apply security monitoring middleware
app.use(securityMonitor.createMonitoringMiddleware());

// Health check endpoint
app.get('/health', securityMiddleware.createHealthCheck());

// Security status endpoint
app.get('/security/status', securityMiddleware.createSecurityStatus());

// Security monitoring endpoint
app.get('/security/monitor', (req, res) => {
  res.json({
    stats: securityMonitor.getSecurityStats(),
    recommendations: securityMonitor.getSecurityRecommendations()
  });
});

// Crypto utilities endpoint
app.get('/security/crypto/info', (req, res) => {
  res.json(cryptoManager.getCryptoInfo());
});

// Generate secure keys endpoint
app.post('/security/crypto/generate-keys', 
  securityManager.secureEndpoint(async (req, res) => {
    const { type, options } = req.body;
    
    let result;
    switch (type) {
      case 'rsa':
        result = cryptoManager.generateRSAKeyPair(options?.keySize || 2048);
        break;
      case 'ec':
        result = cryptoManager.generateECKeyPair(options?.curve || 'secp256k1');
        break;
      case 'api-key':
        result = { apiKey: cryptoManager.generateAPIKey(options?.prefix || 'vc') };
        break;
      case 'token':
        result = { token: cryptoManager.generateSecureToken(options?.length || 32) };
        break;
      default:
        return res.status(400).json({ error: 'Invalid key type' });
    }
    
    res.json(result);
  }, {
    requireAuth: true,
    allowedRoles: ['admin']
  })
);

// Encrypt data endpoint
app.post('/security/crypto/encrypt',
  securityManager.secureEndpoint(async (req, res) => {
    const { data, key } = req.body;
    
    if (!data || !key) {
      return res.status(400).json({ error: 'Data and key are required' });
    }
    
    const encrypted = cryptoManager.encrypt(data, key);
    res.json(encrypted);
  }, {
    requireAuth: true
  })
);

// Decrypt data endpoint
app.post('/security/crypto/decrypt',
  securityManager.secureEndpoint(async (req, res) => {
    const { encryptedData, key } = req.body;
    
    if (!encryptedData || !key) {
      return res.status(400).json({ error: 'Encrypted data and key are required' });
    }
    
    try {
      const decrypted = cryptoManager.decrypt(encryptedData, key);
      res.json({ decrypted });
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }, {
    requireAuth: true
  })
);

// Hash password endpoint
app.post('/security/crypto/hash-password',
  securityManager.secureEndpoint(async (req, res) => {
    const { password } = req.body;
    
    if (!password) {
      return res.status(400).json({ error: 'Password is required' });
    }
    
    try {
      const hashed = cryptoManager.hashPassword(password);
      res.json(hashed);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  })
);

// Verify password endpoint
app.post('/security/crypto/verify-password',
  securityManager.secureEndpoint(async (req, res) => {
    const { password, hash, salt, iterations } = req.body;
    
    if (!password || !hash || !salt || !iterations) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    const isValid = cryptoManager.verifyPassword(password, hash, salt, iterations);
    res.json({ isValid });
  })
);

// Digital signature endpoint
app.post('/security/crypto/sign',
  securityManager.secureEndpoint(async (req, res) => {
    const { data, privateKey, algorithm } = req.body;
    
    if (!data || !privateKey) {
      return res.status(400).json({ error: 'Data and private key are required' });
    }
    
    try {
      const signature = cryptoManager.sign(data, privateKey, algorithm);
      res.json(signature);
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  }, {
    requireAuth: true
  })
);

// Verify signature endpoint
app.post('/security/crypto/verify',
  securityManager.secureEndpoint(async (req, res) => {
    const { data, signature, publicKey, algorithm } = req.body;
    
    if (!data || !signature || !publicKey) {
      return res.status(400).json({ error: 'Data, signature, and public key are required' });
    }
    
    const isValid = cryptoManager.verify(data, signature, publicKey, algorithm);
    res.json({ isValid });
  })
);

// Secure user registration with comprehensive validation
app.post('/api/users/register',
  securityManager.secureEndpoint(async (req, res) => {
    const { email, password, username, firstName, lastName, profile } = req.body;
    
    // Get validation schema
    const validator = securityManager.getComponent('inputValidator');
    const validation = validator.validate(req.body, validator.schemas.userRegistration);
    
    if (!validation.isValid) {
      // Log validation failure
      await securityMonitor.logSecurityEvent('INPUT_VALIDATION_FAILURE', {
        field: 'user_registration',
        errors: validation.errors,
        ip: req.ip
      }, 'medium');
      
      return res.status(400).json({
        error: 'Validation failed',
        details: validation.errors
      });
    }
    
    // Hash password securely
    const hashedPassword = cryptoManager.hashPassword(password);
    
    // Encrypt sensitive profile data
    const encryptionKey = cryptoManager.generateRandomBytes(32);
    const encryptedProfile = cryptoManager.encrypt(JSON.stringify(profile), encryptionKey);
    
    // Store user in database
    const dbOperation = securityManager.secureDatabaseOperation('insert', {
      table: 'users',
      data: {
        email: validator.sanitizeEmail(email),
        password_hash: hashedPassword.hash,
        password_salt: hashedPassword.salt,
        password_iterations: hashedPassword.iterations,
        username: validator.sanitizeString(username, { removeSpecialChars: true }),
        first_name: validator.sanitizeString(firstName, { removeHTML: true }),
        last_name: validator.sanitizeString(lastName, { removeHTML: true }),
        profile_encrypted: encryptedProfile.encrypted,
        profile_iv: encryptedProfile.iv,
        profile_auth_tag: encryptedProfile.authTag,
        encryption_key_encrypted: cryptoManager.encrypt(encryptionKey.toString('hex'), process.env.MASTER_KEY).encrypted,
        created_at: new Date(),
        role: 'user'
      }
    });
    
    const result = await dbOperation();
    
    // Log successful registration
    await securityMonitor.logSecurityEvent('USER_REGISTERED', {
      userId: result.rows[0].id,
      email: validator.sanitizeEmail(email),
      ip: req.ip
    }, 'low');
    
    res.status(201).json({
      message: 'User registered successfully',
      userId: result.rows[0].id
    });
  }, {
    validation: securityManager.getComponent('inputValidator').schemas.userRegistration
  })
);

// Secure login with monitoring
app.post('/api/users/login',
  securityManager.secureEndpoint(async (req, res) => {
    const { email, password } = req.body;
    
    // Validate input
    const validator = securityManager.getComponent('inputValidator');
    const validation = validator.validate(req.body, validator.schemas.userLogin);
    
    if (!validation.isValid) {
      await securityMonitor.logSecurityEvent('INPUT_VALIDATION_FAILURE', {
        field: 'user_login',
        errors: validation.errors,
        ip: req.ip
      }, 'medium');
      
      return res.status(400).json({
        error: 'Invalid input',
        details: validation.errors
      });
    }
    
    // Get user from database
    const dbOperation = securityManager.secureDatabaseOperation('select', {
      table: 'users',
      conditions: { email: validator.sanitizeEmail(email) },
      columns: ['id', 'email', 'password_hash', 'password_salt', 'password_iterations', 'role', 'locked_until']
    });
    
    const result = await dbOperation();
    
    if (result.rows.length === 0) {
      await securityMonitor.logSecurityEvent('LOGIN_FAILED', {
        email: validator.sanitizeEmail(email),
        reason: 'User not found',
        ip: req.ip
      }, 'medium');
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Check if account is locked
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      await securityMonitor.logSecurityEvent('LOGIN_FAILED', {
        email: validator.sanitizeEmail(email),
        reason: 'Account locked',
        ip: req.ip
      }, 'medium');
      
      return res.status(423).json({ error: 'Account temporarily locked' });
    }
    
    // Verify password
    const isValid = cryptoManager.verifyPassword(
      password, 
      user.password_hash, 
      user.password_salt, 
      user.password_iterations
    );
    
    if (!isValid) {
      await securityMonitor.logSecurityEvent('LOGIN_FAILED', {
        email: validator.sanitizeEmail(email),
        reason: 'Invalid password',
        ip: req.ip
      }, 'medium');
      
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const authManager = securityManager.getComponent('authManager');
    const accessToken = authManager.generateToken({
      userId: user.id,
      email: user.email,
      role: user.role
    });
    
    const refreshToken = authManager.generateRefreshToken(user.id);
    
    // Log successful login
    await securityMonitor.logSecurityEvent('LOGIN_SUCCESS', {
      userId: user.id,
      email: user.email,
      ip: req.ip
    }, 'low');
    
    res.json({
      message: 'Login successful',
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        email: user.email,
        role: user.role
      }
    });
  }, {
    validation: securityManager.getComponent('inputValidator').schemas.userLogin
  })
);

// Secure profile management
app.get('/api/users/profile',
  securityManager.secureEndpoint(async (req, res) => {
    const userId = req.user.userId;
    
    // Get user profile from database
    const dbOperation = securityManager.secureDatabaseOperation('select', {
      table: 'users',
      conditions: { id: userId },
      columns: ['profile_encrypted', 'profile_iv', 'profile_auth_tag', 'encryption_key_encrypted']
    });
    
    const result = await dbOperation();
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = result.rows[0];
    
    // Decrypt profile data
    const encryptedKey = cryptoManager.decrypt(
      { encrypted: user.encryption_key_encrypted },
      process.env.MASTER_KEY
    );
    
    const decryptedProfile = cryptoManager.decrypt(
      {
        encrypted: user.profile_encrypted,
        iv: user.profile_iv,
        authTag: user.profile_auth_tag,
        algorithm: 'aes-256-gcm'
      },
      Buffer.from(encryptedKey, 'hex')
    );
    
    const profile = JSON.parse(decryptedProfile);
    
    res.json({
      profile,
      message: 'Profile retrieved successfully'
    });
  }, {
    requireAuth: true
  })
);

// Secure file upload with validation
app.post('/api/files/upload',
  securityManager.secureEndpoint(async (req, res) => {
    // File upload handling would go here
    // The security framework provides comprehensive file validation
    
    const validator = securityManager.getComponent('inputValidator');
    
    res.json({
      message: 'File upload endpoint (implementation needed)',
      note: 'Use validator.validateFile() for file validation',
      security: {
        maxFileSize: validator.maxFileSize,
        allowedTypes: validator.allowedFileTypes
      }
    });
  }, {
    requireAuth: true
  })
);

// Secure search with XSS protection
app.get('/api/search',
  securityManager.secureEndpoint(async (req, res) => {
    const { q, category, filters } = req.query;
    
    // Validate search query
    const validator = securityManager.getComponent('inputValidator');
    const validation = validator.validate(req.query, validator.schemas.searchQuery);
    
    if (!validation.isValid) {
      await securityMonitor.logSecurityEvent('INPUT_VALIDATION_FAILURE', {
        field: 'search_query',
        errors: validation.errors,
        ip: req.ip
      }, 'medium');
      
      return res.status(400).json({
        error: 'Invalid search parameters',
        details: validation.errors
      });
    }
    
    // Sanitize search query to prevent XSS
    const sanitizedQuery = validator.sanitizeString(q, { 
      removeHTML: true, 
      removeScripts: true 
    });
    
    // Perform search (example)
    const searchResults = [
      { 
        id: 1, 
        title: `Results for: ${sanitizedQuery}`, 
        category,
        timestamp: new Date().toISOString()
      }
    ];
    
    // Log search activity
    await securityMonitor.logSecurityEvent('SEARCH_PERFORMED', {
      query: sanitizedQuery,
      category,
      resultsCount: searchResults.length,
      userId: req.user?.userId,
      ip: req.ip
    }, 'low');
    
    res.json({
      query: sanitizedQuery,
      results: searchResults,
      count: searchResults.length,
      timestamp: new Date().toISOString()
    });
  }, {
    validation: securityManager.getComponent('inputValidator').schemas.searchQuery
  })
);

// Admin endpoint with role-based access
app.get('/api/admin/users',
  securityManager.secureEndpoint(async (req, res) => {
    const { page = 1, limit = 10, sortBy = 'created_at', sortOrder = 'desc' } = req.query;
    
    // Validate pagination parameters
    const validator = securityManager.getComponent('inputValidator');
    const validation = validator.validate(req.query, validator.schemas.pagination);
    
    if (!validation.isValid) {
      return res.status(400).json({
        error: 'Invalid pagination parameters',
        details: validation.errors
      });
    }
    
    // Get users from database
    const dbOperation = securityManager.secureDatabaseOperation('select', {
      table: 'users',
      columns: ['id', 'email', 'username', 'first_name', 'last_name', 'role', 'created_at'],
      conditions: {},
      orderBy: `${sortBy} ${sortOrder}`,
      limit: parseInt(limit),
      offset: (parseInt(page) - 1) * parseInt(limit)
    });
    
    const result = await dbOperation();
    
    // Log admin activity
    await securityMonitor.logSecurityEvent('ADMIN_ACTION', {
      action: 'list_users',
      adminId: req.user.userId,
      page,
      limit,
      ip: req.ip
    }, 'low');
    
    res.json({
      users: result.rows,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: result.rows.length,
        sortBy,
        sortOrder
      }
    });
  }, {
    requireAuth: true,
    allowedRoles: ['admin']
  })
);

// Security audit endpoint
app.get('/api/security/audit',
  securityManager.secureEndpoint(async (req, res) => {
    const auditData = {
      timestamp: new Date().toISOString(),
      security: {
        framework: 'VibeCoded Security Framework',
        version: require('../package.json').version,
        components: Object.keys(securityManager.components),
        status: securityManager.getSecurityStatus()
      },
      monitoring: securityMonitor.getSecurityStats(),
      crypto: cryptoManager.getCryptoInfo(),
      recommendations: securityMonitor.getSecurityRecommendations()
    };
    
    res.json(auditData);
  }, {
    requireAuth: true,
    allowedRoles: ['admin']
  })
);

// Error handling middleware
app.use(securityMiddleware.createErrorHandler());

// 404 handler
app.use(securityMiddleware.createNotFoundHandler());

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🔄 Shutting down gracefully...');
  securityMonitor.stopMonitoring();
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🔄 Shutting down gracefully...');
  securityMonitor.stopMonitoring();
  process.exit(0);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Advanced Secure VibeCoded API running on port ${PORT}`);
  console.log(`🔒 Security Framework Status:`, securityManager.getSecurityStatus());
  console.log(`📊 Security Monitor Status:`, securityMonitor.getSecurityStats());
  console.log(`🔐 Crypto Manager Status:`, cryptoManager.getCryptoInfo());
});

module.exports = app;
