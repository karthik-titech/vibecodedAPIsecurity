const express = require('express');
const SecurityManager = require('../src/security/SecurityManager');

/**
 * Basic Usage Example for VibeCoded Security Manager
 * 
 * This example demonstrates how to integrate the security framework
 * into a typical vibe-coded application to prevent common vulnerabilities.
 */

// Initialize security manager with configuration
const securityManager = new SecurityManager({
  // Secret management configuration
  secrets: {
    vaultPath: '.vault',
    encryptionKey: process.env.ENCRYPTION_KEY
  },
  
  // Database security configuration
  database: {
    type: 'postgresql',
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'vibecoded_app',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password'
  },
  
  // XSS protection configuration
  xss: {
    csp: {
      'default-src': ["'self'"],
      'script-src': ["'self'", "'unsafe-inline'"],
      'style-src': ["'self'", "'unsafe-inline'"],
      'img-src': ["'self'", 'data:', 'https:'],
      'connect-src': ["'self'"]
    }
  },
  
  // Authentication configuration
  auth: {
    secretKey: process.env.JWT_SECRET || 'your-secret-key',
    tokenExpiry: '24h',
    maxLoginAttempts: 5,
    lockoutDuration: 15 * 60 * 1000 // 15 minutes
  },
  
  // Input validation configuration
  validation: {
    strictMode: true,
    maxInputLength: 10000,
    allowedFileTypes: ['jpg', 'jpeg', 'png', 'gif', 'pdf'],
    maxFileSize: 5 * 1024 * 1024 // 5MB
  }
});

// Create Express app
const app = express();
app.use(express.json());

// Apply security middleware
const securityMiddleware = securityManager.createExpressMiddleware();
app.use(securityMiddleware);

// Example: Secure user registration endpoint
app.post('/api/register', 
  securityManager.secureEndpoint(async (req, res) => {
    const { email, password, username, firstName, lastName } = req.body;
    
    // Get validation schema
    const validator = securityManager.getComponent('inputValidator');
    const validation = validator.validate(req.body, validator.schemas.userRegistration);
    
    if (!validation.isValid) {
      return res.status(400).json({
        error: 'Validation failed',
        details: validation.errors
      });
    }
    
    // Hash password securely
    const authManager = securityManager.getComponent('authManager');
    const hashedPassword = await authManager.hashPassword(password);
    
    // Store user in database (using secure database operation)
    const dbOperation = securityManager.secureDatabaseOperation('insert', {
      table: 'users',
      data: {
        email: validator.sanitizeEmail(email),
        password: hashedPassword,
        username: validator.sanitizeString(username, { removeSpecialChars: true }),
        first_name: validator.sanitizeString(firstName, { removeHTML: true }),
        last_name: validator.sanitizeString(lastName, { removeHTML: true }),
        created_at: new Date()
      }
    });
    
    const result = await dbOperation();
    
    res.status(201).json({
      message: 'User registered successfully',
      userId: result.rows[0].id
    });
  }, {
    validation: securityManager.getComponent('inputValidator').schemas.userRegistration
  })
);

// Example: Secure login endpoint
app.post('/api/login',
  securityManager.secureEndpoint(async (req, res) => {
    const { email, password } = req.body;
    
    // Validate input
    const validator = securityManager.getComponent('inputValidator');
    const validation = validator.validate(req.body, validator.schemas.userLogin);
    
    if (!validation.isValid) {
      return res.status(400).json({
        error: 'Invalid input',
        details: validation.errors
      });
    }
    
    // Get user from database
    const dbOperation = securityManager.secureDatabaseOperation('select', {
      table: 'users',
      conditions: { email: validator.sanitizeEmail(email) },
      columns: ['id', 'email', 'password', 'role']
    });
    
    const result = await dbOperation();
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const user = result.rows[0];
    
    // Authenticate user
    const authManager = securityManager.getComponent('authManager');
    const authResult = await authManager.authenticate(email, password, user);
    
    res.json({
      message: 'Login successful',
      accessToken: authResult.accessToken,
      refreshToken: authResult.refreshToken,
      user: authResult.user
    });
  }, {
    validation: securityManager.getComponent('inputValidator').schemas.userLogin
  })
);

// Example: Protected endpoint with role-based access
app.get('/api/admin/users',
  securityManager.secureEndpoint(async (req, res) => {
    // This endpoint requires authentication and admin role
    const dbOperation = securityManager.secureDatabaseOperation('select', {
      table: 'users',
      columns: ['id', 'email', 'username', 'first_name', 'last_name', 'created_at']
    });
    
    const result = await dbOperation();
    
    res.json({
      users: result.rows,
      count: result.rows.length
    });
  }, {
    requireAuth: true,
    allowedRoles: ['admin']
  })
);

// Example: Secure search endpoint
app.get('/api/search',
  securityManager.secureEndpoint(async (req, res) => {
    const { q, category } = req.query;
    
    // Validate search query
    const validator = securityManager.getComponent('inputValidator');
    const validation = validator.validate(req.query, validator.schemas.searchQuery);
    
    if (!validation.isValid) {
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
      { id: 1, title: `Results for: ${sanitizedQuery}`, category }
    ];
    
    res.json({
      query: sanitizedQuery,
      results: searchResults,
      count: searchResults.length
    });
  }, {
    validation: securityManager.getComponent('inputValidator').schemas.searchQuery
  })
);

// Example: Security status endpoint
app.get('/api/security/status', (req, res) => {
  const status = securityManager.getSecurityStatus();
  res.json(status);
});

// Example: Security scan endpoint
app.get('/api/security/scan', async (req, res) => {
  try {
    const scanResults = await securityManager.securityScan('.');
    res.json(scanResults);
  } catch (error) {
    res.status(500).json({
      error: 'Scan failed',
      message: error.message
    });
  }
});

// Example: Secure file upload endpoint
app.post('/api/upload',
  securityManager.secureEndpoint(async (req, res) => {
    // File upload handling would go here
    // The security framework provides file validation
    const validator = securityManager.getComponent('inputValidator');
    
    res.json({
      message: 'File upload endpoint (implementation needed)',
      note: 'Use validator.validateFile() for file validation'
    });
  }, {
    requireAuth: true
  })
);

// Error handling middleware
app.use((error, req, res, next) => {
  console.error('Application error:', error);
  
  // Log security event
  const authManager = securityManager.getComponent('authManager');
  authManager.logSecurityEvent('APPLICATION_ERROR', {
    path: req.path,
    method: req.method,
    error: error.message,
    ip: req.ip
  });
  
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
  });
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Secure VibeCoded API running on port ${PORT}`);
  console.log(`🔒 Security Manager Status:`, securityManager.getSecurityStatus());
});

module.exports = app;
