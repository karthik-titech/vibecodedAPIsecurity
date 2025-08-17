const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/**
 * Authentication and Authorization Manager for Vibe-Coded Applications
 * Prevents authentication and authorization flaws
 * 
 * @description This class provides secure authentication with proper password hashing,
 * JWT token management, rate limiting, and role-based access control.
 */
class AuthManager {
  constructor(options = {}) {
    this.secretKey = options.secretKey || process.env.JWT_SECRET;
    this.saltRounds = options.saltRounds || 12;
    this.tokenExpiry = options.tokenExpiry || '24h';
    this.refreshTokenExpiry = options.refreshTokenExpiry || '7d';
    this.maxLoginAttempts = options.maxLoginAttempts || 5;
    this.lockoutDuration = options.lockoutDuration || 15 * 60 * 1000; // 15 minutes
    this.failedAttempts = new Map();
    this.refreshTokens = new Map();
  }

  /**
   * Hash password using bcrypt
   * @param {string} password - Plain text password
   * @returns {Promise<string>} Hashed password
   */
  async hashPassword(password) {
    if (!password || typeof password !== 'string') {
      throw new Error('Password must be a non-empty string');
    }
    
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }
    
    return await bcrypt.hash(password, this.saltRounds);
  }

  /**
   * Verify password against hash
   * @param {string} password - Plain text password
   * @param {string} hash - Hashed password
   * @returns {Promise<boolean>} True if password matches
   */
  async verifyPassword(password, hash) {
    return await bcrypt.compare(password, hash);
  }

  /**
   * Generate JWT token
   * @param {Object} payload - Token payload
   * @param {string} type - Token type ('access' or 'refresh')
   * @returns {string} JWT token
   */
  generateToken(payload, type = 'access') {
    const expiry = type === 'refresh' ? this.refreshTokenExpiry : this.tokenExpiry;
    
    return jwt.sign(payload, this.secretKey, {
      expiresIn: expiry,
      issuer: 'vibecoded-security',
      audience: 'vibecoded-app'
    });
  }

  /**
   * Verify JWT token
   * @param {string} token - JWT token
   * @returns {Object} Decoded token payload
   */
  verifyToken(token) {
    try {
      return jwt.verify(token, this.secretKey, {
        issuer: 'vibecoded-security',
        audience: 'vibecoded-app'
      });
    } catch (error) {
      throw new Error(`Token verification failed: ${error.message}`);
    }
  }

  /**
   * Generate refresh token
   * @param {string} userId - User ID
   * @returns {string} Refresh token
   */
  generateRefreshToken(userId) {
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = Date.now() + this.lockoutDuration;
    
    this.refreshTokens.set(token, {
      userId,
      expiry
    });
    
    return token;
  }

  /**
   * Verify refresh token
   * @param {string} token - Refresh token
   * @returns {string|null} User ID if valid, null otherwise
   */
  verifyRefreshToken(token) {
    const tokenData = this.refreshTokens.get(token);
    
    if (!tokenData || Date.now() > tokenData.expiry) {
      this.refreshTokens.delete(token);
      return null;
    }
    
    return tokenData.userId;
  }

  /**
   * Revoke refresh token
   * @param {string} token - Refresh token to revoke
   */
  revokeRefreshToken(token) {
    this.refreshTokens.delete(token);
  }

  /**
   * Check if user is locked out due to failed attempts
   * @param {string} identifier - User identifier (email, username, IP)
   * @returns {boolean} True if locked out
   */
  isLockedOut(identifier) {
    const attempts = this.failedAttempts.get(identifier);
    
    if (!attempts) return false;
    
    if (Date.now() > attempts.lockoutUntil) {
      this.failedAttempts.delete(identifier);
      return false;
    }
    
    return attempts.count >= this.maxLoginAttempts;
  }

  /**
   * Record failed login attempt
   * @param {string} identifier - User identifier
   */
  recordFailedAttempt(identifier) {
    const attempts = this.failedAttempts.get(identifier) || {
      count: 0,
      lockoutUntil: 0
    };
    
    attempts.count++;
    
    if (attempts.count >= this.maxLoginAttempts) {
      attempts.lockoutUntil = Date.now() + this.lockoutDuration;
    }
    
    this.failedAttempts.set(identifier, attempts);
  }

  /**
   * Clear failed attempts for user
   * @param {string} identifier - User identifier
   */
  clearFailedAttempts(identifier) {
    this.failedAttempts.delete(identifier);
  }

  /**
   * Authenticate user with proper security measures
   * @param {string} identifier - User identifier
   * @param {string} password - Plain text password
   * @param {Object} userData - User data from database
   * @returns {Object} Authentication result
   */
  async authenticate(identifier, password, userData) {
    // Check if user is locked out
    if (this.isLockedOut(identifier)) {
      throw new Error('Account temporarily locked due to too many failed attempts');
    }

    // Verify password
    const isValid = await this.verifyPassword(password, userData.password);
    
    if (!isValid) {
      this.recordFailedAttempt(identifier);
      throw new Error('Invalid credentials');
    }

    // Clear failed attempts on successful login
    this.clearFailedAttempts(identifier);

    // Generate tokens
    const accessToken = this.generateToken({
      userId: userData.id,
      email: userData.email,
      role: userData.role
    });

    const refreshToken = this.generateRefreshToken(userData.id);

    return {
      accessToken,
      refreshToken,
      user: {
        id: userData.id,
        email: userData.email,
        role: userData.role
      }
    };
  }

  /**
   * Refresh access token using refresh token
   * @param {string} refreshToken - Refresh token
   * @param {Object} userData - User data
   * @returns {Object} New tokens
   */
  refreshAccessToken(refreshToken, userData) {
    const userId = this.verifyRefreshToken(refreshToken);
    
    if (!userId || userId !== userData.id) {
      throw new Error('Invalid refresh token');
    }

    const accessToken = this.generateToken({
      userId: userData.id,
      email: userData.email,
      role: userData.role
    });

    return { accessToken };
  }

  /**
   * Create middleware for JWT authentication
   * @param {Array} allowedRoles - Allowed roles for the route
   * @returns {Function} Express middleware
   */
  requireAuth(allowedRoles = []) {
    return (req, res, next) => {
      try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
          return res.status(401).json({ error: 'No token provided' });
        }

        const token = authHeader.substring(7);
        const decoded = this.verifyToken(token);
        
        req.user = decoded;
        
        // Check role-based access
        if (allowedRoles.length > 0 && !allowedRoles.includes(decoded.role)) {
          return res.status(403).json({ error: 'Insufficient permissions' });
        }
        
        next();
      } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
      }
    };
  }

  /**
   * Create middleware for rate limiting
   * @param {Object} options - Rate limiting options
   * @returns {Function} Express middleware
   */
  rateLimit(options = {}) {
    const windowMs = options.windowMs || 15 * 60 * 1000; // 15 minutes
    const maxRequests = options.maxRequests || 100;
    const requests = new Map();

    return (req, res, next) => {
      const identifier = req.ip || req.connection.remoteAddress;
      const now = Date.now();
      
      const userRequests = requests.get(identifier) || [];
      
      // Remove old requests outside the window
      const validRequests = userRequests.filter(time => now - time < windowMs);
      
      if (validRequests.length >= maxRequests) {
        return res.status(429).json({ error: 'Too many requests' });
      }
      
      validRequests.push(now);
      requests.set(identifier, validRequests);
      
      next();
    };
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @returns {Object} Validation result
   */
  validatePasswordStrength(password) {
    const errors = [];
    
    if (password.length < 8) {
      errors.push('Password must be at least 8 characters long');
    }
    
    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    }
    
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    }
    
    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    }
    
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    }
    
    return {
      isValid: errors.length === 0,
      errors
    };
  }

  /**
   * Log security events
   * @param {string} event - Event type
   * @param {Object} data - Event data
   */
  logSecurityEvent(event, data) {
    const logEntry = {
      timestamp: new Date().toISOString(),
      event,
      data,
      ip: data.ip || 'unknown'
    };
    
    // In production, send to security monitoring system
    console.log('SECURITY EVENT:', logEntry);
  }
}

module.exports = AuthManager;
