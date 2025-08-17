const crypto = require('crypto');

/**
 * Performance Security Manager for Vibe-Coded Applications
 * 
 * @description This class optimizes security operations for high-performance
 * applications while maintaining security standards. It provides caching,
 * connection pooling, and performance monitoring for security operations.
 */
class PerformanceSecurityManager {
  constructor(options = {}) {
    this.options = {
      // Performance settings
      enableCaching: options.enableCaching !== false,
      cacheTTL: options.cacheTTL || 300000, // 5 minutes
      maxCacheSize: options.maxCacheSize || 1000,
      
      // Connection pooling
      enableConnectionPooling: options.enableConnectionPooling !== false,
      poolSize: options.poolSize || 10,
      poolTimeout: options.poolTimeout || 30000, // 30 seconds
      
      // Rate limiting
      enableRateLimiting: options.enableRateLimiting !== false,
      rateLimitWindow: options.rateLimitWindow || 60000, // 1 minute
      rateLimitMax: options.rateLimitMax || 1000,
      
      // Performance monitoring
      enableMonitoring: options.enableMonitoring !== false,
      monitoringInterval: options.monitoringInterval || 60000, // 1 minute
      
      // Optimization settings
      enableCompression: options.enableCompression !== false,
      enableParallelProcessing: options.enableParallelProcessing !== false,
      maxParallelOperations: options.maxParallelOperations || 5,
      
      ...options
    };
    
    // Performance caches
    this.caches = {
      hashCache: new Map(),
      encryptionCache: new Map(),
      validationCache: new Map(),
      authCache: new Map()
    };
    
    // Connection pools
    this.connectionPools = new Map();
    
    // Rate limiters
    this.rateLimiters = new Map();
    
    // Performance metrics
    this.metrics = {
      operations: {
        total: 0,
        cached: 0,
        uncached: 0,
        failed: 0
      },
      performance: {
        averageResponseTime: 0,
        maxResponseTime: 0,
        minResponseTime: Infinity,
        totalResponseTime: 0
      },
      cache: {
        hits: 0,
        misses: 0,
        size: 0
      },
      connections: {
        active: 0,
        idle: 0,
        total: 0
      }
    };
    
    // Performance monitoring
    this.startPerformanceMonitoring();
  }

  /**
   * Start performance monitoring
   */
  startPerformanceMonitoring() {
    if (!this.options.enableMonitoring) return;
    
    setInterval(() => {
      this.updatePerformanceMetrics();
      this.cleanupCaches();
      this.monitorConnectionPools();
    }, this.options.monitoringInterval);
  }

  /**
   * Optimized hash function with caching
   */
  async optimizedHash(data, algorithm = 'sha256', salt = null) {
    const cacheKey = this.generateCacheKey('hash', { data, algorithm, salt });
    
    // Check cache first
    if (this.options.enableCaching) {
      const cached = this.getFromCache('hashCache', cacheKey);
      if (cached) {
        this.metrics.cache.hits++;
        return cached;
      }
    }
    
    // Perform hash operation
    const startTime = Date.now();
    const result = await this.performHash(data, algorithm, salt);
    const duration = Date.now() - startTime;
    
    // Update metrics
    this.updateOperationMetrics('hash', duration, true);
    
    // Cache result
    if (this.options.enableCaching) {
      this.setCache('hashCache', cacheKey, result, this.options.cacheTTL);
    }
    
    return result;
  }

  /**
   * Perform actual hash operation
   */
  async performHash(data, algorithm, salt) {
    return new Promise((resolve, reject) => {
      try {
        const hash = crypto.createHash(algorithm);
        hash.update(data);
        if (salt) {
          hash.update(salt);
        }
        
        const result = {
          hash: hash.digest('hex'),
          algorithm,
          salt: salt ? salt.toString('hex') : null,
          timestamp: new Date().toISOString()
        };
        
        resolve(result);
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Optimized encryption with caching
   */
  async optimizedEncrypt(data, key, algorithm = 'aes-256-gcm') {
    const cacheKey = this.generateCacheKey('encrypt', { data, key: key.toString('hex'), algorithm });
    
    // Check cache first
    if (this.options.enableCaching) {
      const cached = this.getFromCache('encryptionCache', cacheKey);
      if (cached) {
        this.metrics.cache.hits++;
        return cached;
      }
    }
    
    // Perform encryption
    const startTime = Date.now();
    const result = await this.performEncryption(data, key, algorithm);
    const duration = Date.now() - startTime;
    
    // Update metrics
    this.updateOperationMetrics('encrypt', duration, true);
    
    // Cache result
    if (this.options.enableCaching) {
      this.setCache('encryptionCache', cacheKey, result, this.options.cacheTTL);
    }
    
    return result;
  }

  /**
   * Perform actual encryption
   */
  async performEncryption(data, key, algorithm) {
    return new Promise((resolve, reject) => {
      try {
        const iv = crypto.randomBytes(16);
        const cipher = crypto.createCipher(algorithm, key);
        
        let encrypted = cipher.update(data, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        
        const authTag = cipher.getAuthTag();
        
        const result = {
          encrypted,
          iv: iv.toString('hex'),
          authTag: authTag.toString('hex'),
          algorithm,
          timestamp: new Date().toISOString()
        };
        
        resolve(result);
      } catch (error) {
        reject(error);
      }
    });
  }

  /**
   * Optimized validation with caching
   */
  async optimizedValidation(data, schema, options = {}) {
    const cacheKey = this.generateCacheKey('validation', { data, schema: JSON.stringify(schema), options: JSON.stringify(options) });
    
    // Check cache first
    if (this.options.enableCaching) {
      const cached = this.getFromCache('validationCache', cacheKey);
      if (cached) {
        this.metrics.cache.hits++;
        return cached;
      }
    }
    
    // Perform validation
    const startTime = Date.now();
    const result = await this.performValidation(data, schema, options);
    const duration = Date.now() - startTime;
    
    // Update metrics
    this.updateOperationMetrics('validation', duration, result.isValid);
    
    // Cache result
    if (this.options.enableCaching) {
      this.setCache('validationCache', cacheKey, result, this.options.cacheTTL);
    }
    
    return result;
  }

  /**
   * Perform actual validation
   */
  async performValidation(data, schema, options) {
    // This would integrate with a validation library like Joi
    // For now, return a simple validation result
    return {
      isValid: true,
      errors: [],
      warnings: [],
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Optimized authentication with caching
   */
  async optimizedAuthentication(credentials, options = {}) {
    const cacheKey = this.generateCacheKey('auth', { 
      username: credentials.username, 
      options: JSON.stringify(options) 
    });
    
    // Check cache first (for successful authentications only)
    if (this.options.enableCaching) {
      const cached = this.getFromCache('authCache', cacheKey);
      if (cached && cached.isValid) {
        this.metrics.cache.hits++;
        return cached;
      }
    }
    
    // Perform authentication
    const startTime = Date.now();
    const result = await this.performAuthentication(credentials, options);
    const duration = Date.now() - startTime;
    
    // Update metrics
    this.updateOperationMetrics('auth', duration, result.isValid);
    
    // Cache successful authentication
    if (this.options.enableCaching && result.isValid) {
      this.setCache('authCache', cacheKey, result, 300000); // 5 minutes for auth
    }
    
    return result;
  }

  /**
   * Perform actual authentication
   */
  async performAuthentication(credentials, options) {
    // This would integrate with authentication system
    // For now, return a simple authentication result
    return {
      isValid: true,
      user: {
        id: 'user123',
        username: credentials.username,
        role: 'user'
      },
      token: 'jwt_token_here',
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Optimized database operations with connection pooling
   */
  async optimizedDatabaseOperation(operation, query, params = []) {
    // Get connection from pool
    const connection = await this.getConnectionFromPool('database');
    
    try {
      const startTime = Date.now();
      const result = await this.performDatabaseOperation(connection, operation, query, params);
      const duration = Date.now() - startTime;
      
      // Update metrics
      this.updateOperationMetrics('database', duration, true);
      
      return result;
    } finally {
      // Return connection to pool
      this.returnConnectionToPool('database', connection);
    }
  }

  /**
   * Get connection from pool
   */
  async getConnectionFromPool(poolName) {
    if (!this.options.enableConnectionPooling) {
      return null; // No pooling
    }
    
    let pool = this.connectionPools.get(poolName);
    if (!pool) {
      pool = {
        connections: [],
        active: 0,
        maxSize: this.options.poolSize
      };
      this.connectionPools.set(poolName, pool);
    }
    
    // Get available connection or create new one
    let connection = pool.connections.find(conn => !conn.inUse);
    if (!connection && pool.active < pool.maxSize) {
      connection = await this.createConnection(poolName);
      pool.connections.push(connection);
      pool.active++;
    }
    
    if (connection) {
      connection.inUse = true;
      connection.lastUsed = Date.now();
    }
    
    this.metrics.connections.active = pool.active;
    this.metrics.connections.total = pool.connections.length;
    
    return connection;
  }

  /**
   * Return connection to pool
   */
  returnConnectionToPool(poolName, connection) {
    if (!connection || !this.options.enableConnectionPooling) return;
    
    const pool = this.connectionPools.get(poolName);
    if (pool) {
      connection.inUse = false;
      this.metrics.connections.idle = pool.connections.filter(conn => !conn.inUse).length;
    }
  }

  /**
   * Create new connection
   */
  async createConnection(poolName) {
    // This would create actual database connections
    // For now, return a mock connection
    return {
      id: `conn_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      inUse: false,
      created: Date.now(),
      lastUsed: Date.now()
    };
  }

  /**
   * Perform database operation
   */
  async performDatabaseOperation(connection, operation, query, params) {
    // This would perform actual database operations
    // For now, return a mock result
    return {
      success: true,
      rows: [],
      rowCount: 0,
      operation,
      query,
      timestamp: new Date().toISOString()
    };
  }

  /**
   * Rate limiting with performance optimization
   */
  async checkRateLimit(identifier, limit = null, window = null) {
    const actualLimit = limit || this.options.rateLimitMax;
    const actualWindow = window || this.options.rateLimitWindow;
    
    if (!this.options.enableRateLimiting) {
      return { allowed: true, remaining: actualLimit };
    }
    
    const key = `rate_limit_${identifier}`;
    let limiter = this.rateLimiters.get(key);
    
    if (!limiter) {
      limiter = {
        count: 0,
        resetTime: Date.now() + actualWindow,
        limit: actualLimit
      };
      this.rateLimiters.set(key, limiter);
    }
    
    // Check if window has expired
    if (Date.now() > limiter.resetTime) {
      limiter.count = 0;
      limiter.resetTime = Date.now() + actualWindow;
    }
    
    // Check limit
    if (limiter.count >= limiter.limit) {
      return { allowed: false, remaining: 0, resetTime: limiter.resetTime };
    }
    
    limiter.count++;
    return { allowed: true, remaining: limiter.limit - limiter.count };
  }

  /**
   * Cache management
   */
  getFromCache(cacheName, key) {
    const cache = this.caches[cacheName];
    if (!cache) return null;
    
    const item = cache.get(key);
    if (!item) {
      this.metrics.cache.misses++;
      return null;
    }
    
    // Check if expired
    if (Date.now() > item.expires) {
      cache.delete(key);
      this.metrics.cache.misses++;
      return null;
    }
    
    this.metrics.cache.hits++;
    return item.value;
  }

  setCache(cacheName, key, value, ttl) {
    const cache = this.caches[cacheName];
    if (!cache) return;
    
    // Check cache size limit
    if (cache.size >= this.options.maxCacheSize) {
      this.evictOldestFromCache(cache);
    }
    
    cache.set(key, {
      value,
      expires: Date.now() + ttl,
      created: Date.now()
    });
    
    this.metrics.cache.size = this.getTotalCacheSize();
  }

  evictOldestFromCache(cache) {
    let oldestKey = null;
    let oldestTime = Date.now();
    
    for (const [key, item] of cache.entries()) {
      if (item.created < oldestTime) {
        oldestTime = item.created;
        oldestKey = key;
      }
    }
    
    if (oldestKey) {
      cache.delete(oldestKey);
    }
  }

  getTotalCacheSize() {
    return Object.values(this.caches).reduce((total, cache) => total + cache.size, 0);
  }

  /**
   * Generate cache key
   */
  generateCacheKey(prefix, data) {
    const hash = crypto.createHash('md5');
    hash.update(JSON.stringify(data));
    return `${prefix}_${hash.digest('hex')}`;
  }

  /**
   * Update operation metrics
   */
  updateOperationMetrics(operation, duration, success) {
    this.metrics.operations.total++;
    
    if (success) {
      this.metrics.operations.cached++;
    } else {
      this.metrics.operations.failed++;
    }
    
    // Update performance metrics
    this.metrics.performance.totalResponseTime += duration;
    this.metrics.performance.averageResponseTime = 
      this.metrics.performance.totalResponseTime / this.metrics.operations.total;
    
    if (duration > this.metrics.performance.maxResponseTime) {
      this.metrics.performance.maxResponseTime = duration;
    }
    
    if (duration < this.metrics.performance.minResponseTime) {
      this.metrics.performance.minResponseTime = duration;
    }
  }

  /**
   * Update performance metrics
   */
  updatePerformanceMetrics() {
    // Calculate cache hit rate
    const totalCacheAccess = this.metrics.cache.hits + this.metrics.cache.misses;
    const cacheHitRate = totalCacheAccess > 0 ? (this.metrics.cache.hits / totalCacheAccess) * 100 : 0;
    
    // Log performance metrics
    console.log('📊 Performance Security Metrics:', {
      operations: {
        total: this.metrics.operations.total,
        successRate: ((this.metrics.operations.total - this.metrics.operations.failed) / this.metrics.operations.total * 100).toFixed(2) + '%'
      },
      performance: {
        averageResponseTime: this.metrics.performance.averageResponseTime.toFixed(2) + 'ms',
        maxResponseTime: this.metrics.performance.maxResponseTime + 'ms',
        minResponseTime: this.metrics.performance.minResponseTime === Infinity ? 'N/A' : this.metrics.performance.minResponseTime + 'ms'
      },
      cache: {
        hitRate: cacheHitRate.toFixed(2) + '%',
        size: this.metrics.cache.size
      },
      connections: {
        active: this.metrics.connections.active,
        idle: this.metrics.connections.idle,
        total: this.metrics.connections.total
      }
    });
  }

  /**
   * Cleanup caches
   */
  cleanupCaches() {
    for (const [cacheName, cache] of Object.entries(this.caches)) {
      for (const [key, item] of cache.entries()) {
        if (Date.now() > item.expires) {
          cache.delete(key);
        }
      }
    }
    
    this.metrics.cache.size = this.getTotalCacheSize();
  }

  /**
   * Monitor connection pools
   */
  monitorConnectionPools() {
    for (const [poolName, pool] of this.connectionPools.entries()) {
      // Clean up idle connections
      const idleConnections = pool.connections.filter(conn => !conn.inUse);
      const activeConnections = pool.connections.filter(conn => conn.inUse);
      
      this.metrics.connections.active = activeConnections.length;
      this.metrics.connections.idle = idleConnections.length;
      this.metrics.connections.total = pool.connections.length;
      
      console.log(`🔗 Connection Pool ${poolName}:`, {
        active: activeConnections.length,
        idle: idleConnections.length,
        total: pool.connections.length,
        maxSize: pool.maxSize
      });
    }
  }

  /**
   * Get performance statistics
   */
  getPerformanceStats() {
    const totalCacheAccess = this.metrics.cache.hits + this.metrics.cache.misses;
    const cacheHitRate = totalCacheAccess > 0 ? (this.metrics.cache.hits / totalCacheAccess) * 100 : 0;
    const successRate = this.metrics.operations.total > 0 ? 
      ((this.metrics.operations.total - this.metrics.operations.failed) / this.metrics.operations.total) * 100 : 0;
    
    return {
      operations: {
        total: this.metrics.operations.total,
        successRate: successRate.toFixed(2) + '%',
        failed: this.metrics.operations.failed
      },
      performance: {
        averageResponseTime: this.metrics.performance.averageResponseTime.toFixed(2) + 'ms',
        maxResponseTime: this.metrics.performance.maxResponseTime + 'ms',
        minResponseTime: this.metrics.performance.minResponseTime === Infinity ? 'N/A' : this.metrics.performance.minResponseTime + 'ms'
      },
      cache: {
        hitRate: cacheHitRate.toFixed(2) + '%',
        size: this.metrics.cache.size,
        hits: this.metrics.cache.hits,
        misses: this.metrics.cache.misses
      },
      connections: {
        active: this.metrics.connections.active,
        idle: this.metrics.connections.idle,
        total: this.metrics.connections.total
      },
      configuration: {
        enableCaching: this.options.enableCaching,
        enableConnectionPooling: this.options.enableConnectionPooling,
        enableRateLimiting: this.options.enableRateLimiting,
        enableMonitoring: this.options.enableMonitoring
      }
    };
  }

  /**
   * Optimize security operations for batch processing
   */
  async batchSecurityOperations(operations) {
    if (!this.options.enableParallelProcessing) {
      // Sequential processing
      const results = [];
      for (const operation of operations) {
        const result = await this.executeSecurityOperation(operation);
        results.push(result);
      }
      return results;
    }
    
    // Parallel processing
    const chunks = this.chunkArray(operations, this.options.maxParallelOperations);
    const results = [];
    
    for (const chunk of chunks) {
      const chunkResults = await Promise.all(
        chunk.map(operation => this.executeSecurityOperation(operation))
      );
      results.push(...chunkResults);
    }
    
    return results;
  }

  /**
   * Execute single security operation
   */
  async executeSecurityOperation(operation) {
    const startTime = Date.now();
    
    try {
      let result;
      
      switch (operation.type) {
        case 'hash':
          result = await this.optimizedHash(operation.data, operation.algorithm, operation.salt);
          break;
        case 'encrypt':
          result = await this.optimizedEncrypt(operation.data, operation.key, operation.algorithm);
          break;
        case 'validate':
          result = await this.optimizedValidation(operation.data, operation.schema, operation.options);
          break;
        case 'authenticate':
          result = await this.optimizedAuthentication(operation.credentials, operation.options);
          break;
        default:
          throw new Error(`Unknown operation type: ${operation.type}`);
      }
      
      const duration = Date.now() - startTime;
      this.updateOperationMetrics(operation.type, duration, true);
      
      return {
        success: true,
        operation: operation.type,
        result,
        duration
      };
    } catch (error) {
      const duration = Date.now() - startTime;
      this.updateOperationMetrics(operation.type, duration, false);
      
      return {
        success: false,
        operation: operation.type,
        error: error.message,
        duration
      };
    }
  }

  /**
   * Chunk array for parallel processing
   */
  chunkArray(array, chunkSize) {
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      chunks.push(array.slice(i, i + chunkSize));
    }
    return chunks;
  }

  /**
   * Create Express middleware for performance monitoring
   */
  createPerformanceMiddleware() {
    return (req, res, next) => {
      const startTime = Date.now();
      
      // Add performance headers
      res.setHeader('X-Performance-Security', 'enabled');
      res.setHeader('X-Performance-Version', '1.0');
      
      // Monitor response time
      res.on('finish', () => {
        const duration = Date.now() - startTime;
        this.updateOperationMetrics('http', duration, res.statusCode < 400);
      });
      
      next();
    };
  }
}

module.exports = PerformanceSecurityManager;
