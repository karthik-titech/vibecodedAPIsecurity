const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');

/**
 * Key Expiration Manager for Vibe-Coded Applications
 * Manages automatic key expiration, rotation, and lifecycle
 * 
 * @description This class provides comprehensive key lifecycle management including
 * automatic expiration, rotation, and replacement of various security keys used
 * throughout the application.
 */
class KeyExpirationManager extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.config = {
      // Key types and their expiration periods (in milliseconds)
      keyTypes: {
        jwt: options.jwtExpiry || 30 * 24 * 60 * 60 * 1000, // 30 days
        encryption: options.encryptionExpiry || 90 * 24 * 60 * 60 * 1000, // 90 days
        api: options.apiExpiry || 60 * 24 * 60 * 60 * 1000, // 60 days
        refresh: options.refreshExpiry || 7 * 24 * 60 * 60 * 1000, // 7 days
        session: options.sessionExpiry || 24 * 60 * 60 * 1000, // 24 hours
        webhook: options.webhookExpiry || 180 * 24 * 60 * 60 * 1000, // 180 days
        database: options.databaseExpiry || 365 * 24 * 60 * 60 * 1000, // 1 year
        ssl: options.sslExpiry || 365 * 24 * 60 * 60 * 1000, // 1 year
        oauth: options.oauthExpiry || 45 * 24 * 60 * 60 * 1000, // 45 days
        backup: options.backupExpiry || 730 * 24 * 60 * 60 * 1000 // 2 years
      },
      
      // Rotation settings
      rotation: {
        enableAutoRotation: options.enableAutoRotation !== false,
        rotationThreshold: options.rotationThreshold || 0.1, // 10% of expiry time
        gracePeriod: options.gracePeriod || 24 * 60 * 60 * 1000, // 24 hours
        maxKeyVersions: options.maxKeyVersions || 3,
        backupOldKeys: options.backupOldKeys !== false
      },
      
      // Storage settings
      storage: {
        keyStorePath: options.keyStorePath || '.keys',
        backupPath: options.backupPath || '.keys/backup',
        encryptionKey: process.env.KEY_ENCRYPTION_KEY || crypto.randomBytes(32)
      },
      
      // Notification settings
      notifications: {
        enableNotifications: options.enableNotifications !== false,
        notifyBeforeExpiry: options.notifyBeforeExpiry || 7 * 24 * 60 * 60 * 1000, // 7 days
        notifyOnRotation: options.notifyOnRotation !== false,
        notifyOnExpiry: options.notifyOnExpiry !== false,
        webhookUrl: options.webhookUrl || process.env.KEY_NOTIFICATION_WEBHOOK,
        emailRecipients: options.emailRecipients || process.env.KEY_NOTIFICATION_EMAIL?.split(',') || []
      }
    };
    
    this.keys = new Map();
    this.rotationQueue = new Map();
    this.expiryTimers = new Map();
    this.initialized = false;
    this.monitoring = false;
  }

  /**
   * Initialize the key expiration manager
   */
  async initialize() {
    try {
      // Create storage directories
      await fs.mkdir(this.config.storage.keyStorePath, { recursive: true });
      await fs.mkdir(this.config.storage.backupPath, { recursive: true });
      
      // Load existing keys
      await this.loadExistingKeys();
      
      // Start monitoring
      if (this.config.rotation.enableAutoRotation) {
        await this.startMonitoring();
      }
      
      this.initialized = true;
      console.log('✅ Key Expiration Manager initialized successfully');
    } catch (error) {
      console.error('❌ Key Expiration Manager initialization failed:', error.message);
      throw error;
    }
  }

  /**
   * Register a new key for expiration management
   * @param {string} keyId - Unique key identifier
   * @param {string} keyType - Type of key (jwt, encryption, api, etc.)
   * @param {string} keyValue - The actual key value
   * @param {Object} metadata - Additional key metadata
   */
  async registerKey(keyId, keyType, keyValue, metadata = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    const expiryTime = this.config.keyTypes[keyType];
    if (!expiryTime) {
      throw new Error(`Unknown key type: ${keyType}`);
    }

    const keyInfo = {
      id: keyId,
      type: keyType,
      value: keyValue,
      createdAt: Date.now(),
      expiresAt: Date.now() + expiryTime,
      metadata: {
        ...metadata,
        version: 1,
        rotationCount: 0
      },
      status: 'active'
    };

    // Encrypt and store the key
    await this.storeKey(keyInfo);
    
    // Add to memory
    this.keys.set(keyId, keyInfo);
    
    // Set up expiry timer
    this.setupExpiryTimer(keyId, keyInfo.expiresAt);
    
    // Set up rotation timer
    if (this.config.rotation.enableAutoRotation) {
      this.setupRotationTimer(keyId, keyInfo.expiresAt);
    }

    this.emit('keyRegistered', { keyId, keyType, expiresAt: keyInfo.expiresAt });
    
    return keyInfo;
  }

  /**
   * Rotate a key before expiration
   * @param {string} keyId - Key to rotate
   * @param {Function} keyGenerator - Function to generate new key value
   */
  async rotateKey(keyId, keyGenerator) {
    if (!this.keys.has(keyId)) {
      throw new Error(`Key not found: ${keyId}`);
    }

    const oldKey = this.keys.get(keyId);
    
    try {
      // Generate new key
      const newKeyValue = await keyGenerator(oldKey);
      
      // Create new key info
      const newKeyInfo = {
        ...oldKey,
        value: newKeyValue,
        createdAt: Date.now(),
        expiresAt: Date.now() + this.config.keyTypes[oldKey.type],
        metadata: {
          ...oldKey.metadata,
          version: oldKey.metadata.version + 1,
          rotationCount: oldKey.metadata.rotationCount + 1,
          rotatedFrom: oldKey.id
        }
      };

      // Backup old key if enabled
      if (this.config.rotation.backupOldKeys) {
        await this.backupKey(oldKey);
      }

      // Store new key
      await this.storeKey(newKeyInfo);
      
      // Update memory
      this.keys.set(keyId, newKeyInfo);
      
      // Clear old timers
      this.clearTimers(keyId);
      
      // Set up new timers
      this.setupExpiryTimer(keyId, newKeyInfo.expiresAt);
      this.setupRotationTimer(keyId, newKeyInfo.expiresAt);

      // Notify about rotation
      if (this.config.notifications.notifyOnRotation) {
        await this.sendNotification('keyRotated', {
          keyId,
          keyType: oldKey.type,
          oldExpiry: oldKey.expiresAt,
          newExpiry: newKeyInfo.expiresAt
        });
      }

      this.emit('keyRotated', { keyId, oldKey, newKey: newKeyInfo });
      
      return newKeyInfo;
    } catch (error) {
      console.error(`Failed to rotate key ${keyId}:`, error.message);
      throw error;
    }
  }

  /**
   * Get key information
   * @param {string} keyId - Key identifier
   * @returns {Object} Key information
   */
  getKeyInfo(keyId) {
    if (!this.keys.has(keyId)) {
      throw new Error(`Key not found: ${keyId}`);
    }
    
    const keyInfo = this.keys.get(keyId);
    return {
      ...keyInfo,
      value: undefined, // Don't expose the actual key value
      timeUntilExpiry: keyInfo.expiresAt - Date.now(),
      isExpired: Date.now() > keyInfo.expiresAt,
      needsRotation: this.shouldRotate(keyInfo)
    };
  }

  /**
   * Get all keys of a specific type
   * @param {string} keyType - Type of keys to retrieve
   * @returns {Array} Array of key information
   */
  getKeysByType(keyType) {
    const keys = [];
    for (const [keyId, keyInfo] of this.keys) {
      if (keyInfo.type === keyType) {
        keys.push(this.getKeyInfo(keyId));
      }
    }
    return keys;
  }

  /**
   * Get keys that need rotation
   * @returns {Array} Array of keys that need rotation
   */
  getKeysNeedingRotation() {
    const keysNeedingRotation = [];
    for (const [keyId, keyInfo] of this.keys) {
      if (this.shouldRotate(keyInfo)) {
        keysNeedingRotation.push(this.getKeyInfo(keyId));
      }
    }
    return keysNeedingRotation;
  }

  /**
   * Get expired keys
   * @returns {Array} Array of expired keys
   */
  getExpiredKeys() {
    const expiredKeys = [];
    for (const [keyId, keyInfo] of this.keys) {
      if (Date.now() > keyInfo.expiresAt) {
        expiredKeys.push(this.getKeyInfo(keyId));
      }
    }
    return expiredKeys;
  }

  /**
   * Revoke a key
   * @param {string} keyId - Key to revoke
   * @param {string} reason - Reason for revocation
   */
  async revokeKey(keyId, reason = 'manual_revocation') {
    if (!this.keys.has(keyId)) {
      throw new Error(`Key not found: ${keyId}`);
    }

    const keyInfo = this.keys.get(keyId);
    keyInfo.status = 'revoked';
    keyInfo.revokedAt = Date.now();
    keyInfo.revocationReason = reason;

    // Clear timers
    this.clearTimers(keyId);
    
    // Store updated key info
    await this.storeKey(keyInfo);
    
    // Update memory
    this.keys.set(keyId, keyInfo);

    this.emit('keyRevoked', { keyId, reason, revokedAt: keyInfo.revokedAt });
    
    return keyInfo;
  }

  /**
   * Start monitoring for key expiration and rotation
   */
  async startMonitoring() {
    if (this.monitoring) {
      return;
    }

    this.monitoring = true;
    
    // Check for keys needing rotation every hour
    setInterval(async () => {
      await this.checkRotationNeeds();
    }, 60 * 60 * 1000);

    // Check for expired keys every 15 minutes
    setInterval(async () => {
      await this.checkExpiredKeys();
    }, 15 * 60 * 1000);

    // Send notifications for keys expiring soon
    setInterval(async () => {
      await this.checkExpiryNotifications();
    }, 60 * 60 * 1000); // Every hour

    console.log('✅ Key expiration monitoring started');
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    this.monitoring = false;
    
    // Clear all timers
    for (const [keyId] of this.keys) {
      this.clearTimers(keyId);
    }
    
    console.log('⏹️ Key expiration monitoring stopped');
  }

  /**
   * Get monitoring statistics
   * @returns {Object} Monitoring statistics
   */
  getMonitoringStats() {
    const stats = {
      totalKeys: this.keys.size,
      activeKeys: 0,
      expiredKeys: 0,
      revokedKeys: 0,
      keysNeedingRotation: 0,
      byType: {}
    };

    for (const [keyId, keyInfo] of this.keys) {
      if (keyInfo.status === 'active') {
        stats.activeKeys++;
      } else if (keyInfo.status === 'revoked') {
        stats.revokedKeys++;
      }

      if (Date.now() > keyInfo.expiresAt) {
        stats.expiredKeys++;
      }

      if (this.shouldRotate(keyInfo)) {
        stats.keysNeedingRotation++;
      }

      if (!stats.byType[keyInfo.type]) {
        stats.byType[keyInfo.type] = 0;
      }
      stats.byType[keyInfo.type]++;
    }

    return stats;
  }

  // Private methods

  /**
   * Check if a key should be rotated
   * @param {Object} keyInfo - Key information
   * @returns {boolean} True if key should be rotated
   */
  shouldRotate(keyInfo) {
    if (keyInfo.status !== 'active') {
      return false;
    }

    const timeUntilExpiry = keyInfo.expiresAt - Date.now();
    const rotationThreshold = this.config.keyTypes[keyInfo.type] * this.config.rotation.rotationThreshold;
    
    return timeUntilExpiry <= rotationThreshold;
  }

  /**
   * Set up expiry timer for a key
   * @param {string} keyId - Key identifier
   * @param {number} expiresAt - Expiration timestamp
   */
  setupExpiryTimer(keyId, expiresAt) {
    const timeUntilExpiry = expiresAt - Date.now();
    
    if (timeUntilExpiry > 0) {
      const timer = setTimeout(async () => {
        await this.handleKeyExpiry(keyId);
      }, timeUntilExpiry);
      
      this.expiryTimers.set(keyId, timer);
    }
  }

  /**
   * Set up rotation timer for a key
   * @param {string} keyId - Key identifier
   * @param {number} expiresAt - Expiration timestamp
   */
  setupRotationTimer(keyId, expiresAt) {
    const timeUntilExpiry = expiresAt - Date.now();
    const rotationThreshold = this.config.keyTypes[this.keys.get(keyId).type] * this.config.rotation.rotationThreshold;
    
    if (timeUntilExpiry > rotationThreshold) {
      const timer = setTimeout(async () => {
        await this.handleKeyRotation(keyId);
      }, timeUntilExpiry - rotationThreshold);
      
      this.rotationQueue.set(keyId, timer);
    }
  }

  /**
   * Clear timers for a key
   * @param {string} keyId - Key identifier
   */
  clearTimers(keyId) {
    if (this.expiryTimers.has(keyId)) {
      clearTimeout(this.expiryTimers.get(keyId));
      this.expiryTimers.delete(keyId);
    }
    
    if (this.rotationQueue.has(keyId)) {
      clearTimeout(this.rotationQueue.get(keyId));
      this.rotationQueue.delete(keyId);
    }
  }

  /**
   * Handle key expiry
   * @param {string} keyId - Expired key identifier
   */
  async handleKeyExpiry(keyId) {
    const keyInfo = this.keys.get(keyId);
    if (!keyInfo) return;

    keyInfo.status = 'expired';
    keyInfo.expiredAt = Date.now();

    // Notify about expiry
    if (this.config.notifications.notifyOnExpiry) {
      await this.sendNotification('keyExpired', {
        keyId,
        keyType: keyInfo.type,
        expiredAt: keyInfo.expiredAt
      });
    }

    this.emit('keyExpired', { keyId, keyType: keyInfo.type, expiredAt: keyInfo.expiredAt });
  }

  /**
   * Handle automatic key rotation
   * @param {string} keyId - Key identifier to rotate
   */
  async handleKeyRotation(keyId) {
    const keyInfo = this.keys.get(keyId);
    if (!keyInfo || !this.shouldRotate(keyInfo)) return;

    // Default key generator
    const defaultKeyGenerator = (oldKey) => {
      switch (oldKey.type) {
        case 'jwt':
          return crypto.randomBytes(32).toString('hex');
        case 'encryption':
          return crypto.randomBytes(32);
        case 'api':
          return crypto.randomBytes(16).toString('hex');
        default:
          return crypto.randomBytes(16).toString('hex');
      }
    };

    try {
      await this.rotateKey(keyId, defaultKeyGenerator);
    } catch (error) {
      console.error(`Automatic rotation failed for key ${keyId}:`, error.message);
    }
  }

  /**
   * Check for keys needing rotation
   */
  async checkRotationNeeds() {
    const keysNeedingRotation = this.getKeysNeedingRotation();
    
    if (keysNeedingRotation.length > 0) {
      this.emit('rotationNeeded', { keys: keysNeedingRotation });
    }
  }

  /**
   * Check for expired keys
   */
  async checkExpiredKeys() {
    const expiredKeys = this.getExpiredKeys();
    
    if (expiredKeys.length > 0) {
      this.emit('keysExpired', { keys: expiredKeys });
    }
  }

  /**
   * Check and send expiry notifications
   */
  async checkExpiryNotifications() {
    const now = Date.now();
    const notifyThreshold = this.config.notifications.notifyBeforeExpiry;
    
    for (const [keyId, keyInfo] of this.keys) {
      if (keyInfo.status !== 'active') continue;
      
      const timeUntilExpiry = keyInfo.expiresAt - now;
      
      if (timeUntilExpiry > 0 && timeUntilExpiry <= notifyThreshold) {
        await this.sendNotification('keyExpiringSoon', {
          keyId,
          keyType: keyInfo.type,
          expiresAt: keyInfo.expiresAt,
          timeUntilExpiry
        });
      }
    }
  }

  /**
   * Store key securely
   * @param {Object} keyInfo - Key information to store
   */
  async storeKey(keyInfo) {
    const encryptedValue = this.encrypt(keyInfo.value);
    const keyData = {
      ...keyInfo,
      value: encryptedValue
    };
    
    const filePath = path.join(this.config.storage.keyStorePath, `${keyInfo.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(keyData, null, 2));
  }

  /**
   * Load existing keys from storage
   */
  async loadExistingKeys() {
    try {
      const files = await fs.readdir(this.config.storage.keyStorePath);
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const filePath = path.join(this.config.storage.keyStorePath, file);
          const keyData = JSON.parse(await fs.readFile(filePath, 'utf8'));
          
          // Decrypt the key value
          keyData.value = this.decrypt(keyData.value);
          
          this.keys.set(keyData.id, keyData);
          
          // Set up timers for active keys
          if (keyData.status === 'active') {
            this.setupExpiryTimer(keyData.id, keyData.expiresAt);
            this.setupRotationTimer(keyData.id, keyData.expiresAt);
          }
        }
      }
    } catch (error) {
      // Directory might not exist yet, which is fine
      if (error.code !== 'ENOENT') {
        throw error;
      }
    }
  }

  /**
   * Backup a key
   * @param {Object} keyInfo - Key to backup
   */
  async backupKey(keyInfo) {
    const backupData = {
      ...keyInfo,
      backedUpAt: Date.now(),
      backupReason: 'rotation'
    };
    
    const fileName = `${keyInfo.id}_${Date.now()}.json`;
    const filePath = path.join(this.config.storage.backupPath, fileName);
    
    await fs.writeFile(filePath, JSON.stringify(backupData, null, 2));
  }

  /**
   * Encrypt data
   * @param {string|Buffer} data - Data to encrypt
   * @returns {string} Encrypted data
   */
  encrypt(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-gcm', this.config.storage.encryptionKey);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return JSON.stringify({
      iv: iv.toString('hex'),
      encrypted: encrypted,
      authTag: authTag.toString('hex')
    });
  }

  /**
   * Decrypt data
   * @param {string} encryptedData - Encrypted data
   * @returns {string} Decrypted data
   */
  decrypt(encryptedData) {
    const data = JSON.parse(encryptedData);
    const decipher = crypto.createDecipher('aes-256-gcm', this.config.storage.encryptionKey);
    
    decipher.setAuthTag(Buffer.from(data.authTag, 'hex'));
    
    let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  /**
   * Send notification
   * @param {string} event - Event type
   * @param {Object} data - Notification data
   */
  async sendNotification(event, data) {
    if (!this.config.notifications.enableNotifications) {
      return;
    }

    const notification = {
      event,
      timestamp: Date.now(),
      data
    };

    // Send webhook notification
    if (this.config.notifications.webhookUrl) {
      try {
        const response = await fetch(this.config.notifications.webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(notification)
        });
        
        if (!response.ok) {
          console.error('Failed to send webhook notification:', response.statusText);
        }
      } catch (error) {
        console.error('Webhook notification failed:', error.message);
      }
    }

    // Send email notification (placeholder for email service integration)
    if (this.config.notifications.emailRecipients.length > 0) {
      console.log('Email notification would be sent:', {
        to: this.config.notifications.emailRecipients,
        subject: `Key Management: ${event}`,
        body: JSON.stringify(notification, null, 2)
      });
    }
  }
}

module.exports = KeyExpirationManager;
