const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

/**
 * Secure Secret Manager for Vibe-Coded Applications
 * Prevents hardcoded credentials and exposed secrets
 * 
 * @description This class provides secure secret management using environment variables,
 * encrypted storage, and vault integration to prevent credential exposure in source code.
 */
class SecretManager {
  constructor(options = {}) {
    this.vaultPath = options.vaultPath || '.vault';
    this.encryptionKey = process.env.ENCRYPTION_KEY || crypto.randomBytes(32);
    this.secrets = new Map();
    this.initialized = false;
  }

  /**
   * Initialize the secret manager
   * @throws {Error} If initialization fails
   */
  async initialize() {
    try {
      await fs.mkdir(this.vaultPath, { recursive: true });
      this.initialized = true;
    } catch (error) {
      throw new Error(`Failed to initialize SecretManager: ${error.message}`);
    }
  }

  /**
   * Get a secret from environment variables or encrypted storage
   * @param {string} key - Secret key name
   * @param {string} defaultValue - Default value if not found
   * @returns {string} The secret value
   */
  async getSecret(key, defaultValue = null) {
    if (!this.initialized) {
      await this.initialize();
    }

    // First check environment variables (preferred method)
    const envValue = process.env[key];
    if (envValue) {
      return envValue;
    }

    // Check encrypted storage
    const encryptedValue = await this.getFromVault(key);
    if (encryptedValue) {
      return this.decrypt(encryptedValue);
    }

    if (defaultValue !== null) {
      return defaultValue;
    }

    throw new Error(`Secret '${key}' not found in environment or vault`);
  }

  /**
   * Store a secret securely
   * @param {string} key - Secret key name
   * @param {string} value - Secret value
   * @param {boolean} encrypt - Whether to encrypt before storing
   */
  async setSecret(key, value, encrypt = true) {
    if (!this.initialized) {
      await this.initialize();
    }

    if (encrypt) {
      const encryptedValue = this.encrypt(value);
      await this.saveToVault(key, encryptedValue);
    } else {
      await this.saveToVault(key, value);
    }
  }

  /**
   * Encrypt sensitive data
   * @param {string} data - Data to encrypt
   * @returns {string} Encrypted data
   */
  encrypt(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-gcm', this.encryptionKey);
    
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
   * Decrypt sensitive data
   * @param {string} encryptedData - Encrypted data
   * @returns {string} Decrypted data
   */
  decrypt(encryptedData) {
    try {
      const { iv, encrypted, authTag } = JSON.parse(encryptedData);
      
      const decipher = crypto.createDecipher('aes-256-gcm', this.encryptionKey);
      decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error(`Failed to decrypt data: ${error.message}`);
    }
  }

  /**
   * Save secret to vault
   * @param {string} key - Secret key
   * @param {string} value - Secret value
   */
  async saveToVault(key, value) {
    const vaultFile = path.join(this.vaultPath, `${key}.enc`);
    await fs.writeFile(vaultFile, value, 'utf8');
  }

  /**
   * Get secret from vault
   * @param {string} key - Secret key
   * @returns {string|null} Secret value or null if not found
   */
  async getFromVault(key) {
    try {
      const vaultFile = path.join(this.vaultPath, `${key}.enc`);
      return await fs.readFile(vaultFile, 'utf8');
    } catch (error) {
      return null;
    }
  }

  /**
   * Validate that no hardcoded secrets exist in the codebase
   * @param {string} directory - Directory to scan
   * @returns {Array} List of potential hardcoded secrets
   */
  async scanForHardcodedSecrets(directory = '.') {
    const patterns = [
      /sk_live_[a-zA-Z0-9]{24}/g,
      /sk_test_[a-zA-Z0-9]{24}/g,
      /pk_live_[a-zA-Z0-9]{24}/g,
      /pk_test_[a-zA-Z0-9]{24}/g,
      /[a-zA-Z0-9]{32,}/g, // Generic long strings that might be keys
    ];

    const results = [];
    
    // This is a simplified scan - in production, use tools like TruffleHog
    const files = await this.getAllFiles(directory);
    
    for (const file of files) {
      if (file.includes('node_modules') || file.includes('.git')) continue;
      
      try {
        const content = await fs.readFile(file, 'utf8');
        
        for (const pattern of patterns) {
          const matches = content.match(pattern);
          if (matches) {
            results.push({
              file,
              pattern: pattern.toString(),
              matches: matches.length
            });
          }
        }
      } catch (error) {
        // Skip files that can't be read
      }
    }
    
    return results;
  }

  /**
   * Get all files in a directory recursively
   * @param {string} dir - Directory to scan
   * @returns {Array} List of file paths
   */
  async getAllFiles(dir) {
    const files = [];
    
    try {
      const items = await fs.readdir(dir, { withFileTypes: true });
      
      for (const item of items) {
        const fullPath = path.join(dir, item.name);
        
        if (item.isDirectory()) {
          files.push(...await this.getAllFiles(fullPath));
        } else {
          files.push(fullPath);
        }
      }
    } catch (error) {
      // Skip directories that can't be read
    }
    
    return files;
  }
}

module.exports = SecretManager;
