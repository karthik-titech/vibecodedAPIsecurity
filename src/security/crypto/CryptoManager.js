const crypto = require('crypto');

/**
 * Cryptography Manager for Vibe-Coded Applications
 * 
 * @description This class provides secure cryptographic operations including
 * encryption, hashing, key generation, and digital signatures to prevent
 * custom cryptography flaws in vibe-coded applications.
 */
class CryptoManager {
  constructor(options = {}) {
    this.options = {
      // Encryption algorithms
      encryptionAlgorithm: options.encryptionAlgorithm || 'aes-256-gcm',
      keyLength: options.keyLength || 32, // 256 bits
      ivLength: options.ivLength || 16, // 128 bits
      
      // Hashing algorithms
      hashAlgorithm: options.hashAlgorithm || 'sha256',
      saltLength: options.saltLength || 32,
      
      // Key derivation
      pbkdf2Iterations: options.pbkdf2Iterations || 100000,
      pbkdf2KeyLength: options.pbkdf2KeyLength || 32,
      
      // Digital signatures
      signatureAlgorithm: options.signatureAlgorithm || 'RSA-SHA256',
      
      // Random generation
      randomBytesLength: options.randomBytesLength || 32,
      
      ...options
    };
    
    this.secureAlgorithms = {
      encryption: ['aes-256-gcm', 'aes-256-cbc', 'chacha20-poly1305'],
      hashing: ['sha256', 'sha384', 'sha512', 'blake2b512'],
      keyDerivation: ['pbkdf2', 'scrypt', 'argon2'],
      signatures: ['RSA-SHA256', 'RSA-SHA384', 'RSA-SHA512', 'ECDSA']
    };
  }

  /**
   * Generate cryptographically secure random bytes
   * @param {number} length - Number of bytes to generate
   * @returns {Buffer} Random bytes
   */
  generateRandomBytes(length = this.options.randomBytesLength) {
    return crypto.randomBytes(length);
  }

  /**
   * Generate a secure random string
   * @param {number} length - Length of the string
   * @param {string} charset - Character set to use
   * @returns {string} Random string
   */
  generateRandomString(length = 32, charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
    const bytes = this.generateRandomBytes(length);
    let result = '';
    
    for (let i = 0; i < length; i++) {
      result += charset[bytes[i] % charset.length];
    }
    
    return result;
  }

  /**
   * Generate a secure UUID v4
   * @returns {string} UUID v4
   */
  generateUUID() {
    return crypto.randomUUID();
  }

  /**
   * Encrypt data using AES-256-GCM
   * @param {string|Buffer} data - Data to encrypt
   * @param {string|Buffer} key - Encryption key
   * @param {Buffer} iv - Initialization vector (optional, auto-generated)
   * @returns {Object} Encrypted data with metadata
   */
  encrypt(data, key, iv = null) {
    try {
      // Validate inputs
      if (!data || !key) {
        throw new Error('Data and key are required for encryption');
      }

      // Generate IV if not provided
      const initializationVector = iv || this.generateRandomBytes(this.options.ivLength);
      
      // Create cipher
      const cipher = crypto.createCipher(this.options.encryptionAlgorithm, key);
      
      // Encrypt data
      let encrypted = cipher.update(data, 'utf8', 'hex');
      encrypted += cipher.final('hex');
      
      // Get authentication tag
      const authTag = cipher.getAuthTag();
      
      return {
        encrypted,
        iv: initializationVector.toString('hex'),
        authTag: authTag.toString('hex'),
        algorithm: this.options.encryptionAlgorithm,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using AES-256-GCM
   * @param {Object} encryptedData - Encrypted data object
   * @param {string|Buffer} key - Decryption key
   * @returns {string} Decrypted data
   */
  decrypt(encryptedData, key) {
    try {
      // Validate inputs
      if (!encryptedData || !key) {
        throw new Error('Encrypted data and key are required for decryption');
      }

      const { encrypted, iv, authTag, algorithm } = encryptedData;
      
      // Validate algorithm
      if (algorithm !== this.options.encryptionAlgorithm) {
        throw new Error(`Unsupported encryption algorithm: ${algorithm}`);
      }
      
      // Create decipher
      const decipher = crypto.createDecipher(algorithm, key);
      
      // Set authentication tag
      if (authTag) {
        decipher.setAuthTag(Buffer.from(authTag, 'hex'));
      }
      
      // Decrypt data
      let decrypted = decipher.update(encrypted, 'hex', 'utf8');
      decrypted += decipher.final('utf8');
      
      return decrypted;
    } catch (error) {
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Hash data using SHA-256
   * @param {string|Buffer} data - Data to hash
   * @param {Buffer} salt - Salt for hashing (optional, auto-generated)
   * @returns {Object} Hash with metadata
   */
  hash(data, salt = null) {
    try {
      // Validate inputs
      if (!data) {
        throw new Error('Data is required for hashing');
      }

      // Generate salt if not provided
      const hashSalt = salt || this.generateRandomBytes(this.options.saltLength);
      
      // Create hash
      const hash = crypto.createHash(this.options.hashAlgorithm);
      hash.update(data);
      hash.update(hashSalt);
      
      const hashValue = hash.digest('hex');
      
      return {
        hash: hashValue,
        salt: hashSalt.toString('hex'),
        algorithm: this.options.hashAlgorithm,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Hashing failed: ${error.message}`);
    }
  }

  /**
   * Verify hash
   * @param {string|Buffer} data - Original data
   * @param {string} hash - Hash to verify
   * @param {string} salt - Salt used for hashing
   * @returns {boolean} True if hash matches
   */
  verifyHash(data, hash, salt) {
    try {
      const computedHash = this.hash(data, Buffer.from(salt, 'hex'));
      return computedHash.hash === hash;
    } catch (error) {
      return false;
    }
  }

  /**
   * Derive key from password using PBKDF2
   * @param {string} password - Password to derive key from
   * @param {Buffer} salt - Salt for key derivation (optional, auto-generated)
   * @param {number} iterations - Number of iterations (optional)
   * @returns {Object} Derived key with metadata
   */
  deriveKey(password, salt = null, iterations = null) {
    try {
      // Validate inputs
      if (!password) {
        throw new Error('Password is required for key derivation');
      }

      // Generate salt if not provided
      const keySalt = salt || this.generateRandomBytes(this.options.saltLength);
      const keyIterations = iterations || this.options.pbkdf2Iterations;
      
      // Derive key using PBKDF2
      const derivedKey = crypto.pbkdf2Sync(
        password,
        keySalt,
        keyIterations,
        this.options.pbkdf2KeyLength,
        this.options.hashAlgorithm
      );
      
      return {
        key: derivedKey.toString('hex'),
        salt: keySalt.toString('hex'),
        iterations: keyIterations,
        algorithm: 'pbkdf2',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Key derivation failed: ${error.message}`);
    }
  }

  /**
   * Generate RSA key pair
   * @param {number} keySize - Key size in bits (default: 2048)
   * @returns {Object} Key pair with public and private keys
   */
  generateRSAKeyPair(keySize = 2048) {
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: keySize,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'pkcs8',
          format: 'pem'
        }
      });
      
      return {
        publicKey,
        privateKey,
        keySize,
        algorithm: 'RSA',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`RSA key pair generation failed: ${error.message}`);
    }
  }

  /**
   * Generate EC key pair
   * @param {string} curve - Elliptic curve (default: 'secp256k1')
   * @returns {Object} Key pair with public and private keys
   */
  generateECKeyPair(curve = 'secp256k1') {
    try {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
        namedCurve: curve,
        publicKeyEncoding: {
          type: 'spki',
          format: 'pem'
        },
        privateKeyEncoding: {
          type: 'sec1',
          format: 'pem'
        }
      });
      
      return {
        publicKey,
        privateKey,
        curve,
        algorithm: 'ECDSA',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`EC key pair generation failed: ${error.message}`);
    }
  }

  /**
   * Create digital signature
   * @param {string|Buffer} data - Data to sign
   * @param {string} privateKey - Private key for signing
   * @param {string} algorithm - Signature algorithm (optional)
   * @returns {Object} Signature with metadata
   */
  sign(data, privateKey, algorithm = this.options.signatureAlgorithm) {
    try {
      // Validate inputs
      if (!data || !privateKey) {
        throw new Error('Data and private key are required for signing');
      }

      // Create signer
      const signer = crypto.createSign(algorithm);
      signer.update(data);
      
      // Create signature
      const signature = signer.sign(privateKey, 'hex');
      
      return {
        signature,
        algorithm,
        data: typeof data === 'string' ? data : data.toString('hex'),
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Signing failed: ${error.message}`);
    }
  }

  /**
   * Verify digital signature
   * @param {string|Buffer} data - Original data
   * @param {string} signature - Signature to verify
   * @param {string} publicKey - Public key for verification
   * @param {string} algorithm - Signature algorithm (optional)
   * @returns {boolean} True if signature is valid
   */
  verify(data, signature, publicKey, algorithm = this.options.signatureAlgorithm) {
    try {
      // Validate inputs
      if (!data || !signature || !publicKey) {
        return false;
      }

      // Create verifier
      const verifier = crypto.createVerify(algorithm);
      verifier.update(data);
      
      // Verify signature
      return verifier.verify(publicKey, signature, 'hex');
    } catch (error) {
      return false;
    }
  }

  /**
   * Generate secure password hash using Argon2-like approach
   * @param {string} password - Password to hash
   * @param {Buffer} salt - Salt for hashing (optional, auto-generated)
   * @returns {Object} Password hash with metadata
   */
  hashPassword(password, salt = null) {
    try {
      // Validate password strength
      this.validatePasswordStrength(password);
      
      // Generate salt if not provided
      const passwordSalt = salt || this.generateRandomBytes(this.options.saltLength);
      
      // Use PBKDF2 for password hashing (Argon2 would be better but not built-in)
      const derivedKey = this.deriveKey(password, passwordSalt, this.options.pbkdf2Iterations);
      
      return {
        hash: derivedKey.key,
        salt: derivedKey.salt,
        iterations: derivedKey.iterations,
        algorithm: 'pbkdf2',
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      throw new Error(`Password hashing failed: ${error.message}`);
    }
  }

  /**
   * Verify password hash
   * @param {string} password - Password to verify
   * @param {string} hash - Stored hash
   * @param {string} salt - Stored salt
   * @param {number} iterations - Number of iterations used
   * @returns {boolean} True if password matches
   */
  verifyPassword(password, hash, salt, iterations) {
    try {
      const derivedKey = this.deriveKey(password, Buffer.from(salt, 'hex'), iterations);
      return derivedKey.key === hash;
    } catch (error) {
      return false;
    }
  }

  /**
   * Validate password strength
   * @param {string} password - Password to validate
   * @throws {Error} If password is too weak
   */
  validatePasswordStrength(password) {
    if (!password || typeof password !== 'string') {
      throw new Error('Password must be a non-empty string');
    }
    
    if (password.length < 8) {
      throw new Error('Password must be at least 8 characters long');
    }
    
    // Check for common patterns
    const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'letmein'];
    if (commonPasswords.includes(password.toLowerCase())) {
      throw new Error('Password is too common');
    }
    
    // Check for character variety
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    if (!(hasLower && hasUpper && hasNumber && hasSpecial)) {
      throw new Error('Password must contain lowercase, uppercase, number, and special character');
    }
  }

  /**
   * Generate secure token
   * @param {number} length - Token length (default: 32)
   * @returns {string} Secure token
   */
  generateSecureToken(length = 32) {
    return this.generateRandomString(length, 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789');
  }

  /**
   * Generate API key
   * @param {string} prefix - Key prefix (optional)
   * @returns {string} API key
   */
  generateAPIKey(prefix = 'vc') {
    const timestamp = Date.now().toString(36);
    const random = this.generateRandomString(16);
    return `${prefix}_${timestamp}_${random}`;
  }

  /**
   * Get cryptographic information
   * @returns {Object} Crypto information
   */
  getCryptoInfo() {
    return {
      algorithms: this.secureAlgorithms,
      options: this.options,
      capabilities: {
        encryption: true,
        hashing: true,
        keyDerivation: true,
        digitalSignatures: true,
        keyGeneration: true,
        randomGeneration: true
      },
      recommendations: [
        'Use AES-256-GCM for encryption',
        'Use SHA-256 or better for hashing',
        'Use PBKDF2 with 100,000+ iterations for password hashing',
        'Use RSA-2048 or better for digital signatures',
        'Generate cryptographically secure random values',
        'Never reuse encryption keys or IVs'
      ]
    };
  }
}

module.exports = CryptoManager;
