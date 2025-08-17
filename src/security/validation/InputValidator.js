const Joi = require('joi');

/**
 * Input Validation and Sanitization for Vibe-Coded Applications
 * Prevents input-related vulnerabilities and injection attacks
 * 
 * @description This class provides comprehensive input validation using Joi schemas,
 * custom sanitization rules, and protection against various injection attacks.
 */
class InputValidator {
  constructor(options = {}) {
    this.strictMode = options.strictMode !== false;
    this.maxInputLength = options.maxInputLength || 10000;
    this.allowedFileTypes = options.allowedFileTypes || ['jpg', 'jpeg', 'png', 'gif', 'pdf'];
    this.maxFileSize = options.maxFileSize || 5 * 1024 * 1024; // 5MB
  }

  /**
   * Common validation schemas
   */
  get schemas() {
    return {
      // User registration and login
      userRegistration: Joi.object({
        email: Joi.string().email().required().max(255),
        password: Joi.string().min(8).max(128).required()
          .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/),
        username: Joi.string().alphanum().min(3).max(30).required(),
        firstName: Joi.string().max(50).required(),
        lastName: Joi.string().max(50).required()
      }),

      userLogin: Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().required()
      }),

      // Payment processing
      paymentInfo: Joi.object({
        amount: Joi.number().positive().precision(2).required(),
        currency: Joi.string().length(3).uppercase().required(),
        description: Joi.string().max(255).required(),
        customerEmail: Joi.string().email().required()
      }),

      // API endpoints
      pagination: Joi.object({
        page: Joi.number().integer().min(1).default(1),
        limit: Joi.number().integer().min(1).max(100).default(10),
        sortBy: Joi.string().valid('created_at', 'updated_at', 'name', 'email').default('created_at'),
        sortOrder: Joi.string().valid('asc', 'desc').default('desc')
      }),

      // Search queries
      searchQuery: Joi.object({
        q: Joi.string().max(255).required(),
        filters: Joi.object().optional(),
        category: Joi.string().max(50).optional()
      }),

      // File upload
      fileUpload: Joi.object({
        file: Joi.object({
          mimetype: Joi.string().valid('image/jpeg', 'image/png', 'image/gif', 'application/pdf').required(),
          size: Joi.number().max(this.maxFileSize).required(),
          originalname: Joi.string().max(255).required()
        }).required()
      })
    };
  }

  /**
   * Validate input against schema
   * @param {Object} data - Input data
   * @param {Object} schema - Joi schema
   * @param {Object} options - Validation options
   * @returns {Object} Validation result
   */
  validate(data, schema, options = {}) {
    try {
      const validationOptions = {
        abortEarly: false,
        allowUnknown: !this.strictMode,
        stripUnknown: true,
        ...options
      };

      const result = schema.validate(data, validationOptions);
      
      if (result.error) {
        return {
          isValid: false,
          errors: result.error.details.map(detail => ({
            field: detail.path.join('.'),
            message: detail.message,
            type: detail.type
          }))
        };
      }

      return {
        isValid: true,
        data: result.value
      };
    } catch (error) {
      return {
        isValid: false,
        errors: [{
          field: 'validation',
          message: 'Validation failed',
          type: 'error'
        }]
      };
    }
  }

  /**
   * Sanitize string input
   * @param {string} input - Input string
   * @param {Object} options - Sanitization options
   * @returns {string} Sanitized string
   */
  sanitizeString(input, options = {}) {
    if (typeof input !== 'string') {
      return input;
    }

    let sanitized = input;

    // Remove null bytes
    sanitized = sanitized.replace(/\0/g, '');

    // Trim whitespace
    sanitized = sanitized.trim();

    // Remove HTML tags if specified
    if (options.removeHTML) {
      sanitized = sanitized.replace(/<[^>]*>/g, '');
    }

    // Remove script tags and event handlers
    if (options.removeScripts) {
      sanitized = sanitized
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
        .replace(/on\w+\s*=\s*["'][^"']*["']/gi, '')
        .replace(/javascript:/gi, '')
        .replace(/vbscript:/gi, '');
    }

    // Limit length
    if (options.maxLength && sanitized.length > options.maxLength) {
      sanitized = sanitized.substring(0, options.maxLength);
    }

    // Convert to lowercase if specified
    if (options.toLowerCase) {
      sanitized = sanitized.toLowerCase();
    }

    // Remove special characters if specified
    if (options.removeSpecialChars) {
      sanitized = sanitized.replace(/[^a-zA-Z0-9\s]/g, '');
    }

    return sanitized;
  }

  /**
   * Sanitize email address
   * @param {string} email - Email address
   * @returns {string} Sanitized email
   */
  sanitizeEmail(email) {
    if (typeof email !== 'string') {
      return email;
    }

    return email.toLowerCase().trim();
  }

  /**
   * Sanitize URL
   * @param {string} url - URL to sanitize
   * @param {Array} allowedProtocols - Allowed protocols
   * @returns {string} Sanitized URL
   */
  sanitizeURL(url, allowedProtocols = ['http', 'https']) {
    if (typeof url !== 'string') {
      return url;
    }

    const sanitized = url.trim();

    try {
      const parsed = new URL(sanitized);
      
      if (!allowedProtocols.includes(parsed.protocol.replace(':', ''))) {
        throw new Error('Invalid protocol');
      }

      return parsed.toString();
    } catch (error) {
      throw new Error('Invalid URL format');
    }
  }

  /**
   * Validate and sanitize file upload
   * @param {Object} file - File object
   * @returns {Object} Validation result
   */
  validateFile(file) {
    const errors = [];

    if (!file) {
      errors.push('No file provided');
      return { isValid: false, errors };
    }

    // Check file size
    if (file.size > this.maxFileSize) {
      errors.push(`File size exceeds maximum allowed size of ${this.maxFileSize / 1024 / 1024}MB`);
    }

    // Check file type
    const fileExtension = file.originalname.split('.').pop().toLowerCase();
    if (!this.allowedFileTypes.includes(fileExtension)) {
      errors.push(`File type not allowed. Allowed types: ${this.allowedFileTypes.join(', ')}`);
    }

    // Check MIME type
    const allowedMimeTypes = {
      'jpg': 'image/jpeg',
      'jpeg': 'image/jpeg',
      'png': 'image/png',
      'gif': 'image/gif',
      'pdf': 'application/pdf'
    };

    if (file.mimetype !== allowedMimeTypes[fileExtension]) {
      errors.push('File MIME type does not match file extension');
    }

    // Sanitize filename
    const sanitizedFilename = this.sanitizeString(file.originalname, {
      removeSpecialChars: true,
      maxLength: 255
    });

    return {
      isValid: errors.length === 0,
      errors,
      sanitizedFilename
    };
  }

  /**
   * Validate JSON input
   * @param {string} jsonString - JSON string
   * @returns {Object} Validation result
   */
  validateJSON(jsonString) {
    try {
      const parsed = JSON.parse(jsonString);
      
      // Check for circular references
      const seen = new WeakSet();
      const checkCircular = (obj) => {
        if (obj && typeof obj === 'object') {
          if (seen.has(obj)) {
            throw new Error('Circular reference detected');
          }
          seen.add(obj);
          
          for (const key in obj) {
            if (obj.hasOwnProperty(key)) {
              checkCircular(obj[key]);
            }
          }
        }
      };
      
      checkCircular(parsed);
      
      return {
        isValid: true,
        data: parsed
      };
    } catch (error) {
      return {
        isValid: false,
        errors: [{
          field: 'json',
          message: error.message,
          type: 'json_error'
        }]
      };
    }
  }

  /**
   * Create custom validation schema
   * @param {Object} rules - Validation rules
   * @returns {Object} Joi schema
   */
  createSchema(rules) {
    let schema = Joi.object();

    for (const [field, rule] of Object.entries(rules)) {
      let fieldSchema = Joi.any();

      switch (rule.type) {
        case 'string':
          fieldSchema = Joi.string();
          if (rule.maxLength) fieldSchema = fieldSchema.max(rule.maxLength);
          if (rule.minLength) fieldSchema = fieldSchema.min(rule.minLength);
          if (rule.pattern) fieldSchema = fieldSchema.pattern(new RegExp(rule.pattern));
          break;

        case 'number':
          fieldSchema = Joi.number();
          if (rule.min !== undefined) fieldSchema = fieldSchema.min(rule.min);
          if (rule.max !== undefined) fieldSchema = fieldSchema.max(rule.max);
          break;

        case 'email':
          fieldSchema = Joi.string().email();
          break;

        case 'url':
          fieldSchema = Joi.string().uri();
          break;

        case 'boolean':
          fieldSchema = Joi.boolean();
          break;

        case 'array':
          fieldSchema = Joi.array();
          if (rule.maxItems) fieldSchema = fieldSchema.max(rule.maxItems);
          if (rule.minItems) fieldSchema = fieldSchema.min(rule.minItems);
          break;
      }

      if (rule.required) {
        fieldSchema = fieldSchema.required();
      }

      schema = schema.keys({ [field]: fieldSchema });
    }

    return schema;
  }

  /**
   * Create Express middleware for validation
   * @param {Object} schema - Joi schema
   * @param {string} source - Source of data ('body', 'query', 'params')
   * @returns {Function} Express middleware
   */
  middleware(schema, source = 'body') {
    return (req, res, next) => {
      const data = req[source];
      const result = this.validate(data, schema);

      if (!result.isValid) {
        return res.status(400).json({
          error: 'Validation failed',
          details: result.errors
        });
      }

      req[source] = result.data;
      next();
    };
  }
}

module.exports = InputValidator;
