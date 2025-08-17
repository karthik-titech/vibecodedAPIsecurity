const { Pool } = require('pg');
const mysql = require('mysql2/promise');

/**
 * SQL Injection Protection for Vibe-Coded Applications
 * Prevents SQL injection vulnerabilities through parameterized queries
 * 
 * @description This class provides secure database operations with automatic
 * input sanitization and parameterized queries to prevent SQL injection attacks.
 */
class SQLInjectionProtection {
  constructor(config) {
    this.config = config;
    this.pool = null;
    this.dbType = config.type || 'postgresql';
  }

  /**
   * Initialize database connection with security measures
   */
  async initialize() {
    try {
      if (this.dbType === 'postgresql') {
        this.pool = new Pool({
          ...this.config,
          ssl: this.config.ssl || { rejectUnauthorized: false },
          max: 20,
          idleTimeoutMillis: 30000,
          connectionTimeoutMillis: 2000,
        });
      } else if (this.dbType === 'mysql') {
        this.pool = mysql.createPool({
          ...this.config,
          connectionLimit: 20,
          acquireTimeout: 2000,
          timeout: 30000,
        });
      }

      // Test connection
      await this.testConnection();
    } catch (error) {
      throw new Error(`Database initialization failed: ${error.message}`);
    }
  }

  /**
   * Test database connection
   */
  async testConnection() {
    const client = await this.pool.connect();
    try {
      await client.query('SELECT 1');
    } finally {
      client.release();
    }
  }

  /**
   * Execute a parameterized query safely
   * @param {string} query - SQL query with placeholders
   * @param {Array} params - Parameters for the query
   * @returns {Object} Query result
   */
  async executeQuery(query, params = []) {
    if (!this.pool) {
      await this.initialize();
    }

    // Validate query for potential injection patterns
    this.validateQuery(query);

    // Sanitize parameters
    const sanitizedParams = params.map(param => this.sanitizeParameter(param));

    try {
      const client = await this.pool.connect();
      try {
        const result = await client.query(query, sanitizedParams);
        return result;
      } finally {
        client.release();
      }
    } catch (error) {
      throw new Error(`Query execution failed: ${error.message}`);
    }
  }

  /**
   * Validate query for potential SQL injection patterns
   * @param {string} query - SQL query to validate
   */
  validateQuery(query) {
    const dangerousPatterns = [
      /;\s*$/i,           // Trailing semicolon
      /--\s*$/i,          // SQL comments
      /\/\*.*\*\//i,      // Multi-line comments
      /union\s+select/i,  // UNION SELECT
      /drop\s+table/i,    // DROP TABLE
      /delete\s+from/i,   // DELETE FROM
      /update\s+.*\s+set/i, // UPDATE SET
      /insert\s+into/i,   // INSERT INTO
      /create\s+table/i,  // CREATE TABLE
      /alter\s+table/i,   // ALTER TABLE
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(query)) {
        throw new Error(`Potentially dangerous SQL pattern detected: ${pattern.source}`);
      }
    }

    // Check for string concatenation (common injection vector)
    if (query.includes("'") && !query.includes('$')) {
      throw new Error('Query contains unescaped quotes - use parameterized queries');
    }
  }

  /**
   * Sanitize parameter to prevent injection
   * @param {any} param - Parameter to sanitize
   * @returns {any} Sanitized parameter
   */
  sanitizeParameter(param) {
    if (typeof param === 'string') {
      // Remove potentially dangerous characters
      return param.replace(/[;'"\\]/g, '');
    }
    return param;
  }

  /**
   * Build a safe SELECT query
   * @param {string} table - Table name
   * @param {Object} conditions - WHERE conditions
   * @param {Array} columns - Columns to select
   * @returns {Object} Query and parameters
   */
  buildSelectQuery(table, conditions = {}, columns = ['*']) {
    const validColumns = columns.map(col => this.sanitizeColumn(col));
    const columnList = validColumns.join(', ');
    
    let query = `SELECT ${columnList} FROM ${this.sanitizeTable(table)}`;
    const params = [];
    let paramIndex = 1;

    if (Object.keys(conditions).length > 0) {
      const whereClauses = [];
      
      for (const [key, value] of Object.entries(conditions)) {
        const sanitizedKey = this.sanitizeColumn(key);
        whereClauses.push(`${sanitizedKey} = $${paramIndex}`);
        params.push(value);
        paramIndex++;
      }
      
      query += ` WHERE ${whereClauses.join(' AND ')}`;
    }

    return { query, params };
  }

  /**
   * Build a safe INSERT query
   * @param {string} table - Table name
   * @param {Object} data - Data to insert
   * @returns {Object} Query and parameters
   */
  buildInsertQuery(table, data) {
    const columns = Object.keys(data).map(col => this.sanitizeColumn(col));
    const placeholders = columns.map((_, index) => `$${index + 1}`);
    const values = Object.values(data);

    const query = `
      INSERT INTO ${this.sanitizeTable(table)} 
      (${columns.join(', ')}) 
      VALUES (${placeholders.join(', ')})
    `;

    return { query: query.trim(), params: values };
  }

  /**
   * Build a safe UPDATE query
   * @param {string} table - Table name
   * @param {Object} data - Data to update
   * @param {Object} conditions - WHERE conditions
   * @returns {Object} Query and parameters
   */
  buildUpdateQuery(table, data, conditions = {}) {
    const setClauses = [];
    const whereClauses = [];
    const params = [];
    let paramIndex = 1;

    // Build SET clauses
    for (const [key, value] of Object.entries(data)) {
      const sanitizedKey = this.sanitizeColumn(key);
      setClauses.push(`${sanitizedKey} = $${paramIndex}`);
      params.push(value);
      paramIndex++;
    }

    // Build WHERE clauses
    for (const [key, value] of Object.entries(conditions)) {
      const sanitizedKey = this.sanitizeColumn(key);
      whereClauses.push(`${sanitizedKey} = $${paramIndex}`);
      params.push(value);
      paramIndex++;
    }

    let query = `UPDATE ${this.sanitizeTable(table)} SET ${setClauses.join(', ')}`;
    
    if (whereClauses.length > 0) {
      query += ` WHERE ${whereClauses.join(' AND ')}`;
    }

    return { query, params };
  }

  /**
   * Sanitize column name
   * @param {string} column - Column name to sanitize
   * @returns {string} Sanitized column name
   */
  sanitizeColumn(column) {
    // Only allow alphanumeric characters, underscores, and dots
    if (!/^[a-zA-Z_][a-zA-Z0-9_.]*$/.test(column)) {
      throw new Error(`Invalid column name: ${column}`);
    }
    return column;
  }

  /**
   * Sanitize table name
   * @param {string} table - Table name to sanitize
   * @returns {string} Sanitized table name
   */
  sanitizeTable(table) {
    // Only allow alphanumeric characters and underscores
    if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(table)) {
      throw new Error(`Invalid table name: ${table}`);
    }
    return table;
  }

  /**
   * Execute a transaction with multiple queries
   * @param {Array} queries - Array of {query, params} objects
   * @returns {Array} Results from all queries
   */
  async executeTransaction(queries) {
    if (!this.pool) {
      await this.initialize();
    }

    const client = await this.pool.connect();
    
    try {
      await client.query('BEGIN');
      
      const results = [];
      for (const { query, params = [] } of queries) {
        this.validateQuery(query);
        const sanitizedParams = params.map(param => this.sanitizeParameter(param));
        const result = await client.query(query, sanitizedParams);
        results.push(result);
      }
      
      await client.query('COMMIT');
      return results;
    } catch (error) {
      await client.query('ROLLBACK');
      throw new Error(`Transaction failed: ${error.message}`);
    } finally {
      client.release();
    }
  }

  /**
   * Close database connection
   */
  async close() {
    if (this.pool) {
      await this.pool.end();
    }
  }
}

module.exports = SQLInjectionProtection;
