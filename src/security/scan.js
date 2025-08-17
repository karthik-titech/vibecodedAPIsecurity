#!/usr/bin/env node

const fs = require('fs').promises;
const path = require('path');
const SecurityManager = require('./SecurityManager');

/**
 * VibeCoded Security Scanner
 * 
 * Standalone security scanner for vibe-coded applications
 * Can be run independently or integrated with CI/CD pipelines
 */

class SecurityScanner {
  constructor(options = {}) {
    this.options = {
      directory: options.directory || '.',
      output: options.output || 'security-report.json',
      verbose: options.verbose || false,
      fix: options.fix || false,
      ...options
    };
    
    this.securityManager = new SecurityManager();
    this.scanResults = {
      timestamp: new Date().toISOString(),
      directory: this.options.directory,
      vulnerabilities: [],
      recommendations: [],
      score: 100,
      summary: {
        total: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
      }
    };
  }

  /**
   * Run comprehensive security scan
   */
  async scan() {
    console.log('🔍 Starting VibeCoded Security Scan...\n');
    
    try {
      // Initialize security manager
      await this.securityManager.initializeComponents();
      
      // Run all security checks
      await this.scanForHardcodedSecrets();
      await this.scanForSQLInjection();
      await this.scanForXSSVulnerabilities();
      await this.scanForAuthenticationIssues();
      await this.scanForInputValidation();
      await this.scanForDependencyVulnerabilities();
      await this.scanForConfigurationIssues();
      await this.scanForFilePermissions();
      
      // Generate recommendations
      this.generateRecommendations();
      
      // Calculate security score
      this.calculateSecurityScore();
      
      // Generate report
      await this.generateReport();
      
      // Display results
      this.displayResults();
      
      return this.scanResults;
      
    } catch (error) {
      console.error('❌ Security scan failed:', error.message);
      throw error;
    }
  }

  /**
   * Scan for hardcoded secrets
   */
  async scanForHardcodedSecrets() {
    console.log('🔐 Scanning for hardcoded secrets...');
    
    try {
      const secretManager = this.securityManager.getComponent('secretManager');
      const secrets = await secretManager.scanForHardcodedSecrets(this.options.directory);
      
      if (secrets.length > 0) {
        this.addVulnerability({
          type: 'HARDCODED_SECRETS',
          severity: 'HIGH',
          title: 'Hardcoded Credentials Detected',
          description: 'API keys, passwords, or tokens found in source code',
          count: secrets.length,
          details: secrets,
          recommendation: 'Move all secrets to environment variables or secure vaults'
        });
      } else {
        console.log('✅ No hardcoded secrets found');
      }
    } catch (error) {
      console.warn('⚠️ Secret scan failed:', error.message);
    }
  }

  /**
   * Scan for SQL injection vulnerabilities
   */
  async scanForSQLInjection() {
    console.log('💉 Scanning for SQL injection vulnerabilities...');
    
    try {
      const files = await this.getAllFiles(this.options.directory, ['.js', '.ts', '.jsx', '.tsx']);
      const sqlPatterns = [
        /query\s*=\s*["'][^"']*\$\{[^}]*\}[^"']*["']/g,
        /`[^`]*\$\{[^}]*\}[^`]*`/g,
        /SELECT.*WHERE.*\+/gi,
        /INSERT.*VALUES.*\+/gi,
        /UPDATE.*SET.*\+/gi,
        /DELETE.*WHERE.*\+/gi
      ];
      
      const vulnerabilities = [];
      
      for (const file of files) {
        try {
          const content = await fs.readFile(file, 'utf8');
          
          for (const pattern of sqlPatterns) {
            const matches = content.match(pattern);
            if (matches) {
              vulnerabilities.push({
                file,
                pattern: pattern.source,
                matches: matches.length,
                lines: this.getLineNumbers(content, pattern)
              });
            }
          }
        } catch (error) {
          // Skip files that can't be read
        }
      }
      
      if (vulnerabilities.length > 0) {
        this.addVulnerability({
          type: 'SQL_INJECTION',
          severity: 'HIGH',
          title: 'Potential SQL Injection Vulnerabilities',
          description: 'String concatenation in SQL queries detected',
          count: vulnerabilities.length,
          details: vulnerabilities,
          recommendation: 'Use parameterized queries and the SQLInjectionProtection component'
        });
      } else {
        console.log('✅ No SQL injection vulnerabilities found');
      }
    } catch (error) {
      console.warn('⚠️ SQL injection scan failed:', error.message);
    }
  }

  /**
   * Scan for XSS vulnerabilities
   */
  async scanForXSSVulnerabilities() {
    console.log('🛡️ Scanning for XSS vulnerabilities...');
    
    try {
      const files = await this.getAllFiles(this.options.directory, ['.js', '.ts', '.jsx', '.tsx', '.html', '.ejs']);
      const xssPatterns = [
        /innerHTML\s*=\s*[^;]+/g,
        /outerHTML\s*=\s*[^;]+/g,
        /document\.write\s*\([^)]*\)/g,
        /eval\s*\([^)]*\)/g,
        /<script[^>]*>/gi
      ];
      
      const vulnerabilities = [];
      
      for (const file of files) {
        try {
          const content = await fs.readFile(file, 'utf8');
          
          for (const pattern of xssPatterns) {
            const matches = content.match(pattern);
            if (matches) {
              vulnerabilities.push({
                file,
                pattern: pattern.source,
                matches: matches.length,
                lines: this.getLineNumbers(content, pattern)
              });
            }
          }
        } catch (error) {
          // Skip files that can't be read
        }
      }
      
      if (vulnerabilities.length > 0) {
        this.addVulnerability({
          type: 'XSS_VULNERABILITY',
          severity: 'HIGH',
          title: 'Potential XSS Vulnerabilities',
          description: 'Unsafe DOM manipulation detected',
          count: vulnerabilities.length,
          details: vulnerabilities,
          recommendation: 'Use the XSSProtection component for output encoding'
        });
      } else {
        console.log('✅ No XSS vulnerabilities found');
      }
    } catch (error) {
      console.warn('⚠️ XSS scan failed:', error.message);
    }
  }

  /**
   * Scan for authentication issues
   */
  async scanForAuthenticationIssues() {
    console.log('🔑 Scanning for authentication issues...');
    
    try {
      const files = await this.getAllFiles(this.options.directory, ['.js', '.ts', '.jsx', '.tsx']);
      const authPatterns = [
        /password\s*==\s*[^;]+/g,
        /password\s*===\s*[^;]+/g,
        /localStorage\.isAdmin/g,
        /sessionStorage\.isAdmin/g,
        /\.password\s*=\s*[^;]+/g
      ];
      
      const vulnerabilities = [];
      
      for (const file of files) {
        try {
          const content = await fs.readFile(file, 'utf8');
          
          for (const pattern of authPatterns) {
            const matches = content.match(pattern);
            if (matches) {
              vulnerabilities.push({
                file,
                pattern: pattern.source,
                matches: matches.length,
                lines: this.getLineNumbers(content, pattern)
              });
            }
          }
        } catch (error) {
          // Skip files that can't be read
        }
      }
      
      if (vulnerabilities.length > 0) {
        this.addVulnerability({
          type: 'AUTHENTICATION_ISSUES',
          severity: 'HIGH',
          title: 'Authentication Security Issues',
          description: 'Weak authentication patterns detected',
          count: vulnerabilities.length,
          details: vulnerabilities,
          recommendation: 'Use the AuthManager component for secure authentication'
        });
      } else {
        console.log('✅ No authentication issues found');
      }
    } catch (error) {
      console.warn('⚠️ Authentication scan failed:', error.message);
    }
  }

  /**
   * Scan for input validation issues
   */
  async scanForInputValidation() {
    console.log('✅ Scanning for input validation issues...');
    
    try {
      const files = await this.getAllFiles(this.options.directory, ['.js', '.ts', '.jsx', '.tsx']);
      const validationPatterns = [
        /req\.body[^;]*\.[^;]*=/g,
        /req\.query[^;]*\.[^;]*=/g,
        /req\.params[^;]*\.[^;]*=/g
      ];
      
      const vulnerabilities = [];
      
      for (const file of files) {
        try {
          const content = await fs.readFile(file, 'utf8');
          
          for (const pattern of validationPatterns) {
            const matches = content.match(pattern);
            if (matches) {
              vulnerabilities.push({
                file,
                pattern: pattern.source,
                matches: matches.length,
                lines: this.getLineNumbers(content, pattern)
              });
            }
          }
        } catch (error) {
          // Skip files that can't be read
        }
      }
      
      if (vulnerabilities.length > 0) {
        this.addVulnerability({
          type: 'INPUT_VALIDATION',
          severity: 'MEDIUM',
          title: 'Input Validation Issues',
          description: 'Direct use of request data without validation',
          count: vulnerabilities.length,
          details: vulnerabilities,
          recommendation: 'Use the InputValidator component for all user inputs'
        });
      } else {
        console.log('✅ No input validation issues found');
      }
    } catch (error) {
      console.warn('⚠️ Input validation scan failed:', error.message);
    }
  }

  /**
   * Scan for dependency vulnerabilities
   */
  async scanForDependencyVulnerabilities() {
    console.log('📦 Scanning for dependency vulnerabilities...');
    
    try {
      const packageJsonPath = path.join(this.options.directory, 'package.json');
      const packageLockPath = path.join(this.options.directory, 'package-lock.json');
      
      // Check if package-lock.json exists
      try {
        await fs.access(packageLockPath);
        console.log('✅ package-lock.json found');
      } catch (error) {
        this.addVulnerability({
          type: 'DEPENDENCY_LOCK',
          severity: 'MEDIUM',
          title: 'Missing package-lock.json',
          description: 'No package lock file found',
          recommendation: 'Use npm install to generate package-lock.json'
        });
      }
      
      // Check for outdated dependencies
      const packageJson = JSON.parse(await fs.readFile(packageJsonPath, 'utf8'));
      const dependencies = { ...packageJson.dependencies, ...packageJson.devDependencies };
      
      const outdatedPatterns = [
        /^\^/,
        /^~/,
        /^>|^<|^>=|^<=/
      ];
      
      const outdatedDeps = [];
      
      for (const [dep, version] of Object.entries(dependencies)) {
        for (const pattern of outdatedPatterns) {
          if (pattern.test(version)) {
            outdatedDeps.push({ dependency: dep, version });
            break;
          }
        }
      }
      
      if (outdatedDeps.length > 0) {
        this.addVulnerability({
          type: 'OUTDATED_DEPENDENCIES',
          severity: 'MEDIUM',
          title: 'Outdated Dependencies',
          description: 'Dependencies with version ranges detected',
          count: outdatedDeps.length,
          details: outdatedDeps,
          recommendation: 'Pin dependency versions and regularly update'
        });
      } else {
        console.log('✅ No outdated dependencies found');
      }
      
    } catch (error) {
      console.warn('⚠️ Dependency scan failed:', error.message);
    }
  }

  /**
   * Scan for configuration issues
   */
  async scanForConfigurationIssues() {
    console.log('⚙️ Scanning for configuration issues...');
    
    try {
      const configFiles = [
        'config.js',
        'config.json',
        '.env',
        '.env.example',
        'docker-compose.yml',
        'Dockerfile'
      ];
      
      const issues = [];
      
      for (const configFile of configFiles) {
        const filePath = path.join(this.options.directory, configFile);
        
        try {
          await fs.access(filePath);
          
          if (configFile === '.env.example') {
            const content = await fs.readFile(filePath, 'utf8');
            if (content.includes('password') || content.includes('secret') || content.includes('key')) {
              issues.push({
                file: configFile,
                issue: 'Sensitive data in example file'
              });
            }
          }
        } catch (error) {
          // File doesn't exist
        }
      }
      
      if (issues.length > 0) {
        this.addVulnerability({
          type: 'CONFIGURATION_ISSUES',
          severity: 'LOW',
          title: 'Configuration Issues',
          description: 'Potential configuration security issues',
          count: issues.length,
          details: issues,
          recommendation: 'Review configuration files for sensitive data'
        });
      } else {
        console.log('✅ No configuration issues found');
      }
      
    } catch (error) {
      console.warn('⚠️ Configuration scan failed:', error.message);
    }
  }

  /**
   * Scan for file permission issues
   */
  async scanForFilePermissions() {
    console.log('📁 Scanning for file permission issues...');
    
    try {
      const sensitiveFiles = [
        '.env',
        '.vault',
        'package-lock.json',
        'yarn.lock'
      ];
      
      const issues = [];
      
      for (const file of sensitiveFiles) {
        const filePath = path.join(this.options.directory, file);
        
        try {
          const stats = await fs.stat(filePath);
          const mode = stats.mode.toString(8);
          
          // Check if file is world-readable
          if (mode.endsWith('666') || mode.endsWith('777')) {
            issues.push({
              file,
              mode,
              issue: 'File has overly permissive permissions'
            });
          }
        } catch (error) {
          // File doesn't exist
        }
      }
      
      if (issues.length > 0) {
        this.addVulnerability({
          type: 'FILE_PERMISSIONS',
          severity: 'LOW',
          title: 'File Permission Issues',
          description: 'Files with overly permissive permissions',
          count: issues.length,
          details: issues,
          recommendation: 'Set appropriate file permissions (600 for sensitive files)'
        });
      } else {
        console.log('✅ No file permission issues found');
      }
      
    } catch (error) {
      console.warn('⚠️ File permission scan failed:', error.message);
    }
  }

  /**
   * Add vulnerability to scan results
   */
  addVulnerability(vulnerability) {
    this.scanResults.vulnerabilities.push(vulnerability);
    this.scanResults.summary.total++;
    
    switch (vulnerability.severity) {
      case 'HIGH':
        this.scanResults.summary.high++;
        break;
      case 'MEDIUM':
        this.scanResults.summary.medium++;
        break;
      case 'LOW':
        this.scanResults.summary.low++;
        break;
      case 'INFO':
        this.scanResults.summary.info++;
        break;
    }
  }

  /**
   * Generate security recommendations
   */
  generateRecommendations() {
    this.scanResults.recommendations = [
      'Use the VibeCoded Security Framework for comprehensive protection',
      'Implement environment variables for all sensitive data',
      'Use parameterized queries for database operations',
      'Validate and sanitize all user inputs',
      'Implement proper authentication and authorization',
      'Use HTTPS in production',
      'Regularly update dependencies',
      'Implement rate limiting',
      'Use secure session management',
      'Enable security headers',
      'Conduct regular security audits',
      'Use SAST/DAST tools for continuous security testing'
    ];
  }

  /**
   * Calculate security score
   */
  calculateSecurityScore() {
    let score = 100;
    
    for (const vuln of this.scanResults.vulnerabilities) {
      switch (vuln.severity) {
        case 'HIGH':
          score -= 20;
          break;
        case 'MEDIUM':
          score -= 10;
          break;
        case 'LOW':
          score -= 5;
          break;
        case 'INFO':
          score -= 1;
          break;
      }
    }
    
    this.scanResults.score = Math.max(0, score);
  }

  /**
   * Generate security report
   */
  async generateReport() {
    try {
      await fs.writeFile(this.options.output, JSON.stringify(this.scanResults, null, 2));
      console.log(`📄 Security report saved to: ${this.options.output}`);
    } catch (error) {
      console.warn('⚠️ Failed to save security report:', error.message);
    }
  }

  /**
   * Display scan results
   */
  displayResults() {
    console.log('\n📊 Security Scan Results');
    console.log('========================');
    console.log(`Security Score: ${this.scanResults.score}/100`);
    console.log(`Total Issues: ${this.scanResults.summary.total}`);
    console.log(`High: ${this.scanResults.summary.high} | Medium: ${this.scanResults.summary.medium} | Low: ${this.scanResults.summary.low} | Info: ${this.scanResults.summary.info}`);
    
    if (this.scanResults.vulnerabilities.length > 0) {
      console.log('\n🚨 Vulnerabilities Found:');
      for (const vuln of this.scanResults.vulnerabilities) {
        console.log(`\n${vuln.severity}: ${vuln.title}`);
        console.log(`   ${vuln.description}`);
        console.log(`   Recommendation: ${vuln.recommendation}`);
      }
    } else {
      console.log('\n✅ No vulnerabilities found!');
    }
    
    console.log('\n💡 Recommendations:');
    for (const rec of this.scanResults.recommendations.slice(0, 5)) {
      console.log(`   • ${rec}`);
    }
  }

  /**
   * Get all files in directory
   */
  async getAllFiles(dir, extensions = []) {
    const files = [];
    
    try {
      const items = await fs.readdir(dir, { withFileTypes: true });
      
      for (const item of items) {
        const fullPath = path.join(dir, item.name);
        
        if (item.isDirectory() && !item.name.startsWith('.') && item.name !== 'node_modules') {
          files.push(...await this.getAllFiles(fullPath, extensions));
        } else if (item.isFile()) {
          if (extensions.length === 0 || extensions.some(ext => fullPath.endsWith(ext))) {
            files.push(fullPath);
          }
        }
      }
    } catch (error) {
      // Skip directories that can't be read
    }
    
    return files;
  }

  /**
   * Get line numbers for pattern matches
   */
  getLineNumbers(content, pattern) {
    const lines = content.split('\n');
    const lineNumbers = [];
    
    for (let i = 0; i < lines.length; i++) {
      if (pattern.test(lines[i])) {
        lineNumbers.push(i + 1);
      }
    }
    
    return lineNumbers;
  }
}

// CLI interface
if (require.main === module) {
  const args = process.argv.slice(2);
  const options = {};
  
  for (let i = 0; i < args.length; i++) {
    switch (args[i]) {
      case '--directory':
      case '-d':
        options.directory = args[++i];
        break;
      case '--output':
      case '-o':
        options.output = args[++i];
        break;
      case '--verbose':
      case '-v':
        options.verbose = true;
        break;
      case '--fix':
      case '-f':
        options.fix = true;
        break;
      case '--help':
      case '-h':
        console.log(`
VibeCoded Security Scanner

Usage: node scan.js [options]

Options:
  -d, --directory <path>  Directory to scan (default: .)
  -o, --output <file>     Output file for report (default: security-report.json)
  -v, --verbose          Verbose output
  -f, --fix              Attempt to fix issues automatically
  -h, --help             Show this help message

Examples:
  node scan.js
  node scan.js -d ./src -o report.json
  node scan.js --verbose
        `);
        process.exit(0);
    }
  }
  
  const scanner = new SecurityScanner(options);
  scanner.scan().catch(error => {
    console.error('❌ Scan failed:', error.message);
    process.exit(1);
  });
}

module.exports = SecurityScanner;
