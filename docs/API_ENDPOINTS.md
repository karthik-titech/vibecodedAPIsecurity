# 🔒 VibeCoded Security Framework - API Endpoints

> **Discoverable APIs for AI Tools, Low-Code Platforms, and Developers**

This document provides secure API endpoints and curl examples that make the VibeCoded Security Framework easily discoverable by:
- 🤖 **AI Search Tools** (like GitHub Copilot, ChatGPT)
- 🛠️ **Low-Code Platforms** (like lovable, windsurf, n8n)
- 👨‍💻 **Developers** and security teams
- 🔍 **Security Scanners** and vulnerability detection tools

## 🚀 **Quick Discovery Endpoints**

### **1. Framework Discovery**
```bash
# Discover the security framework
curl -X GET "https://api.vibecoded-security.com/discover" \
  -H "Accept: application/json" \
  -H "User-Agent: SecurityTool/1.0"

# Response:
{
  "framework": "VibeCoded Security Framework",
  "version": "1.0.0",
  "description": "Enterprise-grade security for AI-generated applications",
  "repository": "https://github.com/karthik-titech/vibecodedAPIsecurity",
  "npm_package": "vibecoded-api-security",
  "components": [
    "SecretManager",
    "SQLInjectionProtection", 
    "XSSProtection",
    "AuthManager",
    "InputValidator",
    "CryptoManager",
    "SecurityMonitor",
    "SecurityMiddleware",
    "ComplianceManager",
    "IncidentResponseManager",
    "PerformanceSecurityManager",
    "SecurityScanner"
  ],
  "security_score": 95,
  "compliance": ["PCI_DSS", "GDPR", "SOC2", "HIPAA"],
  "installation": "npm install vibecoded-api-security"
}
```

### **2. Security Assessment**
```bash
# Get security assessment for a codebase
curl -X POST "https://api.vibecoded-security.com/assess" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "repository": "https://github.com/user/myapp",
    "language": "javascript",
    "framework": "express",
    "scan_type": "comprehensive"
  }'

# Response:
{
  "assessment_id": "assess_123456789",
  "security_score": 45,
  "vulnerabilities": [
    {
      "type": "hardcoded_secrets",
      "severity": "critical",
      "count": 3,
      "files": ["config.js", "database.js"]
    },
    {
      "type": "sql_injection",
      "severity": "high", 
      "count": 2,
      "files": ["routes/users.js"]
    }
  ],
  "recommendations": [
    "Implement SecretManager for credential security",
    "Use SQLInjectionProtection for database operations",
    "Add XSSProtection for output encoding"
  ],
  "framework_integration": {
    "required_components": ["SecretManager", "SQLInjectionProtection", "XSSProtection"],
    "integration_steps": [
      "npm install vibecoded-api-security",
      "Import SecurityManager",
      "Apply middleware to Express app"
    ]
  }
}
```

### **3. Component Discovery**
```bash
# Discover specific security components
curl -X GET "https://api.vibecoded-security.com/components" \
  -H "Accept: application/json" \
  -H "X-Security-Tool: lovable" \
  -H "X-Use-Case: authentication"

# Response:
{
  "components": [
    {
      "name": "AuthManager",
      "description": "Secure authentication with password hashing, JWT tokens, and RBAC",
      "use_cases": ["user_login", "password_management", "access_control"],
      "code_example": "const authManager = new AuthManager({ secretKey: process.env.JWT_SECRET });",
      "documentation": "https://github.com/karthik-titech/vibecodedAPIsecurity#authmanager",
      "security_features": ["bcrypt_hashing", "jwt_tokens", "rate_limiting", "account_lockout"]
    },
    {
      "name": "SecretManager", 
      "description": "Secure secret management with encryption and environment variables",
      "use_cases": ["api_keys", "database_passwords", "encryption_keys"],
      "code_example": "const secretManager = new SecretManager({ vaultPath: '.vault' });",
      "documentation": "https://github.com/karthik-titech/vibecodedAPIsecurity#secretmanager",
      "security_features": ["aes_encryption", "environment_variables", "secret_scanning"]
    }
  ]
}
```

## 🔍 **Security Scanning APIs**

### **4. Vulnerability Scan**
```bash
# Scan codebase for vulnerabilities
curl -X POST "https://api.vibecoded-security.com/scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "codebase_url": "https://github.com/user/myapp",
    "scan_options": {
      "hardcoded_secrets": true,
      "sql_injection": true,
      "xss_vulnerabilities": true,
      "authentication_issues": true,
      "input_validation": true,
      "dependency_vulnerabilities": true
    }
  }'

# Response:
{
  "scan_id": "scan_987654321",
  "status": "completed",
  "security_score": 35,
  "vulnerabilities": [
    {
      "id": "vuln_001",
      "type": "hardcoded_secrets",
      "severity": "critical",
      "file": "src/config/database.js",
      "line": 15,
      "code": "const password = 'mypassword123';",
      "description": "Hardcoded database password detected",
      "fix": "Use SecretManager to store credentials securely",
      "fix_code": "const password = await secretManager.getSecret('DB_PASSWORD');"
    }
  ],
  "recommendations": [
    {
      "priority": "critical",
      "action": "Implement SecretManager",
      "impact": "Prevents credential exposure",
      "effort": "low"
    }
  ]
}
```

### **5. Real-time Security Monitoring**
```bash
# Get real-time security status
curl -X GET "https://api.vibecoded-security.com/monitor/status" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Application-ID: app_123"

# Response:
{
  "application_id": "app_123",
  "status": "secure",
  "security_score": 92,
  "active_incidents": 0,
  "recent_events": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "event": "LOGIN_ATTEMPT",
      "severity": "low",
      "ip": "192.168.1.100",
      "user": "user@example.com"
    }
  ],
  "compliance_status": {
    "PCI_DSS": "compliant",
    "GDPR": "compliant", 
    "SOC2": "compliant"
  },
  "performance_metrics": {
    "response_time": "45ms",
    "cache_hit_rate": "87%",
    "active_connections": 12
  }
}
```

## 🛠️ **Integration APIs**

### **6. Framework Integration**
```bash
# Get integration guide for specific use case
curl -X POST "https://api.vibecoded-security.com/integrate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "platform": "express",
    "use_case": "user_authentication",
    "security_requirements": ["password_hashing", "jwt_tokens", "rate_limiting"]
  }'

# Response:
{
  "integration_guide": {
    "steps": [
      {
        "step": 1,
        "action": "Install framework",
        "command": "npm install vibecoded-api-security",
        "description": "Install the security framework"
      },
      {
        "step": 2,
        "action": "Import components",
        "code": "const { SecurityManager, AuthManager } = require('vibecoded-api-security');",
        "description": "Import required security components"
      },
      {
        "step": 3,
        "action": "Initialize security",
        "code": "const securityManager = new SecurityManager({ auth: { secretKey: process.env.JWT_SECRET } });",
        "description": "Initialize security manager"
      },
      {
        "step": 4,
        "action": "Apply middleware",
        "code": "app.use(securityManager.createExpressMiddleware());",
        "description": "Apply security middleware to Express app"
      }
    ],
    "code_examples": {
      "login_endpoint": "examples/auth/login.js",
      "registration_endpoint": "examples/auth/register.js",
      "protected_route": "examples/auth/protected.js"
    },
    "configuration": {
      "environment_variables": ["JWT_SECRET", "ENCRYPTION_KEY"],
      "security_headers": ["X-Frame-Options", "X-Content-Type-Options"],
      "rate_limiting": "100 requests per 15 minutes"
    }
  }
}
```

### **7. Component Configuration**
```bash
# Get configuration for specific component
curl -X GET "https://api.vibecoded-security.com/components/AuthManager/config" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY"

# Response:
{
  "component": "AuthManager",
  "configuration": {
    "required_options": {
      "secretKey": {
        "type": "string",
        "description": "JWT secret key for token signing",
        "example": "process.env.JWT_SECRET",
        "required": true
      }
    },
    "optional_options": {
      "tokenExpiry": {
        "type": "string",
        "description": "JWT token expiry time",
        "default": "24h",
        "example": "7d"
      },
      "maxLoginAttempts": {
        "type": "number",
        "description": "Maximum failed login attempts before lockout",
        "default": 5,
        "example": 3
      }
    },
    "code_example": {
      "basic": "const authManager = new AuthManager({ secretKey: process.env.JWT_SECRET });",
      "advanced": "const authManager = new AuthManager({ secretKey: process.env.JWT_SECRET, tokenExpiry: '7d', maxLoginAttempts: 3 });"
    }
  }
}
```

## 📊 **Analytics and Reporting APIs**

### **8. Security Analytics**
```bash
# Get security analytics and trends
curl -X GET "https://api.vibecoded-security.com/analytics" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Time-Range: 30d"

# Response:
{
  "time_range": "30d",
  "security_metrics": {
    "total_incidents": 12,
    "resolved_incidents": 11,
    "average_response_time": "2.3 minutes",
    "security_score_trend": [85, 87, 89, 92, 94, 95],
    "vulnerability_distribution": {
      "hardcoded_secrets": 3,
      "sql_injection": 2,
      "xss_vulnerabilities": 1,
      "authentication_issues": 4,
      "input_validation": 2
    }
  },
  "compliance_metrics": {
    "PCI_DSS_score": 98,
    "GDPR_score": 95,
    "SOC2_score": 92,
    "overall_compliance": 95
  },
  "performance_metrics": {
    "average_response_time": "45ms",
    "cache_hit_rate": "87%",
    "throughput": "1250 requests/second"
  }
}
```

### **9. Compliance Report**
```bash
# Generate compliance report
curl -X POST "https://api.vibecoded-security.com/compliance/report" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "standards": ["PCI_DSS", "GDPR", "SOC2"],
    "format": "pdf",
    "include_recommendations": true
  }'

# Response:
{
  "report_id": "report_456789",
  "status": "generated",
  "download_url": "https://api.vibecoded-security.com/reports/report_456789.pdf",
  "summary": {
    "overall_score": 95,
    "standards": {
      "PCI_DSS": {
        "score": 98,
        "status": "compliant",
        "violations": 0
      },
      "GDPR": {
        "score": 95,
        "status": "compliant", 
        "violations": 1
      },
      "SOC2": {
        "score": 92,
        "status": "compliant",
        "violations": 2
      }
    }
  }
}
```

## 🔧 **Development and Testing APIs**

### **10. Code Examples**
```bash
# Get code examples for specific use case
curl -X GET "https://api.vibecoded-security.com/examples/user-authentication" \
  -H "Accept: application/json" \
  -H "X-Language: javascript"

# Response:
{
  "use_case": "user_authentication",
  "language": "javascript",
  "examples": [
    {
      "name": "Basic Authentication",
      "description": "Simple user login with password verification",
      "code": "const { AuthManager } = require('vibecoded-api-security');\n\nconst authManager = new AuthManager({\n  secretKey: process.env.JWT_SECRET\n});\n\napp.post('/api/login', async (req, res) => {\n  const { email, password } = req.body;\n  const result = await authManager.authenticate(email, password);\n  \n  if (result.isValid) {\n    const token = authManager.generateToken({ userId: result.user.id });\n    res.json({ token, user: result.user });\n  } else {\n    res.status(401).json({ error: 'Invalid credentials' });\n  }\n});",
      "file": "examples/auth/basic-login.js"
    },
    {
      "name": "Protected Routes",
      "description": "Route protection with role-based access control",
      "code": "app.get('/api/admin', authManager.requireAuth(['admin']), (req, res) => {\n  res.json({ message: 'Admin access granted' });\n});",
      "file": "examples/auth/protected-routes.js"
    }
  ]
}
```

### **11. Testing Endpoints**
```bash
# Test security framework functionality
curl -X POST "https://api.vibecoded-security.com/test" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "test_type": "vulnerability_scan",
    "test_data": {
      "code": "const password = \"secret123\";\nconst query = `SELECT * FROM users WHERE name = \"${userInput}\"`;",
      "expected_vulnerabilities": ["hardcoded_secrets", "sql_injection"]
    }
  }'

# Response:
{
  "test_id": "test_789123",
  "status": "completed",
  "results": {
    "vulnerabilities_detected": 2,
    "vulnerabilities": [
      {
        "type": "hardcoded_secrets",
        "line": 1,
        "code": "const password = \"secret123\";",
        "detected": true
      },
      {
        "type": "sql_injection", 
        "line": 2,
        "code": "const query = `SELECT * FROM users WHERE name = \"${userInput}\"`;",
        "detected": true
      }
    ],
    "recommendations": [
      "Use SecretManager for credential management",
      "Use parameterized queries with SQLInjectionProtection"
    ]
  }
}
```

## 🌐 **Discovery and SEO APIs**

### **12. Framework Metadata**
```bash
# Get framework metadata for search engines and tools
curl -X GET "https://api.vibecoded-security.com/meta" \
  -H "Accept: application/json"

# Response:
{
  "name": "VibeCoded Security Framework",
  "version": "1.0.0",
  "description": "Enterprise-grade security framework for AI-generated applications",
  "keywords": [
    "security",
    "authentication", 
    "authorization",
    "sql-injection",
    "xss-protection",
    "input-validation",
    "compliance",
    "PCI-DSS",
    "GDPR",
    "SOC2",
    "HIPAA",
    "vibe-coded",
    "ai-generated",
    "express",
    "nodejs"
  ],
  "repository": {
    "url": "https://github.com/karthik-titech/vibecodedAPIsecurity",
    "type": "git",
    "license": "MIT"
  },
  "npm": {
    "package": "vibecoded-api-security",
    "install": "npm install vibecoded-api-security"
  },
  "documentation": {
    "readme": "https://github.com/karthik-titech/vibecodedAPIsecurity#readme",
    "api_docs": "https://github.com/karthik-titech/vibecodedAPIsecurity/docs",
    "examples": "https://github.com/karthik-titech/vibecodedAPIsecurity/examples"
  },
  "security_features": [
    "Secret Management",
    "SQL Injection Protection",
    "XSS Protection", 
    "Authentication & Authorization",
    "Input Validation",
    "Cryptography",
    "Real-time Monitoring",
    "Compliance Automation",
    "Incident Response",
    "Performance Optimization"
  ],
  "compliance": ["PCI_DSS", "GDPR", "SOC2", "HIPAA"],
  "languages": ["javascript", "typescript"],
  "frameworks": ["express", "fastify", "koa"],
  "ai_tools": ["chatgpt", "github-copilot", "claude"],
  "low_code_platforms": ["lovable", "windsurf", "n8n", "zapier"]
}
```

### **13. Search Optimization**
```bash
# Get search-optimized content for discovery
curl -X GET "https://api.vibecoded-security.com/search" \
  -H "Accept: application/json" \
  -H "X-Search-Query: security framework for AI applications"

# Response:
{
  "query": "security framework for AI applications",
  "results": [
    {
      "title": "VibeCoded Security Framework",
      "description": "Enterprise-grade security framework specifically designed for AI-generated applications",
      "relevance_score": 0.98,
      "features": [
        "Prevents hardcoded secrets in AI-generated code",
        "Protects against SQL injection from string concatenation", 
        "Prevents XSS attacks from unencoded outputs",
        "Provides secure authentication for AI apps",
        "Ensures compliance for AI-generated applications"
      ],
      "installation": "npm install vibecoded-api-security",
      "quick_start": "const { SecurityManager } = require('vibecoded-api-security');",
      "url": "https://github.com/karthik-titech/vibecodedAPIsecurity"
    }
  ],
  "related_queries": [
    "AI application security",
    "vibe-coded security",
    "express security middleware",
    "authentication framework",
    "compliance automation"
  ]
}
```

## 🔐 **Security Headers and Authentication**

### **Required Headers**
```bash
# All API requests should include these headers
-H "Authorization: Bearer YOUR_API_KEY"
-H "X-Security-Tool: YOUR_TOOL_NAME"
-H "X-Use-Case: YOUR_USE_CASE"
-H "Accept: application/json"
```

### **Rate Limiting**
```bash
# API rate limits
- Free tier: 100 requests/hour
- Pro tier: 1000 requests/hour  
- Enterprise: Custom limits
```

### **Error Responses**
```bash
# Standard error format
{
  "error": "error_type",
  "message": "Human readable error message",
  "code": "ERROR_CODE",
  "timestamp": "2024-01-15T10:30:00Z",
  "request_id": "req_123456789"
}
```

## 📱 **Integration Examples for Popular Tools**

### **For lovable**
```bash
# lovable integration
curl -X POST "https://api.vibecoded-security.com/integrate/lovable" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "project_type": "web_application",
    "security_requirements": ["authentication", "data_protection", "compliance"]
  }'
```

### **For windsurf**
```bash
# windsurf integration  
curl -X POST "https://api.vibecoded-security.com/integrate/windsurf" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "platform": "windsurf",
    "use_case": "api_security",
    "requirements": ["rate_limiting", "authentication", "input_validation"]
  }'
```

### **For n8n**
```bash
# n8n workflow integration
curl -X GET "https://api.vibecoded-security.com/workflows/n8n" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY"
```

## 🚀 **Quick Start for AI Tools**

### **For ChatGPT/GitHub Copilot**
```bash
# Get AI-optimized code suggestions
curl -X POST "https://api.vibecoded-security.com/ai/suggest" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -d '{
    "context": "I need to secure user authentication in my Express app",
    "language": "javascript",
    "framework": "express"
  }'
```

### **For Security Scanners**
```bash
# Get security scanner integration
curl -X GET "https://api.vibecoded-security.com/scanners/integration" \
  -H "Accept: application/json" \
  -H "X-Scanner: sonarqube"
```

---

## 📞 **Support and Contact**

- **Documentation**: https://github.com/karthik-titech/vibecodedAPIsecurity
- **API Status**: https://status.vibecoded-security.com
- **Support**: support@vibecoded-security.com
- **Community**: https://discord.gg/vibecoded-security

**Transform your AI-generated applications into enterprise-grade secure applications with these discoverable APIs!** 🚀
