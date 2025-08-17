# 🔒 VibeCoded Security Framework - Ready-to-Use CURL Examples

> **Copy-paste curl commands for AI tools, low-code platforms, and developers**

This document provides ready-to-use curl commands that make the VibeCoded Security Framework easily discoverable and testable by:
- 🤖 **AI Search Tools** (ChatGPT, GitHub Copilot, Claude)
- 🛠️ **Low-Code Platforms** (lovable, windsurf, n8n, Zapier)
- 👨‍💻 **Developers** and security teams
- 🔍 **Security Scanners** and vulnerability detection tools

## 🚀 **Quick Discovery Commands**

### **1. Framework Discovery**
```bash
# Discover the security framework (no auth required)
curl -X GET "https://api.vibecoded-security.com/discover" \
  -H "Accept: application/json" \
  -H "User-Agent: SecurityTool/1.0" \
  -H "X-Security-Tool: lovable" \
  -H "X-Use-Case: framework_discovery"
```

### **2. Get Framework Metadata**
```bash
# Get comprehensive framework metadata for search engines
curl -X GET "https://api.vibecoded-security.com/meta" \
  -H "Accept: application/json" \
  -H "X-Search-Engine: google" \
  -H "X-Keywords: security,authentication,compliance"
```

### **3. Search for Security Solutions**
```bash
# Search for security framework for AI applications
curl -X GET "https://api.vibecoded-security.com/search" \
  -H "Accept: application/json" \
  -H "X-Search-Query: security framework for AI applications" \
  -H "X-Platform: express" \
  -H "X-Language: javascript"
```

## 🔍 **Security Assessment Commands**

### **4. Assess Codebase Security**
```bash
# Assess security of a GitHub repository
curl -X POST "https://api.vibecoded-security.com/assess" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Security-Tool: sonarqube" \
  -d '{
    "repository": "https://github.com/user/myapp",
    "language": "javascript",
    "framework": "express",
    "scan_type": "comprehensive",
    "include_recommendations": true
  }'
```

### **5. Scan for Vulnerabilities**
```bash
# Comprehensive vulnerability scan
curl -X POST "https://api.vibecoded-security.com/scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Scanner: automated" \
  -d '{
    "codebase_url": "https://github.com/user/myapp",
    "scan_options": {
      "hardcoded_secrets": true,
      "sql_injection": true,
      "xss_vulnerabilities": true,
      "authentication_issues": true,
      "input_validation": true,
      "dependency_vulnerabilities": true,
      "compliance_check": true
    },
    "output_format": "json"
  }'
```

### **6. Get Real-time Security Status**
```bash
# Get current security status of an application
curl -X GET "https://api.vibecoded-security.com/monitor/status" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Application-ID: app_123" \
  -H "X-Monitoring-Type: realtime"
```

## 🛠️ **Integration Commands**

### **7. Get Integration Guide for Express**
```bash
# Get step-by-step integration guide for Express.js
curl -X POST "https://api.vibecoded-security.com/integrate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Platform: express" \
  -d '{
    "platform": "express",
    "use_case": "user_authentication",
    "security_requirements": [
      "password_hashing",
      "jwt_tokens", 
      "rate_limiting",
      "input_validation",
      "sql_injection_protection"
    ],
    "complexity": "beginner"
  }'
```

### **8. Get Component Configuration**
```bash
# Get configuration for AuthManager component
curl -X GET "https://api.vibecoded-security.com/components/AuthManager/config" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Component: AuthManager" \
  -H "X-Use-Case: authentication"
```

### **9. Discover Components by Use Case**
```bash
# Find components for authentication use case
curl -X GET "https://api.vibecoded-security.com/components" \
  -H "Accept: application/json" \
  -H "X-Security-Tool: lovable" \
  -H "X-Use-Case: authentication" \
  -H "X-Platform: express"
```

## 📊 **Analytics and Reporting Commands**

### **10. Get Security Analytics**
```bash
# Get 30-day security analytics
curl -X GET "https://api.vibecoded-security.com/analytics" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Time-Range: 30d" \
  -H "X-Metrics: security,compliance,performance"
```

### **11. Generate Compliance Report**
```bash
# Generate PCI DSS and GDPR compliance report
curl -X POST "https://api.vibecoded-security.com/compliance/report" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Report-Type: compliance" \
  -d '{
    "standards": ["PCI_DSS", "GDPR", "SOC2"],
    "format": "pdf",
    "include_recommendations": true,
    "include_remediation_steps": true
  }'
```

### **12. Get Performance Metrics**
```bash
# Get performance metrics for security operations
curl -X GET "https://api.vibecoded-security.com/performance/metrics" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Metrics: response_time,cache_hit_rate,throughput"
```

## 🔧 **Development and Testing Commands**

### **13. Get Code Examples**
```bash
# Get authentication code examples
curl -X GET "https://api.vibecoded-security.com/examples/user-authentication" \
  -H "Accept: application/json" \
  -H "X-Language: javascript" \
  -H "X-Framework: express" \
  -H "X-Complexity: beginner"
```

### **14. Test Security Framework**
```bash
# Test vulnerability detection functionality
curl -X POST "https://api.vibecoded-security.com/test" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Test-Type: vulnerability_scan" \
  -d '{
    "test_type": "vulnerability_scan",
    "test_data": {
      "code": "const password = \"secret123\";\nconst query = `SELECT * FROM users WHERE name = \"${userInput}\"`;",
      "expected_vulnerabilities": ["hardcoded_secrets", "sql_injection"],
      "language": "javascript"
    }
  }'
```

### **15. Validate Security Configuration**
```bash
# Validate security configuration
curl -X POST "https://api.vibecoded-security.com/validate/config" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Validation-Type: configuration" \
  -d '{
    "config": {
      "auth": {
        "secretKey": "process.env.JWT_SECRET",
        "tokenExpiry": "24h"
      },
      "secrets": {
        "vaultPath": ".vault"
      }
    },
    "platform": "express"
  }'
```

## 🌐 **SEO and Discovery Commands**

### **16. Get SEO Metadata**
```bash
# Get SEO-optimized metadata for search engines
curl -X GET "https://api.vibecoded-security.com/seo/metadata" \
  -H "Accept: application/json" \
  -H "X-Search-Engine: google" \
  -H "X-Keywords: security,authentication,compliance,ai"
```

### **17. Get Sitemap**
```bash
# Get sitemap for search engine indexing
curl -X GET "https://api.vibecoded-security.com/sitemap" \
  -H "Accept: application/xml" \
  -H "X-Sitemap-Type: security_framework"
```

### **18. Get Open Graph Data**
```bash
# Get Open Graph data for social media sharing
curl -X GET "https://api.vibecoded-security.com/og/data" \
  -H "Accept: application/json" \
  -H "X-Platform: github" \
  -H "X-Content-Type: security_framework"
```

## 📱 **Platform-Specific Integration Commands**

### **19. lovable Integration**
```bash
# Get lovable-specific integration guide
curl -X POST "https://api.vibecoded-security.com/integrate/lovable" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Platform: lovable" \
  -d '{
    "project_type": "web_application",
    "security_requirements": [
      "authentication",
      "data_protection", 
      "compliance",
      "input_validation"
    ],
    "complexity": "beginner"
  }'
```

### **20. windsurf Integration**
```bash
# Get windsurf-specific integration guide
curl -X POST "https://api.vibecoded-security.com/integrate/windsurf" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Platform: windsurf" \
  -d '{
    "platform": "windsurf",
    "use_case": "api_security",
    "requirements": [
      "rate_limiting",
      "authentication",
      "input_validation",
      "sql_injection_protection"
    ]
  }'
```

### **21. n8n Workflow Integration**
```bash
# Get n8n workflow templates
curl -X GET "https://api.vibecoded-security.com/workflows/n8n" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Workflow-Type: security_monitoring"
```

### **22. Zapier Integration**
```bash
# Get Zapier integration templates
curl -X GET "https://api.vibecoded-security.com/integrate/zapier" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Integration-Type: webhook"
```

## 🤖 **AI Tool Integration Commands**

### **23. ChatGPT Integration**
```bash
# Get AI-optimized code suggestions for ChatGPT
curl -X POST "https://api.vibecoded-security.com/ai/suggest" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-AI-Tool: chatgpt" \
  -d '{
    "context": "I need to secure user authentication in my Express app",
    "language": "javascript",
    "framework": "express",
    "complexity": "beginner",
    "include_examples": true
  }'
```

### **24. GitHub Copilot Integration**
```bash
# Get GitHub Copilot code suggestions
curl -X POST "https://api.vibecoded-security.com/ai/copilot" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-AI-Tool: github-copilot" \
  -d '{
    "context": "Secure user login endpoint",
    "language": "javascript",
    "framework": "express",
    "include_comments": true,
    "include_tests": true
  }'
```

### **25. Claude Integration**
```bash
# Get Claude-optimized security recommendations
curl -X POST "https://api.vibecoded-security.com/ai/claude" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-AI-Tool: claude" \
  -d '{
    "context": "Security audit for Express.js application",
    "focus_areas": [
      "authentication",
      "input_validation",
      "sql_injection",
      "xss_protection"
    ],
    "include_remediation": true
  }'
```

## 🔍 **Security Scanner Integration Commands**

### **26. SonarQube Integration**
```bash
# Get SonarQube security rules
curl -X GET "https://api.vibecoded-security.com/scanners/sonarqube" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Scanner: sonarqube" \
  -H "X-Language: javascript"
```

### **27. Snyk Integration**
```bash
# Get Snyk security policies
curl -X GET "https://api.vibecoded-security.com/scanners/snyk" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Scanner: snyk" \
  -H "X-Scan-Type: dependency"
```

### **28. OWASP ZAP Integration**
```bash
# Get OWASP ZAP security rules
curl -X GET "https://api.vibecoded-security.com/scanners/owasp-zap" \
  -H "Accept: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Scanner: owasp-zap" \
  -H "X-Scan-Type: web_application"
```

## 📊 **Monitoring and Alerting Commands**

### **29. Set Up Security Alerts**
```bash
# Configure security alerting
curl -X POST "https://api.vibecoded-security.com/alerts/configure" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Alert-Type: security" \
  -d '{
    "alerts": {
      "failed_logins": {
        "threshold": 5,
        "channels": ["email", "slack"]
      },
      "sql_injection_attempts": {
        "threshold": 1,
        "channels": ["email", "slack", "sms"]
      },
      "xss_attempts": {
        "threshold": 1,
        "channels": ["email", "slack"]
      }
    },
    "notification_channels": {
      "email": "security@myapp.com",
      "slack": "https://hooks.slack.com/security-channel",
      "sms": "+1234567890"
    }
  }'
```

### **30. Get Incident History**
```bash
# Get recent security incidents
curl -X GET "https://api.vibecoded-security.com/incidents/history" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Time-Range: 7d" \
  -H "X-Severity: high,critical"
```

## 🔐 **Authentication and Authorization Commands**

### **31. Get API Key**
```bash
# Request API key for testing
curl -X POST "https://api.vibecoded-security.com/auth/request-key" \
  -H "Content-Type: application/json" \
  -H "X-Use-Case: testing" \
  -H "X-Platform: development" \
  -d '{
    "email": "developer@myapp.com",
    "use_case": "security_framework_testing",
    "platform": "express",
    "expected_usage": "development"
  }'
```

### **32. Validate API Key**
```bash
# Validate API key
curl -X GET "https://api.vibecoded-security.com/auth/validate" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Validation-Type: api_key"
```

## 📈 **Performance and Health Commands**

### **33. Health Check**
```bash
# Check API health status
curl -X GET "https://api.vibecoded-security.com/health" \
  -H "Accept: application/json" \
  -H "X-Health-Check: comprehensive"
```

### **34. Performance Metrics**
```bash
# Get API performance metrics
curl -X GET "https://api.vibecoded-security.com/performance" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Metrics: response_time,throughput,error_rate"
```

## 🚀 **Quick Start Commands**

### **35. One-Click Security Setup**
```bash
# Get complete security setup for Express app
curl -X POST "https://api.vibecoded-security.com/setup/express" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Setup-Type: complete" \
  -d '{
    "app_type": "express",
    "security_level": "enterprise",
    "compliance": ["PCI_DSS", "GDPR"],
    "include_monitoring": true,
    "include_documentation": true
  }'
```

### **36. Security Framework Installation**
```bash
# Get installation commands
curl -X GET "https://api.vibecoded-security.com/install" \
  -H "Accept: application/json" \
  -H "X-Platform: express" \
  -H "X-Package-Manager: npm"
```

## 📞 **Support and Documentation Commands**

### **37. Get Documentation**
```bash
# Get comprehensive documentation
curl -X GET "https://api.vibecoded-security.com/docs" \
  -H "Accept: application/json" \
  -H "X-Doc-Type: api_reference" \
  -H "X-Format: markdown"
```

### **38. Get Support**
```bash
# Get support information
curl -X GET "https://api.vibecoded-security.com/support" \
  -H "Accept: application/json" \
  -H "X-Support-Type: technical" \
  -H "X-Platform: express"
```

## 🔧 **Environment Setup Commands**

### **39. Set Environment Variables**
```bash
# Get required environment variables
curl -X GET "https://api.vibecoded-security.com/env/setup" \
  -H "Accept: application/json" \
  -H "X-Platform: express" \
  -H "X-Security-Level: enterprise"
```

### **40. Validate Environment**
```bash
# Validate environment configuration
curl -X POST "https://api.vibecoded-security.com/env/validate" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "X-Validation-Type: environment" \
  -d '{
    "environment": {
      "NODE_ENV": "production",
      "JWT_SECRET": "set",
      "ENCRYPTION_KEY": "set",
      "DB_PASSWORD": "set"
    }
  }'
```

---

## 📋 **Usage Instructions**

### **For AI Tools**
1. Copy the relevant curl command
2. Replace `YOUR_API_KEY` with your actual API key
3. Modify the request body as needed
4. Execute the command to get security recommendations

### **For Low-Code Platforms**
1. Use the platform-specific integration commands
2. Follow the returned integration guide
3. Implement the security framework
4. Monitor security metrics

### **For Developers**
1. Start with the discovery commands
2. Use assessment commands to evaluate your codebase
3. Follow integration guides for your platform
4. Set up monitoring and alerting

### **For Security Teams**
1. Use vulnerability scanning commands
2. Set up compliance monitoring
3. Configure incident response
4. Monitor security metrics

## 🔐 **Security Notes**

- All API keys should be kept secure
- Use HTTPS for all requests
- Implement proper rate limiting
- Monitor API usage for security
- Keep API keys rotated regularly

---

**Transform your AI-generated applications into enterprise-grade secure applications with these ready-to-use curl commands!** 🚀
