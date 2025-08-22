# 🔄 Workflow Orchestration Documentation

> **Comprehensive Key Expiration and Workflow Handle Rotation Workflows**

This document provides detailed information about the workflow orchestration system that manages key expiration and workflow handle rotation in the VibeCoded API Security Framework.

## 📋 Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Key Expiration Management](#key-expiration-management)
4. [Workflow Handle Rotation](#workflow-handle-rotation)
5. [Workflow Orchestration](#workflow-orchestration)
6. [Configuration](#configuration)
7. [API Reference](#api-reference)
8. [Examples](#examples)
9. [Best Practices](#best-practices)
10. [Troubleshooting](#troubleshooting)

## 🎯 Overview

The Workflow Orchestration System provides comprehensive management of:

- **Key Expiration**: Automatic rotation and expiration of security keys
- **Workflow Handle Rotation**: Management of workflow execution handles
- **Session Management**: Secure session lifecycle management
- **Circuit Breaker Pattern**: Fault tolerance and failure handling
- **Load Balancing**: Distribution of workflow execution
- **Monitoring & Alerting**: Real-time monitoring and notifications

### Key Features

- ✅ **Automatic Key Rotation**: Proactive key rotation before expiration
- ✅ **Workflow Handle Management**: Secure handle lifecycle management
- ✅ **Session Orchestration**: Coordinated session management
- ✅ **Circuit Breaker Protection**: Automatic failure detection and recovery
- ✅ **Load Balancing**: Intelligent workflow distribution
- ✅ **Real-time Monitoring**: Comprehensive metrics and alerting
- ✅ **Event-driven Architecture**: Reactive system with event notifications
- ✅ **Encrypted Storage**: Secure storage of keys and handles
- ✅ **Backup & Recovery**: Automatic backup of rotated components

## 🏗️ Architecture

### System Components

```
WorkflowOrchestrationManager (Main Controller)
├── KeyExpirationManager (Key Lifecycle Management)
│   ├── Key Registration & Storage
│   ├── Automatic Rotation
│   ├── Expiration Monitoring
│   └── Notification System
├── WorkflowHandleRotationManager (Handle Management)
│   ├── Handle Creation & Storage
│   ├── Session Management
│   ├── Execution Tracking
│   └── Rotation Coordination
└── Orchestration Engine
    ├── Workflow Registration
    ├── Execution Management
    ├── Circuit Breaker
    ├── Load Balancing
    └── Monitoring & Metrics
```

### Data Flow

1. **Workflow Registration**: Register workflows with key and handle management
2. **Key Generation**: Generate appropriate keys for workflow type
3. **Handle Creation**: Create execution handles with rotation policies
4. **Execution**: Execute workflows with automatic component rotation
5. **Monitoring**: Monitor execution, rotation, and health metrics
6. **Notification**: Send alerts for events and issues

## 🔑 Key Expiration Management

### Key Types

The system supports multiple key types with different expiration periods:

| Key Type | Expiration Period | Use Case |
|----------|------------------|----------|
| `jwt` | 30 days | JWT token signing |
| `encryption` | 90 days | Data encryption |
| `api` | 60 days | API authentication |
| `refresh` | 7 days | Token refresh |
| `session` | 24 hours | Session management |
| `webhook` | 180 days | Webhook authentication |
| `database` | 1 year | Database connections |
| `ssl` | 1 year | SSL certificates |
| `oauth` | 45 days | OAuth tokens |
| `backup` | 2 years | Backup encryption |

### Key Lifecycle

```
Key Creation → Active Period → Rotation Threshold → Automatic Rotation → Expiration
     ↓              ↓                ↓                    ↓              ↓
  Register      Monitor         Generate New         Replace Old      Mark Expired
  Encrypt       Validate        Backup Old           Update Timers    Notify
  Store         Track           Notify               Monitor          Cleanup
```

### Configuration

```javascript
const keyManager = new KeyExpirationManager({
  // Key expiration periods
  jwtExpiry: 30 * 24 * 60 * 60 * 1000, // 30 days
  encryptionExpiry: 90 * 24 * 60 * 60 * 1000, // 90 days
  apiExpiry: 60 * 24 * 60 * 60 * 1000, // 60 days
  
  // Rotation settings
  enableAutoRotation: true,
  rotationThreshold: 0.1, // 10% of expiry time
  gracePeriod: 24 * 60 * 60 * 1000, // 24 hours
  maxKeyVersions: 3,
  backupOldKeys: true,
  
  // Storage settings
  keyStorePath: '.keys',
  backupPath: '.keys/backup',
  encryptionKey: process.env.KEY_ENCRYPTION_KEY,
  
  // Notification settings
  enableNotifications: true,
  notifyBeforeExpiry: 7 * 24 * 60 * 60 * 1000, // 7 days
  notifyOnRotation: true,
  notifyOnExpiry: true,
  webhookUrl: process.env.KEY_NOTIFICATION_WEBHOOK,
  emailRecipients: ['admin@myapp.com']
});
```

## 🔧 Workflow Handle Rotation

### Handle Types

| Handle Type | Rotation Period | Max Concurrent | Timeout | Use Case |
|-------------|----------------|----------------|---------|----------|
| `session` | 30 minutes | 100 | 30 min | User sessions |
| `api` | 1 hour | 10 | 30 min | API endpoints |
| `webhook` | 24 hours | 5 | 5 min | Webhook processing |
| `oauth` | 7 days | 2 | 15 min | OAuth flows |
| `batch` | 12 hours | 3 | 60 min | Batch processing |
| `critical` | 15 minutes | 1 | 10 min | Critical operations |

### Handle Lifecycle

```
Handle Creation → Active Execution → Rotation Threshold → Automatic Rotation → Expiration
       ↓                ↓                    ↓                    ↓              ↓
    Register         Monitor             Generate New         Replace Old      Mark Expired
    Encrypt          Track               Backup Old           Update Timers    Notify
    Store            Validate            Notify               Monitor          Cleanup
```

### Session Management

The handle manager provides comprehensive session management:

- **Session Creation**: Automatic session creation for workflows
- **Session Tracking**: Monitor session activity and idle time
- **Session Expiry**: Automatic session cleanup
- **Session Recovery**: Handle session failures gracefully

### Configuration

```javascript
const handleManager = new WorkflowHandleRotationManager({
  // Handle rotation periods
  sessionRotation: 30 * 60 * 1000, // 30 minutes
  apiRotation: 60 * 60 * 1000, // 1 hour
  webhookRotation: 24 * 60 * 60 * 1000, // 24 hours
  
  // Rotation settings
  enableAutoRotation: true,
  rotationThreshold: 0.2, // 20% of rotation time
  gracePeriod: 5 * 60 * 1000, // 5 minutes
  maxHandleVersions: 5,
  
  // Session management
  maxConcurrentSessions: 100,
  sessionTimeout: 30 * 60 * 1000, // 30 minutes
  idleTimeout: 15 * 60 * 1000, // 15 minutes
  enableSessionTracking: true,
  
  // Storage settings
  handleStorePath: '.workflows',
  backupPath: '.workflows/backup',
  sessionStorePath: '.workflows/sessions',
  encryptionKey: process.env.WORKFLOW_ENCRYPTION_KEY
});
```

## 🎼 Workflow Orchestration

### Workflow Types

The orchestration manager supports different workflow types with optimized configurations:

#### API Workflow
```javascript
{
  keyType: 'api',
  handleType: 'api',
  rotationInterval: 60 * 60 * 1000, // 1 hour
  maxConcurrent: 10,
  timeout: 30 * 60 * 1000 // 30 minutes
}
```

#### Webhook Workflow
```javascript
{
  keyType: 'webhook',
  handleType: 'webhook',
  rotationInterval: 24 * 60 * 60 * 1000, // 24 hours
  maxConcurrent: 5,
  timeout: 5 * 60 * 1000 // 5 minutes
}
```

#### Batch Workflow
```javascript
{
  keyType: 'api',
  handleType: 'batch',
  rotationInterval: 12 * 60 * 60 * 1000, // 12 hours
  maxConcurrent: 3,
  timeout: 60 * 60 * 1000 // 1 hour
}
```

#### OAuth Workflow
```javascript
{
  keyType: 'oauth',
  handleType: 'oauth',
  rotationInterval: 7 * 24 * 60 * 60 * 1000, // 7 days
  maxConcurrent: 2,
  timeout: 15 * 60 * 1000 // 15 minutes
}
```

#### Critical Workflow
```javascript
{
  keyType: 'api',
  handleType: 'critical',
  rotationInterval: 15 * 60 * 1000, // 15 minutes
  maxConcurrent: 1,
  timeout: 10 * 60 * 1000 // 10 minutes
}
```

### Circuit Breaker Pattern

The orchestration manager implements a circuit breaker pattern for fault tolerance:

```javascript
{
  enableCircuitBreaker: true,
  circuitBreakerThreshold: 5, // Failures before opening
  retryDelay: 5 * 60 * 1000, // 5 minutes before retry
  maxRetries: 3
}
```

**Circuit Breaker States:**
- **Closed**: Normal operation
- **Open**: Failures detected, requests blocked
- **Half-Open**: Testing if service recovered

### Load Balancing

The system supports multiple load balancing strategies:

- **Round Robin**: Distribute requests evenly
- **Least Loaded**: Send to least busy workflow
- **Random**: Random distribution

```javascript
{
  enableLoadBalancing: true,
  loadBalancingStrategy: 'round-robin' // 'round-robin', 'least-loaded', 'random'
}
```

## ⚙️ Configuration

### Environment Variables

```bash
# Key Management
KEY_ENCRYPTION_KEY=your-32-byte-encryption-key
KEY_NOTIFICATION_WEBHOOK=https://hooks.slack.com/...
KEY_NOTIFICATION_EMAIL=admin@myapp.com

# Workflow Management
WORKFLOW_ENCRYPTION_KEY=your-32-byte-workflow-encryption-key
WORKFLOW_NOTIFICATION_WEBHOOK=https://hooks.slack.com/...
WORKFLOW_NOTIFICATION_EMAIL=admin@myapp.com

# General Security
JWT_SECRET=your-jwt-secret
ENCRYPTION_KEY=your-general-encryption-key
```

### Complete Configuration Example

```javascript
const orchestrationManager = new WorkflowOrchestrationManager({
  // Enable features
  enableAutoOrchestration: true,
  enableMonitoring: true,
  enableHealthChecks: true,
  enableCircuitBreaker: true,
  enableLoadBalancing: true,
  
  // Orchestration settings
  workflowTimeout: 60 * 60 * 1000, // 1 hour
  maxRetries: 3,
  retryDelay: 5 * 60 * 1000, // 5 minutes
  circuitBreakerThreshold: 5,
  loadBalancingStrategy: 'round-robin',
  
  // Monitoring settings
  metricsInterval: 60 * 1000, // 1 minute
  healthCheckInterval: 30 * 1000, // 30 seconds
  alertThresholds: {
    workflowFailures: 5,
    keyExpirations: 3,
    handleRotations: 10
  },
  
  // Integration settings
  enableCrossDependencies: true,
  dependencyTimeout: 10 * 60 * 1000, // 10 minutes
  
  // Key manager configuration
  keyManager: {
    enableAutoRotation: true,
    notifyBeforeExpiry: 7 * 24 * 60 * 60 * 1000, // 7 days
    webhookUrl: process.env.KEY_NOTIFICATION_WEBHOOK,
    emailRecipients: [process.env.KEY_NOTIFICATION_EMAIL]
  },
  
  // Handle manager configuration
  handleManager: {
    enableAutoRotation: true,
    rotationThreshold: 0.2,
    maxConcurrentSessions: 100,
    sessionTimeout: 30 * 60 * 1000 // 30 minutes
  }
});
```

## 📚 API Reference

### WorkflowOrchestrationManager

#### Constructor
```javascript
new WorkflowOrchestrationManager(options)
```

#### Methods

##### `initialize()`
Initialize the orchestration manager and all components.

##### `registerWorkflow(workflowId, workflowType, workflowFunction, config)`
Register a new workflow for orchestration.

**Parameters:**
- `workflowId` (string): Unique workflow identifier
- `workflowType` (string): Type of workflow (api, webhook, batch, oauth, critical)
- `workflowFunction` (Function): The workflow function to execute
- `config` (Object): Workflow-specific configuration

**Returns:** Workflow information object

##### `executeWorkflow(workflowId, data, options)`
Execute a registered workflow.

**Parameters:**
- `workflowId` (string): Workflow identifier
- `data` (Object): Input data for the workflow
- `options` (Object): Execution options

**Returns:** Workflow execution result

##### `getWorkflowInfo(workflowId)`
Get detailed information about a workflow.

**Parameters:**
- `workflowId` (string): Workflow identifier

**Returns:** Workflow information object

##### `getAllWorkflows()`
Get information about all registered workflows.

**Returns:** Array of workflow information objects

##### `getWorkflowsByType(workflowType)`
Get workflows of a specific type.

**Parameters:**
- `workflowType` (string): Workflow type

**Returns:** Array of workflow information objects

##### `getOrchestrationStats()`
Get comprehensive orchestration statistics.

**Returns:** Statistics object

##### `startMonitoring()`
Start monitoring and health checks.

##### `stopMonitoring()`
Stop monitoring and health checks.

### KeyExpirationManager

#### Methods

##### `registerKey(keyId, keyType, keyValue, metadata)`
Register a new key for expiration management.

##### `rotateKey(keyId, keyGenerator)`
Rotate a key before expiration.

##### `getKeyInfo(keyId)`
Get key information.

##### `getKeysByType(keyType)`
Get keys of a specific type.

##### `getKeysNeedingRotation()`
Get keys that need rotation.

##### `revokeKey(keyId, reason)`
Revoke a key.

##### `getMonitoringStats()`
Get key management statistics.

### WorkflowHandleRotationManager

#### Methods

##### `createWorkflowHandle(workflowId, handleType, workflowConfig, metadata)`
Create a new workflow handle.

##### `rotateHandle(handleId, handleGenerator)`
Rotate a workflow handle.

##### `createSession(handleId, sessionData)`
Create a new session for a workflow handle.

##### `executeWorkflow(handleId, executionData, workflowFunction)`
Execute a workflow using a handle.

##### `getHandleInfo(handleId)`
Get handle information.

##### `getHandlesByType(handleType)`
Get handles of a specific type.

##### `getHandlesNeedingRotation()`
Get handles that need rotation.

##### `getMonitoringStats()`
Get handle management statistics.

## 💡 Examples

### Basic Workflow Registration

```javascript
const orchestrationManager = new WorkflowOrchestrationManager();
await orchestrationManager.initialize();

// Register an API workflow
const apiWorkflow = await orchestrationManager.registerWorkflow(
  'user-api',
  'api',
  async (data) => {
    // Your API logic here
    return { status: 'success', data };
  },
  {
    maxConcurrent: 5,
    timeout: 30 * 1000
  }
);

// Execute the workflow
const result = await orchestrationManager.executeWorkflow('user-api', {
  userId: '123',
  action: 'get_profile'
});
```

### Webhook Workflow with Automatic Rotation

```javascript
// Register a webhook workflow
const webhookWorkflow = await orchestrationManager.registerWorkflow(
  'stripe-webhook',
  'webhook',
  async (data) => {
    // Process webhook event
    switch (data.event) {
      case 'payment.succeeded':
        return await processPayment(data);
      case 'customer.created':
        return await createCustomer(data);
      default:
        return { status: 'ignored' };
    }
  },
  {
    maxConcurrent: 3,
    timeout: 10 * 1000
  }
);

// Execute webhook events
await orchestrationManager.executeWorkflow('stripe-webhook', {
  event: 'payment.succeeded',
  amount: 99.99,
  customerId: 'cus_123'
});
```

### Batch Processing with Circuit Breaker

```javascript
// Register a batch workflow
const batchWorkflow = await orchestrationManager.registerWorkflow(
  'data-processing',
  'batch',
  async (data) => {
    const results = [];
    for (const item of data.items) {
      // Process each item
      const result = await processItem(item);
      results.push(result);
    }
    return { processed: results.length, results };
  },
  {
    maxConcurrent: 2,
    timeout: 5 * 60 * 1000
  }
);

// Execute batch processing
const result = await orchestrationManager.executeWorkflow('data-processing', {
  batchId: 'batch_001',
  items: [/* array of items */]
});
```

### Monitoring and Statistics

```javascript
// Get comprehensive statistics
const stats = orchestrationManager.getOrchestrationStats();

console.log('Workflow Statistics:', {
  total: stats.workflows.total,
  active: stats.workflows.active,
  queued: stats.workflows.queued,
  byType: stats.workflows.byType
});

console.log('Execution Metrics:', {
  total: stats.metrics.totalWorkflows,
  successful: stats.metrics.successfulWorkflows,
  failed: stats.metrics.failedWorkflows,
  keyRotations: stats.metrics.keyRotations,
  handleRotations: stats.metrics.handleRotations
});

console.log('Circuit Breaker Stats:', {
  total: stats.circuitBreakers.total,
  open: stats.circuitBreakers.open,
  closed: stats.circuitBreakers.closed
});
```

### Event Monitoring

```javascript
// Set up event listeners
orchestrationManager.on('workflowExecuted', (data) => {
  console.log(`Workflow executed: ${data.workflowId} (${data.duration}ms)`);
});

orchestrationManager.on('workflowError', (data) => {
  console.error(`Workflow error: ${data.workflowId} - ${data.error}`);
});

orchestrationManager.on('keyRotated', (data) => {
  console.log(`Key rotated: ${data.keyId} (${data.keyType})`);
});

orchestrationManager.on('handleRotated', (data) => {
  console.log(`Handle rotated: ${data.handleId} for workflow ${data.workflowId}`);
});

orchestrationManager.on('healthCheck', (data) => {
  console.log('Health check:', data);
});
```

## 🎯 Best Practices

### Key Management

1. **Use Appropriate Key Types**: Choose the right key type for your use case
2. **Set Reasonable Expiration Periods**: Balance security with operational overhead
3. **Enable Automatic Rotation**: Let the system handle key rotation automatically
4. **Monitor Key Health**: Set up alerts for key expiration and rotation
5. **Backup Keys**: Enable key backup for disaster recovery

### Workflow Design

1. **Choose Right Workflow Type**: Select the appropriate workflow type for your use case
2. **Set Appropriate Timeouts**: Configure timeouts based on expected execution time
3. **Handle Failures Gracefully**: Implement proper error handling in workflow functions
4. **Use Circuit Breakers**: Enable circuit breakers for fault tolerance
5. **Monitor Performance**: Track execution metrics and optimize accordingly

### Security Considerations

1. **Encrypt Sensitive Data**: All keys and handles are encrypted at rest
2. **Use Environment Variables**: Store sensitive configuration in environment variables
3. **Implement Least Privilege**: Use minimal required permissions for workflows
4. **Monitor Access**: Track who accesses what and when
5. **Regular Audits**: Periodically review and audit workflow configurations

### Performance Optimization

1. **Configure Concurrency Limits**: Set appropriate maxConcurrent values
2. **Use Load Balancing**: Enable load balancing for better resource utilization
3. **Monitor Resource Usage**: Track CPU, memory, and I/O usage
4. **Optimize Workflow Functions**: Make workflow functions efficient
5. **Use Caching**: Implement caching where appropriate

### Monitoring and Alerting

1. **Set Up Comprehensive Monitoring**: Monitor all aspects of the system
2. **Configure Alert Thresholds**: Set appropriate alert thresholds
3. **Use Multiple Notification Channels**: Email, webhooks, Slack, etc.
4. **Track Metrics**: Monitor key performance indicators
5. **Set Up Dashboards**: Create dashboards for visualization

## 🔧 Troubleshooting

### Common Issues

#### Key Rotation Failures

**Problem**: Keys are not rotating automatically
**Solution**: 
- Check if `enableAutoRotation` is enabled
- Verify key expiration periods are set correctly
- Check for storage permission issues
- Review error logs for specific failure reasons

#### Workflow Execution Failures

**Problem**: Workflows are failing to execute
**Solution**:
- Check circuit breaker status
- Verify workflow function implementation
- Check timeout configurations
- Review error logs for specific failure reasons

#### Session Management Issues

**Problem**: Sessions are expiring unexpectedly
**Solution**:
- Check session timeout configurations
- Verify idle timeout settings
- Check for session storage issues
- Review session cleanup processes

#### Performance Issues

**Problem**: System performance is degraded
**Solution**:
- Check concurrent execution limits
- Monitor resource usage
- Review workflow function efficiency
- Consider load balancing configuration

### Debug Mode

Enable debug mode for detailed logging:

```javascript
const orchestrationManager = new WorkflowOrchestrationManager({
  debug: true,
  logLevel: 'debug'
});
```

### Health Checks

Monitor system health:

```javascript
// Get health status
orchestrationManager.on('healthCheck', (data) => {
  console.log('Health Status:', data);
  
  if (!data.keyManager || !data.handleManager) {
    console.error('System components not initialized');
  }
  
  if (data.activeWorkflows > 100) {
    console.warn('High number of active workflows');
  }
});
```

### Error Recovery

Implement error recovery strategies:

```javascript
// Handle workflow errors
orchestrationManager.on('workflowError', async (data) => {
  console.error('Workflow error:', data);
  
  // Implement retry logic
  if (data.error.includes('timeout')) {
    // Retry with longer timeout
    await orchestrationManager.executeWorkflow(data.workflowId, data.data, {
      timeout: data.options.timeout * 2
    });
  }
  
  // Notify administrators
  await sendAlert('Workflow Error', data);
});
```

## 📞 Support

For additional support and questions:

- **Documentation**: Check this documentation and API reference
- **Examples**: Review the provided examples in `examples/workflow-orchestration-examples.js`
- **Issues**: Report issues through the project's issue tracker
- **Community**: Join the community discussions

---

**Made with ❤️ for secure workflow orchestration**
