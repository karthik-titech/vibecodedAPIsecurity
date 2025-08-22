const { SecurityManager } = require('../src/security/SecurityManager');

/**
 * Workflow Orchestration Demo
 * Demonstrates key expiration and workflow handle rotation with SecurityManager
 */

async function demo() {
  console.log('🚀 Starting Workflow Orchestration Demo\n');

  // Initialize SecurityManager with workflow orchestration
  const securityManager = new SecurityManager({
    // Basic security configuration
    secrets: { vaultPath: '.vault' },
    auth: { secretKey: process.env.JWT_SECRET || 'demo-secret-key' },
    validation: { strictMode: true },
    
    // Key management configuration
    keyManagement: {
      enableAutoRotation: true,
      notifyBeforeExpiry: 7 * 24 * 60 * 60 * 1000, // 7 days
      webhookUrl: process.env.KEY_NOTIFICATION_WEBHOOK
    },
    
    // Workflow management configuration
    workflowManagement: {
      enableAutoRotation: true,
      rotationThreshold: 0.2,
      maxConcurrentSessions: 50,
      sessionTimeout: 30 * 60 * 1000 // 30 minutes
    },
    
    // Workflow orchestration configuration
    workflowOrchestration: {
      enableAutoOrchestration: true,
      enableMonitoring: true,
      enableHealthChecks: true,
      enableCircuitBreaker: true,
      workflowTimeout: 60 * 60 * 1000, // 1 hour
      maxRetries: 3,
      retryDelay: 5 * 60 * 1000, // 5 minutes
      circuitBreakerThreshold: 5
    }
  });

  await securityManager.initialize();

  // Set up event listeners for monitoring
  setupEventListeners(securityManager);

  console.log('✅ SecurityManager initialized with workflow orchestration\n');

  // Demo 1: Register and execute an API workflow
  await demoApiWorkflow(securityManager);

  // Demo 2: Register and execute a webhook workflow
  await demoWebhookWorkflow(securityManager);

  // Demo 3: Register and execute a batch workflow
  await demoBatchWorkflow(securityManager);

  // Demo 4: Show orchestration statistics
  await demoOrchestrationStats(securityManager);

  console.log('\n✅ Workflow orchestration demo completed!');
}

/**
 * Demo API workflow with automatic key rotation
 */
async function demoApiWorkflow(securityManager) {
  console.log('📡 Demo 1: API Workflow with Automatic Key Rotation');

  // Define API workflow function
  const apiWorkflowFunction = async (data) => {
    console.log(`  🔑 Processing API request: ${data.action}`);
    
    // Simulate API processing
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    return {
      status: 'success',
      action: data.action,
      userId: data.userId,
      processedAt: new Date().toISOString(),
      apiVersion: 'v1.0'
    };
  };

  // Register the API workflow
  const workflow = await securityManager.registerWorkflow(
    'user-api',
    'api',
    apiWorkflowFunction,
    {
      maxConcurrent: 5,
      timeout: 30 * 1000 // 30 seconds
    }
  );

  console.log(`  📝 Registered workflow: ${workflow.id}`);

  // Execute the workflow multiple times
  const executions = [];
  for (let i = 0; i < 3; i++) {
    const execution = securityManager.executeWorkflow('user-api', {
      action: `get_user_${i + 1}`,
      userId: `user_${i + 1}`,
      timestamp: Date.now()
    });
    executions.push(execution);
  }

  // Wait for all executions to complete
  const results = await Promise.all(executions);
  console.log(`  📊 Completed ${results.length} API workflow executions\n`);
}

/**
 * Demo webhook workflow with handle rotation
 */
async function demoWebhookWorkflow(securityManager) {
  console.log('🔗 Demo 2: Webhook Workflow with Handle Rotation');

  // Define webhook workflow function
  const webhookWorkflowFunction = async (data) => {
    console.log(`  🔗 Processing webhook: ${data.event}`);
    
    // Simulate webhook processing
    await new Promise(resolve => setTimeout(resolve, 500));
    
    let result;
    switch (data.event) {
      case 'user.created':
        result = { status: 'user_created', userId: data.userId };
        break;
      case 'payment.completed':
        result = { status: 'payment_processed', amount: data.amount };
        break;
      default:
        result = { status: 'event_processed', event: data.event };
    }
    
    return result;
  };

  // Register the webhook workflow
  const workflow = await securityManager.registerWorkflow(
    'stripe-webhook',
    'webhook',
    webhookWorkflowFunction,
    {
      maxConcurrent: 3,
      timeout: 10 * 1000 // 10 seconds
    }
  );

  console.log(`  📝 Registered workflow: ${workflow.id}`);

  // Execute webhook events
  const webhookEvents = [
    { event: 'user.created', userId: 'user_123' },
    { event: 'payment.completed', amount: 99.99 },
    { event: 'subscription.updated', plan: 'premium' }
  ];

  for (const event of webhookEvents) {
    await securityManager.executeWorkflow('stripe-webhook', event);
  }

  console.log(`  📊 Processed ${webhookEvents.length} webhook events\n`);
}

/**
 * Demo batch workflow with circuit breaker
 */
async function demoBatchWorkflow(securityManager) {
  console.log('📦 Demo 3: Batch Workflow with Circuit Breaker');

  // Define batch workflow function
  const batchWorkflowFunction = async (data) => {
    console.log(`  📦 Processing batch: ${data.batchId} with ${data.items.length} items`);
    
    const results = [];
    
    // Process each item in the batch
    for (const item of data.items) {
      // Simulate item processing
      await new Promise(resolve => setTimeout(resolve, 100));
      
      const processedItem = {
        id: item.id,
        status: 'processed',
        processedAt: new Date().toISOString(),
        result: `Processed item ${item.id}`
      };
      
      results.push(processedItem);
    }
    
    return {
      batchId: data.batchId,
      totalItems: data.items.length,
      processedItems: results.length,
      results: results
    };
  };

  // Register the batch workflow
  const workflow = await securityManager.registerWorkflow(
    'data-processing',
    'batch',
    batchWorkflowFunction,
    {
      maxConcurrent: 2,
      timeout: 5 * 60 * 1000 // 5 minutes
    }
  );

  console.log(`  📝 Registered workflow: ${workflow.id}`);

  // Create sample batch data
  const batchData = {
    batchId: 'batch_001',
    items: Array.from({ length: 5 }, (_, i) => ({
      id: `item_${i + 1}`,
      data: `Sample data for item ${i + 1}`
    }))
  };

  // Execute batch processing
  const result = await securityManager.executeWorkflow('data-processing', batchData);
  console.log(`  📊 Batch processing completed: ${result.processedItems} items processed\n`);
}

/**
 * Demo orchestration statistics
 */
async function demoOrchestrationStats(securityManager) {
  console.log('📊 Demo 4: Workflow Orchestration Statistics');

  // Get comprehensive statistics
  const stats = securityManager.getWorkflowOrchestrationStats();
  
  console.log('  📈 Workflow Statistics:');
  console.log(`    Total Workflows: ${stats.workflows.total}`);
  console.log(`    Active Workflows: ${stats.workflows.active}`);
  console.log(`    Queued Workflows: ${stats.workflows.queued}`);
  console.log(`    Workflows by Type:`, stats.workflows.byType);
  
  console.log('\n  📊 Execution Metrics:');
  console.log(`    Total Executions: ${stats.metrics.totalWorkflows}`);
  console.log(`    Successful: ${stats.metrics.successfulWorkflows}`);
  console.log(`    Failed: ${stats.metrics.failedWorkflows}`);
  console.log(`    Key Rotations: ${stats.metrics.keyRotations}`);
  console.log(`    Handle Rotations: ${stats.metrics.handleRotations}`);
  
  console.log('\n  🔑 Key Manager Stats:');
  console.log(`    Total Keys: ${stats.keyManager.totalKeys}`);
  console.log(`    Active Keys: ${stats.keyManager.activeKeys}`);
  console.log(`    Expired Keys: ${stats.keyManager.expiredKeys}`);
  console.log(`    Keys Needing Rotation: ${stats.keyManager.keysNeedingRotation}`);
  
  console.log('\n  🔧 Handle Manager Stats:');
  console.log(`    Total Handles: ${stats.handleManager.totalHandles}`);
  console.log(`    Active Handles: ${stats.handleManager.activeHandles}`);
  console.log(`    Handles Needing Rotation: ${stats.handleManager.handlesNeedingRotation}`);
  
  console.log('\n  🔌 Circuit Breaker Stats:');
  console.log(`    Total Circuit Breakers: ${stats.circuitBreakers.total}`);
  console.log(`    Open: ${stats.circuitBreakers.open}`);
  console.log(`    Closed: ${stats.circuitBreakers.closed}`);

  // Get security status
  const securityStatus = securityManager.getSecurityStatus();
  console.log('\n  🛡️ Security Status:');
  console.log(`    Initialized: ${securityStatus.initialized}`);
  console.log(`    Components: ${securityStatus.components.join(', ')}`);
  console.log(`    Features: ${securityStatus.features.join(', ')}`);
}

/**
 * Set up event listeners for monitoring
 */
function setupEventListeners(securityManager) {
  const orchestrationManager = securityManager.getWorkflowOrchestrationManager();

  // Key management events
  orchestrationManager.on('keyRegistered', (data) => {
    console.log(`🔑 Key registered: ${data.keyId} (${data.keyType})`);
  });

  orchestrationManager.on('keyRotated', (data) => {
    console.log(`🔄 Key rotated: ${data.keyId} (${data.keyType})`);
  });

  // Handle management events
  orchestrationManager.on('handleCreated', (data) => {
    console.log(`🔧 Handle created: ${data.handleId} for workflow ${data.workflowId}`);
  });

  orchestrationManager.on('handleRotated', (data) => {
    console.log(`🔄 Handle rotated: ${data.handleId} for workflow ${data.workflowId}`);
  });

  // Workflow execution events
  orchestrationManager.on('workflowExecuted', (data) => {
    console.log(`✅ Workflow executed: ${data.workflowId} (${data.duration}ms)`);
  });

  orchestrationManager.on('workflowError', (data) => {
    console.log(`❌ Workflow error: ${data.workflowId} - ${data.error}`);
  });

  // Health check events
  orchestrationManager.on('healthCheck', (data) => {
    console.log(`💓 Health check: ${JSON.stringify(data)}`);
  });
}

// Run the demo
if (require.main === module) {
  demo().catch(console.error);
}

module.exports = { demo };
