const { WorkflowOrchestrationManager } = require('../src/security/workflow/WorkflowOrchestrationManager');

/**
 * Comprehensive Examples for Workflow Orchestration
 * Demonstrates key expiration and workflow handle rotation workflows
 */

async function main() {
  console.log('🚀 Starting Workflow Orchestration Examples\n');

  // Initialize the workflow orchestration manager
  const orchestrationManager = new WorkflowOrchestrationManager({
    enableAutoOrchestration: true,
    enableMonitoring: true,
    enableHealthChecks: true,
    enableCircuitBreaker: true,
    keyManager: {
      enableAutoRotation: true,
      notifyBeforeExpiry: 7 * 24 * 60 * 60 * 1000, // 7 days
      webhookUrl: process.env.KEY_NOTIFICATION_WEBHOOK
    },
    handleManager: {
      enableAutoRotation: true,
      rotationThreshold: 0.2
    }
  });

  await orchestrationManager.initialize();

  // Set up event listeners for monitoring
  setupEventListeners(orchestrationManager);

  // Example 1: API Workflow with Automatic Key Rotation
  await exampleApiWorkflow(orchestrationManager);

  // Example 2: Webhook Workflow with Handle Rotation
  await exampleWebhookWorkflow(orchestrationManager);

  // Example 3: Batch Processing Workflow
  await exampleBatchWorkflow(orchestrationManager);

  // Example 4: OAuth Workflow with Session Management
  await exampleOAuthWorkflow(orchestrationManager);

  // Example 5: Critical Workflow with Circuit Breaker
  await exampleCriticalWorkflow(orchestrationManager);

  // Example 6: Workflow Orchestration Dashboard
  await exampleOrchestrationDashboard(orchestrationManager);

  console.log('\n✅ All workflow orchestration examples completed!');
}

/**
 * Example 1: API Workflow with Automatic Key Rotation
 */
async function exampleApiWorkflow(orchestrationManager) {
  console.log('📡 Example 1: API Workflow with Automatic Key Rotation');

  // Define the API workflow function
  const apiWorkflowFunction = async (data) => {
    console.log(`  🔑 Executing API workflow with data:`, data);
    
    // Simulate API call
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Simulate processing
    const result = {
      status: 'success',
      data: data,
      processedAt: new Date().toISOString(),
      apiVersion: 'v1.0'
    };
    
    console.log(`  ✅ API workflow completed successfully`);
    return result;
  };

  // Register the API workflow
  const apiWorkflow = await orchestrationManager.registerWorkflow(
    'user-api',
    'api',
    apiWorkflowFunction,
    {
      maxConcurrent: 5,
      timeout: 30 * 1000, // 30 seconds
      retries: 2
    }
  );

  console.log(`  📝 Registered API workflow: ${apiWorkflow.id}`);

  // Execute the workflow multiple times
  const executions = [];
  for (let i = 0; i < 3; i++) {
    const execution = orchestrationManager.executeWorkflow('user-api', {
      userId: `user_${i + 1}`,
      action: 'get_profile',
      timestamp: Date.now()
    });
    executions.push(execution);
  }

  // Wait for all executions to complete
  const results = await Promise.all(executions);
  console.log(`  📊 Completed ${results.length} API workflow executions`);

  // Get workflow information
  const workflowInfo = orchestrationManager.getWorkflowInfo('user-api');
  console.log(`  📈 Workflow stats: ${workflowInfo.executionCount} executions, ${workflowInfo.errorCount} errors`);
}

/**
 * Example 2: Webhook Workflow with Handle Rotation
 */
async function exampleWebhookWorkflow(orchestrationManager) {
  console.log('\n🔗 Example 2: Webhook Workflow with Handle Rotation');

  // Define the webhook workflow function
  const webhookWorkflowFunction = async (data) => {
    console.log(`  🔗 Processing webhook:`, data.event);
    
    // Simulate webhook processing
    await new Promise(resolve => setTimeout(resolve, 500));
    
    // Simulate different event types
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
    
    console.log(`  ✅ Webhook processed: ${data.event}`);
    return result;
  };

  // Register the webhook workflow
  const webhookWorkflow = await orchestrationManager.registerWorkflow(
    'stripe-webhook',
    'webhook',
    webhookWorkflowFunction,
    {
      maxConcurrent: 3,
      timeout: 10 * 1000 // 10 seconds
    }
  );

  console.log(`  📝 Registered webhook workflow: ${webhookWorkflow.id}`);

  // Execute webhook events
  const webhookEvents = [
    { event: 'user.created', userId: 'user_123' },
    { event: 'payment.completed', amount: 99.99 },
    { event: 'subscription.updated', plan: 'premium' }
  ];

  for (const event of webhookEvents) {
    await orchestrationManager.executeWorkflow('stripe-webhook', event);
  }

  console.log(`  📊 Processed ${webhookEvents.length} webhook events`);
}

/**
 * Example 3: Batch Processing Workflow
 */
async function exampleBatchWorkflow(orchestrationManager) {
  console.log('\n📦 Example 3: Batch Processing Workflow');

  // Define the batch workflow function
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
    
    console.log(`  ✅ Batch completed: ${results.length} items processed`);
    return {
      batchId: data.batchId,
      totalItems: data.items.length,
      processedItems: results.length,
      results: results
    };
  };

  // Register the batch workflow
  const batchWorkflow = await orchestrationManager.registerWorkflow(
    'data-processing',
    'batch',
    batchWorkflowFunction,
    {
      maxConcurrent: 2,
      timeout: 5 * 60 * 1000 // 5 minutes
    }
  );

  console.log(`  📝 Registered batch workflow: ${batchWorkflow.id}`);

  // Create sample batch data
  const batchData = {
    batchId: 'batch_001',
    items: Array.from({ length: 10 }, (_, i) => ({
      id: `item_${i + 1}`,
      data: `Sample data for item ${i + 1}`
    }))
  };

  // Execute batch processing
  const result = await orchestrationManager.executeWorkflow('data-processing', batchData);
  console.log(`  📊 Batch processing completed: ${result.processedItems} items processed`);
}

/**
 * Example 4: OAuth Workflow with Session Management
 */
async function exampleOAuthWorkflow(orchestrationManager) {
  console.log('\n🔐 Example 4: OAuth Workflow with Session Management');

  // Define the OAuth workflow function
  const oauthWorkflowFunction = async (data) => {
    console.log(`  🔐 Processing OAuth flow: ${data.provider}`);
    
    // Simulate OAuth authentication
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Simulate token generation
    const tokens = {
      accessToken: `access_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      refreshToken: `refresh_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      expiresIn: 3600,
      tokenType: 'Bearer'
    };
    
    console.log(`  ✅ OAuth authentication completed for ${data.provider}`);
    return {
      provider: data.provider,
      userId: data.userId,
      tokens: tokens,
      authenticatedAt: new Date().toISOString()
    };
  };

  // Register the OAuth workflow
  const oauthWorkflow = await orchestrationManager.registerWorkflow(
    'oauth-authentication',
    'oauth',
    oauthWorkflowFunction,
    {
      maxConcurrent: 1,
      timeout: 30 * 1000 // 30 seconds
    }
  );

  console.log(`  📝 Registered OAuth workflow: ${oauthWorkflow.id}`);

  // Execute OAuth flows for different providers
  const oauthProviders = ['google', 'github', 'facebook'];
  
  for (const provider of oauthProviders) {
    const result = await orchestrationManager.executeWorkflow('oauth-authentication', {
      provider: provider,
      userId: `user_${provider}_123`,
      redirectUri: `https://myapp.com/oauth/callback/${provider}`
    });
    
    console.log(`  🔐 OAuth completed for ${provider}: ${result.tokens.accessToken.substring(0, 20)}...`);
  }
}

/**
 * Example 5: Critical Workflow with Circuit Breaker
 */
async function exampleCriticalWorkflow(orchestrationManager) {
  console.log('\n⚠️ Example 5: Critical Workflow with Circuit Breaker');

  // Define the critical workflow function (simulates failures)
  const criticalWorkflowFunction = async (data) => {
    console.log(`  ⚠️ Executing critical workflow: ${data.operation}`);
    
    // Simulate occasional failures
    if (Math.random() < 0.3) {
      throw new Error(`Critical operation failed: ${data.operation}`);
    }
    
    // Simulate processing
    await new Promise(resolve => setTimeout(resolve, 500));
    
    console.log(`  ✅ Critical workflow completed: ${data.operation}`);
    return {
      operation: data.operation,
      status: 'success',
      completedAt: new Date().toISOString()
    };
  };

  // Register the critical workflow
  const criticalWorkflow = await orchestrationManager.registerWorkflow(
    'payment-processing',
    'critical',
    criticalWorkflowFunction,
    {
      maxConcurrent: 1,
      timeout: 15 * 1000 // 15 seconds
    }
  );

  console.log(`  📝 Registered critical workflow: ${criticalWorkflow.id}`);

  // Execute critical operations (some will fail)
  const operations = [
    'process_payment_1',
    'process_payment_2',
    'process_payment_3',
    'process_payment_4',
    'process_payment_5'
  ];

  for (const operation of operations) {
    try {
      const result = await orchestrationManager.executeWorkflow('payment-processing', {
        operation: operation,
        amount: 100.00,
        currency: 'USD'
      });
      console.log(`  💰 Payment processed: ${operation}`);
    } catch (error) {
      console.log(`  ❌ Payment failed: ${operation} - ${error.message}`);
    }
  }

  // Check circuit breaker status
  const workflowInfo = orchestrationManager.getWorkflowInfo('payment-processing');
  console.log(`  🔌 Circuit breaker status:`, workflowInfo.circuitBreakerStatus);
}

/**
 * Example 6: Workflow Orchestration Dashboard
 */
async function exampleOrchestrationDashboard(orchestrationManager) {
  console.log('\n📊 Example 6: Workflow Orchestration Dashboard');

  // Get comprehensive orchestration statistics
  const stats = orchestrationManager.getOrchestrationStats();
  
  console.log('  📈 Workflow Orchestration Statistics:');
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

  // Get detailed workflow information
  console.log('\n  📋 Detailed Workflow Information:');
  const allWorkflows = orchestrationManager.getAllWorkflows();
  
  for (const workflow of allWorkflows) {
    console.log(`    ${workflow.id} (${workflow.type}):`);
    console.log(`      Status: ${workflow.status}`);
    console.log(`      Executions: ${workflow.executionCount}`);
    console.log(`      Errors: ${workflow.errorCount}`);
    console.log(`      Active: ${workflow.activeExecutions}`);
    console.log(`      Queued: ${workflow.queuedWorkflows}`);
    console.log(`      Circuit Breaker: ${workflow.circuitBreakerStatus.status}`);
  }
}

/**
 * Set up event listeners for monitoring
 */
function setupEventListeners(orchestrationManager) {
  // Key management events
  orchestrationManager.on('keyRegistered', (data) => {
    console.log(`🔑 Key registered: ${data.keyId} (${data.keyType})`);
  });

  orchestrationManager.on('keyRotated', (data) => {
    console.log(`🔄 Key rotated: ${data.keyId} (${data.keyType})`);
  });

  orchestrationManager.on('keyExpired', (data) => {
    console.log(`⏰ Key expired: ${data.keyId} (${data.keyType})`);
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

  orchestrationManager.on('workflowQueued', (data) => {
    console.log(`⏳ Workflow queued: ${data.workflowId}`);
  });

  // Orchestration events
  orchestrationManager.on('workflowComponentsRotated', (data) => {
    console.log(`🔄 Workflow components rotated: ${data.workflowId}`);
  });

  orchestrationManager.on('workflowRotationNeeded', (data) => {
    console.log(`⚠️ Workflow rotation needed: ${data.workflowId}`);
  });

  // Health check events
  orchestrationManager.on('healthCheck', (data) => {
    console.log(`💓 Health check: ${JSON.stringify(data)}`);
  });
}

// Run the examples
if (require.main === module) {
  main().catch(console.error);
}

module.exports = {
  main,
  exampleApiWorkflow,
  exampleWebhookWorkflow,
  exampleBatchWorkflow,
  exampleOAuthWorkflow,
  exampleCriticalWorkflow,
  exampleOrchestrationDashboard
};
