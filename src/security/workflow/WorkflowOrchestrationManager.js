const KeyExpirationManager = require('../key-management/KeyExpirationManager');
const WorkflowHandleRotationManager = require('./WorkflowHandleRotationManager');
const EventEmitter = require('events');

/**
 * Workflow Orchestration Manager for Vibe-Coded Applications
 * Integrates key expiration and workflow handle rotation into unified workflows
 * 
 * @description This class provides comprehensive workflow orchestration that combines
 * key management, handle rotation, and workflow execution into a cohesive system.
 */
class WorkflowOrchestrationManager extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.config = {
      // Workflow types and their configurations
      workflowTypes: {
        api: {
          keyType: 'api',
          handleType: 'api',
          rotationInterval: 60 * 60 * 1000, // 1 hour
          maxConcurrent: 10,
          timeout: 30 * 60 * 1000 // 30 minutes
        },
        webhook: {
          keyType: 'webhook',
          handleType: 'webhook',
          rotationInterval: 24 * 60 * 60 * 1000, // 24 hours
          maxConcurrent: 5,
          timeout: 5 * 60 * 1000 // 5 minutes
        },
        batch: {
          keyType: 'api',
          handleType: 'batch',
          rotationInterval: 12 * 60 * 60 * 1000, // 12 hours
          maxConcurrent: 3,
          timeout: 60 * 60 * 1000 // 1 hour
        },
        oauth: {
          keyType: 'oauth',
          handleType: 'oauth',
          rotationInterval: 7 * 24 * 60 * 60 * 1000, // 7 days
          maxConcurrent: 2,
          timeout: 15 * 60 * 1000 // 15 minutes
        },
        critical: {
          keyType: 'api',
          handleType: 'critical',
          rotationInterval: 15 * 60 * 1000, // 15 minutes
          maxConcurrent: 1,
          timeout: 10 * 60 * 1000 // 10 minutes
        }
      },
      
      // Orchestration settings
      orchestration: {
        enableAutoOrchestration: options.enableAutoOrchestration !== false,
        workflowTimeout: options.workflowTimeout || 60 * 60 * 1000, // 1 hour
        maxRetries: options.maxRetries || 3,
        retryDelay: options.retryDelay || 5 * 60 * 1000, // 5 minutes
        enableCircuitBreaker: options.enableCircuitBreaker !== false,
        circuitBreakerThreshold: options.circuitBreakerThreshold || 5,
        enableLoadBalancing: options.enableLoadBalancing !== false,
        loadBalancingStrategy: options.loadBalancingStrategy || 'round-robin' // 'round-robin', 'least-loaded', 'random'
      },
      
      // Monitoring and alerting
      monitoring: {
        enableMonitoring: options.enableMonitoring !== false,
        metricsInterval: options.metricsInterval || 60 * 1000, // 1 minute
        alertThresholds: {
          workflowFailures: options.workflowFailureThreshold || 5,
          keyExpirations: options.keyExpirationThreshold || 3,
          handleRotations: options.handleRotationThreshold || 10
        },
        enableHealthChecks: options.enableHealthChecks !== false,
        healthCheckInterval: options.healthCheckInterval || 30 * 1000 // 30 seconds
      },
      
      // Integration settings
      integration: {
        keyManager: options.keyManager || {},
        handleManager: options.handleManager || {},
        enableCrossDependencies: options.enableCrossDependencies !== false,
        dependencyTimeout: options.dependencyTimeout || 10 * 60 * 1000 // 10 minutes
      }
    };
    
    // Initialize managers
    this.keyManager = new KeyExpirationManager(this.config.integration.keyManager);
    this.handleManager = new WorkflowHandleRotationManager(this.config.integration.handleManager);
    
    // Workflow state
    this.workflows = new Map();
    this.activeWorkflows = new Map();
    this.workflowQueue = new Map();
    this.circuitBreakers = new Map();
    this.metrics = {
      totalWorkflows: 0,
      successfulWorkflows: 0,
      failedWorkflows: 0,
      activeWorkflows: 0,
      queuedWorkflows: 0,
      keyRotations: 0,
      handleRotations: 0
    };
    
    this.initialized = false;
    this.monitoring = false;
  }

  /**
   * Initialize the workflow orchestration manager
   */
  async initialize() {
    try {
      // Initialize key and handle managers
      await this.keyManager.initialize();
      await this.handleManager.initialize();
      
      // Set up event listeners
      this.setupEventListeners();
      
      // Start monitoring if enabled
      if (this.config.monitoring.enableMonitoring) {
        await this.startMonitoring();
      }
      
      this.initialized = true;
      console.log('✅ Workflow Orchestration Manager initialized successfully');
    } catch (error) {
      console.error('❌ Workflow Orchestration Manager initialization failed:', error.message);
      throw error;
    }
  }

  /**
   * Register a new workflow
   * @param {string} workflowId - Unique workflow identifier
   * @param {string} workflowType - Type of workflow (api, webhook, batch, etc.)
   * @param {Function} workflowFunction - The workflow function to execute
   * @param {Object} config - Workflow configuration
   */
  async registerWorkflow(workflowId, workflowType, workflowFunction, config = {}) {
    if (!this.initialized) {
      await this.initialize();
    }

    const workflowConfig = this.config.workflowTypes[workflowType];
    if (!workflowConfig) {
      throw new Error(`Unknown workflow type: ${workflowType}`);
    }

    // Create key for the workflow
    const keyId = `${workflowId}_key`;
    const keyValue = this.generateKeyValue(workflowConfig.keyType);
    await this.keyManager.registerKey(keyId, workflowConfig.keyType, keyValue, {
      workflowId,
      workflowType
    });

    // Create handle for the workflow
    const handleConfig = {
      workflowFunction,
      keyId,
      maxConcurrent: config.maxConcurrent || workflowConfig.maxConcurrent,
      timeout: config.timeout || workflowConfig.timeout,
      retries: config.retries || this.config.orchestration.maxRetries,
      ...config
    };

    const handle = await this.handleManager.createWorkflowHandle(
      workflowId,
      workflowConfig.handleType,
      handleConfig,
      { workflowType, keyId }
    );

    // Register the workflow
    const workflowInfo = {
      id: workflowId,
      type: workflowType,
      keyId,
      handleId: handle.id,
      config: handleConfig,
      createdAt: Date.now(),
      status: 'registered',
      executionCount: 0,
      lastExecuted: null,
      errorCount: 0,
      lastError: null
    };

    this.workflows.set(workflowId, workflowInfo);

    this.emit('workflowRegistered', { workflowId, workflowType, keyId, handleId: handle.id });
    
    return workflowInfo;
  }

  /**
   * Execute a workflow
   * @param {string} workflowId - Workflow identifier
   * @param {Object} data - Input data for the workflow
   * @param {Object} options - Execution options
   */
  async executeWorkflow(workflowId, data = {}, options = {}) {
    if (!this.workflows.has(workflowId)) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    const workflow = this.workflows.get(workflowId);
    const workflowConfig = this.config.workflowTypes[workflow.type];

    // Check circuit breaker
    if (this.isCircuitBreakerOpen(workflowId)) {
      throw new Error(`Circuit breaker is open for workflow ${workflowId}`);
    }

    // Check concurrent execution limits
    if (this.activeWorkflows.get(workflowId)?.length >= workflowConfig.maxConcurrent) {
      // Queue the workflow
      return this.queueWorkflow(workflowId, data, options);
    }

    // Get current key and handle
    const keyInfo = await this.keyManager.getKeyInfo(workflow.keyId);
    const handleInfo = this.handleManager.getHandleInfo(workflow.handleId);

    // Check if key or handle needs rotation
    if (keyInfo.needsRotation || handleInfo.needsRotation) {
      await this.rotateWorkflowComponents(workflowId);
    }

    // Create execution context
    const executionId = this.generateExecutionId(workflowId);
    const executionContext = {
      id: executionId,
      workflowId,
      keyId: workflow.keyId,
      handleId: workflow.handleId,
      data,
      options,
      startedAt: Date.now(),
      status: 'running'
    };

    // Track active workflow
    if (!this.activeWorkflows.has(workflowId)) {
      this.activeWorkflows.set(workflowId, []);
    }
    this.activeWorkflows.get(workflowId).push(executionContext);

    try {
      // Execute the workflow
      const result = await this.executeWithTimeout(
        () => this.handleManager.executeWorkflow(workflow.handleId, data, workflow.config.workflowFunction),
        workflowConfig.timeout
      );

      // Update execution context
      executionContext.status = 'completed';
      executionContext.completedAt = Date.now();
      executionContext.duration = executionContext.completedAt - executionContext.startedAt;
      executionContext.result = result;

      // Update workflow metrics
      workflow.executionCount++;
      workflow.lastExecuted = Date.now();
      this.workflows.set(workflowId, workflow);

      // Update global metrics
      this.metrics.successfulWorkflows++;
      this.metrics.totalWorkflows++;

      // Reset circuit breaker
      this.resetCircuitBreaker(workflowId);

      this.emit('workflowExecuted', { executionId, workflowId, result, duration: executionContext.duration });

      return result;
    } catch (error) {
      // Update execution context
      executionContext.status = 'failed';
      executionContext.completedAt = Date.now();
      executionContext.duration = executionContext.completedAt - executionContext.startedAt;
      executionContext.error = error.message;

      // Update workflow metrics
      workflow.errorCount++;
      workflow.lastError = error.message;
      this.workflows.set(workflowId, workflow);

      // Update global metrics
      this.metrics.failedWorkflows++;
      this.metrics.totalWorkflows++;

      // Update circuit breaker
      this.updateCircuitBreaker(workflowId, error);

      this.emit('workflowError', { executionId, workflowId, error: error.message });

      throw error;
    } finally {
      // Remove from active workflows
      const activeWorkflows = this.activeWorkflows.get(workflowId);
      const index = activeWorkflows.findIndex(w => w.id === executionId);
      if (index > -1) {
        activeWorkflows.splice(index, 1);
      }

      // Process queued workflows
      await this.processQueuedWorkflows(workflowId);
    }
  }

  /**
   * Rotate workflow components (key and handle)
   * @param {string} workflowId - Workflow identifier
   */
  async rotateWorkflowComponents(workflowId) {
    const workflow = this.workflows.get(workflowId);
    if (!workflow) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    try {
      // Rotate key
      const keyGenerator = (oldKey) => this.generateKeyValue(oldKey.type);
      await this.keyManager.rotateKey(workflow.keyId, keyGenerator);
      this.metrics.keyRotations++;

      // Rotate handle
      const handleGenerator = (oldHandle) => ({
        ...oldHandle.config,
        rotatedAt: Date.now(),
        version: oldHandle.metadata.version + 1
      });
      await this.handleManager.rotateHandle(workflow.handleId, handleGenerator);
      this.metrics.handleRotations++;

      this.emit('workflowComponentsRotated', { workflowId, keyId: workflow.keyId, handleId: workflow.handleId });
    } catch (error) {
      console.error(`Failed to rotate components for workflow ${workflowId}:`, error.message);
      throw error;
    }
  }

  /**
   * Get workflow information
   * @param {string} workflowId - Workflow identifier
   * @returns {Object} Workflow information
   */
  getWorkflowInfo(workflowId) {
    if (!this.workflows.has(workflowId)) {
      throw new Error(`Workflow not found: ${workflowId}`);
    }

    const workflow = this.workflows.get(workflowId);
    const activeExecutions = this.activeWorkflows.get(workflowId) || [];
    const queuedWorkflows = this.workflowQueue.get(workflowId) || [];

    return {
      ...workflow,
      activeExecutions: activeExecutions.length,
      queuedWorkflows: queuedWorkflows.length,
      circuitBreakerStatus: this.getCircuitBreakerStatus(workflowId),
      keyInfo: this.keyManager.getKeyInfo(workflow.keyId),
      handleInfo: this.handleManager.getHandleInfo(workflow.handleId)
    };
  }

  /**
   * Get all workflows
   * @returns {Array} Array of workflow information
   */
  getAllWorkflows() {
    const workflows = [];
    for (const [workflowId] of this.workflows) {
      workflows.push(this.getWorkflowInfo(workflowId));
    }
    return workflows;
  }

  /**
   * Get workflows by type
   * @param {string} workflowType - Workflow type
   * @returns {Array} Array of workflows of the specified type
   */
  getWorkflowsByType(workflowType) {
    const workflows = [];
    for (const [workflowId, workflow] of this.workflows) {
      if (workflow.type === workflowType) {
        workflows.push(this.getWorkflowInfo(workflowId));
      }
    }
    return workflows;
  }

  /**
   * Get orchestration statistics
   * @returns {Object} Orchestration statistics
   */
  getOrchestrationStats() {
    return {
      workflows: {
        total: this.workflows.size,
        byType: this.getWorkflowTypeStats(),
        active: this.getActiveWorkflowCount(),
        queued: this.getQueuedWorkflowCount()
      },
      metrics: { ...this.metrics },
      keyManager: this.keyManager.getMonitoringStats(),
      handleManager: this.handleManager.getMonitoringStats(),
      circuitBreakers: this.getCircuitBreakerStats()
    };
  }

  /**
   * Start monitoring
   */
  async startMonitoring() {
    if (this.monitoring) {
      return;
    }

    this.monitoring = true;

    // Monitor metrics
    setInterval(() => {
      this.updateMetrics();
    }, this.config.monitoring.metricsInterval);

    // Health checks
    if (this.config.monitoring.enableHealthChecks) {
      setInterval(() => {
        this.performHealthChecks();
      }, this.config.monitoring.healthCheckInterval);
    }

    // Check for workflows needing rotation
    setInterval(() => {
      this.checkWorkflowRotations();
    }, 15 * 60 * 1000); // Every 15 minutes

    console.log('✅ Workflow orchestration monitoring started');
  }

  /**
   * Stop monitoring
   */
  stopMonitoring() {
    this.monitoring = false;
    console.log('⏹️ Workflow orchestration monitoring stopped');
  }

  // Private methods

  /**
   * Set up event listeners for key and handle managers
   */
  setupEventListeners() {
    // Key manager events
    this.keyManager.on('keyRegistered', (data) => {
      this.emit('keyRegistered', data);
    });

    this.keyManager.on('keyRotated', (data) => {
      this.emit('keyRotated', data);
    });

    this.keyManager.on('keyExpired', (data) => {
      this.emit('keyExpired', data);
    });

    // Handle manager events
    this.handleManager.on('handleCreated', (data) => {
      this.emit('handleCreated', data);
    });

    this.handleManager.on('handleRotated', (data) => {
      this.emit('handleRotated', data);
    });

    this.handleManager.on('workflowExecuted', (data) => {
      this.emit('workflowExecuted', data);
    });

    this.handleManager.on('workflowError', (data) => {
      this.emit('workflowError', data);
    });
  }

  /**
   * Queue a workflow for execution
   * @param {string} workflowId - Workflow identifier
   * @param {Object} data - Input data
   * @param {Object} options - Execution options
   */
  async queueWorkflow(workflowId, data, options) {
    if (!this.workflowQueue.has(workflowId)) {
      this.workflowQueue.set(workflowId, []);
    }

    const queuedWorkflow = {
      id: this.generateExecutionId(workflowId),
      workflowId,
      data,
      options,
      queuedAt: Date.now()
    };

    this.workflowQueue.get(workflowId).push(queuedWorkflow);
    this.metrics.queuedWorkflows++;

    this.emit('workflowQueued', queuedWorkflow);

    // Return a promise that resolves when the workflow is executed
    return new Promise((resolve, reject) => {
      queuedWorkflow.resolve = resolve;
      queuedWorkflow.reject = reject;
    });
  }

  /**
   * Process queued workflows for a specific workflow type
   * @param {string} workflowId - Workflow identifier
   */
  async processQueuedWorkflows(workflowId) {
    const queue = this.workflowQueue.get(workflowId);
    if (!queue || queue.length === 0) {
      return;
    }

    const workflow = this.workflows.get(workflowId);
    const workflowConfig = this.config.workflowTypes[workflow.type];
    const activeCount = this.activeWorkflows.get(workflowId)?.length || 0;

    while (queue.length > 0 && activeCount < workflowConfig.maxConcurrent) {
      const queuedWorkflow = queue.shift();
      this.metrics.queuedWorkflows--;

      try {
        const result = await this.executeWorkflow(workflowId, queuedWorkflow.data, queuedWorkflow.options);
        queuedWorkflow.resolve(result);
      } catch (error) {
        queuedWorkflow.reject(error);
      }
    }
  }

  /**
   * Execute workflow with timeout
   * @param {Function} workflowFunction - Workflow function
   * @param {number} timeout - Timeout in milliseconds
   */
  async executeWithTimeout(workflowFunction, timeout) {
    return Promise.race([
      workflowFunction(),
      new Promise((_, reject) => {
        setTimeout(() => {
          reject(new Error('Workflow execution timeout'));
        }, timeout);
      })
    ]);
  }

  /**
   * Check circuit breaker status
   * @param {string} workflowId - Workflow identifier
   * @returns {boolean} True if circuit breaker is open
   */
  isCircuitBreakerOpen(workflowId) {
    if (!this.config.orchestration.enableCircuitBreaker) {
      return false;
    }

    const circuitBreaker = this.circuitBreakers.get(workflowId);
    if (!circuitBreaker) {
      return false;
    }

    return circuitBreaker.status === 'open' && 
           Date.now() < circuitBreaker.nextAttempt;
  }

  /**
   * Update circuit breaker
   * @param {string} workflowId - Workflow identifier
   * @param {Error} error - Error that occurred
   */
  updateCircuitBreaker(workflowId, error) {
    if (!this.config.orchestration.enableCircuitBreaker) {
      return;
    }

    let circuitBreaker = this.circuitBreakers.get(workflowId);
    if (!circuitBreaker) {
      circuitBreaker = {
        failureCount: 0,
        status: 'closed',
        lastFailure: null,
        nextAttempt: null
      };
    }

    circuitBreaker.failureCount++;
    circuitBreaker.lastFailure = Date.now();

    if (circuitBreaker.failureCount >= this.config.orchestration.circuitBreakerThreshold) {
      circuitBreaker.status = 'open';
      circuitBreaker.nextAttempt = Date.now() + this.config.orchestration.retryDelay;
    }

    this.circuitBreakers.set(workflowId, circuitBreaker);
  }

  /**
   * Reset circuit breaker
   * @param {string} workflowId - Workflow identifier
   */
  resetCircuitBreaker(workflowId) {
    if (!this.config.orchestration.enableCircuitBreaker) {
      return;
    }

    this.circuitBreakers.delete(workflowId);
  }

  /**
   * Get circuit breaker status
   * @param {string} workflowId - Workflow identifier
   * @returns {Object} Circuit breaker status
   */
  getCircuitBreakerStatus(workflowId) {
    if (!this.config.orchestration.enableCircuitBreaker) {
      return { status: 'disabled' };
    }

    const circuitBreaker = this.circuitBreakers.get(workflowId);
    if (!circuitBreaker) {
      return { status: 'closed', failureCount: 0 };
    }

    return {
      ...circuitBreaker,
      isOpen: this.isCircuitBreakerOpen(workflowId)
    };
  }

  /**
   * Generate key value based on type
   * @param {string} keyType - Key type
   * @returns {string} Generated key value
   */
  generateKeyValue(keyType) {
    const crypto = require('crypto');
    
    switch (keyType) {
      case 'jwt':
        return crypto.randomBytes(32).toString('hex');
      case 'encryption':
        return crypto.randomBytes(32);
      case 'api':
        return crypto.randomBytes(16).toString('hex');
      case 'oauth':
        return crypto.randomBytes(24).toString('hex');
      default:
        return crypto.randomBytes(16).toString('hex');
    }
  }

  /**
   * Generate execution ID
   * @param {string} workflowId - Workflow identifier
   * @returns {string} Unique execution ID
   */
  generateExecutionId(workflowId) {
    const crypto = require('crypto');
    return `${workflowId}_exec_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  /**
   * Update metrics
   */
  updateMetrics() {
    this.metrics.activeWorkflows = this.getActiveWorkflowCount();
    this.metrics.queuedWorkflows = this.getQueuedWorkflowCount();
  }

  /**
   * Perform health checks
   */
  performHealthChecks() {
    const healthStatus = {
      keyManager: this.keyManager.initialized,
      handleManager: this.handleManager.initialized,
      workflows: this.workflows.size,
      activeWorkflows: this.getActiveWorkflowCount(),
      timestamp: Date.now()
    };

    this.emit('healthCheck', healthStatus);
  }

  /**
   * Check for workflows needing rotation
   */
  async checkWorkflowRotations() {
    for (const [workflowId, workflow] of this.workflows) {
      const keyInfo = await this.keyManager.getKeyInfo(workflow.keyId);
      const handleInfo = this.handleManager.getHandleInfo(workflow.handleId);

      if (keyInfo.needsRotation || handleInfo.needsRotation) {
        this.emit('workflowRotationNeeded', { workflowId, keyInfo, handleInfo });
      }
    }
  }

  /**
   * Get workflow type statistics
   * @returns {Object} Workflow type statistics
   */
  getWorkflowTypeStats() {
    const stats = {};
    
    for (const [workflowId, workflow] of this.workflows) {
      if (!stats[workflow.type]) {
        stats[workflow.type] = 0;
      }
      stats[workflow.type]++;
    }
    
    return stats;
  }

  /**
   * Get active workflow count
   * @returns {number} Number of active workflows
   */
  getActiveWorkflowCount() {
    let count = 0;
    for (const [workflowId, executions] of this.activeWorkflows) {
      count += executions.length;
    }
    return count;
  }

  /**
   * Get queued workflow count
   * @returns {number} Number of queued workflows
   */
  getQueuedWorkflowCount() {
    let count = 0;
    for (const [workflowId, queue] of this.workflowQueue) {
      count += queue.length;
    }
    return count;
  }

  /**
   * Get circuit breaker statistics
   * @returns {Object} Circuit breaker statistics
   */
  getCircuitBreakerStats() {
    const stats = {
      total: this.circuitBreakers.size,
      open: 0,
      closed: 0
    };

    for (const [workflowId, circuitBreaker] of this.circuitBreakers) {
      if (circuitBreaker.status === 'open') {
        stats.open++;
      } else {
        stats.closed++;
      }
    }

    return stats;
  }
}

module.exports = WorkflowOrchestrationManager;
