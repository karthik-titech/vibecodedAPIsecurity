const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');
const EventEmitter = require('events');

/**
 * Workflow Handle Rotation Manager for Vibe-Coded Applications
 * Manages workflow handles, session rotation, and workflow lifecycle
 */
class WorkflowHandleRotationManager extends EventEmitter {
  constructor(options = {}) {
    super();
    
    this.config = {
      handleTypes: {
        session: options.sessionRotation || 30 * 60 * 1000,
        api: options.apiRotation || 60 * 60 * 1000,
        webhook: options.webhookRotation || 24 * 60 * 60 * 1000,
        oauth: options.oauthRotation || 7 * 24 * 60 * 60 * 1000,
        batch: options.batchRotation || 12 * 60 * 60 * 1000
      },
      rotation: {
        enableAutoRotation: options.enableAutoRotation !== false,
        rotationThreshold: options.rotationThreshold || 0.2,
        gracePeriod: options.gracePeriod || 5 * 60 * 1000,
        maxHandleVersions: options.maxHandleVersions || 5
      },
      session: {
        maxConcurrentSessions: options.maxConcurrentSessions || 100,
        sessionTimeout: options.sessionTimeout || 30 * 60 * 1000,
        idleTimeout: options.idleTimeout || 15 * 60 * 1000
      },
      storage: {
        handleStorePath: options.handleStorePath || '.workflows',
        backupPath: options.backupPath || '.workflows/backup',
        sessionStorePath: options.sessionStorePath || '.workflows/sessions',
        encryptionKey: process.env.WORKFLOW_ENCRYPTION_KEY || crypto.randomBytes(32)
      }
    };
    
    this.handles = new Map();
    this.sessions = new Map();
    this.rotationQueue = new Map();
    this.expiryTimers = new Map();
    this.initialized = false;
    this.monitoring = false;
  }

  async initialize() {
    try {
      await fs.mkdir(this.config.storage.handleStorePath, { recursive: true });
      await fs.mkdir(this.config.storage.backupPath, { recursive: true });
      await fs.mkdir(this.config.storage.sessionStorePath, { recursive: true });
      
      await this.loadExistingHandles();
      await this.loadExistingSessions();
      
      if (this.config.rotation.enableAutoRotation) {
        await this.startMonitoring();
      }
      
      this.initialized = true;
      console.log('✅ Workflow Handle Rotation Manager initialized');
    } catch (error) {
      console.error('❌ Workflow Handle Rotation Manager initialization failed:', error.message);
      throw error;
    }
  }

  async createWorkflowHandle(workflowId, handleType, workflowConfig = {}, metadata = {}) {
    if (!this.initialized) await this.initialize();

    const rotationTime = this.config.handleTypes[handleType];
    if (!rotationTime) throw new Error(`Unknown handle type: ${handleType}`);

    const handleId = this.generateHandleId(workflowId, handleType);
    
    const handleInfo = {
      id: handleId,
      workflowId,
      type: handleType,
      config: workflowConfig,
      createdAt: Date.now(),
      expiresAt: Date.now() + rotationTime,
      metadata: { ...metadata, version: 1, rotationCount: 0, status: 'active' },
      sessionId: null,
      executionCount: 0,
      lastExecuted: null,
      errorCount: 0
    };

    await this.storeHandle(handleInfo);
    this.handles.set(handleId, handleInfo);
    this.setupRotationTimer(handleId, handleInfo.expiresAt);

    this.emit('handleCreated', { handleId, workflowId, handleType, expiresAt: handleInfo.expiresAt });
    return handleInfo;
  }

  async rotateHandle(handleId, handleGenerator) {
    if (!this.handles.has(handleId)) throw new Error(`Handle not found: ${handleId}`);

    const oldHandle = this.handles.get(handleId);
    
    try {
      const newHandleConfig = await handleGenerator(oldHandle);
      
      const newHandleInfo = {
        ...oldHandle,
        config: newHandleConfig,
        createdAt: Date.now(),
        expiresAt: Date.now() + this.config.handleTypes[oldHandle.type],
        metadata: {
          ...oldHandle.metadata,
          version: oldHandle.metadata.version + 1,
          rotationCount: oldHandle.metadata.rotationCount + 1,
          rotatedFrom: oldHandle.id
        },
        executionCount: 0,
        lastExecuted: null,
        errorCount: 0
      };

      await this.storeHandle(newHandleInfo);
      this.handles.set(handleId, newHandleInfo);
      this.clearTimers(handleId);
      this.setupRotationTimer(handleId, newHandleInfo.expiresAt);

      this.emit('handleRotated', { handleId, oldHandle, newHandle: newHandleInfo });
      return newHandleInfo;
    } catch (error) {
      console.error(`Failed to rotate handle ${handleId}:`, error.message);
      throw error;
    }
  }

  async createSession(handleId, sessionData = {}) {
    if (!this.handles.has(handleId)) throw new Error(`Handle not found: ${handleId}`);

    const handle = this.handles.get(handleId);
    const sessionId = this.generateSessionId(handleId);
    
    const sessionInfo = {
      id: sessionId,
      handleId,
      workflowId: handle.workflowId,
      createdAt: Date.now(),
      expiresAt: Date.now() + this.config.session.sessionTimeout,
      lastActivity: Date.now(),
      data: sessionData,
      status: 'active'
    };

    await this.storeSession(sessionInfo);
    this.sessions.set(sessionId, sessionInfo);
    
    handle.sessionId = sessionId;
    this.handles.set(handleId, handle);
    
    this.setupSessionTimer(sessionId, sessionInfo.expiresAt);

    this.emit('sessionCreated', { sessionId, handleId, workflowId: handle.workflowId });
    return sessionInfo;
  }

  async executeWorkflow(handleId, executionData = {}, workflowFunction) {
    if (!this.handles.has(handleId)) throw new Error(`Handle not found: ${handleId}`);

    const handle = this.handles.get(handleId);
    if (handle.metadata.status !== 'active') throw new Error(`Handle ${handleId} is not active`);

    const executionId = this.generateExecutionId(handleId);
    const startTime = Date.now();
    
    const executionInfo = {
      id: executionId,
      handleId,
      workflowId: handle.workflowId,
      startedAt: startTime,
      data: executionData,
      status: 'running'
    };

    try {
      const result = await this.executeWithRetry(workflowFunction, executionData, handleId);
      
      executionInfo.status = 'completed';
      executionInfo.completedAt = Date.now();
      executionInfo.duration = executionInfo.completedAt - startTime;
      executionInfo.result = result;
      
      handle.executionCount++;
      handle.lastExecuted = Date.now();
      this.handles.set(handleId, handle);
      
      this.emit('workflowExecuted', { executionId, handleId, result, duration: executionInfo.duration });
      return result;
    } catch (error) {
      executionInfo.status = 'failed';
      executionInfo.completedAt = Date.now();
      executionInfo.duration = executionInfo.completedAt - startTime;
      executionInfo.error = error.message;
      
      handle.errorCount++;
      handle.lastError = error.message;
      this.handles.set(handleId, handle);
      
      this.emit('workflowError', { executionId, handleId, error: error.message });
      throw error;
    }
  }

  getHandleInfo(handleId) {
    if (!this.handles.has(handleId)) throw new Error(`Handle not found: ${handleId}`);
    
    const handleInfo = this.handles.get(handleId);
    return {
      ...handleInfo,
      config: undefined,
      timeUntilExpiry: handleInfo.expiresAt - Date.now(),
      isExpired: Date.now() > handleInfo.expiresAt,
      needsRotation: this.shouldRotate(handleInfo)
    };
  }

  getHandlesByType(handleType) {
    const handles = [];
    for (const [handleId, handleInfo] of this.handles) {
      if (handleInfo.type === handleType) {
        handles.push(this.getHandleInfo(handleId));
      }
    }
    return handles;
  }

  getHandlesNeedingRotation() {
    const handlesNeedingRotation = [];
    for (const [handleId, handleInfo] of this.handles) {
      if (this.shouldRotate(handleInfo)) {
        handlesNeedingRotation.push(this.getHandleInfo(handleId));
      }
    }
    return handlesNeedingRotation;
  }

  async startMonitoring() {
    if (this.monitoring) return;

    this.monitoring = true;
    
    setInterval(async () => {
      await this.checkRotationNeeds();
    }, 15 * 60 * 1000);

    setInterval(async () => {
      await this.checkExpiredSessions();
    }, 5 * 60 * 1000);

    console.log('✅ Workflow handle monitoring started');
  }

  getMonitoringStats() {
    const stats = {
      totalHandles: this.handles.size,
      activeHandles: 0,
      revokedHandles: 0,
      handlesNeedingRotation: 0,
      totalSessions: this.sessions.size,
      activeSessions: 0,
      expiredSessions: 0,
      byType: {}
    };

    for (const [handleId, handleInfo] of this.handles) {
      if (handleInfo.metadata.status === 'active') {
        stats.activeHandles++;
      } else if (handleInfo.metadata.status === 'revoked') {
        stats.revokedHandles++;
      }

      if (this.shouldRotate(handleInfo)) {
        stats.handlesNeedingRotation++;
      }

      if (!stats.byType[handleInfo.type]) {
        stats.byType[handleInfo.type] = 0;
      }
      stats.byType[handleInfo.type]++;
    }

    for (const [sessionId, sessionInfo] of this.sessions) {
      if (sessionInfo.status === 'active') {
        stats.activeSessions++;
      } else if (Date.now() > sessionInfo.expiresAt) {
        stats.expiredSessions++;
      }
    }

    return stats;
  }

  // Private methods
  shouldRotate(handleInfo) {
    if (handleInfo.metadata.status !== 'active') return false;

    const timeUntilExpiry = handleInfo.expiresAt - Date.now();
    const rotationThreshold = this.config.handleTypes[handleInfo.type] * this.config.rotation.rotationThreshold;
    
    return timeUntilExpiry <= rotationThreshold;
  }

  setupRotationTimer(handleId, expiresAt) {
    const timeUntilExpiry = expiresAt - Date.now();
    const rotationThreshold = this.config.handleTypes[this.handles.get(handleId).type] * this.config.rotation.rotationThreshold;
    
    if (timeUntilExpiry > rotationThreshold) {
      const timer = setTimeout(async () => {
        await this.handleRotation(handleId);
      }, timeUntilExpiry - rotationThreshold);
      
      this.rotationQueue.set(handleId, timer);
    }
  }

  setupSessionTimer(sessionId, expiresAt) {
    const timeUntilExpiry = expiresAt - Date.now();
    
    if (timeUntilExpiry > 0) {
      const timer = setTimeout(async () => {
        await this.handleSessionExpiry(sessionId);
      }, timeUntilExpiry);
      
      this.expiryTimers.set(sessionId, timer);
    }
  }

  clearTimers(handleId) {
    if (this.rotationQueue.has(handleId)) {
      clearTimeout(this.rotationQueue.get(handleId));
      this.rotationQueue.delete(handleId);
    }
  }

  async handleRotation(handleId) {
    const handleInfo = this.handles.get(handleId);
    if (!handleInfo || !this.shouldRotate(handleInfo)) return;

    const defaultHandleGenerator = (oldHandle) => {
      return {
        ...oldHandle.config,
        rotatedAt: Date.now(),
        version: oldHandle.metadata.version + 1
      };
    };

    try {
      await this.rotateHandle(handleId, defaultHandleGenerator);
    } catch (error) {
      console.error(`Automatic rotation failed for handle ${handleId}:`, error.message);
    }
  }

  async handleSessionExpiry(sessionId) {
    const sessionInfo = this.sessions.get(sessionId);
    if (!sessionInfo) return;

    sessionInfo.status = 'expired';
    sessionInfo.expiredAt = Date.now();

    this.emit('sessionExpired', { sessionId, handleId: sessionInfo.handleId, expiredAt: sessionInfo.expiredAt });
  }

  async executeWithRetry(workflowFunction, executionData, handleId) {
    let lastError;
    
    for (let attempt = 1; attempt <= 3; attempt++) {
      try {
        return await workflowFunction(executionData);
      } catch (error) {
        lastError = error;
        
        if (attempt < 3) {
          await this.delay(5 * 60 * 1000);
        }
      }
    }
    
    throw lastError;
  }

  async checkRotationNeeds() {
    const handlesNeedingRotation = this.getHandlesNeedingRotation();
    
    if (handlesNeedingRotation.length > 0) {
      this.emit('rotationNeeded', { handles: handlesNeedingRotation });
    }
  }

  async checkExpiredSessions() {
    const expiredSessions = [];
    for (const [sessionId, sessionInfo] of this.sessions) {
      if (Date.now() > sessionInfo.expiresAt) {
        expiredSessions.push(sessionInfo);
      }
    }
    
    if (expiredSessions.length > 0) {
      this.emit('sessionsExpired', { sessions: expiredSessions });
    }
  }

  generateHandleId(workflowId, handleType) {
    return `${workflowId}_${handleType}_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  generateSessionId(handleId) {
    return `${handleId}_session_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  generateExecutionId(handleId) {
    return `${handleId}_exec_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;
  }

  async storeHandle(handleInfo) {
    const encryptedConfig = this.encrypt(JSON.stringify(handleInfo.config));
    const handleData = { ...handleInfo, config: encryptedConfig };
    
    const filePath = path.join(this.config.storage.handleStorePath, `${handleInfo.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(handleData, null, 2));
  }

  async storeSession(sessionInfo) {
    const encryptedData = this.encrypt(JSON.stringify(sessionInfo.data));
    const sessionData = { ...sessionInfo, data: encryptedData };
    
    const filePath = path.join(this.config.storage.sessionStorePath, `${sessionInfo.id}.json`);
    await fs.writeFile(filePath, JSON.stringify(sessionData, null, 2));
  }

  async loadExistingHandles() {
    try {
      const files = await fs.readdir(this.config.storage.handleStorePath);
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const filePath = path.join(this.config.storage.handleStorePath, file);
          const handleData = JSON.parse(await fs.readFile(filePath, 'utf8'));
          
          handleData.config = JSON.parse(this.decrypt(handleData.config));
          
          this.handles.set(handleData.id, handleData);
          
          if (handleData.metadata.status === 'active') {
            this.setupRotationTimer(handleData.id, handleData.expiresAt);
          }
        }
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  async loadExistingSessions() {
    try {
      const files = await fs.readdir(this.config.storage.sessionStorePath);
      
      for (const file of files) {
        if (file.endsWith('.json')) {
          const filePath = path.join(this.config.storage.sessionStorePath, file);
          const sessionData = JSON.parse(await fs.readFile(filePath, 'utf8'));
          
          sessionData.data = JSON.parse(this.decrypt(sessionData.data));
          
          this.sessions.set(sessionData.id, sessionData);
          
          if (sessionData.status === 'active') {
            this.setupSessionTimer(sessionData.id, sessionData.expiresAt);
          }
        }
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
    }
  }

  encrypt(data) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipher('aes-256-gcm', this.config.storage.encryptionKey);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const authTag = cipher.getAuthTag();
    
    return JSON.stringify({
      iv: iv.toString('hex'),
      encrypted: encrypted,
      authTag: authTag.toString('hex')
    });
  }

  decrypt(encryptedData) {
    const data = JSON.parse(encryptedData);
    const decipher = crypto.createDecipher('aes-256-gcm', this.config.storage.encryptionKey);
    
    decipher.setAuthTag(Buffer.from(data.authTag, 'hex'));
    
    let decrypted = decipher.update(data.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

module.exports = WorkflowHandleRotationManager;
