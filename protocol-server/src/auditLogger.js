const fs = require('fs');
const path = require('path');

/**
 * Comprehensive logging and auditing system for PAAP v2
 */

class AuditLogger {
  constructor(options = {}) {
    this.logLevel = options.logLevel || 'info'; // debug, info, warn, error
    this.logToFile = options.logToFile !== false;
    this.logFilePath = options.logFilePath || path.join(process.cwd(), 'paap-audit.log');
    this.enableConsole = options.enableConsole !== false;
    this.sensitiveFields = new Set(options.sensitiveFields || [
      'issuanceCode', 'blinded', 'tokenInput', 'blindFactor', 'signature'
    ]);
  }

  formatTimestamp() {
    return new Date().toISOString();
  }

  sanitize(data) {
    if (!data || typeof data !== 'object') return data;
    
    const sanitized = { ...data };
    for (const field of this.sensitiveFields) {
      if (sanitized[field]) {
        sanitized[field] = '[REDACTED]';
      }
    }
    return sanitized;
  }

  formatLogEntry(level, event, data = {}) {
    const entry = {
      timestamp: this.formatTimestamp(),
      level,
      event,
      ...this.sanitize(data)
    };
    return JSON.stringify(entry);
  }

  writeLog(entry) {
    if (this.logToFile) {
      try {
        fs.appendFileSync(this.logFilePath, entry + '\n');
      } catch (error) {
        if (this.enableConsole) {
          console.error('Failed to write to log file:', error.message);
        }
      }
    }

    if (this.enableConsole) {
      const parsed = JSON.parse(entry);
      const consoleMethod = this.levelToConsoleMethod(parsed.level);
      consoleMethod(`[${parsed.timestamp}] [${parsed.level.toUpperCase()}] ${parsed.event}`, this.sanitize(parsed));
    }
  }

  levelToConsoleMethod(level) {
    const methods = {
      debug: console.debug,
      info: console.info,
      warn: console.warn,
      error: console.error
    };
    return methods[level] || console.log;
  }

  shouldLog(level) {
    const levels = ['debug', 'info', 'warn', 'error'];
    return levels.indexOf(level) >= levels.indexOf(this.logLevel);
  }

  log(level, event, data = {}) {
    if (!this.shouldLog(level)) return;
    
    const entry = this.formatLogEntry(level, event, data);
    this.writeLog(entry);
  }

  debug(event, data) {
    this.log('debug', event, data);
  }

  info(event, data) {
    this.log('info', event, data);
  }

  warn(event, data) {
    this.log('warn', event, data);
  }

  error(event, data) {
    this.log('error', event, data);
  }

  // PAAP v2 specific audit events
  logIssuerRequest(clientIp, suiteId) {
    this.info('issuer_request', { clientIp, suiteId });
  }

  logIssuanceRequest(clientIp, contextId, suiteId) {
    this.info('issuance_request', { clientIp, contextId, suiteId });
  }

  logIssuanceSuccess(clientIp, contextId, suiteId, keyId) {
    this.info('issuance_success', { clientIp, contextId, suiteId, keyId });
  }

  logIssuanceFailure(clientIp, contextId, suiteId, reason) {
    this.warn('issuance_failure', { clientIp, contextId, suiteId, reason });
  }

  logRedeemRequest(clientIp, contextId, suiteId, keyId) {
    this.info('redeem_request', { clientIp, contextId, suiteId, keyId });
  }

  logRedeemSuccess(clientIp, contextId, suiteId, keyId) {
    this.info('redeem_success', { clientIp, contextId, suiteId, keyId });
  }

  logRedeemFailure(clientIp, contextId, suiteId, keyId, reason) {
    this.warn('redeem_failure', { clientIp, contextId, suiteId, keyId, reason });
  }

  logRateLimitExceeded(clientIp, endpoint) {
    this.warn('rate_limit_exceeded', { clientIp, endpoint });
  }

  logKeyRotation(oldKeyId, newKeyId) {
    this.info('key_rotation', { oldKeyId, newKeyId });
  }

  logServerStart(port, suiteId) {
    this.info('server_start', { port, suiteId });
  }

  logServerShutdown() {
    this.info('server_shutdown', {});
  }

  logSecurityEvent(event, data) {
    this.error('security_event', { event, ...data });
  }
}

// Singleton instance
let loggerInstance = null;

function getAuditLogger(options) {
  if (!loggerInstance) {
    loggerInstance = new AuditLogger(options);
  }
  return loggerInstance;
}

module.exports = {
  AuditLogger,
  getAuditLogger
};
