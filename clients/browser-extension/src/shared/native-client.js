/**
 * AMPass Extension - Native Messaging Client
 * 
 * SECURITY:
 * - Communicates with AMPass desktop app via Chrome Native Messaging
 * - Optional: extension works without desktop app (falls back to server API)
 * - Never sends plaintext secrets through window.postMessage
 * - Never persists plaintext in extension storage
 * - Desktop app must be unlocked to return sensitive data
 * - All responses validated before use
 */

const NativeClient = {
  HOST_NAME: 'com.ampass.desktop',
  _port: null,
  _connected: false,
  _available: null, // null = unknown, true/false = tested
  _pendingRequests: new Map(),
  _requestCounter: 0,
  _enabled: false,

  /**
   * Check if native messaging is enabled in settings
   */
  async isEnabled() {
    const settings = await Storage.getSettings();
    return settings.useDesktopBridge === true;
  },

  /**
   * Test if the native host is available
   * Returns true/false. Caches result for the session.
   */
  async isAvailable() {
    if (this._available !== null) return this._available;

    this._enabled = await this.isEnabled();
    if (!this._enabled) {
      this._available = false;
      return false;
    }

    try {
      const response = await this.sendMessage({ type: 'ping' }, 3000);
      this._available = response && response.success && response.msg_type === 'pong';
    } catch (e) {
      this._available = false;
    }

    return this._available;
  },

  /**
   * Connect to the native host
   */
  connect() {
    if (this._port) return;

    try {
      this._port = chrome.runtime.connectNative(this.HOST_NAME);

      this._port.onMessage.addListener((msg) => {
        this._handleResponse(msg);
      });

      this._port.onDisconnect.addListener(() => {
        this._port = null;
        this._connected = false;
        this._available = false;
        // Reject all pending requests
        for (const [id, { reject }] of this._pendingRequests) {
          reject(new Error('Native host disconnected'));
        }
        this._pendingRequests.clear();
      });

      this._connected = true;
    } catch (e) {
      this._port = null;
      this._connected = false;
      this._available = false;
    }
  },

  /**
   * Disconnect from native host
   */
  disconnect() {
    if (this._port) {
      this._port.disconnect();
      this._port = null;
    }
    this._connected = false;
  },

  /**
   * Send a message and wait for response (with timeout)
   */
  sendMessage(message, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      if (!this._enabled) {
        reject(new Error('Native messaging disabled'));
        return;
      }

      if (!this._port) {
        this.connect();
      }

      if (!this._port) {
        reject(new Error('Cannot connect to native host'));
        return;
      }

      // Add request ID for correlation
      const requestId = String(++this._requestCounter);
      message.request_id = requestId;

      // Set up timeout
      const timer = setTimeout(() => {
        this._pendingRequests.delete(requestId);
        reject(new Error('Native messaging timeout'));
      }, timeoutMs);

      // Store pending request
      this._pendingRequests.set(requestId, { resolve, reject, timer });

      // Send message
      try {
        this._port.postMessage(message);
      } catch (e) {
        clearTimeout(timer);
        this._pendingRequests.delete(requestId);
        reject(new Error('Failed to send native message'));
      }
    });
  },

  /**
   * Handle incoming response from native host
   */
  _handleResponse(msg) {
    const requestId = msg.request_id;
    if (!requestId || !this._pendingRequests.has(requestId)) {
      // Unsolicited message — ignore
      return;
    }

    const { resolve, timer } = this._pendingRequests.get(requestId);
    clearTimeout(timer);
    this._pendingRequests.delete(requestId);
    resolve(msg);
  },

  // ===== High-Level API =====

  /**
   * Get vault lock status from desktop app
   */
  async getStatus() {
    const response = await this.sendMessage({ type: 'get_status' });
    return response;
  },

  /**
   * Open/focus the desktop app unlock window.
   * SECURITY: Does not pass any secrets. Only tells desktop to show unlock UI.
   */
  async openUnlockWindow(reason = 'browser_request', pageHost = '') {
    return await this.sendMessage({
      type: 'open_unlock_window',
      payload: { reason, page_url_host: pageHost }
    }, 10000); // longer timeout for app launch
  },

  /**
   * Focus the main desktop window
   */
  async focusMainWindow() {
    return await this.sendMessage({ type: 'focus_main_window' });
  },

  /**
   * Request vault unlock (user must unlock in desktop app)
   */
  async requestUnlock() {
    return await this.sendMessage({ type: 'unlock_request' });
  },

  /**
   * Lock the vault via desktop app
   */
  async lockVault() {
    return await this.sendMessage({ type: 'lock' });
  },

  /**
   * Search vault by domain (for autofill)
   */
  async searchByDomain(domain) {
    return await this.sendMessage({
      type: 'search_by_domain',
      payload: { domain }
    });
  },

  /**
   * Get item for autofill
   */
  async getItemForAutofill(itemId) {
    return await this.sendMessage({
      type: 'get_item_for_autofill',
      payload: { item_id: itemId }
    });
  },

  /**
   * Save a detected login
   */
  async saveDetectedLogin(data) {
    return await this.sendMessage({
      type: 'save_detected_login',
      payload: data
    });
  },

  /**
   * Update a detected login
   */
  async updateDetectedLogin(data) {
    return await this.sendMessage({
      type: 'update_detected_login',
      payload: data
    });
  },

  /**
   * Generate a password via desktop app
   */
  async generatePassword(options = {}) {
    return await this.sendMessage({
      type: 'generate_password',
      payload: options
    });
  },

  /**
   * Send an audit event
   */
  async auditEvent(action, details = {}) {
    try {
      await this.sendMessage({
        type: 'audit_event',
        payload: { action, ...details }
      }, 2000);
    } catch (e) {
      // Audit events are fire-and-forget
    }
  },

  /**
   * Get connection status for UI display
   */
  getConnectionStatus() {
    if (!this._enabled) return 'disabled';
    if (this._available === null) return 'unknown';
    if (this._connected && this._available) return 'connected';
    return 'disconnected';
  }
};

if (typeof globalThis !== 'undefined') {
  globalThis.NativeClient = NativeClient;
}
