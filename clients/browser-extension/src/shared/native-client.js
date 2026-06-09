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

  _sessionKey: null,
  _handshakePromise: null,

  _bufferToHex(buffer) {
    return Array.from(buffer).map(b => b.toString(16).padStart(2, '0')).join('');
  },

  _hexToBuffer(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) {
      bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    }
    return bytes;
  },

  _pad(dataStr, blockSize = 16) {
    const encoder = new TextEncoder();
    const dataBytes = encoder.encode(dataStr);
    const paddingLen = blockSize - (dataBytes.length % blockSize);
    const padded = new Uint8Array(dataBytes.length + paddingLen);
    padded.set(dataBytes);
    padded.fill(paddingLen, dataBytes.length);
    return padded;
  },

  _unpad(paddedBytes) {
    const paddingLen = paddedBytes[paddedBytes.length - 1];
    if (paddingLen <= 0 || paddingLen > paddedBytes.length) {
      throw new Error('Invalid padding');
    }
    for (let i = 0; i < paddingLen; i++) {
      if (paddedBytes[paddedBytes.length - 1 - i] !== paddingLen) {
        throw new Error('Invalid padding bytes');
      }
    }
    const decoded = paddedBytes.slice(0, paddedBytes.length - paddingLen);
    return new TextDecoder().decode(decoded);
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
        this._sessionKey = null;
        this._handshakePromise = null;
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
    this._sessionKey = null;
    this._handshakePromise = null;
  },

  /**
   * Perform ephemeral ECDH (X25519) key exchange with native host
   */
  async _performHandshake() {
    if (this._handshakePromise) {
      return this._handshakePromise;
    }

    this._handshakePromise = (async () => {
      // 1. Generate X25519 key pair
      const keyPair = await crypto.subtle.generateKey(
        { name: 'X25519' },
        true,
        ['deriveKey', 'deriveBits']
      );

      // 2. Export public key to hex
      const rawPubKey = await crypto.subtle.exportKey('raw', keyPair.publicKey);
      const clientPubKeyHex = this._bufferToHex(new Uint8Array(rawPubKey));

      // 3. Send handshake_init message to host
      const handshakeMsg = {
        type: 'handshake_init',
        payload: { public_key: clientPubKeyHex }
      };

      const response = await this._sendRawMessage(handshakeMsg, 5000);
      if (!response || !response.success || response.msg_type !== 'handshake_response') {
        throw new Error('Handshake failed: invalid host response');
      }

      const serverPubKeyHex = response.data?.public_key;
      if (!serverPubKeyHex) {
        throw new Error('Handshake failed: missing host public key');
      }

      // 4. Import server public key
      const serverPubKeyBytes = this._hexToBuffer(serverPubKeyHex);
      const serverPubKey = await crypto.subtle.importKey(
        'raw',
        serverPubKeyBytes,
        { name: 'X25519' },
        true,
        []
      );

      // 5. Derive shared secret bits
      const sharedSecret = await crypto.subtle.deriveBits(
        {
          name: 'X25519',
          public: serverPubKey
        },
        keyPair.privateKey,
        256
      );

      // 6. Import shared secret as AES-GCM symmetric session key
      this._sessionKey = await crypto.subtle.importKey(
        'raw',
        sharedSecret,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );
    })();

    try {
      await this._handshakePromise;
    } finally {
      this._handshakePromise = null;
    }
  },

  /**
   * Internal helper to send a raw JSON message without encryption
   */
  _sendRawMessage(message, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      if (!this._port) {
        reject(new Error('Port not connected'));
        return;
      }

      const requestId = String(++this._requestCounter);
      message.request_id = requestId;

      const timer = setTimeout(() => {
        this._pendingRequests.delete(requestId);
        reject(new Error('Native messaging timeout'));
      }, timeoutMs);

      this._pendingRequests.set(requestId, { resolve, reject, timer });

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
   * Send an E2EE encrypted message and wait for response (with timeout)
   */
  async sendMessage(message, timeoutMs = 5000) {
    if (!this._enabled) {
      throw new Error('Native messaging disabled');
    }

    if (!this._port) {
      this.connect();
    }

    if (!this._port) {
      throw new Error('Cannot connect to native host');
    }

    // Handshake check
    if (message.type !== 'handshake_init' && !this._sessionKey) {
      await this._performHandshake();
    }

    // Encrypt the message payload
    const plaintext = JSON.stringify(message);
    const padded = this._pad(plaintext, 16);
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const ciphertextBuffer = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      this._sessionKey,
      padded
    );

    const ciphertextHex = this._bufferToHex(new Uint8Array(ciphertextBuffer));
    const ivHex = this._bufferToHex(iv);

    // Construct the wrapped message
    const wrappedMsg = {
      type: 'encrypted_payload',
      payload: {
        ciphertext: ciphertextHex,
        iv: ivHex
      }
    };

    const response = await this._sendRawMessage(wrappedMsg, timeoutMs);
    if (!response || !response.success) {
      throw new Error(response?.error || 'Native message error');
    }

    if (response.msg_type !== 'encrypted_payload') {
      throw new Error('Expected encrypted payload from native host');
    }

    const respCiphertextHex = response.data?.ciphertext;
    const respIvHex = response.data?.iv;

    if (!respCiphertextHex || !respIvHex) {
      throw new Error('Invalid encrypted response format');
    }

    const respCiphertext = this._hexToBuffer(respCiphertextHex);
    const respIv = this._hexToBuffer(respIvHex);

    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: respIv },
      this._sessionKey,
      respCiphertext
    );

    const decryptedStr = this._unpad(new Uint8Array(decryptedBuffer));
    return JSON.parse(decryptedStr);
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
