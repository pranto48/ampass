// AMPass — zero-knowledge crypto helpers.
// All encryption happens client-side. The server never sees plaintext.

const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64 = {
  encode(buf: ArrayBuffer | Uint8Array): string {
    const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.byteLength; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  },
  decode(s: string): ArrayBuffer {
    const bin = atob(s);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  },
};

export function randomBytes(n: number): ArrayBuffer {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a.buffer;
}

export const PBKDF2_ITERATIONS = 250_000;

/** Derive a 256-bit AES-GCM key from a master password + salt. */
export async function deriveKeyFromPassword(
  password: string,
  saltB64: string,
  iterations = PBKDF2_ITERATIONS,
): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: b64.decode(saltB64),
      iterations,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["wrapKey", "unwrapKey", "encrypt", "decrypt"],
  );
}

/** Generate a fresh random AES-GCM 256 key (the user's vault key). */
export async function generateVaultKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
    "encrypt",
    "decrypt",
    "wrapKey",
    "unwrapKey",
  ]);
}

/** Encrypt a string with an AES-GCM key. Returns base64 ciphertext + iv. */
export async function encryptString(key: CryptoKey, plaintext: string) {
  const iv = randomBytes(12);
  const data = enc.encode(plaintext);
  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength),
  );
  return { ciphertext: b64.encode(ct), iv: b64.encode(iv) };
}

export async function decryptString(
  key: CryptoKey,
  ciphertextB64: string,
  ivB64: string,
): Promise<string> {
  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64.decode(ivB64) },
    key,
    b64.decode(ciphertextB64),
  );
  return dec.decode(pt);
}

/** Export a key as base64 raw bytes (for wrapping). */
export async function exportRawKey(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey("raw", key);
  return b64.encode(raw);
}

export async function importRawKey(rawB64: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    b64.decode(rawB64),
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
  );
}

/** Wrap (encrypt) a CryptoKey using another AES-GCM key. */
export async function wrapKey(keyToWrap: CryptoKey, wrappingKey: CryptoKey) {
  const raw = await exportRawKey(keyToWrap);
  return encryptString(wrappingKey, raw);
}

export async function unwrapKey(
  ciphertextB64: string,
  ivB64: string,
  wrappingKey: CryptoKey,
): Promise<CryptoKey> {
  const raw = await decryptString(wrappingKey, ciphertextB64, ivB64);
  return importRawKey(raw);
}

/** A constant the server stores encrypted; decrypting it proves the master password is correct. */
export const VERIFIER_PLAINTEXT = "AMPass:verifier:v1";

/** Build a fresh user_security row for first-time setup. */
export async function createUserSecurity(masterPassword: string) {
  const saltB64 = b64.encode(randomBytes(16));
  const derivedKey = await deriveKeyFromPassword(masterPassword, saltB64);
  const vaultKey = await generateVaultKey();
  const wrapped = await wrapKey(vaultKey, derivedKey);
  const verifier = await encryptString(derivedKey, VERIFIER_PLAINTEXT);
  return {
    saltB64,
    iterations: PBKDF2_ITERATIONS,
    verifier_ciphertext: verifier.ciphertext,
    verifier_iv: verifier.iv,
    wrapped_vault_key: wrapped.ciphertext,
    wrapped_vault_key_iv: wrapped.iv,
    vaultKey, // returned in-memory only
  };
}

/** Unlock: re-derive the master key, verify, and unwrap the vault key. */
export async function unlockVault(
  masterPassword: string,
  sec: {
    kdf_salt: string;
    kdf_iterations: number;
    verifier_ciphertext: string;
    verifier_iv: string;
    wrapped_vault_key: string;
    wrapped_vault_key_iv: string;
  },
): Promise<CryptoKey> {
  const derived = await deriveKeyFromPassword(
    masterPassword,
    sec.kdf_salt,
    sec.kdf_iterations,
  );
  let verified: string;
  try {
    verified = await decryptString(derived, sec.verifier_ciphertext, sec.verifier_iv);
  } catch {
    throw new Error("Incorrect master password");
  }
  if (verified !== VERIFIER_PLAINTEXT) {
    throw new Error("Incorrect master password");
  }
  return unwrapKey(sec.wrapped_vault_key, sec.wrapped_vault_key_iv, derived);
}
