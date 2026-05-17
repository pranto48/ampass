import { encryptString, decryptString } from "./crypto";

export type VaultItemType =
  | "login"
  | "note"
  | "identity"
  | "card"
  | "wifi"
  | "ssh"
  | "license"
  | "bank"
  | "custom";

export interface VaultItemData {
  title: string;
  url?: string;
  username?: string;
  password?: string;
  notes?: string;
  custom_fields?: { name: string; value: string }[];
  // type-specific blobs (cards, identity, etc.)
  extra?: Record<string, string>;
}

export interface VaultItemRow {
  id: string;
  user_id: string;
  folder_id: string | null;
  item_type: VaultItemType;
  ciphertext: string;
  iv: string;
  favorite: boolean;
  tags: string[];
  last_used_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface DecryptedVaultItem extends Omit<VaultItemRow, "ciphertext" | "iv"> {
  data: VaultItemData;
}

export async function encryptVaultItem(
  key: CryptoKey,
  data: VaultItemData,
): Promise<{ ciphertext: string; iv: string }> {
  return encryptString(key, JSON.stringify(data));
}

export async function decryptVaultItem(
  key: CryptoKey,
  row: VaultItemRow,
): Promise<DecryptedVaultItem> {
  let data: VaultItemData;
  try {
    const json = await decryptString(key, row.ciphertext, row.iv);
    data = JSON.parse(json);
  } catch {
    data = { title: "[Unable to decrypt]" };
  }
  const { ciphertext: _c, iv: _i, ...meta } = row;
  return { ...meta, data };
}

// ----- Password generator -----

const LOWER = "abcdefghijklmnopqrstuvwxyz";
const UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS = "0123456789";
const SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?/~";
const AMBIGUOUS = /[O0Il1|`'"{}\[\]()\/\\]/g;

export interface GenOpts {
  length: number;
  upper: boolean;
  lower: boolean;
  numbers: boolean;
  symbols: boolean;
  avoidAmbiguous: boolean;
}

export function generatePassword(opts: GenOpts): string {
  let pool = "";
  if (opts.lower) pool += LOWER;
  if (opts.upper) pool += UPPER;
  if (opts.numbers) pool += NUMBERS;
  if (opts.symbols) pool += SYMBOLS;
  if (opts.avoidAmbiguous) pool = pool.replace(AMBIGUOUS, "");
  if (!pool) return "";
  const out = new Array(opts.length);
  const r = new Uint32Array(opts.length);
  crypto.getRandomValues(r);
  for (let i = 0; i < opts.length; i++) out[i] = pool[r[i] % pool.length];
  return out.join("");
}

const WORDS = [
  "amber","brave","cloud","delta","ember","forge","glass","harbor",
  "ivory","jade","kite","lunar","maple","nimbus","onyx","prism",
  "quartz","river","spark","tide","umbra","valor","willow","xenon",
  "yarrow","zephyr","atlas","beacon","cipher","drift","echo","flint",
];

export function generatePassphrase(words = 5, sep = "-"): string {
  const r = new Uint32Array(words);
  crypto.getRandomValues(r);
  return Array.from({ length: words }, (_, i) => WORDS[r[i] % WORDS.length]).join(sep);
}

/** Returns a 0..4 strength score plus label. */
export function scorePassword(pw: string): { score: number; label: string } {
  if (!pw) return { score: 0, label: "Empty" };
  let s = 0;
  if (pw.length >= 8) s++;
  if (pw.length >= 14) s++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) s++;
  if (/\d/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  const score = Math.min(4, s - 1 < 0 ? 0 : s - 1);
  const labels = ["Very weak", "Weak", "Fair", "Strong", "Excellent"];
  return { score, label: labels[score] };
}
