/**
 * Byte/text encodings used by the credential pipeline.
 *
 * All functions are pure and environment-agnostic: they work identically under
 * the browser's Web Crypto and Node's `node:crypto` webcrypto, which is what
 * lets the signing and verification logic be unit-tested outside a browser.
 */

const B64_CHUNK = 0x8000;

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_MAP = (() => {
  const map = new Map();
  for (let i = 0; i < BASE58_ALPHABET.length; i += 1) map.set(BASE58_ALPHABET[i], i);
  return map;
})();

/**
 * Convert bytes to a binary string in bounded chunks.
 *
 * The original implementation used `String.fromCharCode(...bytes)`, which
 * spreads every byte as a separate function argument and throws
 * `RangeError: Maximum call stack size exceeded` once the buffer grows past
 * the engine's argument limit (~64–125 k on V8). Chunking removes that ceiling.
 *
 * @param {Uint8Array|ArrayBuffer} input
 * @returns {string}
 */
function toBinaryString(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let out = '';
  for (let i = 0; i < bytes.length; i += B64_CHUNK) {
    out += String.fromCharCode(...bytes.subarray(i, i + B64_CHUNK));
  }
  return out;
}

/**
 * Base64url encode, without padding.
 * @param {Uint8Array|ArrayBuffer} input
 */
export function bytesToBase64Url(input) {
  return btoa(toBinaryString(input)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Base64url decode. Accepts padded or unpadded input.
 * @param {string} text
 * @returns {Uint8Array}
 */
export function base64UrlToBytes(text) {
  if (typeof text !== 'string') throw new TypeError('base64UrlToBytes: expected a string');
  const normalized = text.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** @param {Uint8Array|ArrayBuffer} input */
export function bytesToHex(input) {
  const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/** @param {string} hex */
export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || /[^0-9a-f]/i.test(hex)) {
    throw new TypeError('hexToBytes: expected an even-length hexadecimal string');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** UTF-8 encode. @param {string} text @returns {Uint8Array} */
export function utf8ToBytes(text) {
  return new TextEncoder().encode(text);
}

/**
 * Base58btc encode (Bitcoin alphabet) — the multibase `z` encoding used by
 * `did:key`. Leading zero bytes map to leading `1` characters.
 * @param {Uint8Array} bytes
 */
export function base58Encode(bytes) {
  if (bytes.length === 0) return '';
  const digits = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (let i = 0; i < bytes.length && bytes[i] === 0; i += 1) out += '1';
  for (let i = digits.length - 1; i >= 0; i -= 1) out += BASE58_ALPHABET[digits[i]];
  return out;
}

/**
 * Base58btc decode.
 * @param {string} text
 * @returns {Uint8Array}
 */
export function base58Decode(text) {
  if (typeof text !== 'string') throw new TypeError('base58Decode: expected a string');
  if (text.length === 0) return new Uint8Array(0);
  const bytes = [0];
  for (const char of text) {
    const value = BASE58_MAP.get(char);
    if (value === undefined) throw new Error(`base58Decode: invalid character "${char}"`);
    let carry = value;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  let leadingZeros = 0;
  for (let i = 0; i < text.length && text[i] === '1'; i += 1) leadingZeros += 1;
  return new Uint8Array([...new Array(leadingZeros).fill(0), ...bytes.reverse()]);
}
