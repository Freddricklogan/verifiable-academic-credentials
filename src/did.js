/**
 * `did:key` for NIST P-256 (secp256r1).
 *
 * A `did:key` identifier *is* the public key: the multibase-base58btc encoding
 * of a multicodec-prefixed compressed public key. That makes it genuinely
 * self-resolving — a verifier can recover the signing key from the identifier
 * alone, with no registry, no network call and no trusted third party.
 *
 * The original implementation produced `'did:key:z' + base64url(rawKey).slice(0, 44)`,
 * which is neither the right encoding nor the right key format, and — because it
 * truncates — is not even injective. Nothing could be resolved from it, so
 * verification silently fell back to whatever key happened to be in memory.
 *
 * Everything here is pure integer arithmetic: no Web Crypto, no DOM, no clock.
 */

import { base58Decode, base58Encode } from './encoding.js';
import { bytesToBase64Url, base64UrlToBytes } from './encoding.js';

/** multicodec `p256-pub` = 0x1200, varint-encoded. */
export const P256_MULTICODEC_PREFIX = new Uint8Array([0x80, 0x24]);

/** P-256 field prime. */
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
/** Curve coefficient b for y² = x³ - 3x + b. */
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
/** p ≡ 3 (mod 4), so a square root is a^((p+1)/4). */
const SQRT_EXP = (P + 1n) / 4n;

const COORD_BYTES = 32;

/** @param {bigint} base @param {bigint} exp @param {bigint} mod */
function modPow(base, exp, mod) {
  let result = 1n;
  let b = base % mod;
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return result;
}

/** @param {Uint8Array} bytes */
function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

/** @param {bigint} value @param {number} length */
function bigIntToBytes(value, length) {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new RangeError('bigIntToBytes: value does not fit');
  return out;
}

/**
 * Compress an uncompressed SEC1 point (0x04 || X || Y, 65 bytes) to 33 bytes.
 * @param {Uint8Array} uncompressed
 * @returns {Uint8Array}
 */
export function compressP256Point(uncompressed) {
  if (!(uncompressed instanceof Uint8Array) || uncompressed.length !== 65 || uncompressed[0] !== 0x04) {
    throw new TypeError('compressP256Point: expected a 65-byte uncompressed SEC1 point');
  }
  const x = uncompressed.subarray(1, 1 + COORD_BYTES);
  const y = uncompressed.subarray(1 + COORD_BYTES);
  const prefix = (y[COORD_BYTES - 1] & 1) === 0 ? 0x02 : 0x03;
  const out = new Uint8Array(1 + COORD_BYTES);
  out[0] = prefix;
  out.set(x, 1);
  return out;
}

/**
 * Decompress a 33-byte SEC1 point back to 65 bytes by solving the curve
 * equation for Y and selecting the root with the encoded parity.
 *
 * @param {Uint8Array} compressed
 * @returns {Uint8Array}
 */
export function decompressP256Point(compressed) {
  if (!(compressed instanceof Uint8Array) || compressed.length !== 33) {
    throw new TypeError('decompressP256Point: expected a 33-byte compressed point');
  }
  const prefix = compressed[0];
  if (prefix !== 0x02 && prefix !== 0x03) {
    throw new TypeError('decompressP256Point: invalid point prefix');
  }

  const x = bytesToBigInt(compressed.subarray(1));
  if (x >= P) throw new RangeError('decompressP256Point: X coordinate out of field range');

  const alpha = (((x * x) % P) * x - 3n * x + B) % P;
  const rhs = ((alpha % P) + P) % P;
  let y = modPow(rhs, SQRT_EXP, P);

  if ((y * y) % P !== rhs) {
    throw new Error('decompressP256Point: point is not on the P-256 curve');
  }
  const wantOdd = prefix === 0x03;
  if (((y & 1n) === 1n) !== wantOdd) y = P - y;

  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(bigIntToBytes(x, COORD_BYTES), 1);
  out.set(bigIntToBytes(y, COORD_BYTES), 1 + COORD_BYTES);
  return out;
}

/**
 * Build a `did:key` identifier from a raw (uncompressed) P-256 public key.
 * @param {Uint8Array|ArrayBuffer} rawPublicKey 65-byte SEC1 point
 * @returns {string} e.g. `did:key:zDnae…`
 */
export function encodeDidKeyP256(rawPublicKey) {
  const raw = rawPublicKey instanceof Uint8Array ? rawPublicKey : new Uint8Array(rawPublicKey);
  const compressed = compressP256Point(raw);
  const prefixed = new Uint8Array(P256_MULTICODEC_PREFIX.length + compressed.length);
  prefixed.set(P256_MULTICODEC_PREFIX, 0);
  prefixed.set(compressed, P256_MULTICODEC_PREFIX.length);
  return `did:key:z${base58Encode(prefixed)}`;
}

/**
 * Recover the compressed public key bytes from a `did:key` identifier.
 * @param {string} did
 * @returns {Uint8Array} 33-byte compressed point
 */
export function decodeDidKeyP256(did) {
  if (typeof did !== 'string' || !did.startsWith('did:key:z')) {
    throw new Error('decodeDidKeyP256: not a did:key multibase-base58btc identifier');
  }
  const decoded = base58Decode(did.slice('did:key:z'.length));
  if (
    decoded.length !== P256_MULTICODEC_PREFIX.length + 33 ||
    decoded[0] !== P256_MULTICODEC_PREFIX[0] ||
    decoded[1] !== P256_MULTICODEC_PREFIX[1]
  ) {
    throw new Error('decodeDidKeyP256: not a p256-pub multicodec key');
  }
  return decoded.subarray(P256_MULTICODEC_PREFIX.length);
}

/**
 * Resolve a `did:key` to the public JWK a verifier imports.
 * This is the whole DID resolution step — no network, no registry.
 *
 * @param {string} did
 * @returns {{ kty: 'EC', crv: 'P-256', x: string, y: string, ext: boolean, key_ops: string[] }}
 */
export function resolveDidKeyToJwk(did) {
  const uncompressed = decompressP256Point(decodeDidKeyP256(did));
  return {
    kty: 'EC',
    crv: 'P-256',
    x: bytesToBase64Url(uncompressed.subarray(1, 1 + COORD_BYTES)),
    y: bytesToBase64Url(uncompressed.subarray(1 + COORD_BYTES)),
    ext: true,
    key_ops: ['verify']
  };
}

/**
 * Inverse of {@link resolveDidKeyToJwk} — build the DID from a public JWK.
 * @param {{ crv?: string, x: string, y: string }} jwk
 * @returns {string}
 */
export function didKeyFromJwk(jwk) {
  if (!jwk || jwk.crv !== 'P-256' || typeof jwk.x !== 'string' || typeof jwk.y !== 'string') {
    throw new TypeError('didKeyFromJwk: expected a P-256 public JWK with x and y');
  }
  const x = base64UrlToBytes(jwk.x);
  const y = base64UrlToBytes(jwk.y);
  if (x.length !== COORD_BYTES || y.length !== COORD_BYTES) {
    throw new RangeError('didKeyFromJwk: coordinates must be 32 bytes each');
  }
  const raw = new Uint8Array(65);
  raw[0] = 0x04;
  raw.set(x, 1);
  raw.set(y, 1 + COORD_BYTES);
  return encodeDidKeyP256(raw);
}

/**
 * Shorten a DID for display without losing its distinguishing tail.
 * @param {string} did @param {number} [head=18] @param {number} [tail=6]
 */
export function abbreviateDid(did, head = 18, tail = 6) {
  if (typeof did !== 'string' || did.length <= head + tail + 1) return String(did);
  return `${did.slice(0, head)}…${did.slice(-tail)}`;
}
