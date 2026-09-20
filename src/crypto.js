/**
 * Web Crypto operations: key generation, SHA-256, ECDSA signing and the
 * signature check.
 *
 * Every function takes the SubtleCrypto implementation as an optional argument
 * defaulting to `globalThis.crypto.subtle`. In the browser that is the native
 * Web Crypto; in Vitest it is Node's `node:crypto` webcrypto. Same code, same
 * assertions, no mocks — the tests exercise the real primitives.
 */

import { canonicalize, withoutProof } from './canonicalize.js';
import { base64UrlToBytes, bytesToBase64Url, bytesToHex, utf8ToBytes } from './encoding.js';
import { encodeDidKeyP256, resolveDidKeyToJwk } from './did.js';

const ECDSA_KEY = { name: 'ECDSA', namedCurve: 'P-256' };
const ECDSA_SIGN = { name: 'ECDSA', hash: 'SHA-256' };

/**
 * The cryptosuite actually implemented here: ECDSA over a JSON-canonicalized
 * document. The original code labelled this `ecdsa-2019`, which is not a
 * registered cryptosuite name; the registered name for JCS canonicalization is
 * `ecdsa-jcs-2019`.
 */
export const CRYPTOSUITE = 'ecdsa-jcs-2019';

/** @param {SubtleCrypto} [subtle] */
function requireSubtle(subtle) {
  const impl = subtle ?? globalThis.crypto?.subtle;
  if (!impl) {
    throw new Error(
      'Web Crypto is unavailable. A secure context (https:// or localhost) is required.'
    );
  }
  return impl;
}

/**
 * SHA-256 of a string, lowercase hex.
 * @param {string} text @param {SubtleCrypto} [subtle]
 * @returns {Promise<string>}
 */
export async function sha256Hex(text, subtle) {
  const digest = await requireSubtle(subtle).digest('SHA-256', utf8ToBytes(text));
  return bytesToHex(digest);
}

/**
 * Hash a document by canonicalizing it first, so semantically identical
 * documents hash identically regardless of key order.
 * @param {object} document @param {SubtleCrypto} [subtle]
 */
export async function hashDocument(document, subtle) {
  return sha256Hex(canonicalize(document), subtle);
}

/**
 * Generate a P-256 signing key pair and derive its `did:key` identifier.
 * @param {SubtleCrypto} [subtle]
 * @returns {Promise<{ keyPair: CryptoKeyPair, did: string, publicJwk: JsonWebKey }>}
 */
export async function generateSigningIdentity(subtle) {
  const impl = requireSubtle(subtle);
  const keyPair = await impl.generateKey(ECDSA_KEY, true, ['sign', 'verify']);
  const raw = await impl.exportKey('raw', keyPair.publicKey);
  const publicJwk = await impl.exportKey('jwk', keyPair.publicKey);
  return { keyPair, did: encodeDidKeyP256(new Uint8Array(raw)), publicJwk };
}

/**
 * Import the verification key **from the DID itself**.
 *
 * This is the correction to the central flaw in the original implementation,
 * which verified every credential against whichever key happened to be in
 * memory (`const pub = issuerKeys.publicKey; // in production: resolved from
 * issuer DID`). That made the "issuer DID resolves" check cosmetic: it compared
 * two strings while the signature was checked against an unrelated key, so a
 * credential from any other issuer could not be verified at all, and a
 * credential whose issuer DID had been swapped still verified its signature.
 *
 * @param {string} did
 * @param {SubtleCrypto} [subtle]
 * @returns {Promise<CryptoKey>}
 */
export async function importVerificationKey(did, subtle) {
  const jwk = resolveDidKeyToJwk(did);
  return requireSubtle(subtle).importKey('jwk', jwk, ECDSA_KEY, true, ['verify']);
}

/**
 * Sign a credential, returning a new document with a `proof` member attached.
 *
 * @param {object} credential unsigned credential
 * @param {object} options
 * @param {CryptoKey} options.privateKey
 * @param {string} options.issuerDid
 * @param {string} options.created ISO-8601
 * @param {SubtleCrypto} [options.subtle]
 * @returns {Promise<object>} signed credential
 */
export async function signCredential(credential, { privateKey, issuerDid, created, subtle }) {
  if (credential && credential.proof) {
    throw new Error('signCredential: credential already carries a proof');
  }
  const bytes = utf8ToBytes(canonicalize(credential));
  const signature = await requireSubtle(subtle).sign(ECDSA_SIGN, privateKey, bytes);
  return {
    ...credential,
    proof: {
      type: 'DataIntegrityProof',
      cryptosuite: CRYPTOSUITE,
      created,
      verificationMethod: `${issuerDid}#${issuerDid.slice('did:key:'.length)}`,
      proofPurpose: 'assertionMethod',
      proofValue: bytesToBase64Url(signature)
    }
  };
}

/**
 * Verify a credential's signature against the key resolved from its own
 * issuer DID. Returns a result object rather than throwing, because a failed
 * verification is a normal outcome, not an error.
 *
 * @param {object} signedCredential
 * @param {{ subtle?: SubtleCrypto, expectedIssuerDid?: string }} [options]
 * @returns {Promise<{ valid: boolean, reason: string, did: string|null }>}
 */
export async function verifyCredentialSignature(signedCredential, options = {}) {
  const { subtle, expectedIssuerDid } = options;
  const proof = signedCredential?.proof;
  const did = signedCredential?.issuer?.id ?? null;

  if (!proof || typeof proof.proofValue !== 'string') {
    return { valid: false, reason: 'credential carries no proof', did };
  }
  if (typeof did !== 'string') {
    return { valid: false, reason: 'credential carries no issuer DID', did: null };
  }
  if (expectedIssuerDid && expectedIssuerDid !== did) {
    return { valid: false, reason: 'issuer DID does not match the expected issuer', did };
  }

  let key;
  try {
    key = await importVerificationKey(did, subtle);
  } catch (error) {
    return { valid: false, reason: `issuer DID is not resolvable: ${error.message}`, did };
  }

  let signature;
  try {
    signature = base64UrlToBytes(proof.proofValue);
  } catch {
    return { valid: false, reason: 'proofValue is not valid base64url', did };
  }
  // P-256 ECDSA in the raw (r || s) form Web Crypto expects.
  if (signature.length !== 64) {
    return { valid: false, reason: 'signature is not a 64-byte P-256 signature', did };
  }

  let bytes;
  try {
    bytes = utf8ToBytes(canonicalize(withoutProof(signedCredential)));
  } catch (error) {
    return { valid: false, reason: `credential is not canonicalizable: ${error.message}`, did };
  }

  const valid = await requireSubtle(subtle).verify(ECDSA_SIGN, key, signature, bytes);
  return {
    valid,
    reason: valid
      ? 'the key resolved from the issuer DID verifies the exact signed bytes'
      : 'signature does not match — the credential was altered after signing',
    did
  };
}
