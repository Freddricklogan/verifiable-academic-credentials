/**
 * Bitstring status list (the revocation mechanism behind `StatusList2021Entry`
 * / `BitstringStatusListEntry`).
 *
 * The point of the design is privacy: the issuer publishes one bitstring
 * covering many credentials, so a verifier checking credential #4,217 downloads
 * the same artifact as everybody else and the issuer learns nothing about who
 * is being verified. A per-credential lookup would leak exactly that.
 *
 * The original implementation declared `credentialStatus.type = "StatusList2021Entry"`
 * on every credential but actually kept revocations in a JavaScript `Set` keyed
 * by credential id — the opposite privacy property, and not the mechanism the
 * credential claims to use.
 *
 * Deviation from the published spec, stated openly: the spec requires the
 * bitstring to be GZIP-compressed before base64url encoding. There is no GZIP
 * in the platform that is usable synchronously, and compression is orthogonal
 * to the property being demonstrated, so this module encodes the raw bitstring.
 * Everything else — bit ordering, index semantics, minimum length — follows the
 * spec.
 *
 * Pure module: no DOM, no clock, no crypto.
 */

import { base64UrlToBytes, bytesToBase64Url } from './encoding.js';

/** Spec minimum: 16 KB of bits (131,072 entries) to resist correlation. */
export const DEFAULT_STATUS_LIST_LENGTH = 131072;

/**
 * @param {number} [length=DEFAULT_STATUS_LIST_LENGTH] number of entries (bits)
 * @returns {{ length: number, bits: Uint8Array }}
 */
export function createStatusList(length = DEFAULT_STATUS_LIST_LENGTH) {
  if (!Number.isInteger(length) || length <= 0 || length % 8 !== 0) {
    throw new RangeError('createStatusList: length must be a positive multiple of 8');
  }
  return { length, bits: new Uint8Array(length / 8) };
}

/** @param {{length: number}} list @param {number} index */
function assertIndex(list, index) {
  if (!Number.isInteger(index) || index < 0 || index >= list.length) {
    throw new RangeError(`status list index ${index} is outside 0..${list.length - 1}`);
  }
}

/**
 * Read one entry. Bit 0 is the most significant bit of byte 0, per spec.
 * @param {{length: number, bits: Uint8Array}} list
 * @param {number} index
 * @returns {boolean} true when the credential is revoked
 */
export function getStatus(list, index) {
  assertIndex(list, index);
  const byte = list.bits[index >> 3];
  return ((byte >> (7 - (index & 7))) & 1) === 1;
}

/**
 * Set one entry. Returns the same list object (mutated in place) so callers
 * can chain; the list is the issuer's own state, not shared data.
 *
 * @param {{length: number, bits: Uint8Array}} list
 * @param {number} index
 * @param {boolean} revoked
 */
export function setStatus(list, index, revoked) {
  assertIndex(list, index);
  const byteIndex = index >> 3;
  const mask = 1 << (7 - (index & 7));
  if (revoked) list.bits[byteIndex] |= mask;
  else list.bits[byteIndex] &= ~mask & 0xff;
  return list;
}

/**
 * Flip one entry and report the new value.
 * @param {{length: number, bits: Uint8Array}} list @param {number} index
 */
export function toggleStatus(list, index) {
  const next = !getStatus(list, index);
  setStatus(list, index, next);
  return next;
}

/** Number of revoked entries. @param {{bits: Uint8Array}} list */
export function countRevoked(list) {
  let total = 0;
  for (const byte of list.bits) {
    let b = byte;
    while (b) {
      total += b & 1;
      b >>= 1;
    }
  }
  return total;
}

/**
 * Encode the bitstring for publication.
 * @param {{length: number, bits: Uint8Array}} list
 * @returns {string} base64url, unpadded
 */
export function encodeStatusList(list) {
  return bytesToBase64Url(list.bits);
}

/**
 * Decode a published bitstring.
 * @param {string} encoded
 * @returns {{ length: number, bits: Uint8Array }}
 */
export function decodeStatusList(encoded) {
  const bits = base64UrlToBytes(encoded);
  return { length: bits.length * 8, bits };
}

/**
 * Build the `credentialStatus` entry embedded in a credential.
 *
 * @param {object} input
 * @param {string} input.statusListCredentialUrl
 * @param {number} input.index
 * @param {string} [input.purpose='revocation']
 */
export function statusEntry({ statusListCredentialUrl, index, purpose = 'revocation' }) {
  return {
    id: `${statusListCredentialUrl}#${index}`,
    type: 'BitstringStatusListEntry',
    statusPurpose: purpose,
    statusListIndex: String(index),
    statusListCredential: statusListCredentialUrl
  };
}

/**
 * Check a credential's embedded status entry against a decoded bitstring.
 *
 * @param {{ credentialStatus?: { statusListIndex?: string } }} credential
 * @param {{ length: number, bits: Uint8Array }} list
 * @returns {{ checked: boolean, revoked: boolean, reason: string }}
 */
export function checkCredentialStatus(credential, list) {
  const entry = credential?.credentialStatus;
  if (!entry || entry.statusListIndex === undefined) {
    return { checked: false, revoked: false, reason: 'credential carries no status list entry' };
  }
  const index = Number(entry.statusListIndex);
  if (!Number.isInteger(index) || index < 0 || index >= list.length) {
    return { checked: false, revoked: false, reason: 'status list index is out of range' };
  }
  const revoked = getStatus(list, index);
  return {
    checked: true,
    revoked,
    reason: revoked
      ? `bit ${index} is set — the issuer has revoked this credential`
      : `bit ${index} is clear — active on the issuer's published status list`
  };
}
