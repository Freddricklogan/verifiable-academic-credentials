/**
 * Verification orchestration.
 *
 * A credential is trustworthy only if every independent check holds. Each check
 * is reported separately so a failure says *which* property broke — "the
 * signature is fine but the issuer revoked it" and "the bytes were altered" are
 * very different conversations.
 *
 * Dependencies (ledger, status list, clock, SubtleCrypto) are all injected, so
 * this module is fully testable without a browser.
 */

import { checkValidityPeriod, validateCredentialShape } from './credential.js';
import { hashDocument, sha256Hex, verifyCredentialSignature } from './crypto.js';
import { findAnchor, verifyChain } from './ledger.js';
import { checkCredentialStatus } from './statuslist.js';

/**
 * @typedef {{ id: string, label: string, ok: boolean, detail: string }} Check
 */

/**
 * @param {object} signedCredential
 * @param {object} context
 * @param {Array<object>} context.ledger
 * @param {{ length: number, bits: Uint8Array }} context.statusList
 * @param {number} context.now epoch ms
 * @param {SubtleCrypto} [context.subtle]
 * @returns {Promise<{ pass: boolean, checks: Check[] }>}
 */
export async function verifyCredential(signedCredential, context) {
  const { ledger, statusList, now, subtle } = context;
  /** @type {Check[]} */
  const checks = [];

  // 1. Structure — cheapest check first, and it gives the clearest error.
  const shape = validateCredentialShape(signedCredential);
  checks.push({
    id: 'structure',
    label: 'Credential structure',
    ok: shape.ok,
    detail: shape.ok
      ? 'Well-formed W3C Verifiable Credential 2.0 with an Open Badges 3.0 achievement.'
      : `Malformed: ${shape.problems.join('; ')}.`
  });

  if (!shape.ok) {
    return { pass: false, checks };
  }

  // 2. Signature — verified with the key resolved from the credential's own DID.
  const signature = await verifyCredentialSignature(signedCredential, { subtle });
  checks.push({
    id: 'signature',
    label: 'Cryptographic signature',
    ok: signature.valid,
    detail: `${signature.reason}.`
  });

  // 3. Issuer authenticity — the DID must resolve to a usable key, which is
  //    exactly what step 2 proved when it succeeded. Reported separately
  //    because "unresolvable identifier" and "wrong bytes" are distinct faults.
  const issuerResolvable = signature.did !== null && !signature.reason.includes('not resolvable');
  checks.push({
    id: 'issuer',
    label: 'Issuer identity resolves',
    ok: issuerResolvable,
    detail: issuerResolvable
      ? `did:key resolved to a P-256 public key without contacting any registry (${signedCredential.issuer.name ?? 'unnamed issuer'}).`
      : 'The issuer DID could not be decoded to a public key.'
  });

  // 4. Anchor — the exact credential hash must be on an intact ledger.
  const hash = await hashDocument(signedCredential, subtle);
  const anchor = findAnchor(ledger, hash);
  const chain = await verifyChain(ledger, (input) => sha256Hex(input, subtle));
  const anchorOk = Boolean(anchor) && chain.intact;
  checks.push({
    id: 'anchor',
    label: 'Tamper-evident anchor',
    ok: anchorOk,
    detail: anchorOk
      ? `Hash ${hash.slice(0, 16)}… found in block #${anchor.index}; all ${ledger.length} blocks verified.`
      : !anchor
        ? 'This exact credential hash is not on the ledger — it was never issued here, or it has been modified since.'
        : `Ledger chain is broken: ${chain.reason}.`
  });

  // 5. Revocation — read the issuer's published bitstring, not a lookup keyed
  //    by credential id.
  const status = checkCredentialStatus(signedCredential, statusList);
  checks.push({
    id: 'status',
    label: 'Revocation status',
    ok: status.checked && !status.revoked,
    detail: status.checked
      ? `${status.reason}.`
      : `Cannot determine status: ${status.reason}.`
  });

  // 6. Validity period — asserted by the credential and never previously checked.
  const validity = checkValidityPeriod(signedCredential, now);
  checks.push({
    id: 'validity',
    label: 'Validity period',
    ok: validity.valid,
    detail: `${validity.reason}.`
  });

  return { pass: checks.every((check) => check.ok), checks };
}
