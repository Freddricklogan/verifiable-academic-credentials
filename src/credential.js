/**
 * Credential assembly — a W3C Verifiable Credential 2.0 envelope carrying an
 * Open Badges 3.0 `AchievementCredential`.
 *
 * Pure: the clock and the identifier generator are injected, so a credential
 * built from the same inputs is byte-identical every time. That is what makes
 * the signing path testable at all.
 */

import { statusEntry } from './statuslist.js';

export const VC_CONTEXT = 'https://www.w3.org/ns/credentials/v2';
export const OB_CONTEXT = 'https://purl.imsglobal.org/spec/ob/v3p0/context-3.0.3.json';

export const ACHIEVEMENT_TYPES = Object.freeze([
  'Degree',
  'Micro-credential',
  'Professional Certificate',
  'Course Badge'
]);

/**
 * Split a comma-separated competency list into clean, de-duplicated names.
 * @param {string} input
 * @returns {string[]}
 */
export function parseCompetencies(input) {
  if (typeof input !== 'string') return [];
  const seen = new Set();
  const out = [];
  for (const raw of input.split(',')) {
    const name = raw.trim().replace(/\s+/g, ' ');
    if (!name) continue;
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(name);
  }
  return out;
}

/**
 * Build an unsigned credential.
 *
 * @param {object} input
 * @param {string} input.issuerName
 * @param {string} input.issuerDid
 * @param {string} input.learnerName
 * @param {string} input.learnerDid
 * @param {string} input.title
 * @param {string} input.achievementType
 * @param {string[]} input.competencies
 * @param {number} input.statusListIndex
 * @param {string} input.statusListCredentialUrl
 * @param {string} input.issuedAt ISO-8601
 * @param {string} input.credentialId
 * @param {string} input.achievementId
 * @param {string} [input.validUntil] ISO-8601
 * @returns {object} unsigned Verifiable Credential
 */
export function buildCredential(input) {
  const {
    issuerName,
    issuerDid,
    learnerName,
    learnerDid,
    title,
    achievementType,
    competencies,
    statusListIndex,
    statusListCredentialUrl,
    issuedAt,
    credentialId,
    achievementId,
    validUntil
  } = input;

  for (const [key, value] of Object.entries({
    issuerName, issuerDid, learnerName, learnerDid, title, achievementType,
    issuedAt, credentialId, achievementId, statusListCredentialUrl
  })) {
    if (typeof value !== 'string' || value.trim() === '') {
      throw new TypeError(`buildCredential: "${key}" is required`);
    }
  }
  if (!Number.isInteger(statusListIndex) || statusListIndex < 0) {
    throw new TypeError('buildCredential: "statusListIndex" must be a non-negative integer');
  }

  const credential = {
    '@context': [VC_CONTEXT, OB_CONTEXT],
    id: credentialId,
    type: ['VerifiableCredential', 'OpenBadgeCredential'],
    name: title,
    issuer: { id: issuerDid, type: ['Profile'], name: issuerName },
    validFrom: issuedAt,
    credentialSubject: {
      id: learnerDid,
      type: ['AchievementSubject'],
      identifier: [
        { type: 'IdentityObject', identityType: 'name', hashed: false, identityHash: learnerName }
      ],
      achievement: {
        id: achievementId,
        type: ['Achievement'],
        achievementType,
        name: title,
        description: `${achievementType} conferred to ${learnerName} by ${issuerName}.`,
        criteria: { narrative: `Successful completion of all requirements for ${title}.` },
        competency: (competencies ?? []).map((name) => ({ type: ['Competency'], name }))
      }
    },
    credentialStatus: statusEntry({ statusListCredentialUrl, index: statusListIndex })
  };

  if (validUntil) credential.validUntil = validUntil;
  return credential;
}

/**
 * Temporal validity check. The original implementation set `validFrom` and then
 * never looked at it, so an expired or not-yet-valid credential verified clean.
 *
 * @param {{ validFrom?: string, validUntil?: string }} credential
 * @param {number} now epoch ms
 * @returns {{ valid: boolean, reason: string }}
 */
export function checkValidityPeriod(credential, now) {
  const from = credential?.validFrom ? Date.parse(credential.validFrom) : null;
  const until = credential?.validUntil ? Date.parse(credential.validUntil) : null;

  if (from !== null && Number.isNaN(from)) {
    return { valid: false, reason: 'validFrom is not a parsable date' };
  }
  if (until !== null && Number.isNaN(until)) {
    return { valid: false, reason: 'validUntil is not a parsable date' };
  }
  if (from !== null && now < from) {
    return { valid: false, reason: `not valid until ${credential.validFrom}` };
  }
  if (until !== null && now > until) {
    return { valid: false, reason: `expired on ${credential.validUntil}` };
  }
  if (from === null && until === null) {
    return { valid: true, reason: 'no validity period asserted' };
  }
  return {
    valid: true,
    reason: until
      ? `inside the asserted validity period, expires ${credential.validUntil}`
      : `valid from ${credential.validFrom}, no expiry asserted`
  };
}

/**
 * Structural check — does this even look like an Open Badges 3.0 credential?
 * Run before any cryptography so a paste error reports as a paste error.
 *
 * @param {unknown} candidate
 * @returns {{ ok: boolean, problems: string[] }}
 */
export function validateCredentialShape(candidate) {
  const problems = [];
  const c = candidate;

  if (c === null || typeof c !== 'object' || Array.isArray(c)) {
    return { ok: false, problems: ['not a JSON object'] };
  }
  // `some` with a strict equality predicate rather than `includes`: both are exact
  // array-element matches, but the explicit `===` makes it unambiguous to static
  // analysis that this is not a URL substring check (js/incomplete-url-substring-sanitization).
  const context = c['@context'];
  if (!Array.isArray(context) || !context.some((entry) => entry === VC_CONTEXT)) {
    problems.push(`@context must include ${VC_CONTEXT}`);
  }
  if (!Array.isArray(c.type) || !c.type.includes('VerifiableCredential')) {
    problems.push('type must include "VerifiableCredential"');
  }
  if (typeof c.id !== 'string' || c.id === '') problems.push('missing credential id');
  if (!c.issuer || typeof c.issuer.id !== 'string') problems.push('missing issuer.id');
  if (!c.credentialSubject || typeof c.credentialSubject !== 'object') {
    problems.push('missing credentialSubject');
  }
  if (!c.proof || typeof c.proof.proofValue !== 'string') {
    problems.push('missing proof.proofValue — the credential is unsigned');
  }
  return { ok: problems.length === 0, problems };
}

/**
 * Flatten a signed credential into the fields the wallet UI displays.
 * @param {object} signed
 */
export function summarizeCredential(signed) {
  const achievement = signed?.credentialSubject?.achievement ?? {};
  return {
    id: signed?.id ?? '',
    title: signed?.name ?? achievement.name ?? 'Untitled credential',
    achievementType: achievement.achievementType ?? 'Credential',
    issuerName: signed?.issuer?.name ?? 'Unknown issuer',
    issuerDid: signed?.issuer?.id ?? '',
    learnerDid: signed?.credentialSubject?.id ?? '',
    learnerName:
      signed?.credentialSubject?.identifier?.find((i) => i.identityType === 'name')?.identityHash ??
      'Unknown learner',
    competencies: (achievement.competency ?? []).map((c) => c.name),
    statusListIndex: Number(signed?.credentialStatus?.statusListIndex ?? -1),
    validFrom: signed?.validFrom ?? null
  };
}
