import { describe, expect, it } from 'vitest';
import {
  ACHIEVEMENT_TYPES,
  buildCredential,
  checkValidityPeriod,
  OB_CONTEXT,
  parseCompetencies,
  summarizeCredential,
  validateCredentialShape,
  VC_CONTEXT
} from '../src/credential.js';

const BASE = {
  issuerName: 'Meridian Institute of Technology',
  issuerDid: 'did:key:zDnaeAAA',
  learnerName: 'Jordan Ellis',
  learnerDid: 'did:key:zDnaeBBB',
  title: 'M.S. in Applied Data Science',
  achievementType: 'Degree',
  competencies: ['Machine Learning', 'MLOps'],
  statusListIndex: 7,
  statusListCredentialUrl: 'https://example.edu/status/1',
  issuedAt: '2026-03-01T12:00:00.000Z',
  credentialId: 'urn:uuid:11111111-1111-4111-8111-111111111111',
  achievementId: 'urn:uuid:22222222-2222-4222-8222-222222222222'
};

describe('parseCompetencies', () => {
  it('trims, collapses whitespace and drops empties', () => {
    expect(parseCompetencies(' Machine  Learning ,, MLOps ,')).toEqual(['Machine Learning', 'MLOps']);
  });

  it('de-duplicates case-insensitively, keeping the first spelling', () => {
    expect(parseCompetencies('MLOps, mlops, MLOPS')).toEqual(['MLOps']);
  });

  it('returns an empty list for empty or non-string input', () => {
    expect(parseCompetencies('')).toEqual([]);
    expect(parseCompetencies('   ,  , ')).toEqual([]);
    expect(parseCompetencies(null)).toEqual([]);
  });
});

describe('buildCredential', () => {
  const credential = buildCredential(BASE);

  it('is deterministic — identical inputs produce an identical document', () => {
    expect(JSON.stringify(buildCredential(BASE))).toBe(JSON.stringify(credential));
  });

  it('emits both the VC 2.0 and Open Badges 3.0 contexts', () => {
    expect(credential['@context']).toEqual([VC_CONTEXT, OB_CONTEXT]);
    expect(credential.type).toEqual(['VerifiableCredential', 'OpenBadgeCredential']);
  });

  it('binds the issuer DID and the learner DID', () => {
    expect(credential.issuer.id).toBe(BASE.issuerDid);
    expect(credential.credentialSubject.id).toBe(BASE.learnerDid);
  });

  it('carries competencies as Open Badges Competency objects', () => {
    expect(credential.credentialSubject.achievement.competency).toEqual([
      { type: ['Competency'], name: 'Machine Learning' },
      { type: ['Competency'], name: 'MLOps' }
    ]);
  });

  it('embeds a bitstring status entry at the allocated index', () => {
    expect(credential.credentialStatus).toMatchObject({
      type: 'BitstringStatusListEntry',
      statusListIndex: '7'
    });
  });

  it('is unsigned — the proof is attached by the signing step, not here', () => {
    expect(credential.proof).toBeUndefined();
  });

  it('includes validUntil only when supplied', () => {
    expect(credential.validUntil).toBeUndefined();
    expect(buildCredential({ ...BASE, validUntil: '2030-01-01T00:00:00.000Z' }).validUntil).toBe(
      '2030-01-01T00:00:00.000Z'
    );
  });

  it('rejects missing or blank required fields', () => {
    for (const key of ['issuerName', 'learnerName', 'title', 'credentialId', 'issuerDid']) {
      expect(() => buildCredential({ ...BASE, [key]: '   ' })).toThrow(new RegExp(key));
    }
  });

  it('rejects an invalid status list index', () => {
    expect(() => buildCredential({ ...BASE, statusListIndex: -1 })).toThrow(/statusListIndex/);
    expect(() => buildCredential({ ...BASE, statusListIndex: 1.5 })).toThrow(/statusListIndex/);
  });

  it('accepts every offered achievement type', () => {
    for (const achievementType of ACHIEVEMENT_TYPES) {
      expect(buildCredential({ ...BASE, achievementType }).credentialSubject.achievement
        .achievementType).toBe(achievementType);
    }
  });

  it('tolerates no competencies at all', () => {
    expect(
      buildCredential({ ...BASE, competencies: undefined }).credentialSubject.achievement.competency
    ).toEqual([]);
  });
});

describe('checkValidityPeriod', () => {
  const t = (iso) => Date.parse(iso);

  it('accepts a credential inside its window', () => {
    const credential = { validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z' };
    expect(checkValidityPeriod(credential, t('2026-06-01T00:00:00Z')).valid).toBe(true);
  });

  it('rejects a credential that is not yet valid', () => {
    const result = checkValidityPeriod({ validFrom: '2027-01-01T00:00:00Z' }, t('2026-01-01T00:00:00Z'));
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('not valid until');
  });

  it('rejects an expired credential (never checked in the original)', () => {
    const result = checkValidityPeriod({ validUntil: '2020-01-01T00:00:00Z' }, t('2026-01-01T00:00:00Z'));
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('expired');
  });

  it('accepts exactly the boundary instants', () => {
    const credential = { validFrom: '2026-01-01T00:00:00Z', validUntil: '2027-01-01T00:00:00Z' };
    expect(checkValidityPeriod(credential, t('2026-01-01T00:00:00Z')).valid).toBe(true);
    expect(checkValidityPeriod(credential, t('2027-01-01T00:00:00Z')).valid).toBe(true);
  });

  it('accepts a credential asserting no period at all', () => {
    expect(checkValidityPeriod({}, Date.now())).toEqual({
      valid: true,
      reason: 'no validity period asserted'
    });
  });

  it('rejects unparsable dates rather than treating them as absent', () => {
    expect(checkValidityPeriod({ validFrom: 'soon' }, Date.now()).valid).toBe(false);
    expect(checkValidityPeriod({ validUntil: 'never' }, Date.now()).valid).toBe(false);
  });
});

describe('validateCredentialShape', () => {
  const signed = { ...buildCredential(BASE), proof: { proofValue: 'abc' } };

  it('accepts a well-formed signed credential', () => {
    expect(validateCredentialShape(signed)).toEqual({ ok: true, problems: [] });
  });

  it('rejects non-objects with a single clear problem', () => {
    expect(validateCredentialShape('{}').problems).toEqual(['not a JSON object']);
    expect(validateCredentialShape([]).ok).toBe(false);
    expect(validateCredentialShape(null).ok).toBe(false);
  });

  it('names an unsigned credential as unsigned', () => {
    const result = validateCredentialShape(buildCredential(BASE));
    expect(result.ok).toBe(false);
    expect(result.problems.join(' ')).toContain('the credential is unsigned');
  });

  it('flags a missing context, type, id, issuer and subject', () => {
    const result = validateCredentialShape({ proof: { proofValue: 'x' } });
    expect(result.problems).toHaveLength(5);
  });
});

describe('summarizeCredential', () => {
  const signed = { ...buildCredential(BASE), proof: { proofValue: 'abc' } };

  it('flattens the fields the wallet renders', () => {
    expect(summarizeCredential(signed)).toEqual({
      id: BASE.credentialId,
      title: BASE.title,
      achievementType: 'Degree',
      issuerName: BASE.issuerName,
      issuerDid: BASE.issuerDid,
      learnerDid: BASE.learnerDid,
      learnerName: BASE.learnerName,
      competencies: ['Machine Learning', 'MLOps'],
      statusListIndex: 7,
      validFrom: BASE.issuedAt
    });
  });

  it('degrades gracefully on a credential missing most fields', () => {
    const summary = summarizeCredential({});
    expect(summary.title).toBe('Untitled credential');
    expect(summary.learnerName).toBe('Unknown learner');
    expect(summary.competencies).toEqual([]);
    expect(summary.statusListIndex).toBe(-1);
  });
});
