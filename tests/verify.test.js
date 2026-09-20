import { beforeEach, describe, expect, it } from 'vitest';
import { verifyCredential } from '../src/verify.js';
import { buildCredential } from '../src/credential.js';
import { generateSigningIdentity, hashDocument, signCredential } from '../src/crypto.js';
import { appendBlock, createLedger } from '../src/ledger.js';
import { sha256Hex } from '../src/crypto.js';
import { createStatusList, setStatus } from '../src/statuslist.js';

const NOW = Date.parse('2026-03-01T12:00:00.000Z');
const ISO = new Date(NOW).toISOString();
const hash = (input) => sha256Hex(input);

const checkById = (checks, id) => checks.find((c) => c.id === id);

/** Issue, sign and anchor a credential; return everything the verifier needs. */
async function issueCredential({ statusListIndex = 5, validUntil } = {}) {
  const issuer = await generateSigningIdentity();
  const holder = await generateSigningIdentity();
  const unsigned = buildCredential({
    issuerName: 'Meridian Institute of Technology',
    issuerDid: issuer.did,
    learnerName: 'Jordan Ellis',
    learnerDid: holder.did,
    title: 'M.S. in Applied Data Science',
    achievementType: 'Degree',
    competencies: ['Machine Learning', 'MLOps'],
    statusListIndex,
    statusListCredentialUrl: 'https://example.edu/status/1',
    issuedAt: ISO,
    credentialId: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    achievementId: 'urn:uuid:22222222-2222-4222-8222-222222222222',
    validUntil
  });
  const signed = await signCredential(unsigned, {
    privateKey: issuer.keyPair.privateKey,
    issuerDid: issuer.did,
    created: ISO
  });
  let ledger = await createLedger({ timestamp: ISO, hash });
  ({ ledger } = await appendBlock(ledger, {
    credentialId: signed.id,
    credentialHash: await hashDocument(signed),
    timestamp: ISO,
    hash
  }));
  return { issuer, holder, signed, ledger };
}

describe('verifyCredential', () => {
  let issued;
  let statusList;

  beforeEach(async () => {
    issued = await issueCredential();
    statusList = createStatusList(256);
  });

  it('passes every check for a genuine, anchored, unrevoked credential', async () => {
    const result = await verifyCredential(issued.signed, {
      ledger: issued.ledger,
      statusList,
      now: NOW
    });
    expect(result.pass).toBe(true);
    expect(result.checks.map((c) => c.id)).toEqual([
      'structure',
      'signature',
      'issuer',
      'anchor',
      'status',
      'validity'
    ]);
    expect(result.checks.every((c) => c.ok)).toBe(true);
  });

  it('stops at the structure check for a document that is not a credential', async () => {
    const result = await verifyCredential({ hello: 'world' }, {
      ledger: issued.ledger,
      statusList,
      now: NOW
    });
    expect(result.pass).toBe(false);
    expect(result.checks).toHaveLength(1);
    expect(result.checks[0].id).toBe('structure');
  });

  it('fails the signature AND the anchor when the credential is tampered with', async () => {
    const forged = JSON.parse(JSON.stringify(issued.signed));
    forged.name = 'Ph.D. in Rocket Science';
    forged.credentialSubject.achievement.name = 'Ph.D. in Rocket Science';

    const result = await verifyCredential(forged, {
      ledger: issued.ledger,
      statusList,
      now: NOW
    });
    expect(result.pass).toBe(false);
    expect(checkById(result.checks, 'signature').ok).toBe(false);
    expect(checkById(result.checks, 'anchor').ok).toBe(false);
    expect(checkById(result.checks, 'anchor').detail).toContain('not on the ledger');
  });

  it('fails the anchor for a genuine credential that was never anchored here', async () => {
    const elsewhere = await issueCredential();
    const result = await verifyCredential(elsewhere.signed, {
      ledger: issued.ledger, // a different issuer's ledger
      statusList,
      now: NOW
    });
    expect(checkById(result.checks, 'signature').ok).toBe(true);
    expect(checkById(result.checks, 'anchor').ok).toBe(false);
    expect(result.pass).toBe(false);
  });

  it('fails the anchor when the ledger chain itself has been broken', async () => {
    const broken = issued.ledger.map((b) => ({ ...b }));
    broken[1].timestamp = '2020-01-01T00:00:00.000Z';
    const result = await verifyCredential(issued.signed, {
      ledger: broken,
      statusList,
      now: NOW
    });
    expect(checkById(result.checks, 'anchor').ok).toBe(false);
  });

  it('fails only the status check when the issuer has revoked the credential', async () => {
    setStatus(statusList, 5, true);
    const result = await verifyCredential(issued.signed, {
      ledger: issued.ledger,
      statusList,
      now: NOW
    });
    expect(result.pass).toBe(false);
    expect(checkById(result.checks, 'signature').ok).toBe(true);
    expect(checkById(result.checks, 'anchor').ok).toBe(true);
    expect(checkById(result.checks, 'status').ok).toBe(false);
    expect(checkById(result.checks, 'status').detail).toContain('bit 5 is set');
  });

  it('passes again once the revocation is lifted', async () => {
    setStatus(statusList, 5, true);
    setStatus(statusList, 5, false);
    const result = await verifyCredential(issued.signed, {
      ledger: issued.ledger,
      statusList,
      now: NOW
    });
    expect(result.pass).toBe(true);
  });

  it('fails the validity check for an expired credential', async () => {
    const expiring = await issueCredential({ validUntil: '2026-06-01T00:00:00.000Z' });
    const result = await verifyCredential(expiring.signed, {
      ledger: expiring.ledger,
      statusList,
      now: Date.parse('2027-01-01T00:00:00Z')
    });
    expect(result.pass).toBe(false);
    expect(checkById(result.checks, 'validity').ok).toBe(false);
    expect(checkById(result.checks, 'signature').ok).toBe(true);
  });

  it('fails the issuer check when the DID cannot be resolved to a key', async () => {
    const broken = JSON.parse(JSON.stringify(issued.signed));
    broken.issuer.id = 'did:key:zQ3shSomethingElse';
    const result = await verifyCredential(broken, {
      ledger: issued.ledger,
      statusList,
      now: NOW
    });
    expect(checkById(result.checks, 'issuer').ok).toBe(false);
    expect(checkById(result.checks, 'signature').ok).toBe(false);
  });

  it('does not claim a status when the credential has no status entry', async () => {
    const stripped = JSON.parse(JSON.stringify(issued.signed));
    delete stripped.credentialStatus;
    const result = await verifyCredential(stripped, {
      ledger: issued.ledger,
      statusList,
      now: NOW
    });
    expect(checkById(result.checks, 'status').ok).toBe(false);
    expect(checkById(result.checks, 'status').detail).toContain('Cannot determine status');
  });

  it('gives every check a stable id, label, boolean and human-readable detail', async () => {
    const result = await verifyCredential(issued.signed, {
      ledger: issued.ledger,
      statusList,
      now: NOW
    });
    for (const check of result.checks) {
      expect(typeof check.id).toBe('string');
      expect(typeof check.label).toBe('string');
      expect(typeof check.ok).toBe('boolean');
      expect(check.detail.length).toBeGreaterThan(10);
    }
  });
});
