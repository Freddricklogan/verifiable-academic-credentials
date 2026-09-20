import { beforeAll, describe, expect, it } from 'vitest';
import {
  CRYPTOSUITE,
  generateSigningIdentity,
  hashDocument,
  importVerificationKey,
  sha256Hex,
  signCredential,
  verifyCredentialSignature
} from '../src/crypto.js';
import { buildCredential } from '../src/credential.js';
import { canonicalize } from '../src/canonicalize.js';

const CREATED = '2026-03-01T12:00:00.000Z';

function baseInput(issuerDid, learnerDid) {
  return {
    issuerName: 'Meridian Institute of Technology',
    issuerDid,
    learnerName: 'Jordan Ellis',
    learnerDid,
    title: 'M.S. in Applied Data Science',
    achievementType: 'Degree',
    competencies: ['Machine Learning'],
    statusListIndex: 3,
    statusListCredentialUrl: 'https://example.edu/status/1',
    issuedAt: CREATED,
    credentialId: 'urn:uuid:11111111-1111-4111-8111-111111111111',
    achievementId: 'urn:uuid:22222222-2222-4222-8222-222222222222'
  };
}

let issuer;
let holder;
let signed;

beforeAll(async () => {
  issuer = await generateSigningIdentity();
  holder = await generateSigningIdentity();
  signed = await signCredential(buildCredential(baseInput(issuer.did, holder.did)), {
    privateKey: issuer.keyPair.privateKey,
    issuerDid: issuer.did,
    created: CREATED
  });
});

describe('sha256Hex', () => {
  it('matches the known digest of the empty string', async () => {
    expect(await sha256Hex('')).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    );
  });

  it('matches the known digest of "abc"', async () => {
    expect(await sha256Hex('abc')).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    );
  });

  it('is avalanche-sensitive to a one-character change', async () => {
    expect(await sha256Hex('abc')).not.toBe(await sha256Hex('abd'));
  });
});

describe('hashDocument', () => {
  it('hashes the canonical form, so key order does not change the hash', async () => {
    const a = await hashDocument({ b: 1, a: 2 });
    const b = await hashDocument({ a: 2, b: 1 });
    expect(a).toBe(b);
    expect(a).toBe(await sha256Hex(canonicalize({ a: 2, b: 1 })));
  });

  it('changes when any value changes', async () => {
    expect(await hashDocument({ a: 1 })).not.toBe(await hashDocument({ a: 2 }));
  });
});

describe('generateSigningIdentity', () => {
  it('returns a usable key pair, a did:key and the matching public JWK', () => {
    expect(issuer.keyPair.privateKey.type).toBe('private');
    expect(issuer.did).toMatch(/^did:key:z/);
    expect(issuer.publicJwk.crv).toBe('P-256');
  });

  it('generates a distinct identity each time', async () => {
    const other = await generateSigningIdentity();
    expect(other.did).not.toBe(issuer.did);
  });
});

describe('importVerificationKey', () => {
  it('recovers a working verification key from the DID alone', async () => {
    const key = await importVerificationKey(issuer.did);
    expect(key.type).toBe('public');
    expect(key.usages).toContain('verify');
  });

  it('rejects an identifier that is not a resolvable did:key', async () => {
    await expect(importVerificationKey('did:web:example.edu')).rejects.toThrow();
  });
});

describe('signCredential', () => {
  it('attaches a DataIntegrityProof naming the implemented cryptosuite', () => {
    expect(signed.proof).toMatchObject({
      type: 'DataIntegrityProof',
      cryptosuite: CRYPTOSUITE,
      proofPurpose: 'assertionMethod',
      created: CREATED
    });
    expect(CRYPTOSUITE).toBe('ecdsa-jcs-2019');
  });

  it('points verificationMethod at the issuer DID', () => {
    expect(signed.proof.verificationMethod.startsWith(issuer.did)).toBe(true);
  });

  it('does not mutate the unsigned credential', async () => {
    const unsigned = buildCredential(baseInput(issuer.did, holder.did));
    await signCredential(unsigned, {
      privateKey: issuer.keyPair.privateKey,
      issuerDid: issuer.did,
      created: CREATED
    });
    expect(unsigned.proof).toBeUndefined();
  });

  it('refuses to double-sign an already signed credential', async () => {
    await expect(
      signCredential(signed, {
        privateKey: issuer.keyPair.privateKey,
        issuerDid: issuer.did,
        created: CREATED
      })
    ).rejects.toThrow(/already carries a proof/);
  });
});

describe('verifyCredentialSignature', () => {
  it('verifies a genuine credential using the key resolved from its own DID', async () => {
    const result = await verifyCredentialSignature(signed);
    expect(result.valid).toBe(true);
    expect(result.did).toBe(issuer.did);
    expect(result.reason).toContain('resolved from the issuer DID');
  });

  it('still verifies after a JSON round-trip that reorders keys', async () => {
    const reorder = (v) =>
      Array.isArray(v)
        ? v.map(reorder)
        : v && typeof v === 'object'
          ? Object.fromEntries(Object.keys(v).reverse().map((k) => [k, reorder(v[k])]))
          : v;
    const reordered = reorder(signed);
    expect(JSON.stringify(reordered)).not.toBe(JSON.stringify(signed));
    expect((await verifyCredentialSignature(reordered)).valid).toBe(true);
  });

  it('fails when the credential name is forged', async () => {
    const forged = JSON.parse(JSON.stringify(signed));
    forged.name = 'Ph.D. in Rocket Science';
    const result = await verifyCredentialSignature(forged);
    expect(result.valid).toBe(false);
    expect(result.reason).toContain('altered after signing');
  });

  it('fails when a single character deep in the subject is flipped', async () => {
    const forged = JSON.parse(JSON.stringify(signed));
    forged.credentialSubject.achievement.competency[0].name = 'Machine Learninh';
    expect((await verifyCredentialSignature(forged)).valid).toBe(false);
  });

  it('fails when the issuer DID is swapped for another real issuer', async () => {
    // The original implementation verified against whichever key was in memory,
    // so swapping the stated issuer left the signature check passing.
    const impostor = await generateSigningIdentity();
    const forged = JSON.parse(JSON.stringify(signed));
    forged.issuer.id = impostor.did;
    const result = await verifyCredentialSignature(forged);
    expect(result.valid).toBe(false);
    expect(result.did).toBe(impostor.did);
  });

  it('fails a credential signed by a different issuer than it names', async () => {
    const impostor = await generateSigningIdentity();
    const misSigned = await signCredential(
      buildCredential(baseInput(issuer.did, holder.did)),
      { privateKey: impostor.keyPair.privateKey, issuerDid: issuer.did, created: CREATED }
    );
    expect((await verifyCredentialSignature(misSigned)).valid).toBe(false);
  });

  it('verifies a credential from an issuer it has never seen before', async () => {
    const stranger = await generateSigningIdentity();
    const foreign = await signCredential(
      buildCredential(baseInput(stranger.did, holder.did)),
      { privateKey: stranger.keyPair.privateKey, issuerDid: stranger.did, created: CREATED }
    );
    expect((await verifyCredentialSignature(foreign)).valid).toBe(true);
  });

  it('honours an expected-issuer constraint', async () => {
    const other = await generateSigningIdentity();
    expect(
      (await verifyCredentialSignature(signed, { expectedIssuerDid: other.did })).valid
    ).toBe(false);
    expect(
      (await verifyCredentialSignature(signed, { expectedIssuerDid: issuer.did })).valid
    ).toBe(true);
  });

  it('reports the specific fault for missing, malformed and wrong-length proofs', async () => {
    expect((await verifyCredentialSignature({ issuer: { id: issuer.did } })).reason).toContain(
      'no proof'
    );
    expect((await verifyCredentialSignature({ proof: { proofValue: 'x' } })).reason).toContain(
      'no issuer DID'
    );
    const short = JSON.parse(JSON.stringify(signed));
    short.proof.proofValue = 'AQID';
    expect((await verifyCredentialSignature(short)).reason).toContain('64-byte');
    const unresolvable = JSON.parse(JSON.stringify(signed));
    unresolvable.issuer.id = 'did:key:zNotARealKey';
    expect((await verifyCredentialSignature(unresolvable)).reason).toContain('not resolvable');
  });
});
