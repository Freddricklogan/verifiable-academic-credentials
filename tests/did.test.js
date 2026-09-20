import { describe, expect, it } from 'vitest';
import {
  abbreviateDid,
  compressP256Point,
  decodeDidKeyP256,
  decompressP256Point,
  didKeyFromJwk,
  encodeDidKeyP256,
  P256_MULTICODEC_PREFIX,
  resolveDidKeyToJwk
} from '../src/did.js';
import { generateSigningIdentity } from '../src/crypto.js';

/** Generate a real P-256 key with Web Crypto, exported raw. */
async function rawPublicKey() {
  const keyPair = await crypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );
  return {
    raw: new Uint8Array(await crypto.subtle.exportKey('raw', keyPair.publicKey)),
    jwk: await crypto.subtle.exportKey('jwk', keyPair.publicKey)
  };
}

describe('point compression', () => {
  it('round-trips real P-256 public keys', async () => {
    for (let i = 0; i < 12; i += 1) {
      const { raw } = await rawPublicKey();
      const compressed = compressP256Point(raw);
      expect(compressed).toHaveLength(33);
      expect([0x02, 0x03]).toContain(compressed[0]);
      expect([...decompressP256Point(compressed)]).toEqual([...raw]);
    }
  });

  it('encodes Y parity in the prefix byte', async () => {
    const { raw } = await rawPublicKey();
    const yIsOdd = (raw[64] & 1) === 1;
    expect(compressP256Point(raw)[0]).toBe(yIsOdd ? 0x03 : 0x02);
  });

  it('rejects malformed points', () => {
    expect(() => compressP256Point(new Uint8Array(64))).toThrow(TypeError);
    expect(() => compressP256Point(new Uint8Array(65))).toThrow(TypeError); // prefix is not 0x04
    expect(() => decompressP256Point(new Uint8Array(32))).toThrow(TypeError);
    const badPrefix = new Uint8Array(33);
    badPrefix[0] = 0x05;
    expect(() => decompressP256Point(badPrefix)).toThrow(/invalid point prefix/);
  });

  it('rejects an X coordinate that is not on the curve', () => {
    const offCurve = new Uint8Array(33);
    offCurve[0] = 0x02;
    offCurve[32] = 1; // x = 1 has no square root for y on P-256
    expect(() => decompressP256Point(offCurve)).toThrow(/not on the P-256 curve/);
  });

  it('rejects an X coordinate outside the field', () => {
    const tooBig = new Uint8Array(33).fill(0xff);
    tooBig[0] = 0x02;
    expect(() => decompressP256Point(tooBig)).toThrow(/out of field range/);
  });
});

describe('did:key encoding', () => {
  it('produces a multibase-base58btc identifier with the p256-pub multicodec', async () => {
    const { raw } = await rawPublicKey();
    const did = encodeDidKeyP256(raw);
    expect(did).toMatch(/^did:key:z[1-9A-HJ-NP-Za-km-z]+$/);
    const decoded = decodeDidKeyP256(did);
    expect(decoded).toHaveLength(33);
    expect([...compressP256Point(raw)]).toEqual([...decoded]);
    expect([...P256_MULTICODEC_PREFIX]).toEqual([0x80, 0x24]);
  });

  it('is injective — distinct keys give distinct DIDs', async () => {
    const dids = new Set();
    for (let i = 0; i < 25; i += 1) {
      const { raw } = await rawPublicKey();
      dids.add(encodeDidKeyP256(raw));
    }
    expect(dids.size).toBe(25);
  });

  it('is long enough to carry the whole key (the truncation bug)', async () => {
    const { raw } = await rawPublicKey();
    // 35 bytes base58-encoded is ~48 characters; the original truncated to 44
    // characters of base64url, which cannot represent 35 bytes at all.
    expect(encodeDidKeyP256(raw).length).toBeGreaterThan('did:key:z'.length + 45);
  });

  it('resolves back to the exact public JWK the key was exported as', async () => {
    const { raw, jwk } = await rawPublicKey();
    const resolved = resolveDidKeyToJwk(encodeDidKeyP256(raw));
    expect(resolved.kty).toBe('EC');
    expect(resolved.crv).toBe('P-256');
    expect(resolved.x).toBe(jwk.x);
    expect(resolved.y).toBe(jwk.y);
  });

  it('round-trips DID -> JWK -> DID', async () => {
    const { did } = await generateSigningIdentity();
    expect(didKeyFromJwk(resolveDidKeyToJwk(did))).toBe(did);
  });

  it('rejects identifiers that are not did:key multibase', () => {
    expect(() => decodeDidKeyP256('did:web:example.com')).toThrow(/not a did:key/);
    expect(() => decodeDidKeyP256('did:key:Qabc')).toThrow(/not a did:key/);
    expect(() => decodeDidKeyP256(null)).toThrow(/not a did:key/);
  });

  it('rejects a did:key carrying a different key type', () => {
    // Ed25519 multicodec prefix 0xed 0x01 over 32 bytes.
    const { base58Encode } = { base58Encode: null };
    void base58Encode;
    const ed25519Did = 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
    expect(() => decodeDidKeyP256(ed25519Did)).toThrow(/not a p256-pub multicodec key/);
  });

  it('rejects a JWK that is not a P-256 public key', () => {
    expect(() => didKeyFromJwk({ crv: 'P-384', x: 'a', y: 'b' })).toThrow(TypeError);
    expect(() => didKeyFromJwk(null)).toThrow(TypeError);
    expect(() => didKeyFromJwk({ crv: 'P-256', x: 'AQ', y: 'AQ' })).toThrow(/32 bytes/);
  });
});

describe('abbreviateDid', () => {
  it('keeps the head and the distinguishing tail', () => {
    const did = `did:key:z${'A'.repeat(60)}BCDEF`;
    const short = abbreviateDid(did);
    expect(short.startsWith('did:key:zAAAAAAAAA')).toBe(true);
    expect(short.endsWith('BCDEF')).toBe(true);
    expect(short).toContain('…');
  });

  it('returns short values unchanged', () => {
    expect(abbreviateDid('did:key:z1')).toBe('did:key:z1');
  });
});
