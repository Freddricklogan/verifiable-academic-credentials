import { describe, expect, it } from 'vitest';
import { canonicalize, withoutProof } from '../src/canonicalize.js';

describe('canonicalize', () => {
  it('produces identical output regardless of key insertion order', () => {
    const a = { b: 1, a: 2, c: { z: 3, y: 4 } };
    const b = { c: { y: 4, z: 3 }, a: 2, b: 1 };
    expect(canonicalize(a)).toBe(canonicalize(b));
    expect(canonicalize(a)).toBe('{"a":2,"b":1,"c":{"y":4,"z":3}}');
  });

  it('sorts by UTF-16 code unit, so uppercase precedes lowercase', () => {
    expect(canonicalize({ b: 1, B: 2, a: 3, A: 4 })).toBe('{"A":4,"B":2,"a":3,"b":1}');
  });

  it('preserves array order — arrays are ordered data, not a set', () => {
    expect(canonicalize({ list: ['c', 'a', 'b'] })).toBe('{"list":["c","a","b"]}');
  });

  it('sorts keys inside objects nested in arrays', () => {
    expect(canonicalize([{ b: 1, a: 2 }])).toBe('[{"a":2,"b":1}]');
  });

  it('survives a JSON round-trip — the property signing depends on', () => {
    const credential = {
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      type: ['VerifiableCredential'],
      credentialSubject: { id: 'did:key:zabc', achievement: { name: 'X', type: ['Achievement'] } },
      id: 'urn:uuid:1'
    };
    // Rebuild every object with its keys in reverse insertion order — what a
    // different JSON library, an ORM or a structuredClone can do to a document.
    const reorder = (v) =>
      Array.isArray(v)
        ? v.map(reorder)
        : v && typeof v === 'object'
          ? Object.fromEntries(Object.keys(v).reverse().map((k) => [k, reorder(v[k])]))
          : v;
    const reordered = reorder(credential);
    expect(JSON.stringify(reordered)).not.toBe(JSON.stringify(credential));
    expect(canonicalize(reordered)).toBe(canonicalize(credential));
  });

  it('handles null, booleans, nested empties and unicode', () => {
    expect(canonicalize({ n: null, t: true, e: {}, a: [], s: 'é' })).toBe(
      '{"a":[],"e":{},"n":null,"s":"é","t":true}'
    );
  });

  it('omits undefined members, matching JSON.stringify', () => {
    expect(canonicalize({ a: 1, b: undefined })).toBe('{"a":1}');
  });

  it('rejects circular references instead of overflowing the stack', () => {
    const cyclic = { name: 'loop' };
    cyclic.self = cyclic;
    expect(() => canonicalize(cyclic)).toThrow(/circular/);
  });

  it('allows the same object to appear twice in different branches', () => {
    const shared = { a: 1 };
    expect(canonicalize({ x: shared, y: shared })).toBe('{"x":{"a":1},"y":{"a":1}}');
  });

  it('rejects non-finite numbers rather than silently emitting null', () => {
    expect(() => canonicalize({ n: Number.NaN })).toThrow(/non-finite/);
    expect(() => canonicalize({ n: Number.POSITIVE_INFINITY })).toThrow(/non-finite/);
    expect(JSON.stringify({ n: Number.NaN })).toBe('{"n":null}'); // the behaviour being rejected
  });

  it('rejects BigInt', () => {
    expect(() => canonicalize({ n: 1n })).toThrow(/BigInt/);
  });

  it('rejects a value with no JSON representation', () => {
    expect(() => canonicalize(undefined)).toThrow(TypeError);
  });
});

describe('withoutProof', () => {
  it('removes the proof member without mutating the input', () => {
    const signed = { id: 'urn:uuid:1', proof: { proofValue: 'abc' } };
    const stripped = withoutProof(signed);
    expect(stripped).toEqual({ id: 'urn:uuid:1' });
    expect(signed.proof).toBeDefined();
  });

  it('is a no-op on an unsigned document', () => {
    expect(withoutProof({ id: 'x' })).toEqual({ id: 'x' });
  });

  it('rejects non-objects', () => {
    expect(() => withoutProof(null)).toThrow(TypeError);
    expect(() => withoutProof('nope')).toThrow(TypeError);
  });
});
