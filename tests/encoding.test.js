import { describe, expect, it } from 'vitest';
import {
  base58Decode,
  base58Encode,
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex,
  hexToBytes,
  utf8ToBytes
} from '../src/encoding.js';

describe('base64url', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array(256).map((_, i) => i);
    expect([...base64UrlToBytes(bytesToBase64Url(bytes))]).toEqual([...bytes]);
  });

  it('emits no padding and no + or / characters', () => {
    const encoded = bytesToBase64Url(new Uint8Array([251, 255, 190, 255, 255]));
    expect(encoded).not.toMatch(/[+/=]/);
  });

  it('accepts padded input on decode', () => {
    expect([...base64UrlToBytes('AQID')]).toEqual([1, 2, 3]);
    expect([...base64UrlToBytes('AQI=')]).toEqual([1, 2]);
  });

  it('handles the empty buffer', () => {
    expect(bytesToBase64Url(new Uint8Array(0))).toBe('');
    expect(base64UrlToBytes('')).toHaveLength(0);
  });

  it('does not overflow the call stack on large buffers (the spread-argument bug)', () => {
    const big = new Uint8Array(400_000).fill(0x41);
    const encoded = bytesToBase64Url(big);
    expect(encoded.length).toBeGreaterThan(500_000);
    expect(base64UrlToBytes(encoded)).toHaveLength(big.length);
  });

  it('rejects non-string input', () => {
    expect(() => base64UrlToBytes(42)).toThrow(TypeError);
  });
});

describe('hex', () => {
  it('round-trips and pads single-digit bytes', () => {
    expect(bytesToHex(new Uint8Array([0, 15, 255]))).toBe('000fff');
    expect([...hexToBytes('000fff')]).toEqual([0, 15, 255]);
  });

  it('accepts an ArrayBuffer', () => {
    expect(bytesToHex(new Uint8Array([171, 205]).buffer)).toBe('abcd');
  });

  it('rejects malformed hex', () => {
    expect(() => hexToBytes('abc')).toThrow(TypeError);
    expect(() => hexToBytes('zz')).toThrow(TypeError);
  });
});

describe('base58btc', () => {
  it('round-trips arbitrary bytes', () => {
    const bytes = new Uint8Array(70).map((_, i) => (i * 37 + 11) % 256);
    expect([...base58Decode(base58Encode(bytes))]).toEqual([...bytes]);
  });

  it('maps leading zero bytes to leading "1" characters', () => {
    expect(base58Encode(new Uint8Array([0, 0, 1]))).toBe('112');
    expect([...base58Decode('112')]).toEqual([0, 0, 1]);
  });

  it('uses the Bitcoin alphabet, excluding 0 O I l', () => {
    const encoded = base58Encode(new Uint8Array(64).map((_, i) => i * 4));
    expect(encoded).not.toMatch(/[0OIl]/);
  });

  it('handles the empty input', () => {
    expect(base58Encode(new Uint8Array(0))).toBe('');
    expect(base58Decode('')).toHaveLength(0);
  });

  it('rejects characters outside the alphabet', () => {
    expect(() => base58Decode('abc0def')).toThrow(/invalid character/);
    expect(() => base58Decode(null)).toThrow(TypeError);
  });
});

describe('utf8ToBytes', () => {
  it('encodes multi-byte characters', () => {
    expect([...utf8ToBytes('é')]).toEqual([0xc3, 0xa9]);
    expect(utf8ToBytes('M.S. in Applied Data Science')).toHaveLength(28);
  });
});
