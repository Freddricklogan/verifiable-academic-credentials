import { describe, expect, it } from 'vitest';
import {
  checkCredentialStatus,
  countRevoked,
  createStatusList,
  decodeStatusList,
  DEFAULT_STATUS_LIST_LENGTH,
  encodeStatusList,
  getStatus,
  setStatus,
  statusEntry,
  toggleStatus
} from '../src/statuslist.js';

const URL_ = 'https://example.edu/status/1';

describe('createStatusList', () => {
  it('defaults to the spec minimum of 131,072 entries, all clear', () => {
    const list = createStatusList();
    expect(list.length).toBe(DEFAULT_STATUS_LIST_LENGTH);
    expect(list.bits).toHaveLength(DEFAULT_STATUS_LIST_LENGTH / 8);
    expect(countRevoked(list)).toBe(0);
  });

  it('rejects lengths that are not a positive multiple of 8', () => {
    expect(() => createStatusList(0)).toThrow(RangeError);
    expect(() => createStatusList(12)).toThrow(RangeError);
    expect(() => createStatusList(-8)).toThrow(RangeError);
  });
});

describe('bit access', () => {
  it('treats bit 0 as the most significant bit of byte 0', () => {
    const list = createStatusList(16);
    setStatus(list, 0, true);
    expect(list.bits[0]).toBe(0b1000_0000);
    setStatus(list, 7, true);
    expect(list.bits[0]).toBe(0b1000_0001);
    setStatus(list, 8, true);
    expect(list.bits[1]).toBe(0b1000_0000);
  });

  it('sets and clears independently', () => {
    const list = createStatusList(64);
    setStatus(list, 5, true);
    setStatus(list, 6, true);
    setStatus(list, 5, false);
    expect(getStatus(list, 5)).toBe(false);
    expect(getStatus(list, 6)).toBe(true);
    expect(countRevoked(list)).toBe(1);
  });

  it('toggles and reports the new value', () => {
    const list = createStatusList(8);
    expect(toggleStatus(list, 3)).toBe(true);
    expect(toggleStatus(list, 3)).toBe(false);
    expect(countRevoked(list)).toBe(0);
  });

  it('counts revoked entries across byte boundaries', () => {
    const list = createStatusList(32);
    for (const i of [0, 7, 8, 15, 31]) setStatus(list, i, true);
    expect(countRevoked(list)).toBe(5);
  });

  it('rejects out-of-range and non-integer indices', () => {
    const list = createStatusList(16);
    expect(() => getStatus(list, 16)).toThrow(RangeError);
    expect(() => getStatus(list, -1)).toThrow(RangeError);
    expect(() => setStatus(list, 1.5, true)).toThrow(RangeError);
  });
});

describe('encode / decode', () => {
  it('round-trips a sparse list exactly', () => {
    const list = createStatusList(1024);
    for (const i of [0, 1, 512, 1023]) setStatus(list, i, true);
    const decoded = decodeStatusList(encodeStatusList(list));
    expect(decoded.length).toBe(1024);
    expect(countRevoked(decoded)).toBe(4);
    for (const i of [0, 1, 512, 1023]) expect(getStatus(decoded, i)).toBe(true);
    expect(getStatus(decoded, 2)).toBe(false);
  });

  it('encodes an all-clear list to base64url with no padding', () => {
    expect(encodeStatusList(createStatusList(64))).toBe('AAAAAAAAAAA');
  });

  it('leaks nothing about which index is being checked — one artifact for all', () => {
    const list = createStatusList(256);
    setStatus(list, 100, true);
    const published = encodeStatusList(list);
    // A verifier checking index 100 and one checking index 7 read the same bytes.
    expect(getStatus(decodeStatusList(published), 100)).toBe(true);
    expect(getStatus(decodeStatusList(published), 7)).toBe(false);
  });
});

describe('statusEntry', () => {
  it('builds a BitstringStatusListEntry with a string index', () => {
    expect(statusEntry({ statusListCredentialUrl: URL_, index: 42 })).toEqual({
      id: `${URL_}#42`,
      type: 'BitstringStatusListEntry',
      statusPurpose: 'revocation',
      statusListIndex: '42',
      statusListCredential: URL_
    });
  });

  it('supports a non-default purpose', () => {
    expect(statusEntry({ statusListCredentialUrl: URL_, index: 1, purpose: 'suspension' })
      .statusPurpose).toBe('suspension');
  });
});

describe('checkCredentialStatus', () => {
  const list = createStatusList(256);
  setStatus(list, 9, true);

  it('reports an active credential', () => {
    const credential = { credentialStatus: statusEntry({ statusListCredentialUrl: URL_, index: 3 }) };
    expect(checkCredentialStatus(credential, list)).toMatchObject({ checked: true, revoked: false });
  });

  it('reports a revoked credential and names the bit', () => {
    const credential = { credentialStatus: statusEntry({ statusListCredentialUrl: URL_, index: 9 }) };
    const result = checkCredentialStatus(credential, list);
    expect(result.checked).toBe(true);
    expect(result.revoked).toBe(true);
    expect(result.reason).toContain('bit 9 is set');
  });

  it('does not claim a status when the credential carries no entry', () => {
    expect(checkCredentialStatus({}, list)).toEqual({
      checked: false,
      revoked: false,
      reason: 'credential carries no status list entry'
    });
    expect(checkCredentialStatus(null, list).checked).toBe(false);
  });

  it('does not claim a status for an out-of-range or non-numeric index', () => {
    expect(
      checkCredentialStatus({ credentialStatus: { statusListIndex: '99999' } }, list).checked
    ).toBe(false);
    expect(
      checkCredentialStatus({ credentialStatus: { statusListIndex: 'abc' } }, list).checked
    ).toBe(false);
  });
});
