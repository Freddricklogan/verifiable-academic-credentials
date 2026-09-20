import { describe, expect, it } from 'vitest';
import {
  appendBlock,
  blockPreimage,
  createLedger,
  findAnchor,
  verifyChain,
  ZERO_HASH
} from '../src/ledger.js';
import { sha256Hex } from '../src/crypto.js';

const hash = (input) => sha256Hex(input);
const TS = '2026-03-01T12:00:00.000Z';

async function ledgerWith(count) {
  let ledger = await createLedger({ timestamp: TS, hash });
  for (let i = 0; i < count; i += 1) {
    ({ ledger } = await appendBlock(ledger, {
      credentialId: `urn:uuid:cred-${i}`,
      credentialHash: `${i}`.padStart(64, 'a'),
      timestamp: TS,
      hash
    }));
  }
  return ledger;
}

describe('blockPreimage', () => {
  it('commits to every field in a fixed order', () => {
    expect(
      blockPreimage({
        index: 2,
        timestamp: TS,
        credentialId: 'urn:uuid:x',
        credentialHash: 'aa',
        previousHash: 'bb'
      })
    ).toBe(`2|${TS}|urn:uuid:x|aa|bb`);
  });
});

describe('createLedger', () => {
  it('starts with a self-consistent genesis block', async () => {
    const ledger = await createLedger({ timestamp: TS, hash });
    expect(ledger).toHaveLength(1);
    expect(ledger[0]).toMatchObject({
      index: 0,
      credentialId: 'GENESIS',
      credentialHash: ZERO_HASH,
      previousHash: ZERO_HASH
    });
    expect(ledger[0].blockHash).toMatch(/^[0-9a-f]{64}$/);
    expect((await verifyChain(ledger, hash)).intact).toBe(true);
  });
});

describe('appendBlock', () => {
  it('links each block to its predecessor and does not mutate the input', async () => {
    const genesis = await createLedger({ timestamp: TS, hash });
    const { ledger, block } = await appendBlock(genesis, {
      credentialId: 'urn:uuid:1',
      credentialHash: 'a'.repeat(64),
      timestamp: TS,
      hash
    });
    expect(genesis).toHaveLength(1); // untouched
    expect(ledger).toHaveLength(2);
    expect(block.index).toBe(1);
    expect(block.previousHash).toBe(genesis[0].blockHash);
  });

  it('refuses to append to a ledger with no genesis block', async () => {
    await expect(
      appendBlock([], { credentialId: 'x', credentialHash: 'y', timestamp: TS, hash })
    ).rejects.toThrow(/genesis/);
  });

  it('produces a fully verifiable chain of many blocks', async () => {
    const ledger = await ledgerWith(12);
    expect(ledger).toHaveLength(13);
    const result = await verifyChain(ledger, hash);
    expect(result).toMatchObject({ intact: true, brokenAt: null });
    expect(result.reason).toContain('13 blocks');
  });
});

describe('verifyChain — tamper detection', () => {
  it('detects an edited credential hash inside a block', async () => {
    const ledger = await ledgerWith(5);
    ledger[3] = { ...ledger[3], credentialHash: 'f'.repeat(64) };
    const result = await verifyChain(ledger, hash);
    expect(result.intact).toBe(false);
    expect(result.brokenAt).toBe(3);
    expect(result.reason).toContain('does not match its contents');
  });

  it('detects a block whose blockHash was rewritten to match its edit', async () => {
    const ledger = await ledgerWith(5);
    const forged = { ...ledger[2], credentialHash: 'f'.repeat(64) };
    forged.blockHash = await hash(blockPreimage(forged));
    ledger[2] = forged;
    // Block 2 is now self-consistent, but block 3 still points at the old hash.
    const result = await verifyChain(ledger, hash);
    expect(result.intact).toBe(false);
    expect(result.brokenAt).toBe(3);
    expect(result.reason).toContain('does not link to block 2');
  });

  it('detects a removed block', async () => {
    const ledger = await ledgerWith(5);
    ledger.splice(2, 1);
    const result = await verifyChain(ledger, hash);
    expect(result.intact).toBe(false);
    expect(result.brokenAt).toBe(2);
  });

  it('detects a reordered chain', async () => {
    const ledger = await ledgerWith(4);
    [ledger[2], ledger[3]] = [ledger[3], ledger[2]];
    expect((await verifyChain(ledger, hash)).intact).toBe(false);
  });

  it('detects a broken genesis link', async () => {
    const ledger = await ledgerWith(2);
    ledger[0] = { ...ledger[0], previousHash: 'f'.repeat(64) };
    const result = await verifyChain(ledger, hash);
    expect(result.intact).toBe(false);
    expect(result.brokenAt).toBe(0);
  });

  it('reports an empty ledger rather than claiming it is intact', async () => {
    expect(await verifyChain([], hash)).toMatchObject({ intact: false, brokenAt: null });
    expect((await verifyChain(null, hash)).intact).toBe(false);
  });
});

describe('findAnchor', () => {
  it('finds the block carrying an exact credential hash', async () => {
    const ledger = await ledgerWith(4);
    const target = ledger[2].credentialHash;
    expect(findAnchor(ledger, target).index).toBe(2);
  });

  it('returns null for a hash that was never anchored', async () => {
    const ledger = await ledgerWith(4);
    expect(findAnchor(ledger, 'f'.repeat(64))).toBeNull();
  });
});
