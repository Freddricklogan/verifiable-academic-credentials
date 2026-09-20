/**
 * Append-only, hash-linked anchor ledger.
 *
 * Only the SHA-256 hash of a credential is anchored, never its contents, so no
 * learner data is published. Each block commits to the previous block's hash,
 * so altering any anchored credential — or any block — breaks that block and
 * every block after it. That is the whole tamper-evidence claim, and it is
 * what `verifyChain` checks.
 *
 * The hash function is injected, which keeps this module pure and lets the
 * tests drive it with a trivial deterministic hash as well as with real
 * SHA-256.
 */

export const ZERO_HASH = '0'.repeat(64);

/**
 * The exact bytes a block commits to. Field order is fixed and the separator
 * cannot appear in any field, so two different blocks cannot share a preimage.
 *
 * @param {{index: number, timestamp: string, credentialId: string, credentialHash: string, previousHash: string}} block
 * @returns {string}
 */
export function blockPreimage(block) {
  return [
    block.index,
    block.timestamp,
    block.credentialId,
    block.credentialHash,
    block.previousHash
  ].join('|');
}

/**
 * @typedef {(input: string) => Promise<string>} HashFn
 * @typedef {{ index: number, timestamp: string, credentialId: string,
 *             credentialHash: string, previousHash: string, blockHash: string }} Block
 */

/**
 * Create a ledger containing only the genesis block.
 * @param {{ timestamp: string, hash: HashFn }} deps
 * @returns {Promise<Block[]>}
 */
export async function createLedger({ timestamp, hash }) {
  const genesis = {
    index: 0,
    timestamp,
    credentialId: 'GENESIS',
    credentialHash: ZERO_HASH,
    previousHash: ZERO_HASH
  };
  return [{ ...genesis, blockHash: await hash(blockPreimage(genesis)) }];
}

/**
 * Append an anchor block. Returns a **new** array; the input is not mutated,
 * which keeps the caller's state transitions explicit.
 *
 * @param {Block[]} ledger
 * @param {{ credentialId: string, credentialHash: string, timestamp: string, hash: HashFn }} input
 * @returns {Promise<{ ledger: Block[], block: Block }>}
 */
export async function appendBlock(ledger, { credentialId, credentialHash, timestamp, hash }) {
  if (!Array.isArray(ledger) || ledger.length === 0) {
    throw new Error('appendBlock: ledger must contain at least a genesis block');
  }
  const previous = ledger[ledger.length - 1];
  const draft = {
    index: ledger.length,
    timestamp,
    credentialId,
    credentialHash,
    previousHash: previous.blockHash
  };
  const block = { ...draft, blockHash: await hash(blockPreimage(draft)) };
  return { ledger: [...ledger, block], block };
}

/**
 * Verify the whole chain: every block's hash must match its own contents, and
 * every block must point at its predecessor.
 *
 * @param {Block[]} ledger
 * @param {HashFn} hash
 * @returns {Promise<{ intact: boolean, brokenAt: number|null, reason: string }>}
 */
export async function verifyChain(ledger, hash) {
  if (!Array.isArray(ledger) || ledger.length === 0) {
    return { intact: false, brokenAt: null, reason: 'ledger is empty' };
  }
  for (let i = 0; i < ledger.length; i += 1) {
    const block = ledger[i];
    if (block.index !== i) {
      return { intact: false, brokenAt: i, reason: `block ${i} has index ${block.index}` };
    }
    const expectedPrevious = i === 0 ? ZERO_HASH : ledger[i - 1].blockHash;
    if (block.previousHash !== expectedPrevious) {
      return { intact: false, brokenAt: i, reason: `block ${i} does not link to block ${i - 1}` };
    }
    const recomputed = await hash(blockPreimage(block));
    if (recomputed !== block.blockHash) {
      return { intact: false, brokenAt: i, reason: `block ${i} hash does not match its contents` };
    }
  }
  return { intact: true, brokenAt: null, reason: `all ${ledger.length} blocks verified` };
}

/**
 * Is this exact credential hash anchored?
 * @param {Block[]} ledger @param {string} credentialHash
 * @returns {Block|null}
 */
export function findAnchor(ledger, credentialHash) {
  return ledger.find((block) => block.credentialHash === credentialHash) ?? null;
}
