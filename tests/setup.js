// Node 20+ exposes globalThis.crypto natively; the explicit assignment keeps
// these tests portable to older runtimes and makes the dependency obvious.
import { webcrypto } from 'node:crypto';

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto;
}
