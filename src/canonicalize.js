/**
 * JSON canonicalization.
 *
 * Signing and verifying must agree on the exact byte sequence that was signed.
 * `JSON.stringify` does not: object key order follows insertion order, so a
 * credential that survives a round-trip through a different JSON library, a
 * database, or a `structuredClone` can serialise differently and fail
 * verification even though nothing meaningful changed.
 *
 * This implements the shape of RFC 8785 (JSON Canonicalization Scheme) that
 * matters here: recursive key sorting by UTF-16 code unit, preserved array
 * order, and rejection of values JSON cannot round-trip. It deliberately does
 * *not* re-implement RFC 8785's ECMAScript number serialisation rules beyond
 * what `JSON.stringify` already provides — credentials in this demo carry no
 * floating-point values, and the module rejects non-finite numbers outright
 * rather than silently emitting `null` the way `JSON.stringify` does.
 */

/**
 * Recursively sort object keys, preserving array order.
 * @param {unknown} value
 * @param {WeakSet<object>} seen
 * @returns {unknown}
 */
function normalize(value, seen) {
  if (value === null) return null;

  const type = typeof value;

  if (type === 'number') {
    if (!Number.isFinite(value)) {
      throw new TypeError('canonicalize: non-finite numbers cannot be canonicalized');
    }
    return value;
  }

  if (type === 'bigint') {
    throw new TypeError('canonicalize: BigInt cannot be canonicalized');
  }

  if (type !== 'object') {
    // string, boolean, undefined, function, symbol — JSON.stringify handles the
    // last three by omission, which is the documented behaviour here too.
    return value;
  }

  if (seen.has(value)) {
    throw new TypeError('canonicalize: circular reference');
  }
  seen.add(value);

  let result;
  if (Array.isArray(value)) {
    result = value.map((item) => normalize(item, seen));
  } else {
    result = {};
    for (const key of Object.keys(value).sort()) {
      const normalized = normalize(value[key], seen);
      if (normalized === undefined) continue; // matches JSON.stringify omission
      result[key] = normalized;
    }
  }

  seen.delete(value);
  return result;
}

/**
 * Deterministic JSON serialisation.
 *
 * @param {unknown} value
 * @returns {string}
 * @throws {TypeError} on circular references, BigInt or non-finite numbers
 */
export function canonicalize(value) {
  const normalized = normalize(value, new WeakSet());
  const json = JSON.stringify(normalized);
  if (json === undefined) {
    throw new TypeError('canonicalize: value is not representable as JSON');
  }
  return json;
}

/**
 * Remove the `proof` member, returning the document that was actually signed.
 * Returns a shallow copy; the input is never mutated.
 *
 * @template {object} T
 * @param {T} document
 * @returns {Omit<T, 'proof'>}
 */
export function withoutProof(document) {
  if (document === null || typeof document !== 'object') {
    throw new TypeError('withoutProof: expected an object');
  }
  const rest = {};
  for (const key of Object.keys(document)) {
    if (key !== 'proof') rest[key] = document[key];
  }
  return rest;
}
