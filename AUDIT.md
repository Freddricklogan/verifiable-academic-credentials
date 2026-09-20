# AUDIT — VeriCred / Verifiable Academic Credentials (pre-refactor)

Audit of the previous single-file `index.html` (484 lines: ~85 lines of CSS,
~125 lines of markup, ~240 lines of inline JavaScript). Line numbers are from
the audited file.

The previous implementation was substantially better than a typical demo — it
used real Web Crypto, real ECDSA signatures and a real hash-linked ledger. The
findings below are therefore mostly about *soundness of the security model*
rather than about the absence of one.

---

## A. Cryptographic soundness — the important findings

### A1 — Verification used the in-memory key, not the key named by the credential
`verify()` at `index.html:362`:

```js
const pub = issuerKeys.publicKey; // in production: resolved from issuer DID
```

This is the central flaw. The signature was always checked against whatever key
the page had generated at load, regardless of what the credential said about its
issuer. Three consequences, all demonstrable:

1. The separate "Issuer DID resolves" check (`index.html:369`) compares
   `signedVc.issuer.id === issuerDid` — two strings — while the cryptography
   uses an unrelated key. The check is cosmetic.
2. A genuine credential from any *other* issuer cannot be verified at all, which
   is precisely the interoperability property a verifiable credential exists to
   provide.
3. Swapping `issuer.id` to an attacker's DID left the signature check passing,
   because the signature was never evaluated against the stated issuer's key.

**Fix:** `importVerificationKey(did)` in `src/crypto.js` decodes the DID to a
public key and imports *that*. Asserted by four tests in `tests/crypto.test.js`,
including "verifies a credential from an issuer it has never seen before" and
"fails a credential signed by a different issuer than it names".

### A2 — The DID was not a `did:key`, and was not even injective
`index.html:276`:

```js
issuerDid = 'did:key:z' + b64u(raw).slice(0, 44);
```

Three separate problems. The multibase prefix `z` declares base58btc, but the
payload is base64url. There is no multicodec prefix, so nothing identifies the
key type. And `.slice(0, 44)` truncates: 44 base64url characters carry 33 bytes,
while `raw` is a 65-byte uncompressed point — so the identifier discards half
the key and **is not injective**. Nothing could ever be resolved from it, which
is why A1 had to fall back to the in-memory key.

**Fix:** `src/did.js` implements `did:key` properly — multicodec `p256-pub`
(`0x1200`, varint `0x80 0x24`) over the 33-byte compressed SEC1 point, encoded
base58btc. Resolution decompresses the point by solving `y² = x³ - 3x + b` over
the P-256 field (`p ≡ 3 mod 4`, so `y = a^((p+1)/4)`) and selecting the root
with the encoded parity. Round-trip against real Web Crypto keys, injectivity
over 25 distinct keys, off-curve rejection and out-of-field rejection are all
tested in `tests/did.test.js`.

### A3 — Revocation claimed a status list but implemented a `Set`
The credential declares `credentialStatus: { type: "StatusList2021Entry",
statusPurpose: "revocation" }` (`index.html:317`), but revocation state lives in
`const revoked = new Set()` keyed by credential id (`index.html:265`), and
verification checks `!revoked.has(signedVc.id)` (`index.html:380`).

The entire point of the status-list design is verifier privacy: one published
bitstring covers many credentials, so checking credential #4,217 downloads the
same artifact as everyone else and the issuer learns nothing about who is being
verified. A per-id lookup has exactly the opposite property. The credential also
carries no `statusListIndex`, so it does not actually reference any list.

**Fix:** `src/statuslist.js` implements the bitstring: bit 0 is the most
significant bit of byte 0 per spec, the default list is the spec minimum of
131,072 entries, and each credential carries a real `BitstringStatusListEntry`
with its allocated index. The GZIP step is deliberately omitted and that
omission is documented in the module header rather than hidden.

### A4 — The cryptosuite name was not a real cryptosuite
`cryptosuite: "ecdsa-2019"` (`index.html:326`). No such registered name exists.
The implementation canonicalizes with sorted-key JSON, for which the registered
name is `ecdsa-jcs-2019`.
**Fix:** `CRYPTOSUITE = 'ecdsa-jcs-2019'`, asserted in `tests/crypto.test.js`.

### A5 — Validity period asserted and never checked
Credentials set `validFrom` (`index.html:305`) and `verify()` never looks at it.
An expired or not-yet-valid credential verified completely clean.
**Fix:** `checkValidityPeriod()` in `src/credential.js`, wired in as the sixth
verification check, with boundary-instant and unparsable-date cases tested.

### A6 — The learner "DID" was derived from a name, not from a key
`index.html:295`:

```js
const learnerDid = 'did:key:z' + b64u(enc.encode(learner + id)).slice(0, 44);
```

This hashes nothing and holds no key material — it is a name encoded to look
like a DID. There is no holder key, so holder binding is impossible and the
"learner-owned" claim has no cryptographic content behind it.
**Fix:** every credential issues a real P-256 key pair for the holder and
derives a real `did:key` from its public key.

### A7 — `proofValue` is base64url with no multibase prefix
`index.html:327` emits raw base64url. The Data Integrity specification requires
a multibase-encoded value. Kept as base64url for readability, but now stated
explicitly in the README rather than left as an undocumented deviation.

---

## B. Correctness & robustness

### B1 — `b64u` overflows the call stack on large inputs
`index.html:249`: `String.fromCharCode(...new Uint8Array(buf))` spreads every
byte as a separate argument. Signatures are 64 bytes so this never fired in
practice, but the same helper is used for arbitrary key material and would throw
`RangeError: Maximum call stack size exceeded` past V8's argument limit.
**Fix:** `bytesToBase64Url` chunks at 32 KB; tested against a 400 KB buffer.

### B2 — `initIssuer()` rejection is unhandled
`initIssuer()` is called bare at `index.html:480`. `crypto.subtle` is
`undefined` outside a secure context, so on any plain-HTTP origin other than
localhost the promise rejects, nothing is caught, and the page sits on
"generating…" forever with only a console message. Pages is HTTPS so the live
demo is fine — but a reviewer running `python -m http.server` on a LAN IP sees a
dead page with no explanation.
**Fix:** `boot()` catches, explains that a secure context is required, and
disables the controls instead of leaving them live but broken.

### B3 — Unawaited clipboard write
`index.html:439`: `navigator.clipboard.writeText(...)` with no `await` and no
`.catch`. It rejects when the document is not focused or the context is not
secure, surfacing as an unhandled rejection while the UI cheerfully flashes
"Credential copied".
**Fix:** awaited, with a fallback that loads the credential into the verifier
and says so.

### B4 — `esc()` does not escape the apostrophe, and is bypassed anyway
`index.html:432` escapes `& < > "` but not `'`. More importantly the same
template interpolates an unescaped id directly into an inline handler:
`onclick="toggleRevoke('${c.id}')"` (`index.html:412`). The id is a generated
UUID today, so it is not exploitable — but the escaping function exists
precisely because the author knew the inputs were untrusted, and this path skips
it.
**Fix:** `src/ui.js` builds every node with `createElement` + `textContent`.
There is no escaping function any more because there is nothing to escape.

### B5 — `chainIntact()` does not validate block indices
`index.html:387–393` checks the `prevHash` link and each block's own hash, but
not that `ledger[i].index === i`. A block with a forged index whose hash was
recomputed to match would pass.
**Fix:** `verifyChain()` checks index, linkage and self-hash, and reports
*which* block broke and why. Removal, reordering, in-place edits and
recomputed-hash forgery are each covered by a test.

### B6 — Ledger mutation in place
`anchor()` pushes onto the shared `ledger` array (`index.html:337`), so state
transitions are invisible to the caller.
**Fix:** `appendBlock()` returns a new array and the new block.

---

## C. Testability & structure

### C1 — No `package.json`, no tests, no linting, no CI
Three files: `index.html`, `README.md`, `LICENSE`. A repository whose entire
value proposition is cryptographic correctness had no way to demonstrate it.
**Fix:** 133 Vitest tests over the pure and crypto layers, ESLint flat config,
`html-validate`, and `deploy.yml` + `codeql.yml`.

### C2 — Module-level mutable globals
`issuerKeys`, `issuerJwk`, `issuerDid`, `wallet`, `revoked`, `ledger`,
`issuedCount` (`index.html:263–267`) are free variables. Every function closes
over them, so no function can be exercised with alternative inputs.
**Fix:** a single `store` object in `src/main.js`; every logic function takes
its inputs as parameters, including the ledger, the status list, the clock and
the `SubtleCrypto` implementation.

### C3 — Non-deterministic inputs read from ambient globals
`new Date().toISOString()` and `crypto.randomUUID()` are called inside
`buildCredential` (`index.html:294–296`), so no two builds are comparable.
**Fix:** `issuedAt`, `credentialId` and `achievementId` are parameters.
`buildCredential` is asserted deterministic.

### C4 — Four globals attached to `window` to serve inline handlers
`window.present`, `window.showJson`, `window.copyCred`, `window.toggleRevoke`
(`index.html:434–440`) exist only because the markup uses `onclick`.
**Fix:** handlers are closures passed into the render function; nothing is
attached to `window`.

---

## D. Security of the page itself

### D1 — No CSP, and none possible
Both the application (`index.html:241`) and the JSON-LD block
(`index.html:113`) are inline, and the styles are an inline `<style>` element,
so no policy stricter than `'unsafe-inline'` could be applied.
**Fix:** `default-src 'none'` with `script-src 'self'`, styles in
`src/*.css`, and `connect-src 'none'` — the page is structurally incapable of
making a network request, which is a verifiable form of the "nothing leaves
your browser" claim rather than an assertion in prose.

### D2 — Four inline event handlers
`onclick="present(0)"`, `showJson`, `copyCred`, `toggleRevoke`
(`index.html:409–412`).
**Fix:** `addEventListener` throughout; the Playwright smoke test asserts that
`document.querySelectorAll('[onclick],[onchange],[oninput],[onload],[onsubmit]')`
is empty.

### D3 — Third-party image origins in metadata
`og:image` and `twitter:image` point at Unsplash (`index.html:108–112`),
widening the page's origin surface for no functional benefit.
**Fix:** removed; the favicon is an inline SVG data URI.

---

## E. Accessibility

### E1 — No form control has an accessible name
Every `<label>` (`index.html:151–162`) is a sibling of its input with no `for`
attribute and no nesting, so none of them is programmatically associated.
Screen-reader users hear "edit text, blank" for all five issuer fields and the
verifier textarea.
**Fix:** every control has `for`/`id` association.

### E2 — Tabs are buttons with no tab semantics
`.tab` elements (`index.html:138–141`) carry no `role="tab"`, no
`aria-selected`, no `aria-controls`, no roving `tabindex`, and the panels have
no `role="tabpanel"`. Arrow-key navigation, which is the expected interaction
for a tablist, does nothing.
**Fix:** full ARIA tabs pattern with roving tabindex and Arrow/Home/End keys.

### E3 — Hidden panels are hidden with CSS only
`.view { display: none }` (`index.html:41`) leaves the inactive panels in the
accessibility tree in some configurations.
**Fix:** the `hidden` attribute, so the panels are removed from the tree.

### E4 — The toast is invisible to assistive technology
`.flash` (`index.html:239`, `269–270`) has no `role` and no live region, so
every confirmation the app gives is purely visual.
**Fix:** `role="status"` + `aria-live="polite"`.

### E5 — No `<main>` landmark, and no skip link
The page is a single `.wrap` div (`index.html:116`).
**Fix:** `<main id="demo-root">`, banner/contentinfo landmarks, skip link.

### E6 — Verification results are not announced
`#v-result` is populated on every verification (`index.html:456`) with no live
region, so the outcome of the page's primary action is never announced.
**Fix:** `role="status"` on the result container.

### E7 — Animation ignores `prefers-reduced-motion`
`@keyframes fade` on `.view.active` (`index.html:41–43`) and the toast
transition run unconditionally.
**Fix:** `exec-shell.css` disables animation and smooth scrolling under
`prefers-reduced-motion: reduce`.

### E8 — Status conveyed by colour and a bare glyph
`● Valid` / `● Revoked` (`index.html:405`) differ by colour and a dot.
**Fix:** status pills carry the word, meet WCAG AA contrast, and the check rows
are prefixed with "Pass —" / "Fail —" in text, not only with ✓/✗ glyphs (the
glyphs are now `aria-hidden`).

---

## F. Truthfulness

### F1 — "Blockchain anchoring" overstates a local array
The header chip and panel say "Blockchain Anchoring" (`index.html:129`, `218`).
It is an in-memory, single-process, hash-linked list. It is genuinely
tamper-evident, which is the property that matters, but it is not a blockchain:
there is no distribution, no consensus and no persistence.
**Fix:** renamed throughout to "hash-linked anchor ledger", with the
tamper-evidence property stated precisely and the absence of consensus stated in
the README's ADR-2.

### F2 — "Every signature and hash on this page is computed live in your browser"
This one was **true**, and it remains true — it is repeated in the new page
because it is the strongest honest claim the project has.

---

## Summary

| Category | Findings | Of which cryptographic-soundness defects |
| --- | --- | --- |
| Cryptographic soundness | 7 | 7 |
| Correctness & robustness | 6 | 2 (B1, B5) |
| Testability | 4 | — |
| Page security | 3 | — |
| Accessibility | 8 | — |
| Truthfulness | 1 | — |
| **Total** | **29** | **9** |

All 29 are addressed in this revision. The three that matter most are A1
(verification ignored the credential's stated issuer), A2 (the DID could not be
resolved, which forced A1) and A3 (revocation claimed a privacy-preserving
mechanism it did not implement).
