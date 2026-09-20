# Case Study — Verifiable Academic Credentials

**Repository:** [verifiable-academic-credentials](https://github.com/Freddricklogan/verifiable-academic-credentials) · **Live demo:** [freddricklogan.github.io/verifiable-academic-credentials](https://freddricklogan.github.io/verifiable-academic-credentials/) · **Author:** Freddrick Logan

---

## 1. Who has this problem

A registrar, a career-services office, or a workforce programme that issues credentials people must prove to someone else. In my own work that is Elevate at Illinois Tech, where students complete career-readiness milestones an employer should be able to check. The same problem sits with a state agency issuing licences, a bootcamp issuing certificates, and any HR team fielding verification requests one phone call at a time.

## 2. The problem, as a scenario

A graduate applies for a role in another state. The employer's background-check vendor emails the registrar to confirm the degree. The office is closed for the weekend; confirmation arrives on Tuesday; the vendor charges for the lookup; the graduate, whose achievement it is, can neither prove it herself nor see that the request was made. Now replace the degree with a micro-credential from a programme that closed two years ago. There is nobody to phone. The credential is genuine and unverifiable in the same breath.

## 3. What it costs to leave it alone

Three costs, all structural. Latency: verification takes days at exactly the moment a hiring decision is being made. Fees: each lookup is a transaction someone pays for. Fragility: when an issuer merges, closes or loses records, every credential it ever issued becomes unverifiable, and forgeries become correspondingly easier to pass off. The W3C *Verifiable Credentials Data Model* ([w3.org/TR/vc-data-model-2.0](https://www.w3.org/TR/vc-data-model-2.0/)) and 1EdTech's *Open Badges 3.0* ([1edtech.org/standards/open-badges](https://www.1edtech.org/standards/open-badges)) exist because institutions concluded the phone-call model does not scale; I will not quote adoption or fraud figures because those in circulation vary widely by source.

## 4. The approach, and the alternative I rejected

I built the full lifecycle in the browser — issue, hold, present, verify, revoke — as a reference implementation of those two standards. The issuer signs the credential with a P-256 key; the credential carries the issuer's identity as a `did:key`, which is the public key itself encoded as an identifier; the verifier decodes that key from the document in front of it and runs six checks with no network access and no registry. Revocation uses a shared bitstring status list, so an issuer cannot tell which credential is being checked. A hash of each credential is anchored in a hash-linked ledger; the contents never are.

The alternative I rejected was the one the earlier version of this repository quietly took: look convincing. It verified against the key it had in memory rather than the key named by the credential, used a "DID" derived from a display name, and called a JavaScript `Set` a status list. Each shortcut made the demo simpler and removed the property it claimed to show. Making the mechanism real cost BigInt modular arithmetic for point decompression and a bitstring with the spec's bit ordering; that is the work, so I did it.

## 5. What the code does today

Real: key generation, ECDSA signing and verification via Web Crypto, RFC 8785-style canonicalisation, `did:key` encoding and decoding over the P-256 field, the bitstring status list, the hash-linked anchor ledger, the six-step verifier, and the Open Badges 3.0 envelope. All of it is pure logic with injected dependencies, so the same code runs under Node's `webcrypto` in tests and the browser's in the page.

Simulated: the institutions, learners and achievements are sample data, and the ledger is a local array, not a distributed chain; the page says so.

Worth knowing: two documented deviations from strict conformance — the status list is not GZIP-compressed and the proof value is plain base64url rather than multibase — mean a credential from this demo will not interoperate byte-for-byte with a conforming verifier. Rebuilding it exposed seven cryptographic-soundness defects in the earlier version; all are fixed, tested, and listed in the repository's audit file.

## 6. Evidence

Measured in continuous integration on the current main branch: 133 unit tests passing across eight files, 99.28% statement coverage, lint and HTML validation clean, CodeQL and dependency scanning enabled. The tests exercise real Web Crypto, not mocks, and include one that verifies a credential from a freshly generated issuer the verifier has never seen. Headless-browser smoke test: zero console errors, the guided tour forges a credential live and both the signature check and the anchor check fail. Security posture: Content Security Policy with `default-src 'none'`, no inline handlers, no third-party script.

## 7. What it would take to run this in production

The verifier and the credential format are the reusable parts. A production issuer would need: key custody in an HSM or cloud KMS; an issuer identity the world can resolve — `did:web` under the institution's domain rather than `did:key`; a hosted status list with the spec's compression; a learner wallet, or integration with one that already speaks Open Badges 3.0; identity binding at issuance through campus single sign-on; and an anchor that is not a local array — a public timestamping service or a consortium ledger, chosen for governance rather than novelty. Starting from a student information system, that is an engagement measured in months, most of it integration and policy rather than cryptography.

## 8. Limits and next steps

No wallet, no selective disclosure, no JSON-LD context validation, and the two conformance deviations above. Next: VC-JWT and a byte-exact Open Badges 3.0 export, a QR-code presentation and verification flow, and folding my earlier blockchain-credentials anchoring work in as a module.

## 9. Who should look at this

**Hiring manager:** evidence that I implement a standard rather than a facsimile, and audit my own earlier work honestly.
**Consulting client:** a working model of learner-owned credentials to put in front of a registrar or a workforce board before choosing a vendor.
**Engineer:** read `src/did.js` and `src/verify.js`, then `tests/` — the verifier is checked with real keys, and the audit file explains what "verifies" quietly meant before.
