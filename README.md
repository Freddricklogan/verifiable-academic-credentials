<h1 align="center">VeriCred — Verifiable Academic Credentials</h1>

<p align="center">
  <em>Learner-owned academic credentials on open standards — issue, hold, and verify, with real cryptography and blockchain anchoring.</em>
</p>

<p align="center">
  <a href="https://freddricklogan.github.io/verifiable-academic-credentials/"><img src="https://img.shields.io/badge/Live_Demo-Open_App-c9a227?style=for-the-badge&logo=github" alt="Live Demo"></a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/W3C-Verifiable_Credentials-005a9c" alt="W3C VC">
  <img src="https://img.shields.io/badge/Open_Badges-3.0-ff6b00" alt="Open Badges 3.0">
  <img src="https://img.shields.io/badge/Identity-DIDs-3a0ca3" alt="DIDs">
  <img src="https://img.shields.io/badge/Crypto-ECDSA_P--256_(Web_Crypto)-2a9d8f" alt="Web Crypto">
  <img src="https://img.shields.io/badge/License-MIT-lightgrey" alt="License">
</p>

---

## Overview

**VeriCred** is a working prototype of a modern academic credentialing platform — the kind of system a
university or credentialing body would use to issue tamper-evident, **learner-owned** digital
credentials that anyone can verify independently.

It is built on the same open standards championed by the **[Digital Credentials Consortium](https://dcconsortium.org/)**
(the MIT-led group behind the open-source infrastructure for verifiable academic credentials):
**W3C Verifiable Credentials**, **Open Badges 3.0**, **Decentralized Identifiers (DIDs)**, and
**status-list revocation** — with a **blockchain anchoring** layer added for tamper-evidence.

Everything is real and runs in the browser: credentials are cryptographically signed and verified with
the native **Web Crypto API** (ECDSA P-256). No mock signatures, no backend.

> **▶ [Launch the live demo](https://freddricklogan.github.io/verifiable-academic-credentials/)**

---

## The full credential lifecycle

| Stage | What happens |
|:--|:--|
| **① Issuer** | An institution assembles an Open Badges 3.0 achievement inside a W3C Verifiable Credential and **signs it** with its private key. The issuer identity is a DID derived from its public key. |
| **② Learner Wallet** | The learner **holds and controls** their credentials, can inspect the raw signed JSON, and presents them to any verifier. |
| **③ Verifier** | Independent verification checks **four** things: the cryptographic signature, the issuer DID, the blockchain anchor, and the revocation status. A one-click **tamper test** forges a field and shows the signature check fail. |
| **④ Anchor Ledger** | Each credential's SHA-256 hash is written to an append-only, **hash-linked ledger** — only the hash, never private data — making any later tampering evident across the whole chain. |

---

## Why this project

| Skill demonstrated | Where it shows up |
|:--|:--|
| **Applied cryptography** | Real ECDSA P-256 signing/verification via Web Crypto; deterministic canonicalization so bytes match |
| **Open credentialing standards** | W3C Verifiable Credentials 2.0 + Open Badges 3.0 data model, DIDs, StatusList2021 revocation |
| **Blockchain done right** | Hashes anchored on a tamper-evident chain; private data kept **off-chain** for privacy |
| **Security thinking** | An adversarial "forge a better credential" test that the system catches |
| **EdTech domain fluency** | Degrees, micro-credentials, and competency-based achievements modeled correctly |

---

## Standards & alignment with the DCC

- **W3C Verifiable Credentials Data Model** — the credential envelope, proof, and issuer/subject model.
- **Open Badges 3.0 (1EdTech)** — the `OpenBadgeCredential` / `Achievement` / `Competency` structure.
- **Decentralized Identifiers (DIDs)** — `did:key`-style identifiers derived from public keys.
- **StatusList2021** — the revocation model referenced by `credentialStatus`.
- **Privacy by design** — the ledger stores only credential *hashes*; personal data never goes on-chain.

This mirrors the DCC's core position: credentials should be **portable, learner-owned, cryptographically
verifiable, and vendor-neutral** — not locked inside a single institution's database.

---

## Tech stack

- **Language:** Vanilla JavaScript (ES6+)
- **Cryptography:** Web Crypto API — ECDSA (P-256) signatures, SHA-256 hashing
- **Data model:** W3C VC 2.0 + Open Badges 3.0 (JSON-LD contexts)
- **Runtime:** 100% client-side — no backend, no build step, nothing leaves the browser

---

## Run locally

```bash
git clone https://github.com/Freddricklogan/verifiable-academic-credentials.git
cd verifiable-academic-credentials
python3 -m http.server 8000
# then visit http://localhost:8000
```

> Cryptographic operations require a secure context; `http://localhost` and `https://` both qualify.

---

## Roadmap

- [ ] Resolve issuer keys from a real DID document rather than in-memory
- [ ] QR-code presentation for mobile wallet import (Learner Credential Wallet compatible)
- [ ] JSON-LD canonicalization (RDF Dataset Normalization) for full Data Integrity conformance
- [ ] Batch issuance from a CSV roster

---

## Author

**Freddrick Logan** — Educational Technologist & Technology Leader
[GitHub](https://github.com/Freddricklogan) · [LinkedIn](https://www.linkedin.com/in/freddricklogan/)

## License

Released under the [MIT License](LICENSE). Sample data in the demo is illustrative and does not represent real credentials.
