/**
 * Application entry point: owns state, wires events, drives rendering.
 * All cryptography and all validation live in the pure modules.
 */

import { mountExecShell } from './exec-shell.js';
import {
  buildCredential,
  parseCompetencies,
  summarizeCredential
} from './credential.js';
import {
  generateSigningIdentity,
  hashDocument,
  sha256Hex,
  signCredential
} from './crypto.js';
import { appendBlock, createLedger, verifyChain } from './ledger.js';
import {
  countRevoked,
  createStatusList,
  getStatus,
  toggleStatus
} from './statuslist.js';
import { verifyCredential } from './verify.js';
import {
  createToast,
  renderChainStatus,
  renderIssuerIdentity,
  renderLedger,
  renderVerification,
  renderWallet
} from './ui.js';

const REPO = 'https://github.com/Freddricklogan/verifiable-academic-credentials';
const PAGES = 'https://freddricklogan.github.io/verifiable-academic-credentials/';
const STATUS_LIST_URL = 'https://freddricklogan.github.io/verifiable-academic-credentials/status/1';
const STATUS_LIST_SIZE = 2048;

const hash = (input) => sha256Hex(input);

const store = {
  /** @type {{keyPair: CryptoKeyPair, did: string, publicJwk: JsonWebKey}|null} */
  issuer: null,
  /** @type {Array<object>} */ ledger: [],
  statusList: createStatusList(STATUS_LIST_SIZE),
  /** @type {Array<{summary: object, signed: object, revoked: boolean, index: number}>} */
  wallet: [],
  nextStatusIndex: 0,
  verifications: { attempted: 0, passed: 0 },
  chain: { intact: true, reason: 'not yet verified' }
};

const dom = {
  tabs: [...document.querySelectorAll('[role="tab"]')],
  panels: [...document.querySelectorAll('[role="tabpanel"]')],
  issuerIdentity: document.querySelector('#issuer-identity'),
  form: {
    issuer: document.querySelector('#f-issuer'),
    learner: document.querySelector('#f-learner'),
    title: document.querySelector('#f-title'),
    type: document.querySelector('#f-type'),
    skills: document.querySelector('#f-skills')
  },
  btnIssue: document.querySelector('#btn-issue'),
  wallet: document.querySelector('#wallet-list'),
  verifyInput: document.querySelector('#v-input'),
  btnVerify: document.querySelector('#btn-verify'),
  btnTamper: document.querySelector('#btn-tamper'),
  verifyResult: document.querySelector('#v-result'),
  ledgerList: document.querySelector('#ledger-list'),
  chainStatus: document.querySelector('#chain-status'),
  btnCheckChain: document.querySelector('#btn-checkchain'),
  toast: document.querySelector('#toast')
};

const toast = createToast(dom.toast);

/* -------------------------------------------------------------------------- */
/* Tabs                                                                       */
/* -------------------------------------------------------------------------- */

function switchTab(name) {
  for (const tab of dom.tabs) {
    const selected = tab.dataset.view === name;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
  }
  for (const panel of dom.panels) {
    panel.hidden = panel.dataset.view !== name;
  }
}

function onTabKeydown(event) {
  const index = dom.tabs.indexOf(event.target);
  if (index === -1) return;
  let next = null;
  if (event.key === 'ArrowRight') next = (index + 1) % dom.tabs.length;
  else if (event.key === 'ArrowLeft') next = (index - 1 + dom.tabs.length) % dom.tabs.length;
  else if (event.key === 'Home') next = 0;
  else if (event.key === 'End') next = dom.tabs.length - 1;
  if (next === null) return;
  event.preventDefault();
  switchTab(dom.tabs[next].dataset.view);
  dom.tabs[next].focus();
}

/* -------------------------------------------------------------------------- */
/* Rendering                                                                  */
/* -------------------------------------------------------------------------- */

function renderAll() {
  renderWallet(dom.wallet, store.wallet, walletHandlers);
  renderLedger(dom.ledgerList, store.ledger);
  renderChainStatus(dom.chainStatus, store.chain);
  shell.refreshKpis();
}

const walletHandlers = {
  onPresent(index) {
    dom.verifyInput.value = JSON.stringify(store.wallet[index].signed, null, 2);
    renderVerification(dom.verifyResult, null);
    switchTab('verify');
    dom.btnVerify.focus();
    toast('Credential loaded into the verifier');
  },
  onToggleJson(index, button) {
    const pre = document.querySelector(`#cred-json-${index}`);
    const show = pre.hidden;
    if (show) pre.textContent = JSON.stringify(store.wallet[index].signed, null, 2);
    pre.hidden = !show;
    button.setAttribute('aria-expanded', String(show));
  },
  async onCopy(index) {
    const text = JSON.stringify(store.wallet[index].signed, null, 2);
    try {
      // Rejects outside a secure context and when the document is not focused;
      // the original call was unawaited, so that failure surfaced only as an
      // unhandled promise rejection in the console.
      await navigator.clipboard.writeText(text);
      toast('Signed credential copied to the clipboard');
    } catch {
      dom.verifyInput.value = text;
      switchTab('verify');
      toast('Clipboard unavailable — loaded into the verifier instead');
    }
  },
  onToggleRevoke(index) {
    const entry = store.wallet[index];
    const revoked = toggleStatus(store.statusList, entry.summary.statusListIndex);
    entry.revoked = revoked;
    renderAll();
    toast(revoked ? 'Revoked — bit set on the status list' : 'Reinstated — bit cleared');
  }
};

/* -------------------------------------------------------------------------- */
/* Actions                                                                    */
/* -------------------------------------------------------------------------- */

async function issue() {
  if (!store.issuer) {
    toast('Issuer key is still being generated');
    return;
  }
  const now = new Date().toISOString();
  const statusListIndex = store.nextStatusIndex;
  store.nextStatusIndex += 1;

  const holder = await generateSigningIdentity();
  const unsigned = buildCredential({
    issuerName: dom.form.issuer.value.trim() || 'Unnamed Institution',
    issuerDid: store.issuer.did,
    learnerName: dom.form.learner.value.trim() || 'Unnamed Learner',
    learnerDid: holder.did,
    title: dom.form.title.value.trim() || 'Untitled Credential',
    achievementType: dom.form.type.value,
    competencies: parseCompetencies(dom.form.skills.value),
    statusListIndex,
    statusListCredentialUrl: STATUS_LIST_URL,
    issuedAt: now,
    credentialId: `urn:uuid:${crypto.randomUUID()}`,
    achievementId: `urn:uuid:${crypto.randomUUID()}`
  });

  const signed = await signCredential(unsigned, {
    privateKey: store.issuer.keyPair.privateKey,
    issuerDid: store.issuer.did,
    created: now
  });

  const { ledger } = await appendBlock(store.ledger, {
    credentialId: signed.id,
    credentialHash: await hashDocument(signed),
    timestamp: now,
    hash
  });
  store.ledger = ledger;
  store.chain = await verifyChain(store.ledger, hash);

  store.wallet.unshift({
    summary: summarizeCredential(signed),
    signed,
    revoked: getStatus(store.statusList, statusListIndex)
  });

  renderAll();
  switchTab('wallet');
  toast('Credential signed, anchored and delivered to the wallet');
}

async function verifyPasted() {
  let candidate;
  try {
    candidate = JSON.parse(dom.verifyInput.value);
  } catch {
    renderVerification(dom.verifyResult, {
      pass: false,
      checks: [
        {
          label: 'JSON parse',
          ok: false,
          detail: 'The verifier input is not valid JSON. Paste a signed credential.'
        }
      ]
    });
    return;
  }

  store.verifications.attempted += 1;
  const result = await verifyCredential(candidate, {
    ledger: store.ledger,
    statusList: store.statusList,
    now: Date.now()
  });
  if (result.pass) store.verifications.passed += 1;

  renderVerification(dom.verifyResult, result);
  shell.refreshKpis();
  toast(result.pass ? 'All checks passed' : 'Verification failed — see the checklist');
}

async function tamperTest() {
  if (!store.wallet.length) {
    toast('Issue a credential first');
    return;
  }
  const forged = JSON.parse(JSON.stringify(store.wallet[0].signed));
  forged.name = 'Ph.D. in Rocket Science';
  forged.credentialSubject.achievement.name = 'Ph.D. in Rocket Science';
  dom.verifyInput.value = JSON.stringify(forged, null, 2);
  switchTab('verify');
  await verifyPasted();
  toast('Title forged — the signature and the anchor both fail');
}

async function recheckChain() {
  store.chain = await verifyChain(store.ledger, hash);
  renderChainStatus(dom.chainStatus, store.chain);
  shell.refreshKpis();
  toast(store.chain.intact ? 'Ledger chain verified intact' : 'Ledger chain is broken');
}

/* -------------------------------------------------------------------------- */
/* Executive Shell                                                            */
/* -------------------------------------------------------------------------- */

const shell = mountExecShell({
  title: 'VeriCred — Verifiable Academic Credentials',
  tagline:
    'A browser-based reference implementation of W3C Verifiable Credentials 2.0 and ' +
    'Open Badges 3.0: real ECDSA P-256 signatures, self-resolving did:key identifiers, ' +
    'bitstring status-list revocation and a hash-linked anchor ledger. The cryptography ' +
    'is genuine and runs in your browser; the institutions and learners are illustrative.',
  repo: REPO,
  pagesUrl: PAGES,
  badges: [
    { label: 'Real Web Crypto · ECDSA P-256', tone: 'accent' },
    { label: 'W3C VC 2.0 · Open Badges 3.0' },
    { label: 'Keys never leave the browser', dot: true }
  ],
  kpis: [
    { label: 'Credentials issued', compute: () => store.wallet.length, tone: 'accent' },
    { label: 'Anchor blocks', compute: () => store.ledger.length },
    { label: 'Revoked', compute: () => countRevoked(store.statusList), tone: 'danger' },
    {
      label: 'Verifications passed',
      compute: () => `${store.verifications.passed}/${store.verifications.attempted}`,
      tone: 'ok'
    },
    {
      label: 'Chain integrity',
      compute: () => (store.chain.intact ? 'Intact' : 'Broken'),
      tone: store.chain?.intact === false ? 'danger' : 'ok'
    }
  ],
  tour: [
    {
      selector: '#btn-issue',
      title: '1 · Issue and sign',
      body:
        'The issuer assembles an Open Badges 3.0 achievement inside a W3C Verifiable ' +
        'Credential, canonicalizes it, signs it with a P-256 private key generated in ' +
        'this browser, and anchors its SHA-256 hash to the ledger. Issuing one now.',
      action: () => issue()
    },
    {
      selector: '#wallet-list',
      title: '2 · The learner holds it',
      body:
        'The credential lands in the learner wallet. Nothing was uploaded — the holder ' +
        'has their own did:key, and the credential is theirs to present, copy or keep.',
      action: () => switchTab('wallet')
    },
    {
      selector: '#btn-verify',
      title: '3 · Verify independently',
      body:
        'The verifier recovers the public key from the credential’s own issuer DID — ' +
        'no registry, no phone call to the university — then checks the signature, the ' +
        'anchor, the revocation bit and the validity period. Running all six checks now.',
      action: async () => {
        if (!store.wallet.length) await issue();
        dom.verifyInput.value = JSON.stringify(store.wallet[0].signed, null, 2);
        switchTab('verify');
        await verifyPasted();
      }
    },
    {
      selector: '#btn-tamper',
      title: '4 · Try to forge it',
      body:
        'Upgrading the degree to a Ph.D. in Rocket Science and re-verifying. One changed ' +
        'character means different signed bytes and a different hash, so the signature ' +
        'check and the anchor check both fail. That is tamper-evidence.',
      action: () => tamperTest()
    },
    {
      selector: '#btn-checkchain',
      title: '5 · Re-verify the whole ledger',
      body:
        'Every block commits to its predecessor’s hash, so altering any anchored ' +
        'credential breaks that block and every block after it. Re-verifying the chain ' +
        'end to end.',
      action: async () => {
        switchTab('ledger');
        await recheckChain();
      }
    }
  ]
});

/* -------------------------------------------------------------------------- */
/* Wiring — no inline handlers anywhere                                       */
/* -------------------------------------------------------------------------- */

for (const tab of dom.tabs) {
  tab.addEventListener('click', () => switchTab(tab.dataset.view));
}
document.querySelector('#tablist').addEventListener('keydown', onTabKeydown);
dom.btnIssue.addEventListener('click', () => {
  void issue();
});
dom.btnVerify.addEventListener('click', () => {
  void verifyPasted();
});
dom.btnTamper.addEventListener('click', () => {
  void tamperTest();
});
dom.btnCheckChain.addEventListener('click', () => {
  void recheckChain();
});

/* -------------------------------------------------------------------------- */
/* Boot                                                                       */
/* -------------------------------------------------------------------------- */

async function boot() {
  try {
    store.issuer = await generateSigningIdentity();
    store.ledger = await createLedger({ timestamp: new Date().toISOString(), hash });
    store.chain = await verifyChain(store.ledger, hash);
    renderIssuerIdentity(dom.issuerIdentity, {
      did: store.issuer.did,
      jwk: store.issuer.publicJwk
    });
    renderAll();
  } catch (error) {
    // Web Crypto is unavailable outside a secure context. The original code
    // left the page saying "generating…" forever with an unhandled rejection.
    dom.issuerIdentity.replaceChildren();
    dom.issuerIdentity.append(
      Object.assign(document.createElement('p'), {
        className: 'empty',
        textContent: `Cryptography unavailable: ${error.message} Serve this page over https:// or http://localhost.`
      })
    );
    dom.btnIssue.disabled = true;
    dom.btnVerify.disabled = true;
    dom.btnTamper.disabled = true;
    dom.btnCheckChain.disabled = true;
    toast('Web Crypto unavailable in this context');
  }
}

switchTab('issue');
void boot();
