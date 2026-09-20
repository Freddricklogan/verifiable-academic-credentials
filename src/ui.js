/**
 * Rendering layer — the only module that touches the DOM.
 *
 * Every node is created with `createElement` + `textContent`. Nothing is
 * interpolated into `innerHTML`, so learner names and credential titles can
 * never be re-parsed as markup, and the page needs no escaping helper at all.
 */

import { abbreviateDid } from './did.js';

/** @param {string} tag @param {object} [props] @param {Array<Node|string|null>} [kids] */
export function el(tag, props = {}, kids = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = String(value);
    else if (key === 'dataset') Object.assign(node.dataset, value);
    else node.setAttribute(key, value === true ? '' : String(value));
  }
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
}

/**
 * A toast that is announced to assistive technology instead of being purely
 * visual (the original `.flash` had no role and no live region).
 * @param {HTMLElement} host
 */
export function createToast(host) {
  let timer = null;
  return function toast(message) {
    host.textContent = message;
    host.classList.add('toast--show');
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => host.classList.remove('toast--show'), 2600);
  };
}

/** @param {HTMLElement} host @param {{did: string, jwk: object}} identity */
export function renderIssuerIdentity(host, { did, jwk }) {
  host.replaceChildren(
    el('div', { class: 'field' }, [
      el('label', { for: 'issuer-did-box', text: 'Issuer DID (did:key · P-256)' }),
      el('div', { class: 'did-box', id: 'issuer-did-box', text: did })
    ]),
    el('div', { class: 'field' }, [
      el('label', { for: 'issuer-jwk', text: 'Resolved public key (JWK)' }),
      el('pre', {
        class: 'json',
        id: 'issuer-jwk',
        text: JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y }, null, 2)
      })
    ]),
    el('p', {
      class: 'panel__sub',
      text:
        'The DID is the key: base58btc over the multicodec-prefixed compressed ' +
        'point. A verifier recovers this exact JWK from the identifier alone, ' +
        'with no registry and no network call.'
    })
  );
}

/**
 * Render the learner wallet.
 *
 * @param {HTMLElement} host
 * @param {Array<{summary: object, signed: object, revoked: boolean}>} entries
 * @param {{ onPresent: Function, onToggleJson: Function, onCopy: Function, onToggleRevoke: Function }} handlers
 */
export function renderWallet(host, entries, handlers) {
  if (!entries.length) {
    host.replaceChildren(
      el('p', {
        class: 'empty',
        text: 'No credentials yet — issue one from the Issuer tab.'
      })
    );
    return;
  }

  host.replaceChildren(
    ...entries.map((entry, index) => {
      const { summary, revoked } = entry;
      const jsonId = `cred-json-${index}`;

      const present = el('button', {
        type: 'button',
        class: 'exec-btn exec-btn--primary',
        text: 'Present to verifier'
      });
      const viewJson = el('button', {
        type: 'button',
        class: 'exec-btn',
        'aria-expanded': 'false',
        'aria-controls': jsonId,
        text: 'View signed JSON'
      });
      const copy = el('button', { type: 'button', class: 'exec-btn', text: 'Copy' });
      const revoke = el('button', {
        type: 'button',
        class: 'exec-btn',
        text: revoked ? 'Reinstate' : 'Revoke'
      });

      present.addEventListener('click', () => handlers.onPresent(index));
      viewJson.addEventListener('click', () => handlers.onToggleJson(index, viewJson));
      copy.addEventListener('click', () => handlers.onCopy(index));
      revoke.addEventListener('click', () => handlers.onToggleRevoke(index));

      return el('article', { class: `cred${revoked ? ' cred--revoked' : ''}` }, [
        el('div', { class: 'cred__head' }, [
          el('div', {}, [
            el('h3', { class: 'cred__title', text: summary.title }),
            el('p', {
              class: 'cred__meta',
              text: `${summary.achievementType} · issued to ${summary.learnerName} by ${summary.issuerName}`
            }),
            el('p', {
              class: 'cred__meta',
              text: `Holder ${abbreviateDid(summary.learnerDid)} · status list index ${summary.statusListIndex}`
            })
          ]),
          el('span', {
            class: `status-pill status-pill--${revoked ? 'revoked' : 'valid'}`,
            text: revoked ? 'Revoked' : 'Valid'
          })
        ]),
        summary.competencies.length
          ? el(
              'ul',
              { class: 'cred__competencies' },
              summary.competencies.map((name) => el('li', { text: name }))
            )
          : null,
        el('div', { class: 'cred__actions' }, [present, viewJson, copy, revoke]),
        el('pre', { class: 'json', id: jsonId, hidden: true })
      ]);
    })
  );
}

/**
 * @param {HTMLElement} host
 * @param {{ pass: boolean, checks: Array<{label: string, ok: boolean, detail: string}> }|null} result
 */
export function renderVerification(host, result) {
  if (!result) {
    host.hidden = true;
    host.replaceChildren();
    return;
  }
  host.hidden = false;
  host.className = `result result--${result.pass ? 'pass' : 'fail'}`;
  host.replaceChildren(
    el('p', {
      class: 'result__verdict',
      text: result.pass ? '✓ Credential verified' : '✗ Verification failed'
    }),
    el(
      'ul',
      { class: 'checks' },
      result.checks.map((check) =>
        el('li', { class: `check check--${check.ok ? 'ok' : 'no'}` }, [
          el('span', { class: 'check__icon', 'aria-hidden': 'true', text: check.ok ? '✓' : '✗' }),
          el('span', {}, [
            el('strong', { text: `${check.ok ? 'Pass' : 'Fail'} — ${check.label}` }),
            el('span', { class: 'check__detail', text: check.detail })
          ])
        ])
      )
    )
  );
}

/** @param {HTMLElement} host @param {Array<object>} ledger */
export function renderLedger(host, ledger) {
  host.replaceChildren(
    ...[...ledger].reverse().map((block) =>
      el('article', { class: 'block' }, [
        el('span', {
          class: 'block__index',
          text: `Block #${block.index}${block.index === 0 ? ' · genesis' : ''}`
        }),
        el('span', { class: 'mono', text: `  ${new Date(block.timestamp).toLocaleString()}` }),
        el('dl', {}, [
          el('dt', { text: 'Credential' }),
          el('dd', { text: block.credentialId }),
          el('dt', { text: 'Credential hash' }),
          el('dd', { text: block.credentialHash }),
          el('dt', { text: 'Previous block' }),
          el('dd', { text: block.previousHash }),
          el('dt', { text: 'This block' }),
          el('dd', { text: block.blockHash })
        ])
      ])
    )
  );
}

/** @param {HTMLElement} host @param {{intact: boolean, reason: string}} status */
export function renderChainStatus(host, status) {
  host.replaceChildren(
    el('span', {
      class: `status-pill status-pill--${status.intact ? 'valid' : 'revoked'}`,
      text: status.intact ? 'Chain intact' : 'Chain broken'
    }),
    el('span', { class: 'panel__sub', text: ` ${status.reason}` })
  );
}
