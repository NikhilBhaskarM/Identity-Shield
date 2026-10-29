/**
 * Cryptographic tamper-evident audit log ledger.
 */
import { api, esc, fmtTime, toast } from './api.js';
import { renderLayout } from './layout.js';
import { card, errorState, skeleton, table } from './ui.js';

const content = renderLayout('audit', 'Tamper-Evident Audit Ledger', 'Cryptographic SHA-256 hash-chain guaranteeing non-repudiation of all decisions');

async function renderAudit() {
  content.innerHTML = skeleton(6);

  try {
    const [verify, entries] = await Promise.all([
      api('/audit/verify'),
      api('/audit?limit=200'),
    ]);

    const isValid = verify && verify.valid;
    const count = entries.length;

    content.innerHTML = `
      <!-- Verification Banner -->
      <div class="${isValid ? 'bg-ok/10 border-ok/30 text-ok' : 'bg-crit/10 border-crit/30 text-crit'} border rounded-xl p-4 flex items-center justify-between shadow-sm">
        <div class="flex items-center gap-3">
          <span class="w-8 h-8 rounded-full ${isValid ? 'bg-ok/20 text-ok' : 'bg-crit/20 text-crit'} flex items-center justify-center font-bold text-sm">
            ${isValid ? '✓' : '⚠'}
          </span>
          <div>
            <div class="font-semibold text-sm text-ink">
              ${isValid ? `Cryptographic Audit Chain Intact` : `Chain Integrity Compromised at Seq #${verify.broken_at}`}
            </div>
            <div class="text-xs text-muted">
              ${isValid ? `All ${count} ledger entries verified with unbroken SHA-256 genesis hashes.` : 'Audit record hash mismatch detected.'}
            </div>
          </div>
        </div>

        <button id="btn-reverify" class="px-3 py-1.5 text-xs font-medium rounded border border-line bg-panel2 hover:bg-line text-ink transition-colors">
          Verify Ledger Again
        </button>
      </div>

      <!-- Audit Entries Table -->
      ${card(
        'Recorded Audit Trail',
        table(
          ['Seq', 'Timestamp', 'Agent Module', 'Action', 'Event Details', 'Hash Signature'],
          (entries || []).map(r => `
            <tr class="hover:bg-panel2 transition-colors">
              <td class="px-4 py-2.5 font-mono text-xs text-muted tabular-nums">#${esc(r.seq)}</td>
              <td class="px-4 py-2.5 text-xs text-muted tabular-nums">${fmtTime(r.timestamp)}</td>
              <td class="px-4 py-2.5">
                <span class="px-1.5 py-0.5 rounded text-[10px] font-mono bg-panel2 border border-line text-brand2">
                  ${esc(r.agent)}
                </span>
              </td>
              <td class="px-4 py-2.5 font-mono text-xs font-medium text-ink">${esc(r.action)}</td>
              <td class="px-4 py-2.5 text-xs text-muted max-w-sm truncate" title="${esc(r.detail)}">
                ${esc(r.detail)}
              </td>
              <td class="px-4 py-2.5 font-mono text-xs text-muted" title="${esc(r.hash)}">
                ${esc(r.hash.slice(0, 14))}...
              </td>
            </tr>
          `).join('')
        )
      )}
    `;

    document.getElementById('btn-reverify').onclick = async () => {
      try {
        const v = await api('/audit/verify');
        if (v.valid) {
          toast('Cryptographic audit chain verification succeeded.');
        } else {
          toast(`Verification failed at seq ${v.broken_at}`, 'error');
        }
        renderAudit();
      } catch (e) {
        toast(e.message, 'error');
      }
    };

  } catch (err) {
    content.innerHTML = errorState(`Failed to load audit records: ${err.message}`, 'btn-retry-audit');
    const retry = document.getElementById('btn-retry-audit');
    if (retry) retry.onclick = renderAudit;
  }
}

renderAudit();
