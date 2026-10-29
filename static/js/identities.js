/**
 * Identity inventory and risk exposure table.
 */
import { api, esc, isMock } from './api.js';
import { renderLayout } from './layout.js';
import { bandBadge, card, errorState, riskBar, skeleton, table } from './ui.js';

const content = renderLayout('identities', 'Identity Inventory', 'Entities, privilege posture, and cross-account blast radius');

async function renderIdentities() {
  content.innerHTML = skeleton(6);
  const mockQuery = isMock() ? '?mock=1' : '';

  try {
    const raw = await api('/identities');
    const identities = Array.isArray(raw) ? raw : [];

    function display(items) {
      const tbody = document.getElementById('identities-tbody');
      if (!tbody) return;
      tbody.innerHTML = items.map(id => {
        const band = id.risk >= 90 ? 'revoke' : (id.risk >= 70 ? 'restrict' : (id.risk >= 40 ? 'step_up' : 'monitor'));
        const privDots = '●'.repeat(id.privilege_level) + '○'.repeat(Math.max(0, 5 - id.privilege_level));
        return `
          <tr class="hover:bg-panel2 transition-colors cursor-pointer" onclick="window.location.href='/graph.html?identity=${esc(id.identity_id)}${mockQuery ? '&' + mockQuery.slice(1) : ''}'">
            <td class="px-4 py-3 font-medium text-ink flex items-center gap-2.5">
              <span class="w-7 h-7 rounded-full bg-brand/10 border border-brand/20 flex items-center justify-center text-xs font-mono font-bold text-brand">
                ${esc(id.identity_id.slice(0, 1).toUpperCase())}
              </span>
              <span>${esc(id.identity_id)}</span>
            </td>
            <td class="px-4 py-3">
              <div class="flex items-center gap-2">
                <span class="font-bold tabular-nums text-ink text-sm w-8">${id.risk.toFixed(0)}</span>
                ${riskBar(id.risk, band)}
              </div>
            </td>
            <td class="px-4 py-3">${bandBadge(band)}</td>
            <td class="px-4 py-3 font-mono text-xs text-brand2 tracking-widest" title="Level ${id.privilege_level}">${privDots}</td>
            <td class="px-4 py-3 tabular-nums text-muted">${esc(id.blast_radius)}</td>
            <td class="px-4 py-3 tabular-nums text-ink">${esc(id.alerts)}</td>
            <td class="px-4 py-3">
              <a href="/graph.html?identity=${esc(id.identity_id)}${mockQuery ? '&' + mockQuery.slice(1) : ''}" class="text-xs text-brand hover:underline font-medium">
                View Graph &rarr;
              </a>
            </td>
          </tr>
        `;
      }).join('');
    }

    content.innerHTML = `
      <div class="bg-panel border border-line rounded-xl p-4 flex items-center justify-between">
        <input type="text" id="identities-search" placeholder="Filter identities by name..." class="bg-panel2 border border-line rounded-lg px-3 py-1.5 text-xs text-ink placeholder-muted w-64 focus:outline-none focus:border-brand" />
        <div class="text-xs text-muted font-mono">${identities.length} total monitored identities</div>
      </div>

      <div class="bg-panel border border-line rounded-xl overflow-hidden shadow-sm">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="bg-panel2 text-muted text-xs uppercase font-medium border-b border-line">
              <tr>
                <th class="px-4 py-3 font-semibold">Identity</th>
                <th class="px-4 py-3 font-semibold">Max Risk</th>
                <th class="px-4 py-3 font-semibold">Risk Band</th>
                <th class="px-4 py-3 font-semibold">Privilege</th>
                <th class="px-4 py-3 font-semibold">Blast Radius</th>
                <th class="px-4 py-3 font-semibold">Active Alerts</th>
                <th class="px-4 py-3 font-semibold">Graph</th>
              </tr>
            </thead>
            <tbody id="identities-tbody" class="divide-y divide-line">
            </tbody>
          </table>
        </div>
      </div>
    `;

    document.getElementById('identities-search').oninput = (e) => {
      const q = e.target.value.toLowerCase();
      display(identities.filter(i => i.identity_id.toLowerCase().includes(q)));
    };

    display(identities);

  } catch (err) {
    content.innerHTML = errorState(`Failed to load identity list: ${err.message}`, 'btn-retry-idents');
    const retry = document.getElementById('btn-retry-idents');
    if (retry) retry.onclick = renderIdentities;
  }
}

renderIdentities();
