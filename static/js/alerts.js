/**
 * Alerts queue with live filtering and navigation.
 */
import { api, esc, fmtTime, isMock, qs } from './api.js';
import { renderLayout } from './layout.js';
import { bandBadge, card, emptyState, errorState, patternChip, riskBar, skeleton, table } from './ui.js';

const content = renderLayout('alerts', 'Identity Threat Alerts', 'Prioritized session-level threats requiring SOC intervention');

async function renderAlerts() {
  content.innerHTML = skeleton(6);
  const mockQuery = isMock() ? '?mock=1' : '';

  try {
    const rawAlerts = await api('/alerts');
    const alerts = Array.isArray(rawAlerts) ? rawAlerts : [];

    function filterAndDisplay() {
      const search = (document.getElementById('filter-search')?.value || '').toLowerCase();
      const band = document.getElementById('filter-band')?.value || '';
      const pattern = document.getElementById('filter-pattern')?.value || '';
      const minRisk = parseFloat(document.getElementById('filter-risk')?.value || '0');

      const filtered = alerts.filter(a => {
        if (search && !a.identity_id.toLowerCase().includes(search) && !a.alert_id.toLowerCase().includes(search)) return false;
        if (band && a.band !== band) return false;
        if (pattern && !a.patterns.includes(pattern)) return false;
        if (a.risk < minRisk) return false;
        return true;
      });

      const countRevoke = filtered.filter(a => a.band === 'revoke').length;
      document.getElementById('alerts-count-label').textContent = `${filtered.length} alert${filtered.length === 1 ? '' : 's'} · ${countRevoke} critical`;

      const tbody = document.getElementById('alerts-tbody');
      if (!tbody) return;

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="py-12 text-center text-muted">${emptyState('No alerts match these filters')}</td></tr>`;
        return;
      }

      tbody.innerHTML = filtered.map(a => `
        <tr class="hover:bg-panel2 transition-colors cursor-pointer group" onclick="window.location.href='/alert.html?id=${esc(a.alert_id)}${mockQuery ? '&' + mockQuery.slice(1) : ''}'">
          <td class="px-4 py-3">
            <div class="flex items-center gap-2">
              <span class="font-bold tabular-nums text-ink text-sm w-8">${a.risk.toFixed(0)}</span>
              ${riskBar(a.risk, a.band)}
            </div>
          </td>
          <td class="px-4 py-3">${bandBadge(a.band)}</td>
          <td class="px-4 py-3 font-medium text-ink flex items-center gap-2">
            <span>${esc(a.identity_id)}</span>
          </td>
          <td class="px-4 py-3 font-mono text-xs text-muted max-w-[140px] truncate" title="${esc(a.session_id)}">
            ${esc(a.session_id || '-')}
          </td>
          <td class="px-4 py-3">
            <div class="flex flex-wrap gap-1">
              ${a.patterns.map(p => patternChip(p)).join('')}
            </div>
          </td>
          <td class="px-4 py-3 capitalize text-xs text-muted">${esc(a.recommended_action.replace('_', ' '))}</td>
          <td class="px-4 py-3">
            <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono capitalize ${a.action_status === 'applied' ? 'bg-ok/15 text-ok' : (a.action_status === 'pending' ? 'bg-warn/15 text-warn' : 'bg-line text-muted')}">
              ${esc(a.action_status)}
            </span>
          </td>
          <td class="px-4 py-3 text-xs text-muted tabular-nums">${fmtTime(a.last_seen)}</td>
        </tr>
      `).join('');
    }

    content.innerHTML = `
      <!-- Filter controls -->
      <div class="bg-panel border border-line rounded-xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div class="flex flex-wrap items-center gap-3">
          <input type="text" id="filter-search" placeholder="Search identity or alert ID..." class="bg-panel2 border border-line rounded-lg px-3 py-1.5 text-xs text-ink placeholder-muted w-56 focus:outline-none focus:border-brand" />
          <select id="filter-band" class="bg-panel2 border border-line rounded-lg px-3 py-1.5 text-xs text-ink focus:outline-none">
            <option value="">All Bands</option>
            <option value="revoke">Revoke</option>
            <option value="restrict">Restrict</option>
            <option value="step_up">Step-up</option>
            <option value="monitor">Monitor</option>
          </select>
          <select id="filter-pattern" class="bg-panel2 border border-line rounded-lg px-3 py-1.5 text-xs text-ink focus:outline-none">
            <option value="">All Patterns</option>
            <option value="P1">P1 Impossible travel</option>
            <option value="P2">P2 Dormant account</option>
            <option value="P3">P3 Privilege escalation</option>
            <option value="P4">P4 Unusual API</option>
            <option value="P5">P5 Token abuse</option>
            <option value="ML">ML Behavior anomaly</option>
          </select>
          <div class="flex items-center gap-2 text-xs text-muted pl-2 border-l border-line">
            <span>Min Risk:</span>
            <input type="range" id="filter-risk" min="0" max="100" value="0" class="w-24 accent-brand cursor-pointer" />
            <span id="risk-val" class="font-mono tabular-nums text-ink w-6">0</span>
          </div>
        </div>

        <div id="alerts-count-label" class="text-xs font-medium text-muted font-mono">
          --
        </div>
      </div>

      <!-- Alerts table card -->
      <div class="bg-panel border border-line rounded-xl overflow-hidden shadow-sm">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="bg-panel2 text-muted text-xs uppercase font-medium border-b border-line">
              <tr>
                <th class="px-4 py-3 font-semibold">Risk Score</th>
                <th class="px-4 py-3 font-semibold">Band</th>
                <th class="px-4 py-3 font-semibold">Identity</th>
                <th class="px-4 py-3 font-semibold">Session ID</th>
                <th class="px-4 py-3 font-semibold">Detected Patterns</th>
                <th class="px-4 py-3 font-semibold">Recommended</th>
                <th class="px-4 py-3 font-semibold">Status</th>
                <th class="px-4 py-3 font-semibold">Last Seen</th>
              </tr>
            </thead>
            <tbody id="alerts-tbody" class="divide-y divide-line">
            </tbody>
          </table>
        </div>
      </div>
    `;

    document.getElementById('filter-search').oninput = filterAndDisplay;
    document.getElementById('filter-band').onchange = filterAndDisplay;
    document.getElementById('filter-pattern').onchange = filterAndDisplay;
    const riskSlider = document.getElementById('filter-risk');
    riskSlider.oninput = () => {
      document.getElementById('risk-val').textContent = riskSlider.value;
      filterAndDisplay();
    };

    filterAndDisplay();

  } catch (err) {
    content.innerHTML = errorState(`Failed to load alerts queue: ${err.message}`, 'btn-retry-alerts');
    const retry = document.getElementById('btn-retry-alerts');
    if (retry) retry.onclick = renderAlerts;
  }
}

renderAlerts();
