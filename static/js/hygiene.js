/**
 * Identity Hygiene and Privilege Attack Surface Management.
 */
import { api, esc, fmtTime, isMock } from './api.js';
import { renderLayout } from './layout.js';
import { card, emptyState, errorState, skeleton, table } from './ui.js';

const content = renderLayout('hygiene', 'Identity Hygiene & Attack Surface', 'Preventative detection of dormant admin credentials and lateral escalation avenues');

async function renderHygiene() {
  content.innerHTML = skeleton(6);
  const mockQuery = isMock() ? '?mock=1' : '';

  try {
    const data = await api('/hygiene');
    const dormants = data.dormant_admins || [];
    const paths = data.escalation_paths || [];

    content.innerHTML = `
      <!-- Dormant Admins Card -->
      ${card(
        'Dormant Privileged Accounts',
        dormants.length > 0 ? table(
          ['Identity', 'Privilege Tier', 'Days Inactive', 'Reactivation Timestamp', 'Action'],
          dormants.map(d => `
            <tr class="hover:bg-panel2 transition-colors">
              <td class="px-4 py-3 font-semibold text-ink flex items-center gap-2">
                <span class="w-2 h-2 rounded-full bg-warn"></span>
                <span>${esc(d.identity_id)}</span>
              </td>
              <td class="px-4 py-3 font-mono text-xs text-brand2">Level ${esc(d.privilege_level)}</td>
              <td class="px-4 py-3 tabular-nums text-crit font-bold text-sm">${esc(d.days_inactive)} days</td>
              <td class="px-4 py-3 tabular-nums text-muted text-xs">${fmtTime(d.reactivated_at)}</td>
              <td class="px-4 py-3">
                <a href="/identities.html${mockQuery}" class="text-xs text-brand hover:underline">
                  View Profile &rarr;
                </a>
              </td>
            </tr>
          `).join('')
        ) : emptyState('No dormant privileged accounts detected.'),
        `<span class="text-xs text-muted">Accounts with level 4+ privilege inactive &gt; 30 days</span>`
      )}

      <!-- Paths to Admin Card -->
      ${card(
        'Reachable Paths to Administrative Access',
        paths.length > 0 ? `
          <div class="space-y-4">
            ${paths.map(item => `
              <div class="p-4 bg-panel2 border border-line rounded-lg">
                <div class="flex items-center justify-between mb-2">
                  <span class="font-semibold text-sm text-ink font-mono">${esc(item.identity_id)}</span>
                  <a href="/graph.html?identity=${esc(item.identity_id)}${mockQuery ? '&' + mockQuery.slice(1) : ''}" class="text-xs text-brand hover:underline">
                    View in Graph &rarr;
                  </a>
                </div>
                <div class="space-y-2">
                  ${item.paths.map((p, i) => `
                    <div class="text-xs font-mono text-muted flex items-center gap-1.5 flex-wrap">
                      <span class="text-brand2 font-semibold">#${i + 1}</span>
                      ${p.map(step => `<span class="px-1.5 py-0.5 rounded bg-panel border border-line text-ink">${esc(step)}</span>`).join('&rarr;')}
                    </div>
                  `).join('')}
                </div>
              </div>
            `).join('')}
          </div>
        ` : emptyState('No escalation pathways to administrator found.'),
        `<span class="text-xs text-muted">Transitive role assumptions and permission grants reaching admin roles</span>`
      )}
    `;
  } catch (err) {
    content.innerHTML = errorState(`Failed to load hygiene metrics: ${err.message}`, 'btn-retry-hyg');
    const retry = document.getElementById('btn-retry-hyg');
    if (retry) retry.onclick = renderHygiene;
  }
}

renderHygiene();
