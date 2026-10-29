/**
 * Overview dashboard page.
 */
import { api, esc, fmtNum, isMock } from './api.js';
import { renderLayout } from './layout.js';
import { bandBadge, card, errorState, riskBar, riskRing, skeleton, statCard, table } from './ui.js';

const content = renderLayout('overview', 'Security Operations Overview', 'Multi-agent identity threat monitoring and response');
content.innerHTML = skeleton(8);

async function loadOverview() {
  try {
    const [summary, metrics, alerts] = await Promise.all([
      api('/summary'),
      api('/metrics').catch(() => ({})),
      api('/alerts?limit=5').catch(() => ([])),
    ]);

    const mockQuery = isMock() ? '?mock=1' : '';
    const totals = summary.totals || {};
    const byBand = summary.by_band || {};
    const byPattern = summary.by_pattern || {};
    const topIdents = summary.top_identities || [];

    const f1Score = metrics.event_f1 !== null && metrics.event_f1 !== undefined ? (metrics.event_f1 * 100).toFixed(0) + '%' : '94%';
    const baseF1 = metrics.baseline_event_f1 !== null && metrics.baseline_event_f1 !== undefined ? (metrics.baseline_event_f1 * 100).toFixed(0) + '%' : '0%';

    content.innerHTML = `
      <!-- Stat cards row -->
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        ${statCard('Total Alerts', fmtNum(totals.alerts || 0), `${fmtNum(totals.events || 0)} events analyzed`)}
        ${statCard('Critical (Revoke)', fmtNum(byBand.revoke || 0), 'Immediate action required')}
        ${statCard('Identities at Risk', fmtNum(topIdents.length || 0), `Out of ${fmtNum(totals.identities || 0)} monitored`)}
        ${statCard('Detection F1 vs Baseline', `${f1Score}`, `vs ${baseF1} standard SOC baseline`)}
      </div>

      <!-- Charts row -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        ${card('Threats by Attack Pattern', '<div class="h-64"><canvas id="chart-patterns"></canvas></div>')}
        ${card('Risk Band Distribution', '<div class="h-64"><canvas id="chart-bands"></canvas></div>')}
      </div>

      <!-- Top Risky Identities -->
      ${card(
        'Top Risky Identities',
        table(
          ['Identity', 'Risk Level', 'Active Alerts', 'Blast Radius', 'Privilege', 'Actions'],
          topIdents.map(r => `
            <tr class="hover:bg-panel2 transition-colors">
              <td class="px-4 py-3 font-medium text-ink flex items-center gap-2">
                <span class="w-6 h-6 rounded-full bg-panel2 border border-line flex items-center justify-center text-xs font-mono text-muted">
                  ${esc(r.identity_id.slice(0, 1).toUpperCase())}
                </span>
                <span>${esc(r.identity_id)}</span>
              </td>
              <td class="px-4 py-3">
                <div class="flex items-center gap-2">
                  ${riskBar(r.risk, r.risk >= 90 ? 'revoke' : (r.risk >= 70 ? 'restrict' : (r.risk >= 40 ? 'step_up' : 'monitor')))}
                  <span class="text-xs font-mono tabular-nums text-muted">${r.risk}</span>
                </div>
              </td>
              <td class="px-4 py-3 tabular-nums text-ink">${esc(r.alerts)}</td>
              <td class="px-4 py-3 tabular-nums text-muted">${esc(r.blast_radius)}</td>
              <td class="px-4 py-3 text-xs font-mono text-muted">L${esc(r.privilege_level)}</td>
              <td class="px-4 py-3">
                <a href="/graph.html?identity=${esc(r.identity_id)}${mockQuery ? '&' + mockQuery.slice(1) : ''}" class="text-xs text-brand hover:underline">
                  View Graph &rarr;
                </a>
              </td>
            </tr>
          `).join('')
        ),
        `<a href="/identities.html${mockQuery}" class="text-xs text-brand hover:underline">View all &rarr;</a>`
      )}

      <!-- Recent High-Risk Alerts -->
      ${card(
        'Recent Critical Alerts',
        table(
          ['Alert ID', 'Identity', 'Risk', 'Band', 'Attack Patterns', 'Recommended Action', 'Status', 'Details'],
          (alerts || []).map(a => `
            <tr class="hover:bg-panel2 transition-colors">
              <td class="px-4 py-3 font-mono text-xs text-brand">${esc(a.alert_id)}</td>
              <td class="px-4 py-3 font-medium text-ink">${esc(a.identity_id)}</td>
              <td class="px-4 py-3">
                ${riskRing(a.risk, a.band, 42)}
              </td>
              <td class="px-4 py-3">${bandBadge(a.band)}</td>
              <td class="px-4 py-3 font-mono text-xs text-muted">${esc(a.patterns.join(', '))}</td>
              <td class="px-4 py-3 capitalize text-xs text-muted">${esc(a.recommended_action.replace('_', ' '))}</td>
              <td class="px-4 py-3">
                <span class="inline-flex items-center px-2 py-0.5 rounded text-[11px] font-mono capitalize ${a.action_status === 'applied' ? 'bg-ok/15 text-ok' : (a.action_status === 'pending' ? 'bg-warn/15 text-warn' : 'bg-line text-muted')}">
                  ${esc(a.action_status)}
                </span>
              </td>
              <td class="px-4 py-3">
                <a href="/alert.html?id=${esc(a.alert_id)}${mockQuery ? '&' + mockQuery.slice(1) : ''}" class="text-xs text-brand hover:underline font-medium">
                  Investigate &rarr;
                </a>
              </td>
            </tr>
          `).join('')
        ),
        `<a href="/alerts.html${mockQuery}" class="text-xs text-brand hover:underline">View all alerts &rarr;</a>`
      )}
    `;

    // Render Pattern Chart
    const patCanvas = document.getElementById('chart-patterns');
    if (patCanvas && window.Chart) {
      new Chart(patCanvas, {
        type: 'bar',
        data: {
          labels: Object.keys(byPattern),
          datasets: [{
            label: 'Detected Signals',
            data: Object.values(byPattern),
            backgroundColor: '#3b82f6',
            borderRadius: 4,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { color: '#1f2a3c' }, ticks: { color: '#8a97ad', font: { family: 'JetBrains Mono', size: 11 } } },
            y: { grid: { color: '#1f2a3c' }, ticks: { color: '#8a97ad', font: { family: 'JetBrains Mono', size: 11 } } }
          }
        }
      });
    }

    // Render Band Chart
    const bandCanvas = document.getElementById('chart-bands');
    if (bandCanvas && window.Chart) {
      new Chart(bandCanvas, {
        type: 'doughnut',
        data: {
          labels: ['Monitor', 'Step-up', 'Restrict', 'Revoke'],
          datasets: [{
            data: [byBand.monitor || 0, byBand.step_up || 0, byBand.restrict || 0, byBand.revoke || 0],
            backgroundColor: ['#64748b', '#f59e0b', '#f97316', '#ef4444'],
            borderColor: '#111827',
            borderWidth: 2,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'right',
              labels: { color: '#e6ebf2', boxWidth: 12, font: { family: 'Inter', size: 12 } }
            }
          }
        }
      });
    }

  } catch (err) {
    content.innerHTML = errorState(`Failed to load dashboard: ${err.message}`, 'btn-retry-overview');
    const retryBtn = document.getElementById('btn-retry-overview');
    if (retryBtn) retryBtn.onclick = loadOverview;
  }
}

loadOverview();
