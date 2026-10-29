/**
 * Deep-dive investigation page for a single alert.
 */
import { api, esc, fmtTime, isMock, qs, toast } from './api.js';
import { renderLayout } from './layout.js';
import { bandBadge, button, card, confirmModal, emptyState, errorState, mitreChip, patternChip, riskRing, skeleton, table } from './ui.js';

const alertId = qs('id');
const content = renderLayout('alerts', 'Alert Deep-Dive Investigation', alertId ? `Incident ID: ${alertId}` : 'Incident Details');

if (!alertId) {
  content.innerHTML = emptyState('No Alert ID specified. Please return to the Alerts queue.');
} else {
  loadAlertDetail();
}

async function loadAlertDetail() {
  content.innerHTML = skeleton(8);
  const mockQuery = isMock() ? '?mock=1' : '';

  try {
    const [alert, events] = await Promise.all([
      api(`/alerts/${alertId}`),
      api(`/alerts/${alertId}/events`).catch(() => ([])),
    ]);

    const isApplied = alert.action_status === 'applied' || alert.action_status === 'dismissed';
    const isRevoke = alert.band === 'revoke';

    content.innerHTML = `
      <!-- Header Summary Card -->
      <div class="bg-panel border border-line rounded-xl p-6 shadow-sm">
        <div class="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div class="flex items-center gap-5">
            ${riskRing(alert.risk, alert.band, 84)}
            <div>
              <div class="flex items-center gap-2.5 mb-1">
                <span class="text-xl font-bold text-ink">${esc(alert.identity_id)}</span>
                ${bandBadge(alert.band)}
                <span class="text-xs font-mono text-muted">Blast Radius: <b class="text-ink">${alert.blast_radius}</b></span>
              </div>
              <div class="text-xs text-muted flex flex-wrap items-center gap-x-4 gap-y-1">
                <span>Session: <code class="font-mono text-ink">${esc(alert.session_id || 'synthetic')}</code></span>
                <span>Seen: ${fmtTime(alert.first_seen)} &rarr; ${fmtTime(alert.last_seen)}</span>
                <span>Confidence: <b class="text-ink">${(alert.confidence * 100).toFixed(0)}%</b></span>
              </div>
              <div class="flex flex-wrap gap-1.5 mt-2.5">
                ${(alert.patterns || []).map(p => patternChip(p)).join('')}
                ${(alert.mitre || []).map(m => mitreChip(m)).join('')}
              </div>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center gap-2.5 shrink-0">
            ${isRevoke ? `
              <button id="btn-approve-revoke" class="px-3.5 py-2 text-xs font-medium rounded-lg bg-crit hover:bg-red-600 text-white ${isApplied ? 'opacity-50 cursor-not-allowed' : ''}">
                Approve Revoke
              </button>
            ` : `
              <button id="btn-apply-rec" class="px-3.5 py-2 text-xs font-medium rounded-lg bg-brand hover:bg-blue-600 text-white capitalize ${isApplied ? 'opacity-50 cursor-not-allowed' : ''}">
                Apply ${esc(alert.recommended_action.replace('_', ' '))}
              </button>
            `}
            <button id="btn-dismiss" class="px-3 py-2 text-xs font-medium rounded-lg border border-line hover:bg-panel2 text-ink ${isApplied ? 'opacity-50 cursor-not-allowed' : ''}">
              Dismiss
            </button>
          </div>
        </div>
      </div>

      <!-- 2-Column Investigation Grid -->
      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        <!-- Left: Why flagged, Counterfactuals, Chain, Prediction -->
        <div class="space-y-6">
          <!-- Why Flagged -->
          ${card(
            'Detection Evidence & Rationale',
            `<ul class="space-y-2">
              ${(alert.reasons || []).map((r, i) => `
                <li class="flex items-start gap-2.5 text-sm text-ink/90">
                  <span class="w-5 h-5 rounded-full bg-brand/15 text-brand flex items-center justify-center text-xs font-mono shrink-0 mt-0.5">${i + 1}</span>
                  <span>${esc(r)}</span>
                </li>
              `).join('')}
            </ul>`
          )}

          <!-- Counterfactual Risk Analysis -->
          ${card(
            'Counterfactual Risk Sensitivity (Score without signal)',
            `<p class="text-xs text-muted mb-3">Re-scoring simulation isolating the contribution of each pattern.</p>` +
            table(
              ['Signal Removed', 'Simulated Risk', 'Delta'],
              (alert.counterfactuals || []).map(c => {
                const delta = (c.risk - alert.risk).toFixed(1);
                return `
                  <tr>
                    <td class="px-4 py-2 font-mono text-xs">${patternChip(c.without)}</td>
                    <td class="px-4 py-2 tabular-nums text-xs">${c.risk.toFixed(1)}</td>
                    <td class="px-4 py-2 tabular-nums text-xs font-semibold text-ok">${delta}</td>
                  </tr>
                `;
              }).join('')
            )
          )}

          <!-- Attack Chain Stepper -->
          ${(alert.chain && alert.chain.length > 0) ? card(
            'Escalation Chain Sequence',
            `<div class="space-y-4 relative pl-4 border-l border-line ml-2 my-2">
              ${alert.chain.map((st, i) => `
                <div class="relative">
                  <span class="absolute -left-[23px] top-1 w-3.5 h-3.5 rounded-full bg-brand border-2 border-panel"></span>
                  <div class="text-xs font-mono font-semibold text-ink">${esc(st.state)}: <span class="text-brand font-mono">${esc(st.action)}</span></div>
                  <div class="text-[11px] text-muted">${fmtTime(st.timestamp)} · Event <code class="font-mono text-muted">${esc(st.event_id)}</code></div>
                </div>
              `).join('')}
            </div>`
          ) : ''}

          <!-- Predicted Next Step -->
          ${alert.prediction ? `
            <div class="bg-panel border-l-4 border-brand2 border-y border-r border-line rounded-r-xl p-4">
              <div class="text-xs font-semibold uppercase tracking-wider text-brand2 mb-1">Predicted Attack Progression</div>
              <div class="text-sm font-medium text-ink">
                Next State: <b class="text-brand2">${esc(alert.prediction.next_state)}</b>
                <span class="text-xs font-mono text-muted">(${(alert.prediction.probability * 100).toFixed(0)}% probability)</span>
              </div>
              <div class="text-xs text-muted mt-1">Based on Markov transition graph trained on identity privilege escalation sequences.</div>
            </div>
          ` : ''}
        </div>

        <!-- Right: Evidence events, Feedback, Links -->
        <div class="space-y-6">
          <!-- Analyst Feedback -->
          ${card(
            'Analyst Ground Truth Feedback',
            `<div class="flex items-center justify-between">
              <div class="text-xs text-muted">
                Status: <span class="font-semibold text-ink">${alert.feedback ? alert.feedback.toUpperCase() : 'Unreviewed'}</span>
              </div>
              <div class="flex items-center gap-2">
                <button id="btn-feedback-tp" class="px-3 py-1.5 text-xs font-medium rounded border border-ok/40 bg-ok/10 hover:bg-ok/20 text-ok transition-colors">
                  True Positive
                </button>
                <button id="btn-feedback-fp" class="px-3 py-1.5 text-xs font-medium rounded border border-crit/40 bg-crit/10 hover:bg-crit/20 text-crit transition-colors">
                  False Positive
                </button>
              </div>
            </div>`
          )}

          <!-- Evidence Events -->
          ${card(
            'Evidence Events Replay',
            `<div class="max-h-96 overflow-y-auto">` +
            table(
              ['Time', 'Source', 'Action', 'IP Address'],
              (events || []).map(ev => `
                <tr class="hover:bg-panel2 transition-colors">
                  <td class="px-4 py-2.5 text-xs text-muted tabular-nums">${fmtTime(ev.timestamp)}</td>
                  <td class="px-4 py-2.5">
                    <span class="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-panel2 border border-line ${ev.source === 'okta' ? 'text-blue-400' : 'text-amber-400'}">
                      ${esc(ev.source)}
                    </span>
                  </td>
                  <td class="px-4 py-2.5 font-mono text-xs text-ink">${esc(ev.action)}</td>
                  <td class="px-4 py-2.5 text-xs text-muted font-mono">${esc(ev.src_ip || '-')}</td>
                </tr>
              `).join('')
            ) + `</div>`
          )}

          <!-- Quick Investigation Links -->
          ${card(
            'Visual Investigation Tools',
            `<div class="grid grid-cols-2 gap-3">
              <a href="/graph.html?identity=${esc(alert.identity_id)}${mockQuery ? '&' + mockQuery.slice(1) : ''}" class="p-3 bg-panel2 border border-line rounded-lg hover:border-brand flex flex-col items-center justify-center text-center group">
                <span class="text-xs font-semibold text-ink group-hover:text-brand">Explore Identity Graph &rarr;</span>
                <span class="text-[10px] text-muted mt-0.5">Visualize connections & blast radius</span>
              </a>
              <a href="/timeline.html?session=${esc(alert.session_id || '')}${mockQuery ? '&' + mockQuery.slice(1) : ''}" class="p-3 bg-panel2 border border-line rounded-lg hover:border-brand flex flex-col items-center justify-center text-center group">
                <span class="text-xs font-semibold text-ink group-hover:text-brand">Replay Session Timeline &rarr;</span>
                <span class="text-[10px] text-muted mt-0.5">Step-by-step telemetry replay</span>
              </a>
            </div>`
          )}
        </div>
      </div>
    `;

    // Hook buttons
    const btnApprove = document.getElementById('btn-approve-revoke');
    if (btnApprove && !isApplied) {
      btnApprove.onclick = async () => {
        const ok = await confirmModal('Approve Revocation', `Are you sure you want to revoke session ${alert.session_id} for identity ${alert.identity_id}? This is an active containment action.`);
        if (ok) {
          try {
            const res = await api(`/alerts/${alertId}/action`, { method: 'POST', body: { action: 'revoke', approved_by: 'analyst' } });
            toast(`Action applied: ${res.detail}`);
            setTimeout(loadAlertDetail, 800);
          } catch (e) {
            toast(e.message, 'error');
          }
        }
      };
    }

    const btnApply = document.getElementById('btn-apply-rec');
    if (btnApply && !isApplied) {
      btnApply.onclick = async () => {
        try {
          const res = await api(`/alerts/${alertId}/action`, { method: 'POST', body: { action: alert.recommended_action, approved_by: 'analyst' } });
          toast(`Action applied: ${res.detail}`);
          setTimeout(loadAlertDetail, 800);
        } catch (e) {
          toast(e.message, 'error');
        }
      };
    }

    const btnDismiss = document.getElementById('btn-dismiss');
    if (btnDismiss && !isApplied) {
      btnDismiss.onclick = async () => {
        try {
          const res = await api(`/alerts/${alertId}/action`, { method: 'POST', body: { action: 'dismiss', approved_by: 'analyst' } });
          toast(`Alert dismissed: ${res.detail}`);
          setTimeout(loadAlertDetail, 800);
        } catch (e) {
          toast(e.message, 'error');
        }
      };
    }

    const btnTP = document.getElementById('btn-feedback-tp');
    if (btnTP) {
      btnTP.onclick = async () => {
        try {
          const updated = await api(`/alerts/${alertId}/feedback`, { method: 'POST', body: { label: 'tp' } });
          toast(`Feedback saved: True Positive. Risk updated to ${updated.risk}.`);
          setTimeout(loadAlertDetail, 800);
        } catch (e) {
          toast(e.message, 'error');
        }
      };
    }

    const btnFP = document.getElementById('btn-feedback-fp');
    if (btnFP) {
      btnFP.onclick = async () => {
        try {
          const updated = await api(`/alerts/${alertId}/feedback`, { method: 'POST', body: { label: 'fp' } });
          toast(`Feedback saved: False Positive. Risk updated to ${updated.risk}.`);
          setTimeout(loadAlertDetail, 800);
        } catch (e) {
          toast(e.message, 'error');
        }
      };
    }

  } catch (err) {
    content.innerHTML = errorState(`Failed to load alert details: ${err.message}`, 'btn-retry-alert');
    const retry = document.getElementById('btn-retry-alert');
    if (retry) retry.onclick = loadAlertDetail;
  }
}
