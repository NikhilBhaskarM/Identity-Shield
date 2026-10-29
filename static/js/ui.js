/**
 * Shared UI component library for IdentityShield.
 */
import { esc } from './api.js';

export function card(title, bodyHtml, actionHtml = '') {
  return `
    <div class="bg-panel border border-line rounded-xl p-5 shadow-sm">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-sm font-semibold text-ink">${esc(title)}</h3>
        ${actionHtml ? `<div>${actionHtml}</div>` : ''}
      </div>
      <div>${bodyHtml}</div>
    </div>
  `;
}

export function statCard(label, value, note = '') {
  return `
    <div class="bg-panel border border-line rounded-xl p-5 flex flex-col justify-between">
      <div class="text-xs uppercase tracking-wide text-muted font-medium mb-1">${esc(label)}</div>
      <div class="text-3xl font-semibold tabular-nums text-ink my-1">${esc(value)}</div>
      ${note ? `<div class="text-xs text-muted mt-1">${esc(note)}</div>` : ''}
    </div>
  `;
}

export function bandBadge(band) {
  const b = (band || 'monitor').toLowerCase();
  let styles = 'bg-slate-800 text-slate-300 border border-slate-700';
  let label = 'Monitor';

  if (b === 'revoke') {
    styles = 'bg-crit/15 text-crit border border-crit/30';
    label = 'Revoke';
  } else if (b === 'restrict') {
    styles = 'bg-high/15 text-high border border-high/30';
    label = 'Restrict';
  } else if (b === 'step_up') {
    styles = 'bg-warn/15 text-warn border border-warn/30';
    label = 'Step-up';
  }

  return `<span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${styles}">${label}</span>`;
}

export const PATTERN_NAMES = {
  P1: 'Impossible travel',
  P2: 'Dormant account',
  P3: 'Privilege escalation',
  P4: 'Unusual API',
  P5: 'Token abuse',
  ML: 'Behavior anomaly',
};

export function patternChip(code) {
  const name = PATTERN_NAMES[code] || code;
  return `<span class="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-mono bg-panel2 border border-line text-ink">${esc(code)} ${esc(name)}</span>`;
}

export function mitreChip(id) {
  return `<span class="inline-flex items-center px-1.5 py-0.5 rounded text-[11px] font-mono bg-panel2 border border-line text-brand2">${esc(id)}</span>`;
}

export function riskRing(risk, band, size = 72) {
  const r = Math.max(0, Math.min(100, Number(risk) || 0));
  const b = (band || 'monitor').toLowerCase();
  let color = '#94a3b8'; // slate
  if (b === 'revoke') color = '#ef4444';
  else if (b === 'restrict') color = '#f97316';
  else if (b === 'step_up') color = '#f59e0b';

  const strokeWidth = 6;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (r / 100) * circumference;

  return `
    <div class="relative inline-flex items-center justify-center" style="width:${size}px; height:${size}px;">
      <svg width="${size}" height="${size}" class="transform -rotate-90">
        <circle cx="${size / 2}" cy="${size / 2}" r="${radius}" stroke="#1f2a3c" stroke-width="${strokeWidth}" fill="transparent" />
        <circle cx="${size / 2}" cy="${size / 2}" r="${radius}" stroke="${color}" stroke-width="${strokeWidth}" stroke-dasharray="${circumference}" stroke-dashoffset="${offset}" stroke-linecap="round" fill="transparent" />
      </svg>
      <div class="absolute inset-0 flex items-center justify-center text-sm font-semibold tabular-nums text-ink">
        ${r.toFixed(0)}
      </div>
    </div>
  `;
}

export function riskBar(risk, band) {
  const r = Math.max(0, Math.min(100, Number(risk) || 0));
  const b = (band || 'monitor').toLowerCase();
  let color = 'bg-slate-500';
  if (b === 'revoke') color = 'bg-crit';
  else if (b === 'restrict') color = 'bg-high';
  else if (b === 'step_up') color = 'bg-warn';

  return `
    <div class="w-24 bg-line rounded-full h-1.5 overflow-hidden">
      <div class="${color} h-1.5 rounded-full" style="width: ${r}%"></div>
    </div>
  `;
}

export function table(columns, rowsHtml) {
  return `
    <div class="overflow-x-auto">
      <table class="w-full text-left text-sm">
        <thead class="bg-panel2 text-muted text-xs uppercase font-medium border-b border-line">
          <tr>
            ${columns.map(c => `<th class="px-4 py-2.5 font-semibold">${esc(c)}</th>`).join('')}
          </tr>
        </thead>
        <tbody class="divide-y divide-line">
          ${rowsHtml || `<tr><td colspan="${columns.length}" class="px-4 py-8 text-center text-muted">No records found</td></tr>`}
        </tbody>
      </table>
    </div>
  `;
}

export function button(label, { variant = 'primary', id = '', attrs = '' } = {}) {
  let cls = 'inline-flex items-center justify-center font-medium rounded-lg px-3.5 py-2 text-sm transition-colors ';
  if (variant === 'primary') {
    cls += 'bg-brand hover:bg-blue-600 text-white shadow-sm';
  } else if (variant === 'danger') {
    cls += 'bg-crit/90 hover:bg-crit text-white shadow-sm';
  } else if (variant === 'secondary') {
    cls += 'border border-line hover:bg-panel2 text-ink';
  }
  const idAttr = id ? `id="${esc(id)}"` : '';
  return `<button class="${cls}" ${idAttr} ${attrs}>${esc(label)}</button>`;
}

export function skeleton(lines = 4) {
  let html = '<div class="space-y-3 animate-pulse">';
  for (let i = 0; i < lines; i++) {
    const width = 60 + ((i * 13) % 40);
    html += `<div class="h-4 bg-panel2 rounded" style="width: ${width}%"></div>`;
  }
  html += '</div>';
  return html;
}

export function emptyState(message) {
  return `
    <div class="text-center py-12 px-4">
      <svg class="mx-auto h-10 w-10 text-muted/60 mb-3" fill="none" viewBox="0 0 24 24" stroke="currentColor">
        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.5" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
      </svg>
      <div class="text-sm text-muted">${esc(message)}</div>
    </div>
  `;
}

export function errorState(message, retryId = 'btn-retry') {
  return `
    <div class="bg-crit/10 border border-crit/30 rounded-xl p-5 text-center">
      <div class="text-crit font-semibold text-sm mb-2">Error encountered</div>
      <div class="text-xs text-ink/80 mb-4">${esc(message)}</div>
      <button id="${esc(retryId)}" class="px-3 py-1.5 text-xs bg-panel2 hover:bg-line text-ink rounded border border-line">Retry</button>
    </div>
  `;
}

export function toast(message, type = 'success') {
  let container = document.getElementById('toast-container');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toast-container';
    container.className = 'fixed bottom-4 right-4 z-50 flex flex-col gap-2 pointer-events-none';
    document.body.appendChild(container);
  }

  const el = document.createElement('div');
  const border = type === 'error' ? 'border-crit text-crit' : 'border-ok text-ok';
  el.className = `bg-panel border ${border} rounded-lg px-4 py-3 text-sm shadow-xl flex items-center gap-2 pointer-events-auto transition-opacity duration-300`;
  el.innerHTML = `<span>${type === 'error' ? '⚠' : '✓'}</span><span>${esc(message)}</span>`;
  container.appendChild(el);

  setTimeout(() => {
    el.style.opacity = '0';
    setTimeout(() => el.remove(), 300);
  }, 4000);
}

export function confirmModal(title, message) {
  return new Promise(resolve => {
    const overlay = document.createElement('div');
    overlay.className = 'fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4';
    overlay.innerHTML = `
      <div class="bg-panel border border-line rounded-xl max-w-md w-full p-6 shadow-2xl">
        <h3 class="text-base font-semibold text-ink mb-2">${esc(title)}</h3>
        <p class="text-sm text-muted mb-6">${esc(message)}</p>
        <div class="flex justify-end gap-3">
          <button id="modal-cancel" class="px-3.5 py-2 text-sm border border-line hover:bg-panel2 rounded-lg text-ink">Cancel</button>
          <button id="modal-confirm" class="px-3.5 py-2 text-sm bg-crit hover:bg-red-600 rounded-lg text-white font-medium">Confirm</button>
        </div>
      </div>
    `;
    document.body.appendChild(overlay);

    overlay.querySelector('#modal-cancel').onclick = () => {
      overlay.remove();
      resolve(false);
    };
    overlay.querySelector('#modal-confirm').onclick = () => {
      overlay.remove();
      resolve(true);
    };
  });
}
