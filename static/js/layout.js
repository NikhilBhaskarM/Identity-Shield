/**
 * Shared sidebar and topbar layout for IdentityShield console.
 */
import { api, esc, isMock, toast } from './api.js';

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', href: '/index.html', icon: 'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6' },
  { id: 'scan', label: 'Live scan', href: '/scan.html', icon: 'M13 10V3L4 14h7v7l9-11h-7z' },
  { id: 'agents', label: 'Agents', href: '/agents.html', icon: 'M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10' },
  { id: 'input', label: 'Input data', href: '/input.html', icon: 'M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12' },
  { id: 'alerts', label: 'Alerts', href: '/alerts.html', icon: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9' },
  { id: 'identities', label: 'Identities', href: '/identities.html', icon: 'M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z' },
  { id: 'explorer', label: 'Attack paths', href: '/explorer.html', icon: 'M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4' },
  { id: 'analytics', label: 'Analytics', href: '/analytics.html', icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z' },
  { id: 'hygiene', label: 'Hygiene', href: '/hygiene.html', icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z' },
  { id: 'audit', label: 'Audit Log', href: '/audit.html', icon: 'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01' },
  { id: 'notifications', label: 'Notifications', href: '/notifications.html', icon: 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z' },
];

export function renderLayout(activeId, title, subtitle = '') {
  const app = document.getElementById('app');
  const mockQuery = isMock() ? '?mock=1' : '';

  const navHtml = NAV_ITEMS.map(item => {
    const isActive = item.id === activeId;
    const activeClasses = isActive
      ? 'bg-panel2 text-ink border-l-2 border-brand font-semibold'
      : 'text-muted hover:text-ink hover:bg-panel2/50 border-l-2 border-transparent';
    return `
      <a href="${item.href}${mockQuery}" class="flex items-center gap-3 px-4 py-2.5 text-sm transition-colors ${activeClasses}">
        <svg class="w-4 h-4 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="${item.icon}" />
        </svg>
        <span>${esc(item.label)}</span>
      </a>
    `;
  }).join('');

  app.innerHTML = `
    <div class="flex min-h-screen bg-bg">
      <!-- Sidebar -->
      <aside class="w-60 bg-panel border-r border-line flex flex-col shrink-0">
        <!-- Logo -->
        <div class="h-16 px-5 border-b border-line flex items-center gap-3">
          <div class="w-8 h-8 rounded-lg bg-brand/20 border border-brand/40 flex items-center justify-center text-brand">
            <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          <div>
            <div class="font-bold text-sm text-ink tracking-tight">IdentityShield</div>
            <div class="text-[10px] text-muted uppercase tracking-wider font-mono">Zero Trust SOC</div>
          </div>
        </div>

        <!-- Navigation -->
        <nav class="flex-1 py-4 space-y-0.5 overflow-y-auto">
          ${navHtml}
        </nav>

        <!-- Sidebar footer -->
        <div class="p-4 border-t border-line text-[11px] text-muted">
          <div class="flex items-center gap-2">
            <span class="inline-block w-2 h-2 rounded-full bg-ok animate-pulse"></span>
            <span>Real-time Sentinel</span>
          </div>
          <div class="mt-1 text-slate-500">v2.1 Enterprise Edition</div>
        </div>
      </aside>

      <!-- Main container -->
      <div class="flex-1 flex flex-col min-w-0">
        <!-- Top bar -->
        <header class="h-16 bg-panel border-b border-line px-6 flex items-center justify-between shrink-0">
          <div>
            <h1 class="text-base font-semibold text-ink">${esc(title)}</h1>
            ${subtitle ? `<p class="text-xs text-muted">${esc(subtitle)}</p>` : ''}
          </div>

          <div class="flex items-center gap-3">
            <span id="pill-pipeline" class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-line text-muted">
              <span class="w-1.5 h-1.5 rounded-full bg-muted"></span> Loading...
            </span>
            <span id="pill-datamode" class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-panel2 border border-line text-muted">
              --
            </span>
            <button id="btn-rerun-pipeline" class="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-brand hover:bg-blue-600 text-white transition-colors">
              <svg class="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
              </svg>
              <span>Re-run pipeline</span>
            </button>
          </div>
        </header>

        <!-- Main page content container -->
        <main id="content" class="flex-1 p-6 max-w-7xl w-full mx-auto space-y-6">
        </main>
      </div>
    </div>
  `;

  // Attach pipeline status and re-run handler
  const rerunBtn = document.getElementById('btn-rerun-pipeline');
  if (rerunBtn) {
    rerunBtn.onclick = async () => {
      rerunBtn.disabled = true;
      rerunBtn.classList.add('opacity-50');
      try {
        await api('/pipeline/run', { method: 'POST', body: { use_sample: true } });
        toast('Pipeline execution completed successfully.');
        setTimeout(() => window.location.reload(), 1000);
      } catch (err) {
        toast(`Pipeline run failed: ${err.message}`, 'error');
        rerunBtn.disabled = false;
        rerunBtn.classList.remove('opacity-50');
      }
    };
  }

  // Fetch health status for top pills
  api('/health').then(h => {
    const pipePill = document.getElementById('pill-pipeline');
    const dataPill = document.getElementById('pill-datamode');
    if (pipePill) {
      if (h.pipeline === 'ok') {
        pipePill.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-ok/15 text-ok border border-ok/30';
        pipePill.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-ok"></span> Pipeline OK';
      } else if (h.pipeline === 'degraded') {
        pipePill.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-warn/15 text-warn border border-warn/30';
        pipePill.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-warn"></span> Degraded';
      } else {
        pipePill.className = 'inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-medium bg-crit/15 text-crit border border-crit/30';
        pipePill.innerHTML = '<span class="w-1.5 h-1.5 rounded-full bg-crit"></span> Failed';
      }
    }
    if (dataPill) {
      dataPill.textContent = h.data_mode === 'official' ? 'Official data' : (h.data_mode === 'sample' ? 'Sample data' : h.data_mode);
    }
  }).catch(() => {});

  return document.getElementById('content');
}
