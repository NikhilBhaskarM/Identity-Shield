/**
 * API client and utility functions for IdentityShield.
 */

export function esc(str) {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

export function qs(name) {
  const urlParams = new URLSearchParams(window.location.search);
  return urlParams.get(name);
}

export function isMock() {
  return window.location.search.includes('mock=1');
}

export function fmtTime(iso) {
  if (!iso) return '-';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    });
  } catch (e) {
    return String(iso);
  }
}

export function fmtNum(n) {
  if (n === null || n === undefined || isNaN(n)) return '0';
  return Number(n).toLocaleString();
}

const MOCK_MAP = {
  '/health': '/mock/health.json',
  '/summary': '/mock/summary.json',
  '/alerts': '/mock/alerts.json',
  '/identities': '/mock/identities.json',
  '/hygiene': '/mock/hygiene.json',
  '/metrics': '/mock/metrics.json',
  '/audit': '/mock/audit.json',
  '/audit/verify': '/mock/audit_verify.json',
  '/weights': '/mock/weights.json',
};

export async function api(path, { method = 'GET', body = null } = {}) {
  const mock = isMock();
  const cleanPath = path.startsWith('/api') ? path.substring(4) : path;
  const basePath = cleanPath.split('?')[0];

  if (mock) {
    if (method !== 'GET') {
      return { status: 'mocked', detail: 'mock mode' };
    }
    let target = MOCK_MAP[basePath] || MOCK_MAP[cleanPath];
    if (!target) {
      if (basePath.startsWith('/alerts/') && basePath.endsWith('/events')) {
        target = '/mock/events.json';
      } else if (basePath.startsWith('/alerts/')) {
        target = '/mock/alert.json';
      } else if (basePath.startsWith('/identities/') && basePath.endsWith('/graph')) {
        target = '/mock/graph.json';
      } else if (basePath.startsWith('/sessions/') && basePath.endsWith('/timeline')) {
        target = '/mock/timeline.json';
      } else {
        target = `/mock${basePath}.json`;
      }
    }
    const res = await fetch(target);
    if (!res.ok) {
      throw new Error(`Mock data error: ${target} not found`);
    }
    return await res.json();
  }

  const endpoint = path.startsWith('/api') ? path : `/api${path}`;
  const options = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
  };
  if (body) {
    options.body = JSON.stringify(body);
  }

  const res = await fetch(endpoint, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = data.error || 'error';
    const detail = data.detail || res.statusText;
    throw new Error(`${err}: ${detail}`);
  }
  return data;
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
