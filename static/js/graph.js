/**
 * Interactive NetworkX identity subgraph visualizer using vis-network.
 */
import { api, esc, qs } from './api.js';
import { renderLayout } from './layout.js';
import { card, emptyState, errorState, skeleton } from './ui.js';

const identityId = qs('identity') || 'svc-report';
const content = renderLayout('identities', 'Identity Graph Visualizer', `Investigating node: ${identityId}`);

const NODE_COLORS = {
  user: '#22D3EE',
  session: '#8B5CF6',
  role: '#F59E0B',
  key: '#F97316',
  policy: '#EF4444',
  resource: '#10B981',
  ip: '#64748B',
};

async function renderGraph() {
  content.innerHTML = skeleton(8);

  if (typeof window.vis === 'undefined') {
    content.innerHTML = errorState('vis-network library failed to load from CDN. Please check your network connection.');
    return;
  }

  try {
    const data = await api(`/identities/${encodeURIComponent(identityId)}/graph`);
    const nodes = data.nodes || [];
    const edges = data.edges || [];
    const paths = data.escalation_paths || [];

    content.innerHTML = `
      <div class="grid grid-cols-1 lg:grid-cols-4 gap-6 items-start">
        <!-- Canvas Card -->
        <div class="lg:col-span-3 bg-panel border border-line rounded-xl p-5 shadow-sm flex flex-col">
          <div class="flex items-center justify-between mb-4">
            <h3 class="text-sm font-semibold text-ink">Identity Graph · <span class="font-mono text-brand">${esc(identityId)}</span></h3>
            <button id="btn-fit" class="px-2.5 py-1 text-xs border border-line hover:bg-panel2 rounded text-ink">Fit View</button>
          </div>
          <div id="vis-container" class="w-full h-[600px] rounded-lg border border-line/60 bg-bg/50"></div>
        </div>

        <!-- Right Inspection Panel -->
        <div class="space-y-6">
          <!-- Legend -->
          ${card(
            'Node Types',
            `<div class="grid grid-cols-2 gap-2 text-xs">
              ${Object.entries(NODE_COLORS).map(([k, c]) => `
                <div class="flex items-center gap-2">
                  <span class="w-3 h-3 rounded-full" style="background-color: ${c}"></span>
                  <span class="capitalize text-muted">${k}</span>
                </div>
              `).join('')}
            </div>`
          )}

          <!-- Escalation Paths -->
          ${card(
            'Escalation Paths to Admin',
            paths.length > 0 ? `
              <div class="space-y-2.5">
                ${paths.map((p, idx) => `
                  <div class="p-2.5 bg-panel2 border border-line rounded text-xs font-mono">
                    <div class="text-brand2 font-semibold mb-1">Path #${idx + 1} (${p.length} steps):</div>
                    <div class="text-muted leading-relaxed">${p.map(step => esc(step)).join(' &rarr; ')}</div>
                  </div>
                `).join('')}
              </div>
            ` : `<div class="text-xs text-muted">No direct path reaching administrative privileges.</div>`
          )}

          <!-- Selected Node Details -->
          ${card(
            'Selected Entity',
            `<div id="node-inspector" class="text-xs text-muted">
              Click any node in the graph to view properties.
            </div>`
          )}
        </div>
      </div>
    `;

    const container = document.getElementById('vis-container');
    const visNodes = new vis.DataSet(nodes.map(n => ({
      id: n.id,
      label: n.label,
      title: `${n.kind}: ${n.label}`,
      color: {
        background: NODE_COLORS[n.kind] || '#64748b',
        border: '#111827',
        highlight: { background: '#ffffff', border: NODE_COLORS[n.kind] || '#3b82f6' }
      },
      font: { color: '#E6EBF2', size: 12, face: 'Inter' },
      shape: n.kind === 'user' ? 'box' : (n.kind === 'session' ? 'ellipse' : 'dot'),
      size: n.kind === 'user' ? 24 : 16,
    })));

    const visEdges = new vis.DataSet(edges.map((e, idx) => ({
      id: idx,
      from: e.source,
      to: e.target,
      label: e.label,
      color: { color: e.suspicious ? '#EF4444' : '#334155', highlight: '#3B82F6' },
      width: e.suspicious ? 3 : 1,
      arrows: 'to',
      font: { color: '#8A97AD', size: 10, align: 'middle' },
      smooth: { type: 'continuous' },
    })));

    const options = {
      physics: {
        barnesHut: { gravitationalConstant: -3000, centralGravity: 0.3, springLength: 95 },
        stabilization: { iterations: 150 },
      },
      interaction: { hover: true, tooltipDelay: 100 },
    };

    const network = new vis.Network(container, { nodes: visNodes, edges: visEdges }, options);

    network.on('stabilizationIterationsDone', () => {
      network.setOptions({ physics: false });
    });

    network.on('click', (params) => {
      if (params.nodes.length > 0) {
        const selId = params.nodes[0];
        const nObj = nodes.find(n => n.id === selId);
        if (nObj) {
          document.getElementById('node-inspector').innerHTML = `
            <div class="space-y-1">
              <div><span class="text-muted">ID:</span> <code class="font-mono text-ink">${esc(nObj.id)}</code></div>
              <div><span class="text-muted">Type:</span> <span class="capitalize text-brand font-medium">${esc(nObj.kind)}</span></div>
              <div><span class="text-muted">Label:</span> <span class="text-ink">${esc(nObj.label)}</span></div>
            </div>
          `;
        }
      }
    });

    document.getElementById('btn-fit').onclick = () => network.fit();

  } catch (err) {
    content.innerHTML = errorState(`Failed to render identity graph: ${err.message}`, 'btn-retry-graph');
    const retry = document.getElementById('btn-retry-graph');
    if (retry) retry.onclick = renderGraph;
  }
}

renderGraph();
