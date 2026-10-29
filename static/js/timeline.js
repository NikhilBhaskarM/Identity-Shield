/**
 * Step-by-step interactive telemetry replay for a session.
 */
import { api, esc, fmtTime, qs } from './api.js';
import { renderLayout } from './layout.js';
import { card, emptyState, errorState, patternChip, skeleton } from './ui.js';

const sessionId = qs('session') || '';
const content = renderLayout('alerts', 'Session Telemetry Timeline', sessionId ? `Replay for session: ${sessionId}` : 'Select a session');

if (!sessionId) {
  content.innerHTML = emptyState('No session ID specified. Open an alert or identity to replay its timeline.');
} else {
  loadTimeline();
}

async function loadTimeline() {
  content.innerHTML = skeleton(6);

  try {
    const items = await api(`/sessions/${encodeURIComponent(sessionId)}/timeline`);
    if (!items || items.length === 0) {
      content.innerHTML = emptyState('No telemetry recorded for this session.');
      return;
    }

    let currentIndex = 0;
    let isPlaying = false;
    let playTimer = null;
    let playSpeed = 1000;

    content.innerHTML = `
      <!-- Replay Controls Bar -->
      <div class="bg-panel border border-line rounded-xl p-4 flex flex-wrap items-center justify-between gap-4 sticky top-4 z-20 shadow-md">
        <div class="flex items-center gap-3">
          <button id="btn-play" class="w-9 h-9 rounded-lg bg-brand hover:bg-blue-600 text-white flex items-center justify-center transition-colors">
            ▶
          </button>
          <div class="text-xs font-mono text-ink">
            <span id="step-counter">Step 1 of ${items.length}</span>
          </div>
        </div>

        <div class="flex-1 max-w-md mx-4">
          <input type="range" id="timeline-slider" min="0" max="${items.length - 1}" value="0" class="w-full accent-brand cursor-pointer" />
        </div>

        <div class="flex items-center gap-2 text-xs text-muted">
          <span>Speed:</span>
          <select id="speed-select" class="bg-panel2 border border-line rounded px-2 py-1 text-ink focus:outline-none">
            <option value="1000">1x (1s)</option>
            <option value="500">2x (0.5s)</option>
            <option value="250">4x (0.25s)</option>
          </select>
        </div>
      </div>

      <!-- Events Stepper List -->
      <div id="events-stepper" class="space-y-4 max-w-4xl mx-auto my-6">
        ${items.map((item, idx) => {
          const ev = item.event;
          const sigs = item.signals || [];
          return `
            <div id="event-step-${idx}" class="event-step bg-panel border border-line rounded-xl p-4 transition-all duration-300">
              <div class="flex items-start justify-between gap-4">
                <div class="flex items-center gap-3">
                  <span class="w-7 h-7 rounded-full bg-panel2 border border-line flex items-center justify-center text-xs font-mono text-muted shrink-0">
                    ${idx + 1}
                  </span>
                  <div>
                    <div class="text-sm font-semibold text-ink flex items-center gap-2">
                      <span class="font-mono text-brand">${esc(ev.action)}</span>
                      <span class="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-panel2 border border-line ${ev.source === 'okta' ? 'text-blue-400' : 'text-amber-400'}">
                        ${esc(ev.source)}
                      </span>
                    </div>
                    <div class="text-xs text-muted mt-0.5">
                      ${fmtTime(ev.timestamp)} · IP: <code class="font-mono text-ink">${esc(ev.src_ip || 'n/a')}</code>
                      ${ev.city ? `(${esc(ev.city)}, ${esc(ev.country)})` : ''}
                    </div>
                  </div>
                </div>

                <div class="text-right shrink-0">
                  <span class="text-xs font-mono text-muted">${esc(ev.event_id)}</span>
                </div>
              </div>

              ${sigs.length > 0 ? `
                <div class="mt-3 pt-3 border-t border-line/60 space-y-1.5">
                  ${sigs.map(s => `
                    <div class="p-2 rounded bg-crit/10 border border-crit/30 flex items-center gap-2 text-xs">
                      ${patternChip(s.pattern)}
                      <span class="text-crit font-medium">${esc(s.reason)}</span>
                    </div>
                  `).join('')}
                </div>
              ` : ''}
            </div>
          `;
        }).join('')}
      </div>
    `;

    function updateStep(idx) {
      currentIndex = idx;
      document.getElementById('timeline-slider').value = idx;
      document.getElementById('step-counter').textContent = `Step ${idx + 1} of ${items.length}`;

      for (let i = 0; i < items.length; i++) {
        const el = document.getElementById(`event-step-${i}`);
        if (!el) continue;
        if (i < idx) {
          el.className = 'event-step bg-panel border border-line rounded-xl p-4 transition-all duration-300 opacity-60';
        } else if (i === idx) {
          el.className = 'event-step bg-panel border-2 border-brand rounded-xl p-4 transition-all duration-300 shadow-lg';
          el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        } else {
          el.className = 'event-step bg-panel border border-line rounded-xl p-4 transition-all duration-300 opacity-25';
        }
      }
    }

    function togglePlay() {
      isPlaying = !isPlaying;
      const btn = document.getElementById('btn-play');
      if (isPlaying) {
        btn.textContent = '❚❚';
        if (currentIndex >= items.length - 1) {
          currentIndex = 0;
          updateStep(0);
        }
        playTimer = setInterval(() => {
          if (currentIndex < items.length - 1) {
            updateStep(currentIndex + 1);
          } else {
            togglePlay();
          }
        }, playSpeed);
      } else {
        btn.textContent = '▶';
        clearInterval(playTimer);
      }
    }

    document.getElementById('btn-play').onclick = togglePlay;
    document.getElementById('timeline-slider').oninput = (e) => {
      if (isPlaying) togglePlay();
      updateStep(parseInt(e.target.value));
    };
    document.getElementById('speed-select').onchange = (e) => {
      playSpeed = parseInt(e.target.value);
      if (isPlaying) {
        clearInterval(playTimer);
        playTimer = setInterval(() => {
          if (currentIndex < items.length - 1) {
            updateStep(currentIndex + 1);
          } else {
            togglePlay();
          }
        }, playSpeed);
      }
    };

    updateStep(0);

  } catch (err) {
    content.innerHTML = errorState(`Failed to load timeline: ${err.message}`, 'btn-retry-tl');
    const retry = document.getElementById('btn-retry-tl');
    if (retry) retry.onclick = loadTimeline;
  }
}
