

const _DASH_API_KEY = (function(){ try { return localStorage.getItem('wpvs_api_key') || ''; } catch (e) { return ''; } })();

function apiFetch(url, opts = {}) {
  const h = Object.assign({}, opts.headers || {});
  if (_DASH_API_KEY) h['X-API-Key'] = _DASH_API_KEY;
  return fetch(url, Object.assign({}, opts, { headers: h }));
}

async function fetchJsonWithTimeout(url, opts = {}, timeoutMs = 15000) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await apiFetch(url, Object.assign({}, opts, { signal: controller.signal }));
    if (!res.ok) {
      const txt = await res.text().catch(() => '');
      throw new Error(`HTTP ${res.status}${txt ? `: ${txt.slice(0, 120)}` : ''}`);
    }
    return await res.json();
  } finally {
    clearTimeout(timeoutId);
  }
}


let _rows = [];
let _sortCol = 'scanned_at';
let _sortAsc = false;
let _tlChart = null;

const RISK_CLR = {
  'CRÍTICO': 'var(--red)',
  'ALTO': 'var(--orange)',
  'MEDIO': 'var(--amber)',
  'BAJO': 'var(--green)',
};


function showToast(msg, type = 'ok') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = `toast ${type}`;
  t.style.display = 'block';
  clearTimeout(t._t);
  t._t = setTimeout(() => { t.style.display = 'none'; }, 4000);
}

function animNum(el, target) {
  if (!el) return;
  const start = 0;
  const dur = 700;
  const isFloat = String(target).includes('.');
  const t0 = performance.now();

  const step = (ts) => {
    const pct = Math.min((ts - t0) / dur, 1);
    const ease = 1 - Math.pow(1 - pct, 3);
    const val = start + (target - start) * ease;
    el.textContent = isFloat ? val.toFixed(1) : Math.round(val).toLocaleString('es-ES');
    if (pct < 1) requestAnimationFrame(step);
  };

  requestAnimationFrame(step);
}

function riskColor(score) {
  return score >= 75 ? 'var(--red)' : score >= 50 ? 'var(--orange)' : score >= 25 ? 'var(--amber)' : 'var(--green)';
}


function renderKPIs(d) {
  const kpis = [
    { n: d.total_scans || 0, lbl: 'Escaneos', accent: 'var(--blue)', icon: 'M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2' },
    { n: d.total_vulns || 0, lbl: 'Vulnerabilidades', accent: 'var(--red)', icon: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z' },
    { n: d.total_critical || 0, lbl: 'Criticas', accent: 'var(--red)', icon: 'M12 8v4m0 4h.01M12 2a10 10 0 1 1 0 20A10 10 0 0 1 12 2z' },
    { n: d.total_high || 0, lbl: 'Altas', accent: 'var(--orange)', icon: 'M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5' },
    { n: Math.round(d.avg_risk || 0), lbl: 'Riesgo medio', accent: 'var(--amber)', icon: 'M12 22a10 10 0 1 1 0-20 10 10 0 0 1 0 20zm0-6v.01M12 8v4' },
    { n: Number(d.avg_vulns || 0).toFixed(1), lbl: 'Vulns/sitio', accent: 'var(--teal)', icon: 'M18 20V10M12 20V4M6 20v-6' },
  ];

  const grid = document.getElementById('kpiGrid');
  if (!grid) return;

  grid.innerHTML = kpis.map((k, i) =>
    `<div class="kpi-card" style="--kpi-accent:${k.accent}">
      <div class="kpi-icon"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="${k.icon}"/></svg></div>
      <div class="kpi-num" id="kn-${i}">0</div>
      <div class="kpi-lbl">${k.lbl}</div>
    </div>`
  ).join('');

  kpis.forEach((k, i) => {
    const el = document.getElementById(`kn-${i}`);
    animNum(el, parseFloat(k.n));
  });
}


function renderTimeline(recent) {
  const canvas = document.getElementById('timelineChart');
  if (!canvas || typeof Chart === 'undefined') return;

  const now = new Date();
  const cs = getComputedStyle(document.documentElement);
  const cBlue = (cs.getPropertyValue('--blue') || '').trim() || '#2f83ff';
  const cRed = (cs.getPropertyValue('--red') || '').trim() || '#ff5d6c';
  const cAmber = (cs.getPropertyValue('--amber') || '').trim() || '#ffc14a';
  const cText3 = (cs.getPropertyValue('--text-3') || '').trim() || '#8ea4c8';
  const cText2 = (cs.getPropertyValue('--text-2') || '').trim() || '#c6d4eb';
  const cBorder = (cs.getPropertyValue('--border') || '').trim() || 'rgba(169, 191, 228, 0.14)';
  const cBg3 = (cs.getPropertyValue('--bg-3') || '').trim() || '#10223f';

  const days = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (29 - i));
    return {
      label: d.toLocaleDateString('es-ES', { day: '2-digit', month: '2-digit' }),
      count: 0,
      critical: 0,
      avg_risk: 0,
      total_risk: 0,
    };
  });

  (recent || []).forEach((r) => {
    if (!r.scanned_at) return;
    const sd = new Date(r.scanned_at);
    if (Number.isNaN(sd.getTime())) return;

    const diff = Math.round((now - sd) / 86400000);
    const idx = 29 - diff;
    if (idx >= 0 && idx < 30) {
      days[idx].count += 1;
      days[idx].total_risk += (r.risk_score || 0);
      if (r.risk_label === 'CRÍTICO') days[idx].critical += 1;
    }
  });

  days.forEach((d) => {
    d.avg_risk = d.count ? Math.round(d.total_risk / d.count) : 0;
  });

  const ctx = canvas.getContext('2d');
  if (_tlChart) _tlChart.destroy();
  _tlChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: days.map((d) => d.label),
      datasets: [
        {
          label: 'Escaneos',
          data: days.map((d) => d.count),
          yAxisID: 'y',
          backgroundColor: `${cBlue}33`,
          borderColor: `${cBlue}99`,
          borderWidth: 1,
          borderRadius: 2,
        },
        {
          label: 'Risk score medio',
          data: days.map((d) => d.avg_risk),
          yAxisID: 'y2',
          type: 'line',
          tension: 0.4,
          pointRadius: 2,
          pointHoverRadius: 5,
          fill: false,
          borderColor: `${cAmber}b3`,
          backgroundColor: `${cAmber}26`,
          borderWidth: 1.5,
        },
        {
          label: 'Criticos',
          data: days.map((d) => d.critical),
          yAxisID: 'y',
          backgroundColor: `${cRed}33`,
          borderColor: `${cRed}99`,
          borderWidth: 1,
          borderRadius: 2,
          type: 'bar',
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { labels: { color: cText3, font: { family: 'JetBrains Mono', size: 9 }, boxWidth: 10 } },
        tooltip: {
          backgroundColor: cBg3,
          borderColor: cBorder,
          borderWidth: 1,
          titleColor: cText2,
          bodyColor: cText3,
          titleFont: { family: 'JetBrains Mono', size: 10 },
          bodyFont: { family: 'JetBrains Mono', size: 9 },
        },
      },
      scales: {
        x: { ticks: { color: cText3, font: { family: 'JetBrains Mono', size: 8 }, maxTicksLimit: 10 }, grid: { color: cBorder } },
        y: { ticks: { color: cText3, font: { family: 'JetBrains Mono', size: 8 }, stepSize: 1 }, grid: { color: cBorder }, min: 0 },
        y2: { display: false, min: 0, max: 100 },
      },
    },
  });
}


function renderTopDomains(domains) {
  const el = document.getElementById('topDomainsEl');
  if (!el) return;

  if (!domains || !domains.length) {
    el.innerHTML = '<div style="color:var(--text-3);font-size:11px;font-family:var(--sans);padding:4px">Sin datos aun</div>';
    return;
  }

  const max = Math.max(...domains.map((d) => d.peak_risk || 0), 1);
  el.innerHTML = domains.map((d, i) => {
    const c = riskColor(d.peak_risk || 0);
    const name = (d.url || '').replace(/https?:\/\//, '').split('/')[0];
    const pct = Math.round(((d.peak_risk || 0) / max) * 100);
    return `<div class="top-domain-item">
      <div class="top-domain-rank">${i + 1}</div>
      <div class="top-domain-url">
        <div class="top-domain-name" title="${d.url}">${name}</div>
        <div class="top-domain-meta">${d.scan_count || 0} escaneos · ${d.max_vulns || 0} vulns max</div>
      </div>
      <div class="top-domain-bar-wrap">
        <div class="top-domain-bar" style="width:${pct}%;background:${c}"></div>
      </div>
      <div class="top-domain-score" style="color:${c}">${d.peak_risk || 0}</div>
    </div>`;
  }).join('');
}


function renderDist(byRisk) {
  const el = document.getElementById('distList');
  if (!el) return;

  const ORDER = [
    { label: 'CRÍTICO', clr: 'var(--red)' },
    { label: 'ALTO', clr: 'var(--orange)' },
    { label: 'MEDIO', clr: 'var(--amber)' },
    { label: 'BAJO', clr: 'var(--green)' },
  ];

  const total = (byRisk || []).reduce((s, r) => s + (r.cnt || 0), 0) || 1;
  const map = Object.fromEntries((byRisk || []).map((r) => [r.risk_label, r.cnt || 0]));

  el.innerHTML = ORDER.map((o) => {
    const cnt = map[o.label] || 0;
    const pct = Math.round((cnt / total) * 100);
    return `<div class="dist-row">
      <div class="dist-label" style="color:${o.clr}">${o.label}</div>
      <div class="dist-bar-wrap"><div class="dist-bar" style="width:0%;background:${o.clr}" data-w="${pct}"></div></div>
      <div class="dist-count" style="color:${o.clr}">${cnt}</div>
      <div class="dist-pct">${pct}%</div>
    </div>`;
  }).join('');

  requestAnimationFrame(() => {
    document.querySelectorAll('.dist-bar[data-w]').forEach((bar) => {
      bar.style.width = `${bar.dataset.w}%`;
    });
  });
}


function renderHeatmap(heatmap) {
  const el = document.getElementById('heatmapEl');
  if (!el) return;
  if (!heatmap || !heatmap.length) {
    el.innerHTML = '<div style="color:var(--text-3);font-size:11px;font-family:var(--sans);padding:4px">Sin datos de actividad</div>';
    return;
  }

  const maxCount = Math.max(...heatmap.map((h) => h.count || 0), 1);
  el.innerHTML = heatmap.map((h) => {
    const cnt = h.count || 0;
    const pct = Math.round((cnt / maxCount) * 100);
    const risk = riskColor(h.avg_risk || 0);
    const bar = cnt > 0 ? `background:${risk};opacity:${0.4 + 0.6 * (pct / 100)}` : 'background:var(--bg-2)';
    return `<div class="heatmap-row">
      <div class="heatmap-label">${h.day}</div>
      <div class="heatmap-bar-wrap">
        <div class="heatmap-bar" style="width:0%;${bar}" data-w="${pct}"></div>
      </div>
      <div class="heatmap-meta">${cnt} scan${cnt !== 1 ? 's' : ''}${h.avg_risk ? ` · ${h.avg_risk}` : ''}</div>
    </div>`;
  }).join('');

  requestAnimationFrame(() => {
    document.querySelectorAll('.heatmap-bar[data-w]').forEach((bar) => {
      bar.style.width = `${bar.dataset.w}%`;
    });
  });
}


function buildSparkline(scores, clr) {
  if (!scores || scores.length < 2) return '';
  const mn = Math.min(...scores);
  const mx = Math.max(...scores, mn + 1);
  const rng = mx - mn || 1;
  const W = 80;
  const H = 32;
  const PAD = 3;

  const pts = scores.map((v, i) => {
    const x = PAD + (i / (scores.length - 1)) * (W - 2 * PAD);
    const y = PAD + (1 - (v - mn) / rng) * (H - 2 * PAD);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const last = pts[pts.length - 1].split(',');
  return `<polyline points="${pts.join(' ')}" fill="none" stroke="${clr}" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" opacity="0.8"/>
    <circle cx="${last[0]}" cy="${last[1]}" r="2.5" fill="${clr}" opacity="0.9"/>`;
}

function renderDomainTrends(trends) {
  const el = document.getElementById('domainTrendsEl');
  if (!el) return;

  if (!trends || !trends.length) {
    el.innerHTML = '<div style="color:var(--text-3);font-size:11px;font-family:var(--sans);padding:4px">Sin dominios con historial suficiente</div>';
    return;
  }

  el.innerHTML = trends.map((t, i) => {
    const pts = t.points || [];
    const last = pts[pts.length - 1]?.score || 0;
    const clr = riskColor(last);
    const name = (t.url || '').replace(/https?:\/\//, '').split('/')[0];
    const spark = buildSparkline(pts.map((p) => p.score), clr);
    const trend = pts.length >= 2 ? (pts[pts.length - 1].score - pts[0].score) : 0;
    const trendStr = trend > 0 ? `↑+${trend}` : trend < 0 ? `↓${trend}` : '→0';
    const trendClr = trend > 5 ? 'var(--red)' : trend < -5 ? 'var(--green)' : 'var(--text-3)';

    return `<div class="domain-item">
      <div class="domain-rank">${i + 1}</div>
      <div class="domain-info">
        <div class="domain-name" title="${t.url}">${name}</div>
        <div class="domain-meta">${pts.length} escaneos · <span style="color:${trendClr}">${trendStr}</span></div>
      </div>
      <svg class="domain-spark" viewBox="0 0 80 32">${spark}</svg>
      <div class="domain-score" style="color:${clr}">${last}</div>
    </div>`;
  }).join('');
}


function renderTopPlugins(plugins) {
  const el = document.getElementById('topPluginsEl');
  if (!el) return;

  if (!plugins || !plugins.length) {
    el.innerHTML = '<div style="color:var(--text-3);font-size:11px;font-family:var(--sans);padding:4px">Sin datos de plugins</div>';
    return;
  }

  const max = Math.max(...plugins.map((p) => p.vuln_count || 0), 1);
  el.innerHTML = plugins.map((p, i) => {
    const count = p.vuln_count || 0;
    const pct = Math.round((count / max) * 100);
    const sev = p.severities || {};
    const hasCrit = (sev.critical || 0) > 0;
    const clr = hasCrit ? 'var(--red)' : 'var(--orange)';
    return `<div class="plugin-row">
      <div class="plugin-rank">${i + 1}</div>
      <div class="plugin-name" title="${p.slug}">${p.slug}</div>
      <div class="plugin-bar-wrap"><div class="plugin-bar" style="width:${pct}%;background:${clr}"></div></div>
      <div class="plugin-count" style="color:${clr}">${count}</div>
    </div>`;
  }).join('');
}


function renderLastScan(rows) {
  const card = document.getElementById('lastScanCard');
  if (!card || !rows || !rows.length) return;

  const r = [...rows].sort((a, b) => ((b.scanned_at || '') > (a.scanned_at || '') ? 1 : -1))[0];
  card.style.display = 'block';

  const name = (r.url || '').replace(/https?:\/\//, '').split('/')[0];
  const urlEl = document.getElementById('lsUrl');
  if (urlEl) {
    urlEl.textContent = name || (r.url || '');
    urlEl.href = r.url || '#';
    urlEl.target = '_blank';
  }

  const timeEl = document.getElementById('lsTime');
  if (timeEl) timeEl.textContent = r.scanned_at ? `Fecha: ${r.scanned_at}` : '';

  const viewBtn = document.getElementById('lsViewBtn');
  if (viewBtn) {
    viewBtn.href = `/scan/${r.id || ''}/result`;
    const label = (r.risk_label || '').toString().toUpperCase();
    const score = Number(r.risk_score || 0);
    if (label === 'BAJO' || score < 20) {
      viewBtn.style.display = 'none';
    } else {
      viewBtn.style.display = '';
    }
  }

  const stats = [
    { val: r.vuln_count || 0, lbl: 'Vulnerabilidades', color: (r.vuln_count || 0) > 5 ? 'var(--red)' : (r.vuln_count || 0) > 0 ? 'var(--orange)' : 'var(--green)' },
    { val: r.critical_count || 0, lbl: 'Criticas', color: (r.critical_count || 0) > 0 ? 'var(--red)' : 'var(--text-3)' },
    { val: r.high_count || 0, lbl: 'Altas', color: (r.high_count || 0) > 0 ? 'var(--orange)' : 'var(--text-3)' },
    { val: r.plugin_count || 0, lbl: 'Plugins', color: 'var(--text-2)' },
    { val: r.exposed_count || 0, lbl: 'Expuestos', color: (r.exposed_count || 0) > 0 ? 'var(--orange)' : 'var(--text-3)' },
    { val: r.wp_version || '—', lbl: 'WP Version', color: 'var(--teal)' },
    { val: r.duration ? `${Number(r.duration).toFixed(1)}s` : '—', lbl: 'Duracion', color: 'var(--text-3)' },
  ];

  const statsEl = document.getElementById('lsStats');
  if (statsEl) {
    statsEl.innerHTML = stats.map((s) =>
      `<div class="ls-stat">
        <span class="ls-stat-val" style="color:${s.color}">${s.val}</span>
        <span class="ls-stat-lbl">${s.lbl}</span>
      </div>`
    ).join('');
  }

  const score = r.risk_score || 0;
  const clr = riskColor(score);

  const fill = document.getElementById('lsRiskFill');
  if (fill) {
    fill.style.background = clr;
    fill.style.width = '0%';
    setTimeout(() => { fill.style.width = `${Math.min(score, 100)}%`; }, 80);
  }

  const valEl = document.getElementById('lsRiskVal');
  if (valEl) {
    valEl.textContent = String(score);
    valEl.style.color = clr;
  }

  const pill = document.getElementById('lsRiskPill');
  if (pill) {
    pill.textContent = r.risk_label || '—';
    pill.style.color = clr;
    pill.style.borderColor = clr;
    pill.style.background = `${clr}1a`;
  }
}


async function loadDbStatus() {
  try {
    const d = await fetchJsonWithTimeout('/api/db-status', {}, 10000);
    const fresh = d.db_fresh ?? d.fresh ?? false;
    const days = d.db_days_old ?? d.days_old ?? 999;
    const total = d.db_total_vulns ?? d.db_stats?.total_vulns ?? 0;

    const pill = document.getElementById('dbStatusPill');
    const det = document.getElementById('dbStatusDetail');
    if (!pill) return;

    pill.className = `db-pill ${fresh ? 'fresh' : days < 14 ? 'stale' : 'old'}`;
    pill.textContent = fresh ? '● Al dia' : `⚠ ${days}d sin actualizar`;
    if (det) det.textContent = `${Number(total).toLocaleString('es-ES')} CVEs`;
  } catch (e) {
    const pill = document.getElementById('dbStatusPill');
    if (pill) {
      pill.className = 'db-pill old';
      pill.textContent = '⚠ Error estado BD';
    }
  }
}

async function triggerDbUpdate() {
  showToast('Actualizando base de datos de vulnerabilidades...', 'info');
  try {
    await fetchJsonWithTimeout('/api/db-update', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"source":"all"}',
    }, 10000);
    showToast('Actualizacion de BD iniciada en background', 'ok');
    setTimeout(loadDbStatus, 4000);
  } catch (e) {
    showToast('Error al iniciar actualizacion', 'error');
  }
}


function filterTable() {
  const q = (document.getElementById('tblSearch')?.value || '').toLowerCase();
  const rf = document.getElementById('riskFilter')?.value || '';
  const minS = parseInt(document.getElementById('minScore')?.value || '0', 10) || 0;

  const rows = _rows.filter((r) => {
    if (q && !(r.url || '').toLowerCase().includes(q)) return false;
    if (rf && r.risk_label !== rf) return false;
    if (minS && (r.risk_score || 0) < minS) return false;
    return true;
  }).sort((a, b) => {
    let va = a[_sortCol];
    let vb = b[_sortCol];
    if (typeof va === 'string') {
      va = va.toLowerCase();
      vb = (vb || '').toLowerCase();
    }
    return _sortAsc ? (va < vb ? -1 : va > vb ? 1 : 0) : (va > vb ? -1 : va < vb ? 1 : 0);
  });

  const countEl = document.getElementById('tblCount');
  if (countEl) countEl.textContent = `${rows.length} de ${_rows.length} escaneos`;

  const body = document.getElementById('recentBody');
  if (!body) return;

  body.innerHTML = rows.length ? rows.map((r) => {
    const c = RISK_CLR[r.risk_label] || 'var(--text-3)';
    const name = (r.url || '').replace(/https?:\/\//, '').split('/')[0];
    const rid = r.id || '';
    return `<tr>
      <td><a href="/?url=${encodeURIComponent(r.url || '')}" style="color:var(--blue);text-decoration:none" title="${r.url || ''}">${name}</a></td>
      <td><span class="risk-pill" style="color:${c};border-color:${c};background:${c}1a">${r.risk_score || 0} ${r.risk_label || ''}</span></td>
      <td style="color:${(r.vuln_count || 0) > 5 ? 'var(--red)' : (r.vuln_count || 0) > 0 ? 'var(--orange)' : 'var(--green)'}">${r.vuln_count || 0}</td>
      <td style="color:${(r.critical_count || 0) > 0 ? 'var(--red)' : 'var(--text-3)'}">${r.critical_count || 0}</td>
      <td style="color:var(--text-2)">${r.plugin_count || 0}</td>
      <td style="color:${(r.exposed_count || 0) > 0 ? 'var(--orange)' : 'var(--text-3)'}">${r.exposed_count || 0}</td>
      <td style="color:var(--text-3)">${r.duration ? `${Number(r.duration).toFixed(1)}s` : '—'}</td>
      <td style="color:var(--text-3);font-size:10px;white-space:nowrap">${r.scanned_at || '—'}</td>
      <td style="white-space:nowrap;display:flex;gap:5px;align-items:center">
        <a class="tbl-link" href="/compare?id2=${rid}">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="9" height="18" rx="1"/><rect x="13" y="3" width="9" height="18" rx="1"/></svg>
        </a>
        <a class="tbl-link" href="/scan/${rid}/result" style="color:var(--teal);border-color:rgba(0,200,190,.3)">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7z"/><circle cx="12" cy="12" r="3"/></svg>
        </a>
      </td>
    </tr>`;
  }).join('') :
  `<tr><td colspan="9" style="text-align:center;padding:24px;color:var(--text-3);font-family:var(--sans)">
    ${_rows.length ? 'Sin resultados para este filtro' : 'Sin escaneos — <a href="/" style="color:var(--blue)">realiza el primero aqui</a>'}
  </td></tr>`;
}

function clearFilters() {
  ['tblSearch', 'riskFilter', 'minScore'].forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.value = '';
  });
  filterTable();
}

function sortTable(col) {
  if (_sortCol === col) _sortAsc = !_sortAsc;
  else {
    _sortCol = col;
    _sortAsc = false;
  }
  filterTable();
}

function exportCSV() {
  const hdrs = ['ID', 'URL', 'Fecha', 'Score', 'Nivel', 'Vulns', 'Criticas', 'Altas', 'Plugins', 'Expuestos', 'WP'];
  const rows = _rows.map((r) => [
    r.id || '',
    `"${(r.url || '').replace(/"/g, '""')}"`,
    r.scanned_at || '',
    r.risk_score || 0,
    r.risk_label || '',
    r.vuln_count || 0,
    r.critical_count || 0,
    r.high_count || 0,
    r.plugin_count || 0,
    r.exposed_count || 0,
    r.wp_version || '',
  ].join(','));

  const blob = new Blob([[hdrs.join(','), ...rows].join('\n')], { type: 'text/csv' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `wpvuln-${new Date().toISOString().slice(0, 10)}.csv`;
  a.click();
  showToast(`${_rows.length} escaneos exportados a CSV`, 'ok');
}


function renderDashboardError(message) {
  const kpiEl = document.getElementById('kpiGrid');
  if (!kpiEl) return;

  kpiEl.innerHTML = `
    <div style="grid-column:1/-1;padding:24px;text-align:center;color:var(--red);font-family:var(--sans);font-size:13px">
      <div style="font-size:18px;margin-bottom:8px">⚠</div>
      <strong>Error cargando el dashboard</strong><br>
      <span style="color:var(--text-2);font-size:11px">${message || 'Error desconocido'} — recarga la pagina o revisa la consola</span>
    </div>`;
}

async function loadDashboard() {
  const btn = document.getElementById('refreshBtn');
  if (btn) btn.classList.add('spinning');

  try {
    const [d] = await Promise.all([
      fetchJsonWithTimeout('/api/dashboard', {}, 15000),
      loadDbStatus(),
    ]);

    _rows = d.recent || [];

    renderKPIs(d);
    renderLastScan(_rows);
    renderTimeline(d.recent || []);
    renderTopDomains(d.top_domains || []);
    renderDist(d.by_risk || []);
    renderHeatmap(d.heatmap || []);
    renderDomainTrends(d.domain_trends || []);
    renderTopPlugins(d.top_plugins || []);
    filterTable();

    const now = new Date();
    const upd = document.getElementById('lastUpdate');
    if (upd) {
      upd.textContent = `Actualizado: ${now.toLocaleTimeString('es-ES')} · ${d.total_scans || 0} escaneos · ${d.total_vulns || 0} vulnerabilidades encontradas`;
    }
  } catch (e) {
    console.error('Dashboard load error:', e);
    renderDashboardError(e?.message || 'Error desconocido');

    const body = document.getElementById('recentBody');
    if (body) {
      body.innerHTML = `<tr><td colspan="9" style="text-align:center;padding:24px;color:var(--red)">No se pudo cargar la tabla: ${e?.message || 'error'}</td></tr>`;
    }

    const upd = document.getElementById('lastUpdate');
    if (upd) upd.textContent = 'Error cargando datos';

    showToast(`Error cargando dashboard: ${e?.message || 'desconocido'}`, 'error');
  } finally {
    if (btn) btn.classList.remove('spinning');
  }
}


window.filterTable = filterTable;
window.clearFilters = clearFilters;
window.sortTable = sortTable;
window.exportCSV = exportCSV;
window.triggerDbUpdate = triggerDbUpdate;

document.addEventListener('DOMContentLoaded', loadDashboard);
