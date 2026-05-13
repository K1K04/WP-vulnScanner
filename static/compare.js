

let _scans = [], selA = null, selB = null;
function _escHtmlLocal(s){ return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
const HDR  = {};          // X-API-Key injected at init
let _diffIdx = 0;         // unique IDs for collapsible sections


document.addEventListener('DOMContentLoaded', async () => {  const p = new URLSearchParams(location.search);
  const k = p.get('key');
  if (k) { HDR['X-API-Key'] = k; localStorage.setItem('wpvs_api_key', k); }
  else    { HDR['X-API-Key'] = localStorage.getItem('wpvs_api_key') || ''; }

  await loadScans();
  const a = p.get('id1'), b = p.get('id2');
  if (a) selA = a;
  if (b) selB = b;
  if (a || b) { renderLists(); }
  if (a && b) { document.getElementById('btnCmp').disabled = false; runCompare(); }
});


async function loadScans() {
  ['listA','listB'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '<div class="diff-empty"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg> Cargando escaneos...</div>';
  });

  try {
    const res  = await fetch('/api/history?limit=200', { headers: HDR });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText}`);
    let data;
    try {
      data = await res.json();
    } catch (jsonErr) {
      throw new Error('Respuesta inválida del servidor (no JSON)');
    }

    _scans = (data.data || data.scans || data.items || (Array.isArray(data) ? data : []) || []).filter(s => s && s.id);
    if (!_scans.length) {
      ['listA','listB'].forEach(id => {
        const el = document.getElementById(id);
        if (el) el.innerHTML = '<div class="diff-empty">Sin escaneos disponibles</div>';
      });
      _populateDomainSelect();
      return;
    }

    _populateDomainSelect();
    renderLists();
  } catch(e) {
    console.error('loadScans error:', e);
    ['listA','listB'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = `<div style="color:var(--red);font-size:12px;padding:12px">Error cargando escaneos: ${_escHtmlLocal(e.message || String(e))} <button onclick="loadScans()" style="margin-left:8px">Reintentar</button></div>`;
    });
  }
}

function _populateDomainSelect() {
  const sel = document.getElementById('domainQuickSel');
  if (!sel) return;
  const domains = [...new Set(_scans.map(s => {
    try { return new URL(s.url).hostname; } catch { return s.url; }
  }).filter(Boolean))].sort();
  sel.innerHTML = '<option value="">— Todos los dominios —</option>' +
    domains.map(d => `<option value="${d}">${d}</option>`).join('');
}

function applyDomainFilter() {
  const domain = document.getElementById('domainQuickSel')?.value || '';
  ['A','B'].forEach(col => {
    const inp = document.getElementById('url' + col);
    if (inp) inp.value = domain;
  });
  renderLists();
  if (domain) {
    const domainScans = _scans
      .filter(s => { try { return new URL(s.url).hostname === domain; } catch { return false; } })
      .sort((a,b) => (b.scanned_at||'').localeCompare(a.scanned_at||''));
    if (domainScans.length >= 2) {
      selB = domainScans[0].id;   // most recent → "actual"
      selA = domainScans[1].id;   // second most recent → "base"
      renderLists();
      document.getElementById('btnCmp').disabled = false;
    } else if (domainScans.length === 1) {
      selB = domainScans[0].id;
      renderLists();
    }
  }
}


function filterList(col) {
  renderList(col, document.getElementById('url' + col).value);
}

function renderLists() {
  renderList('A', document.getElementById('urlA').value);
  renderList('B', document.getElementById('urlB').value);
}

function renderList(col, q = '') {
  const el  = document.getElementById('list' + col);
  const cur = col === 'A' ? selA : selB;
  const ql  = q.trim().toLowerCase();
  const arr = ql ? _scans.filter(s => (s.url||'').toLowerCase().includes(ql)) : _scans;

  if (!arr.length) {
    el.innerHTML = '<div class="diff-empty">Sin resultados</div>';
    return;
  }
  el.innerHTML = arr.slice(0,80).map(s => {
    const c = s.risk_score > 75 ? '#E5484D' : s.risk_score > 50 ? '#F4753A'
                                : s.risk_score > 25 ? '#F5A31A' : '#30B86B';
    return `<div class="scan-option${s.id === cur ? ' selected' : ''}" onclick="pick('${col}','${s.id}')">
      <span class="scan-risk" style="color:${c};border-color:${c}">${s.risk_score||0}</span>
      <div class="scan-meta">
        <div class="scan-url">${s.url||'—'}</div>
        <div class="scan-date">${s.scanned_at||''}</div>
      </div>
    </div>`;
  }).join('');
}

function pick(col, id) {
  if (col === 'A') selA = id; else selB = id;
  renderLists();
  document.getElementById('btnCmp').disabled = !(selA && selB);
}


async function runCompare() {
  if (!selA || !selB) return;
  _diffIdx = 0;
  const box = document.getElementById('results');
  box.style.display = 'block';
  box.innerHTML = `<div class="loading-state">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" class="spinning"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.9" y1="4.9" x2="7.8" y2="7.8"/><line x1="16.2" y1="16.2" x2="19.1" y2="19.1"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>
    Analizando diferencias…
  </div>`;

  try {
    const res  = await fetch(`/api/compare/diff?id1=${selA}&id2=${selB}`, { headers: HDR });
    const diff = await res.json();
    if (diff.error) throw new Error(diff.error);
    renderDiff(diff);
  } catch(e) {
    box.innerHTML = `<div style="color:var(--red);padding:16px;font-size:12px">Error: ${e.message}</div>`;
  }
}


function renderDiff(d) {
  const ps = d.progress_summary || {};
  const trend = ps.trend || 'stable';

  const TREND = {
    improving: { label:'MEJORADO',       cls:'improving', fg:'var(--green)',  icon:svgCheck() },
    worsening: { label:'EMPEORADO',      cls:'worsening', fg:'var(--red)',    icon:svgWarn() },
    stable:    { label:'SIN CAMBIOS',    cls:'stable',    fg:'var(--text-2)', icon:svgMinus() },
    mixed:     { label:'CAMBIOS MIXTOS', cls:'mixed',     fg:'var(--amber)',  icon:svgInfo() },
  }[trend];

  const delta   = d.risk_new - d.risk_old;
  const deltaS  = (delta > 0 ? '+' : '') + delta;
  const deltaFg = delta > 0 ? 'var(--red)' : delta < 0 ? 'var(--green)' : 'var(--text-3)';

  let html = `
  
  <div class="status-banner ${TREND.cls}">
    <div class="status-icon" style="background:${TREND.cls==='improving'?'var(--green-dim)':TREND.cls==='worsening'?'var(--red-dim)':'var(--bg-4)'};color:${TREND.fg}">
      ${TREND.icon}
    </div>
    <div style="flex:1">
      <div class="status-label" style="color:${TREND.fg}">${TREND.label}</div>
      <div class="status-meta">
        ${d.target_url||''} · ${d.scan_old_date||''} → ${d.scan_new_date||''}
        ${ps.days_between ? ` · ${ps.days_between}d entre escaneos` : ''}
      </div>
    </div>
    <div class="status-actions">
      <button class="btn btn-outline btn-sm" onclick="downloadPDF()">
        ${svgDownload()} Informe PDF
      </button>
    </div>
  </div>

  
  <div class="summary-grid">
    ${kpi(ps.vulns_fixed||0,    'Resueltas',   ps.vulns_fixed>0    ? 'var(--green)'  : 'var(--text-3)')}
    ${kpi(ps.vulns_new||0,      'Nuevas',      ps.vulns_new>0      ? 'var(--red)'    : 'var(--text-3)')}
    ${kpi(ps.vulns_remaining||0,'Persistentes',ps.vulns_remaining>0? 'var(--amber)'  : 'var(--text-3)')}
    ${kpi(ps.plugins_updated||0,'Actualizados',ps.plugins_updated>0? 'var(--blue)'   : 'var(--text-3)')}
    ${kpi(ps.files_fixed||0,    'Archivos OK', ps.files_fixed>0    ? 'var(--green)'  : 'var(--text-3)')}
    ${kpi(ps.headers_fixed||0,  'Headers OK',  ps.headers_fixed>0  ? 'var(--green)'  : 'var(--text-3)')}
  </div>

  
  <div class="risk-delta-card">
    <div class="risk-section-title">Evolución del Risk Score</div>
    ${riskRow('Anterior', d.risk_old)}
    ${riskRow('Actual',   d.risk_new)}
    <div class="delta-row">
      <span class="risk-delta-pill" style="color:${deltaFg};border-color:${deltaFg}">
        ${delta > 0 ? svgArrowUp() : delta < 0 ? svgArrowDown() : svgMinus()}
        ${deltaS} puntos
      </span>
    </div>
  </div>`;

  
  const fixed   = d.vulns_fixed   || [];
  const newV    = d.vulns_new     || [];
  const persist = d.vulns_persist || [];
  const updated = d.plugins_updated || [];

  html += mkSection({
    title:  `Vulnerabilidades resueltas (${fixed.length})`,
    icon:   svgCheck(), ibg:'var(--green-dim)', ifg:'var(--green)',
    count:  fixed.length, cclr:'var(--green)',
    rows:   fixed.map(v  => rowVuln(v, 'removed', '−')),
    extra:  sevPills(fixed, 'green'),
    empty:  'No hay vulnerabilidades resueltas en este periodo',
    open:   fixed.length > 0,
  });

  html += mkSection({
    title:  `Vulnerabilidades nuevas (${newV.length})`,
    icon:   svgAlert(), ibg:'var(--red-dim)', ifg:'var(--red)',
    count:  newV.length, cclr:'var(--red)',
    rows:   newV.map(v   => rowVuln(v, 'added', '+')),
    extra:  sevPills(newV, 'red'),
    empty:  'No hay vulnerabilidades nuevas',
    open:   newV.length > 0,
  });

  html += mkSection({
    title:  `Vulnerabilidades persistentes (${persist.length})`,
    icon:   svgWarn(), ibg:'rgba(245,163,26,.1)', ifg:'var(--amber)',
    count:  persist.length, cclr:'var(--amber)',
    rows:   persist.map(v => rowVuln(v, 'unchanged', '·')),
    empty:  'No hay vulnerabilidades que persistan',
    open:   false,
  });

  if (updated.length) {
    html += mkSection({
      title:  `Componentes actualizados (${updated.length})`,
      icon:   svgRefresh(), ibg:'var(--blue-dim)', ifg:'var(--blue)',
      count:  updated.length, cclr:'var(--blue)',
      rows:   updated.map(p => `
        <div class="diff-row changed">
          <div class="diff-marker">↻</div>
          <div class="diff-content">
            <div class="diff-main">
              <span style="font-family:var(--mono)">${p.slug}</span>
              <span class="ver-old">${p.old_version}</span>
              <span class="ver-arr">→</span>
              <span class="ver-new">${p.new_version}</span>
              <span style="font-size:10px;color:var(--text-3)">${p.type||'plugin'}</span>
            </div>
          </div>
        </div>`),
      open: true,
    });
  }
  const fileRows = [
    ...(d.files_new||[]).map(f  => rowFile(f, 'added', '+', 'Archivo sensible nuevo expuesto', 'var(--red)')),
    ...(d.files_fixed||[]).map(f=> rowFile(f, 'removed', '−', 'Archivo sensible ya no expuesto', 'var(--green)')),
  ];
  if (fileRows.length) {
    html += mkSection({
      title:  `Archivos sensibles (${fileRows.length} cambios)`,
      icon:   svgFile(), ibg:'rgba(244,117,58,.1)', ifg:'var(--orange)',
      count:  fileRows.length, cclr:'var(--orange)',
      rows:   fileRows, open: true,
    });
  }
  const hdrRows = [
    ...(d.headers_new||[]).map(h  => `<div class="diff-row added"><div class="diff-marker">+</div><div class="diff-content"><div class="diff-main">${h}</div><div class="diff-sub">Nuevo problema de header HTTP</div></div></div>`),
    ...(d.headers_fixed||[]).map(h=> `<div class="diff-row removed"><div class="diff-marker">−</div><div class="diff-content"><div class="diff-main" style="color:var(--green)">${h}</div><div class="diff-sub">Header de seguridad corregido</div></div></div>`),
  ];
  if (hdrRows.length) {
    html += mkSection({
      title:  `HTTP Security Headers (${hdrRows.length} cambios)`,
      icon:   svgServer(), ibg:'var(--bg-4)', ifg:'var(--text-2)',
      count:  hdrRows.length, cclr:'var(--text-2)',
      rows:   hdrRows, open: true,
    });
  }
  if (d.wp_version_old && d.wp_version_new && d.wp_version_old !== d.wp_version_new) {
    html += `<div class="diff-section">
      <div class="diff-header" style="cursor:default">
        <div class="diff-h-icon" style="background:var(--blue-dim);color:var(--blue)">${svgGlobe()}</div>
        <div class="diff-h-title">WordPress Core</div>
      </div>
      <div class="diff-body open">
        <div class="diff-row changed">
          <div class="diff-marker">↻</div>
          <div class="diff-content">
            <div class="diff-main">
              WordPress actualizado
              <span class="ver-old">${d.wp_version_old}</span>
              <span class="ver-arr">→</span>
              <span class="ver-new">${d.wp_version_new}</span>
            </div>
          </div>
        </div>
      </div>
    </div>`;
  }

  const box = document.getElementById('results');
  box.innerHTML = html;
  requestAnimationFrame(() => {
    box.querySelectorAll('.risk-bar').forEach(el => {
      const w = el.style.width; el.style.width = '0%';
      setTimeout(() => { el.style.width = w; }, 60);
    });
  });
}


function kpi(v, lbl, clr) {
  return `<div class="kpi-card">
    <div class="kpi-val" style="color:${clr}">${v}</div>
    <div class="kpi-lbl">${lbl}</div>
  </div>`;
}

function riskRow(lbl, score) {
  const c = score>=75?'var(--red)':score>=50?'var(--orange)':score>=25?'var(--amber)':'var(--green)';
  return `<div class="risk-row">
    <div class="risk-row-label">${lbl}</div>
    <div class="risk-bar-wrap"><div class="risk-bar" style="width:${Math.min(score,100)}%;background:${c}"></div></div>
    <div class="risk-num" style="color:${c}">${score}</div>
  </div>`;
}

function sevPills(vulns, toneColor) {
  if (!vulns || !vulns.length) return '';
  const counts = {critical:0, high:0, medium:0, low:0};
  vulns.forEach(v => { if (counts[v.severity] !== undefined) counts[v.severity]++; });
  const cfg = {
    critical: {label:'CRÍT',  bg:'var(--red-dim)',    color:'var(--red)'},
    high:     {label:'ALTO',  bg:'var(--orange-dim)', color:'var(--orange)'},
    medium:   {label:'MEDIO', bg:'var(--amber-dim)',  color:'var(--amber)'},
    low:      {label:'BAJO',  bg:'rgba(0,214,143,.08)', color:'var(--green)'},
  };
  return Object.entries(counts)
    .filter(([,n]) => n > 0)
    .map(([sev, n]) => `<span style="font-family:var(--head);font-size:9px;font-weight:700;letter-spacing:.5px;
      padding:2px 7px;border-radius:3px;background:${cfg[sev].bg};color:${cfg[sev].color};flex-shrink:0">
      ${n} ${cfg[sev].label}</span>`)
    .join('');
}

function mkSection({title, icon, ibg, ifg, count, cclr, rows, empty, open, extra}) {
  const id  = 'ds' + (_diffIdx++);
  const body = rows.length
    ? rows.join('')
    : `<div class="diff-empty">${svgCheck()}<span>${empty||'Sin cambios'}</span></div>`;
  return `<div class="diff-section">
    <div class="diff-header">
      <div class="diff-h-icon" style="background:${ibg};color:${ifg}">${icon}</div>
      <div class="diff-h-title">${title}</div>
      ${extra ? `<div style="display:flex;gap:4px;align-items:center;flex-wrap:wrap">${extra}</div>` : ''}
      ${count > 0 ? `<span class="diff-h-count" style="background:${ibg};color:${ifg}">${count}</span>` : ''}
    </div>
    <div class="diff-body open" id="${id}">${body}</div>
  </div>`;
}

function toggleSection(id) {
}

function rowVuln(v, cls, m) {
  if (!v || typeof v !== 'object') return '';
  const sev = v.severity || 'low';
  const sevLabel = {critical:'CRÍT',high:'ALTO',medium:'MEDIO',low:'BAJO',info:'INFO'}[sev] || sev.toUpperCase();
  const txtClr = cls==='added'?'color:var(--red)':cls==='removed'?'color:var(--green)':'';
  return `<div class="diff-row ${cls}">
    <div class="diff-marker">${m}</div>
    <div class="diff-content">
      <div class="diff-main" style="${txtClr}">
        <span class="sev-badge sev-${sev}">${sevLabel}</span>
        ${v.title || v.plugin_slug || '—'}
        ${v.cve_id ? `<a class="cve-tag" href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank" style="color:var(--teal,#00C8C0);border-color:rgba(0,200,192,.35)">${v.cve_id}</a>` : ''}
        ${v.cve_id ? `<a class="cve-tag" href="https://www.cve.org/CVERecord?id=${v.cve_id}" target="_blank" style="color:var(--orange);border-color:rgba(255,122,61,.35)">MITRE ↗</a>` : ''}
        ${v.cvss_score ? `<span style="font-size:10px;color:var(--text-3)">CVSS ${v.cvss_score}</span>` : ''}
      </div>
      <div class="diff-sub">
        ${v.plugin_slug||''}${v.plugin_version?` v${v.plugin_version}`:''}${v.fixed_in?` · Corregida en v${v.fixed_in}`:''}
      </div>
    </div>
  </div>`;
}

function rowFile(f, cls, m, note, fg) {
  const path = typeof f === 'string' ? f : (f.path || f);
  return `<div class="diff-row ${cls}">
    <div class="diff-marker">${m}</div>
    <div class="diff-content">
      <div class="diff-main" style="color:${fg}"><span style="font-family:var(--mono)">${path}</span></div>
      <div class="diff-sub">${note}</div>
    </div>
  </div>`;
}

function downloadPDF() {
  if (!selA || !selB) return;
  const k = HDR['X-API-Key'] ? `key=${HDR['X-API-Key']}&` : '';
  location.href = `/api/compare/progress-pdf?${k}id1=${selA}&id2=${selB}`;
}


const svg = (body, s=14) => `<svg width="${s}" height="${s}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">${body}</svg>`;
const svgCheck    = () => svg('<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>');
const svgAlert    = () => svg('<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r=".5" fill="currentColor"/>');
const svgWarn     = () => svg('<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><circle cx="12" cy="17" r=".5" fill="currentColor"/>');
const svgInfo     = () => svg('<circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>');
const svgMinus    = () => svg('<line x1="5" y1="12" x2="19" y2="12"/>');
const svgRefresh  = () => svg('<polyline points="1 4 1 10 7 10"/><path d="M3.51 15a9 9 0 1 0 .49-3.5"/>');
const svgFile     = () => svg('<path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/>');
const svgServer   = () => svg('<rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/>');
const svgGlobe    = () => svg('<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>');
const svgDownload = () => svg('<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>');
const svgArrowUp  = () => svg('<line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/>');
const svgArrowDown= () => svg('<line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/>');
function _scanNameById(id) {
  const s = _scans.find(x => String(x.id) === String(id));
  if (!s) return '—';
  const host = (s.url || '').replace(/^https?:\/\//i, '').split('/')[0] || s.url || '—';
  return `${host} (${s.risk_score || 0})`;
}

function _updateCompareUiState() {
  const canCompare = Boolean(selA && selB);
  const btn = document.getElementById('btnCmp');
  const hint = document.getElementById('compareHint');
  const sel = document.getElementById('compareSelection');
  const vs = document.getElementById('vsDivider');
  if (btn) btn.disabled = !canCompare;
  if (sel) sel.textContent = `Base: ${_scanNameById(selA)} · Actual: ${_scanNameById(selB)}`;
  if (hint) {
    hint.textContent = canCompare
      ? 'Listo para comparar. Pulsa "Comparar escaneos".'
      : (!selA && !selB)
        ? 'Selecciona un escaneo base y otro actual para habilitar la comparación.'
        : (!selA ? 'Falta seleccionar el escaneo base (izquierda).' : 'Falta seleccionar el escaneo actual (derecha).');
  }
  if (vs) vs.classList.toggle('ready', canCompare);
}
document.addEventListener('DOMContentLoaded', () => {
  try { _updateCompareUiState(); } catch (e) {  }
});
