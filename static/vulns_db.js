

const _VDB_API_KEY = (function(){ try { return localStorage.getItem('wpvs_api_key')||''; } catch(e){ return ''; } })();
function apiFetch(url, opts = {}) {
  const h = Object.assign({}, opts.headers || {});
  if (_VDB_API_KEY) h['X-API-Key'] = _VDB_API_KEY;
  return fetch(url, Object.assign({}, opts, { headers: h }));
}

const PAGE_SIZE = 25;
let allVulns = [];
let filtered  = [];
let page      = 1;
let sortCol   = 'cvss';
let sortDir   = 1;
let selectedId = null;
let sevChart, yearChart;
window.addEventListener('DOMContentLoaded', async () => {
  await loadStats();
  await loadVulns();
  populateYearFilter();
  renderCharts();
});

async function loadStats() {
  try {
    const r = await apiFetch('/api/db-status');
    const d = await r.json();
    document.getElementById('kpiTotal').textContent    = (d.vuln_count || 0).toLocaleString();
    document.getElementById('kpiCritical').textContent = (d.critical_count || 0).toLocaleString();
    document.getElementById('kpiHigh').textContent     = (d.high_count || 0).toLocaleString();
    document.getElementById('kpiPlugins').textContent  = (d.plugin_count || '—').toLocaleString();
    const days = d.days_since_update;
    document.getElementById('kpiFreshness').textContent = days != null ? `${days}d` : '—';
    document.getElementById('kpiFreshness').style.color = days == null ? 'var(--text-3)' : days < 3 ? 'var(--green)' : days < 14 ? 'var(--amber)' : 'var(--red)';
    document.getElementById('kpiDate').textContent = d.last_update ? `Actualizada: ${d.last_update.slice(0,10)}` : '';
  } catch(e) { console.warn('Stats error', e); }
}

async function loadVulns() {
  setLoadingState(true);
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 15000);
    const r = await apiFetch('/api/vulns?limit=1000', { signal: controller.signal });
    clearTimeout(timeoutId);
    if (!r.ok) throw new Error(`HTTP ${r.status}`);
    const d = await r.json();
    allVulns = d.vulns || d || [];
    applyFilters();
  } catch(e) {
    document.getElementById('tableContainer').innerHTML = `<div class="loading-state" style="color:var(--red)">Error cargando vulnerabilidades: ${e.message}</div>`;
  } finally {
    setLoadingState(false);
  }
}

function populateYearFilter() {
  const years = [...new Set(allVulns.map(v => {
    const m = (v.cve_id || '').match(/CVE-(\d{4})/);
    return m ? m[1] : null;
  }).filter(Boolean))].sort((a,b)=>b-a);
  const sel = document.getElementById('filterYear');
  years.forEach(y => {
    const opt = document.createElement('option');
    opt.value = y; opt.textContent = y;
    sel.appendChild(opt);
  });
}
let searchTimer;
function onSearch() {
  clearTimeout(searchTimer);
  searchTimer = setTimeout(applyFilters, 200);
}

function applyFilters() {
  const q    = document.getElementById('searchInput').value.trim().toLowerCase();
  const sev  = document.getElementById('filterSev').value;
  const type = document.getElementById('filterType').value;
  const year = document.getElementById('filterYear').value;

  filtered = allVulns.filter(v => {
    if (sev  && v.severity !== sev) return false;
    if (type && v.component_type !== type) return false;
    if (year && !(v.cve_id||'').includes(`CVE-${year}`)) return false;
    if (q) {
      const haystack = [(v.cve_id||''),(v.component_slug||''),(v.title||''),(v.description||'')].join(' ').toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  });

  sortResults();
  page = 1;
  renderTable();
  renderCharts();
}

function sortResults() {
  filtered.sort((a,b) => {
    if (sortCol === 'cvss') {
      return ((b.cvss_score||0) - (a.cvss_score||0)) * sortDir;
    }
    if (sortCol === 'sev') {
      const order = {critical:4,high:3,medium:2,low:1};
      return ((order[b.severity]||0) - (order[a.severity]||0)) * sortDir;
    }
    if (sortCol === 'date') {
      return ((b.published||'') > (a.published||'') ? 1 : -1) * sortDir;
    }
    const va = (a[sortCol]||'').toString().toLowerCase();
    const vb = (b[sortCol]||'').toString().toLowerCase();
    return (va > vb ? 1 : -1) * sortDir;
  });
}

function setSortCol(col) {
  if (sortCol === col) sortDir *= -1;
  else { sortCol = col; sortDir = -1; }
  sortResults();
  renderTable();
}
function renderTable() {
  const start = (page-1) * PAGE_SIZE;
  const slice = filtered.slice(start, start + PAGE_SIZE);

  document.getElementById('resultsCount').textContent = `${filtered.length.toLocaleString()} resultados`;

  if (!filtered.length) {
    document.getElementById('tableContainer').innerHTML = `
      <div class="loading-state">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.7" y2="16.7"/></svg>
        <div style="margin-top:8px">Sin resultados para esta busqueda</div>
      </div>`;
    document.getElementById('pagination').innerHTML = '';
    return;
  }

  const sevIcon = s => ({critical:'▲',high:'●',medium:'◆',low:'▼'}[s]||'');

  const rows = slice.map(v => {
    const cvss = v.cvss_score ? v.cvss_score.toFixed(1) : '—';
    const cvssClass = !v.cvss_score ? '' : v.cvss_score>=9?'cvss-critical':v.cvss_score>=7?'cvss-high':v.cvss_score>=4?'cvss-medium':'cvss-low';
    const date = (v.published||v.fixed_in||'').slice(0,10) || '—';
    return `<tr onclick="selectVuln('${(String(v.cve_id||v.id||'')).replace(/'/g,'')}')" data-id="${v.cve_id||v.id||''}">
      <td><span class="sev-badge sev-${v.severity}">${sevIcon(v.severity)} ${v.severity||'?'}</span></td>
      <td><span class="cve-id">${v.cve_id||'—'}</span></td>
      <td><span class="plugin-name" title="${v.component_slug||''}">${v.component_slug||v.title||'—'}</span></td>
      <td><span class="cvss-chip ${cvssClass}">${cvss}</span></td>
      <td class="date-cell">${date}</td>
    </tr>`;
  }).join('');

  const thSort = col => `onclick="setSortCol('${col}')" class="${sortCol===col?'sorted':''}"`;
  const arrow = col => sortCol===col?(sortDir>0?'&#x25B2;':'&#x25BC;'):'';

  document.getElementById('tableContainer').innerHTML = `
    <table class="results-table">
      <thead>
        <tr>
          <th ${thSort('sev')}>Severidad<span class="sort-icon">${arrow('sev')}</span></th>
          <th ${thSort('cve_id')}>CVE ID<span class="sort-icon">${arrow('cve_id')}</span></th>
          <th ${thSort('component_slug')}>Componente<span class="sort-icon">${arrow('component_slug')}</span></th>
          <th ${thSort('cvss')}>CVSS<span class="sort-icon">${arrow('cvss')}</span></th>
          <th ${thSort('date')}>Publicado<span class="sort-icon">${arrow('date')}</span></th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
  if (selectedId) {
    const tr = document.querySelector(`tr[data-id="${selectedId}"]`);
    if (tr) tr.classList.add('selected');
  }

  renderPagination();
}

function renderPagination() {
  const total = Math.ceil(filtered.length / PAGE_SIZE);
  if (total <= 1) { document.getElementById('pagination').innerHTML = ''; return; }

  let html = `<button class="page-btn" onclick="goPage(${page-1})" ${page<=1?'disabled':''}>&#x25C0;</button>`;
  const win = 2;
  for (let i=1;i<=total;i++) {
    if (i===1||i===total||Math.abs(i-page)<=win) {
      html += `<button class="page-btn ${i===page?'active':''}" onclick="goPage(${i})">${i}</button>`;
    } else if (Math.abs(i-page)===win+1) {
      html += `<span class="page-info">…</span>`;
    }
  }
  html += `<button class="page-btn" onclick="goPage(${page+1})" ${page>=total?'disabled':''}>&#x25B6;</button>`;
  html += `<span class="page-info">${((page-1)*PAGE_SIZE+1)}–${Math.min(page*PAGE_SIZE,filtered.length)} de ${filtered.length}</span>`;
  document.getElementById('pagination').innerHTML = html;
}

function goPage(p) {
  const total = Math.ceil(filtered.length / PAGE_SIZE);
  if (p < 1 || p > total) return;
  page = p;
  renderTable();
  document.querySelector('.results-panel').scrollIntoView({behavior:'smooth',block:'start'});
}
function selectVuln(id) {
  selectedId = id;
  document.querySelectorAll('.results-table tr').forEach(tr => {
    tr.classList.toggle('selected', tr.dataset.id === String(id));
  });

  const v = allVulns.find(x => String(x.cve_id||x.id||'') === String(id));
  if (!v) return;

  const detailPanel = document.getElementById('detailPanel');
  const cvss = v.cvss_score ? v.cvss_score.toFixed(1) : '—';
  const refs = (v.references||[]).slice(0,4);

  detailPanel.innerHTML = `
    <div class="detail-header">
      <div class="detail-cve">${v.cve_id||'Sin CVE'}</div>
      <div class="detail-title">${v.title||v.component_slug||'Sin titulo'}</div>
    </div>
    <div class="detail-body">
      <div class="detail-row">
        <span class="detail-label">Severidad</span>
        <span class="sev-badge sev-${v.severity}">${v.severity||'?'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">CVSS</span>
        <span class="detail-value" style="font-family:var(--mono);font-weight:700">${cvss}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Tipo</span>
        <span class="detail-value">${v.component_type||'—'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Componente</span>
        <span class="detail-value" style="font-family:var(--mono)">${v.component_slug||'—'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Version afectada</span>
        <span class="detail-value">${v.affected_version||v.plugin_version||'—'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Corregida en</span>
        <span class="detail-value" style="color:var(--green)">${v.fixed_in||'No disponible'}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Publicado</span>
        <span class="detail-value">${(v.published||'').slice(0,10)||'—'}</span>
      </div>
    </div>
    ${v.description ? `
    <div class="detail-desc">
      <div class="detail-desc-title">Descripcion</div>
      <div class="detail-desc-text">${v.description}</div>
    </div>` : ''}
    ${refs.length ? `
    <div class="detail-links">
      ${v.cve_id ? `<a class="detail-link" href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        NVD
      </a>` : ''}
      ${v.cve_id ? `<a class="detail-link" href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=${v.cve_id}" target="_blank">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>
        MITRE
      </a>` : ''}
      ${refs.map(r=>`<a class="detail-link" href="${r}" target="_blank" title="${r}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/></svg>
        Ref
      </a>`).join('')}
    </div>` : ''}
  `;
}
function renderCharts() {
  const sevCounts = {critical:0,high:0,medium:0,low:0};
  const yearCounts = {};
  filtered.forEach(v => {
    if (v.severity in sevCounts) sevCounts[v.severity]++;
    const m = (v.cve_id||'').match(/CVE-(\d{4})/);
    if (m) yearCounts[m[1]] = (yearCounts[m[1]]||0)+1;
  });

  const chartDefaults = {
    responsive:true, maintainAspectRatio:false,
    plugins:{legend:{display:false},tooltip:{
      backgroundColor:'rgba(13,15,24,.95)',
      borderColor:'rgba(30,34,54,.8)',borderWidth:1,
      titleColor:'#DCE1F0',bodyColor:'#8890B0',
      titleFont:{family:'Barlow Condensed',size:12,weight:'700'},
    }},
  };

  if (sevChart) sevChart.destroy();
  const sevCtx = document.getElementById('sevChart').getContext('2d');
  sevChart = new Chart(sevCtx, {
    type: 'doughnut',
    data: {
      labels: ['Critico','Alto','Medio','Bajo'],
      datasets:[{
        data: [sevCounts.critical,sevCounts.high,sevCounts.medium,sevCounts.low],
        backgroundColor: ['rgba(229,72,77,.7)','rgba(244,117,58,.7)','rgba(245,163,26,.7)','rgba(48,184,107,.7)'],
        borderColor: ['#E5484D','#F4753A','#F5A31A','#30B86B'],
        borderWidth: 1,
      }]
    },
    options: { ...chartDefaults, cutout:'65%' }
  });

  const years = Object.keys(yearCounts).sort();
  if (yearChart) yearChart.destroy();
  const yearCtx = document.getElementById('yearChart').getContext('2d');
  yearChart = new Chart(yearCtx, {
    type: 'bar',
    data: {
      labels: years,
      datasets:[{
        data: years.map(y=>yearCounts[y]),
        backgroundColor: 'rgba(43,127,255,.6)',
        borderColor: '#2B7FFF',
        borderWidth: 1,
        borderRadius: 2,
      }]
    },
    options: {
      ...chartDefaults,
      scales:{
        x:{ticks:{color:'#454D6A',font:{family:'JetBrains Mono',size:9}},grid:{color:'rgba(30,34,54,.5)'}},
        y:{ticks:{color:'#454D6A',font:{family:'JetBrains Mono',size:9}},grid:{color:'rgba(30,34,54,.5)'}},
      }
    }
  });
}
async function triggerUpdate() {
  const btn = document.getElementById('btnUpdate');
  btn.disabled = true;
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" style="animation:spin .8s linear infinite"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.9" y1="4.9" x2="7.8" y2="7.8"/><line x1="16.2" y1="16.2" x2="19.1" y2="19.1"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg> Actualizando...`;
  try {
    const r = await apiFetch('/api/db-update', {method:'POST'});
    const d = await r.json();
    showToast(d.message || 'Actualizacion iniciada', 'ok');
    setTimeout(async () => { await loadStats(); await loadVulns(); }, 5000);
  } catch(e) {
    showToast('Error al actualizar: ' + e.message, 'err');
  } finally {
    setTimeout(() => {
      btn.disabled = false;
      btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.5 15a9 9 0 1 1-2.8-6.7L23 10"/></svg> Actualizar BD`;
    }, 3000);
  }
}

function showToast(msg, type='ok') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = `toast ${type}`;
  t.style.display = 'block';
  setTimeout(() => t.style.display = 'none', 4000);
}

function setLoadingState(isLoading) {
  const sevLoading = document.getElementById('sevChartLoading');
  const yearLoading = document.getElementById('yearChartLoading');
  if (sevLoading) sevLoading.style.display = isLoading ? 'flex' : 'none';
  if (yearLoading) yearLoading.style.display = isLoading ? 'flex' : 'none';
}
