
'use strict';
function toggleExportMenu(e) {
  try {
    if (e) {
      if (typeof e.stopPropagation === 'function') e.stopPropagation();
      if (typeof e.preventDefault === 'function') e.preventDefault();
    }
  } catch (err) {
    console.warn('[Export] Error in event handling:', err);
  }
  
  try {
    const menu = document.getElementById('exportMenu');
    const btn = document.getElementById('exportDropBtn');
    
    if (!menu) {
      console.error('[Export] Menu element not found');
      return;
    }
    const isShown = menu.style.display === 'block';
    menu.style.display = isShown ? 'none' : 'block';
    if (btn) {
      btn.setAttribute('aria-expanded', isShown ? 'false' : 'true');
    }
    menu.setAttribute('aria-hidden', isShown ? 'true' : 'false');
    
    console.log('[Export] Menu toggled:', { wasShown: isShown, nowShowing: !isShown });
  } catch (err) {
    console.error('[Export] Error in toggleExportMenu:', err);
  }
}

function closeExportMenu() {
  try {
    const menu = document.getElementById('exportMenu');
    const btn = document.getElementById('exportDropBtn');
    
    if (menu) {
      menu.style.display = 'none';
      menu.setAttribute('aria-hidden', 'true');
    }
    
    if (btn) {
      btn.setAttribute('aria-expanded', 'false');
    }
    
    if (document._lastExportFocus && typeof document._lastExportFocus.focus === 'function') {
      document._lastExportFocus.focus();
    }
    document._lastExportFocus = null;
  } catch (err) {
    console.error('[Export] Error in closeExportMenu:', err);
  }
}
function _IDX_API_KEY() {
  try { return localStorage.getItem('wpvs_api_key') || ''; } catch(e) { return ''; }
}


function _esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function _normalizeScanResult(r) {
  const data = (r && typeof r === 'object') ? { ...r } : {};
  const summary = (data.summary && typeof data.summary === 'object') ? { ...data.summary } : {};
  const asNumber = (value) => {
    const n = Number(value);
    return Number.isFinite(n) ? n : 0;
  };
  const asArray = (value) => Array.isArray(value) ? value : [];
  const asCount = (value) => Array.isArray(value) ? value.length : asNumber(value);
  const riskScore = asNumber(data.risk_score);
  const deriveRisk = () => {
    if (riskScore >= 80) return ['CRITICO', 'var(--red)'];
    if (riskScore >= 60) return ['ALTO', 'var(--orange)'];
    if (riskScore >= 35) return ['MEDIO', 'var(--amber)'];
    return ['VERDE', 'var(--green)'];
  };
  const [riskLabel, riskColor] = deriveRisk();
  return {
    ...data,
    risk_score: riskScore,
    risk_label: data.risk_label || riskLabel,
    risk_color: data.risk_color || riskColor,
    vulnerabilities: asArray(data.vulnerabilities),
    plugins: asArray(data.plugins),
    themes: asArray(data.themes),
    exposed_files: asArray(data.exposed_files),
    users: asArray(data.users),
    malware_indicators: asArray(data.malware_indicators),
    headers_issues: asArray(data.headers_issues),
    summary: {
      plugins_found: asNumber(summary.plugins_found ?? data.plugins_found ?? asCount(data.plugins)),
      themes_found: asNumber(summary.themes_found ?? data.themes_found ?? asCount(data.themes)),
      vulns_found: asNumber(summary.vulns_found ?? data.vulns_found ?? asCount(data.vulnerabilities)),
      critical_vulns: asNumber(summary.critical_vulns ?? data.critical_vulns),
      high_vulns: asNumber(summary.high_vulns ?? data.high_vulns),
      medium_vulns: asNumber(summary.medium_vulns ?? data.medium_vulns),
      exposed_files: asNumber(summary.exposed_files ?? data.exposed_files_count ?? asCount(data.exposed_files)),
      header_issues: asNumber(summary.header_issues ?? data.header_issues_count ?? asCount(data.headers_issues)),
      users_found: asNumber(summary.users_found ?? data.users_found ?? asCount(data.users)),
      malware_found: asNumber(summary.malware_found ?? data.malware_found ?? asCount(data.malware_indicators)),
      outdated_plugins: asNumber(summary.outdated_plugins ?? data.outdated_plugins),
      outdated_themes: asNumber(summary.outdated_themes ?? data.outdated_themes),
      wpscan_api_used: Boolean(summary.wpscan_api_used ?? data.wpscan_api_used),
    },
  };
}
function apiFetch(url, opts = {}) {
  const h = Object.assign({}, opts.headers || {});
  const key = _IDX_API_KEY();
  if (key) h['X-API-Key'] = key;
  return fetch(url, Object.assign({}, opts, { headers: h })).then(resp => {
    if (resp.status === 401) {
      showToast('API key incorrecta o expirada — revisa la configuración', 'err');
      const el = document.getElementById('apiErrBanner');
      if (el) { el.classList.add('show'); el.textContent = 'Error 401: API key inválida. Comprueba la configuración.'; }
    }
    return resp;
  });
}


function _dlUrl(path) {
  const key = _IDX_API_KEY();
  if (!key) return path;
  const sep = path.includes('?') ? '&' : '?';
  return `${path}${sep}api_key=${encodeURIComponent(key)}`;
}


function _triggerDownload(url, filename) {
  try {
    const fullUrl = _dlUrl(url);
    console.log('[Download] Disparando descarga:', { url, fullUrl, filename });
    
    const a = document.createElement('a');
    a.href = fullUrl;
    if (filename) a.download = filename;
    a.style.display = 'none';
    document.body.appendChild(a);
    requestAnimationFrame(() => {
      a.click();
      console.log('[Download] Click ejecutado exitosamente');
      setTimeout(() => {
        try {
          document.body.removeChild(a);
        } catch (e) {
          console.warn('[Download] Error limpiando elemento:', e);
        }
      }, 500);
    });
  } catch (err) {
    console.error('[Download] Error en _triggerDownload:', err);
    showToast('❌ Error al descargar - revisa la consola del navegador', 'err');
  }
}

let currentResult = null;
let currentJobId  = null;
let scanStart     = null;
let _scanTickerId = null;
let _scanStartLocked = false;
window._debugExport = function() {
  console.log('=== DIAGNÓSTICO DE EXPORTACIÓN ===');
  console.log('currentJobId:', currentJobId);
  console.log('currentResult:', currentResult);
  const btn = document.getElementById('exportDropBtn');
  console.log('Botón exportar:', btn);
  console.log('Botón visible:', btn ? !!(btn.offsetParent) : 'no existe');
  const menu = document.getElementById('exportMenu');
  console.log('Menú exportar:', menu);
  console.log('Menú display:', menu ? window.getComputedStyle(menu).display : 'no existe');
  console.log('toggleExportMenu función:', typeof toggleExportMenu);
  console.log('_triggerDownload función:', typeof _triggerDownload);
  console.log('showToast función:', typeof showToast);
  console.log('_dlUrl función:', typeof _dlUrl);
  if (!currentJobId) {
    console.warn('⚠️ NO HAY SCAN EN CURSO - Completa un escaneo primero');
  } else {
    console.log('✅ Job ID disponible - Exportación debería funcionar');
  }
  return {currentJobId, hasMenu: !!menu, btnVisible: btn && !!btn.offsetParent};
};
let _scanLastProgressPct = 0;
let _scanLastEventAt = 0;
const _autoDiffCache = {};
const _riskTimelineDataCache = {};
function isValidUrl(raw) {
  const lower = raw.toLowerCase().trim();
  const blocked = ['javascript:', 'data:', 'vbscript:', 'file:', 'ftp:', 'blob:'];
  if (blocked.some(s => lower.startsWith(s))) return false;

  const url = lower.startsWith('http') ? raw : 'https://' + raw;
  try {
    const u = new URL(url);
    if (!['http:', 'https:'].includes(u.protocol)) return false;
    const h = u.hostname;
    if (/^169\.254\./.test(h)) return false;
    if (h === '0.0.0.0') return false;
    return h.length > 0;
  } catch { return false; }
}
function onLegalChange(cb) {
  const box   = document.getElementById('legalBox');
  const title = document.getElementById('legalTitle');
  if (cb.checked) {
    box.classList.add('accepted');
    title.textContent = 'Autorización confirmada';
    title.style.color = 'var(--green2)';
  } else {
    box.classList.remove('accepted');
    title.textContent = 'Declaración de autorización requerida';
    title.style.color = 'var(--yellow)';
  }
}

let _wpDetectTimeout;
async function detectWordPress() {
  const urlInput = document.getElementById('urlInput');
  const wpPanel = document.getElementById('wpDetectorPanel');
  const url = urlInput?.value.trim();
  
  if (!url || !isValidUrl(url)) {
    wpPanel.style.display = 'none';
    return;
  }
  
  wpPanel.style.display = 'flex';
  document.getElementById('wpDetectorIcon').textContent = '🔍';
  document.getElementById('wpDetectorStatus').textContent = 'Detectando...';
  document.getElementById('wpDetectorDetail').textContent = '';
  
  try {
    const res = await apiFetch('/api/check-wp', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url}),
    });
    const data = await res.json();
    
    if (!data.reachable) {
      document.getElementById('wpDetectorIcon').textContent = '⚠️';
      document.getElementById('wpDetectorStatus').textContent = data.reason || 'Sitio no alcanzable';
      const detail = data.detail || data.reason || 'Verifica la URL y tu conexión';
      document.getElementById('wpDetectorDetail').textContent = detail;
    } else if (data.is_wordpress) {
      document.getElementById('wpDetectorIcon').textContent = '✓';
      document.getElementById('wpDetectorStatus').style.color = 'var(--green)';
      document.getElementById('wpDetectorStatus').textContent = 'WordPress detectado';
      document.getElementById('wpDetectorDetail').textContent = data.wp_version ? `Versión: ${data.wp_version}` : 'Instalación activa';
    } else {
      document.getElementById('wpDetectorIcon').textContent = '✗';
      document.getElementById('wpDetectorStatus').style.color = 'var(--amber)';
      document.getElementById('wpDetectorStatus').textContent = 'No es WordPress';
      document.getElementById('wpDetectorDetail').textContent = 'Esta URL no parece ser un sitio WordPress';
    }
  } catch (err) {
    document.getElementById('wpDetectorIcon').textContent = '❌';
    document.getElementById('wpDetectorStatus').textContent = 'Error en detección';
    document.getElementById('wpDetectorDetail').textContent = err.message;
  }
}

function _detectWordPressDebounce() {
  clearTimeout(_wpDetectTimeout);
  _wpDetectTimeout = setTimeout(detectWordPress, 800);
}
async function loadDbStatus() {
  try {
    const res  = await apiFetch('/api/db-status');
    if (!res.ok) return;
    const d    = await res.json();
    const chip = document.getElementById('dbStatusChip');
    const txt  = document.getElementById('dbStatusText');
    if (!chip) return;
    const days  = d.days_old ?? d.db_days_old ?? 0;
    const total = d.total_vulns ?? d.db_total_vulns ?? d.stats?.total_vulns ?? '?';
    const last  = d.last_update ?? d.db_last_update ?? '';
    const dateStr = last ? last.split('T')[0] : 'nunca';
    if (days <= 3) {
      chip.className = 'db-chip fresh';
      txt.textContent = `BD Local — ${total} CVEs — actualizada ${dateStr}`;
    } else if (days <= 14) {
      chip.className = 'db-chip stale';
      txt.textContent = `BD Local — ${total} CVEs — ${days}d sin actualizar`;
    } else {
      chip.className = 'db-chip old';
      txt.textContent = `⚠ BD desactualizada — ${days}d — ejecuta update_vulns.py`;
    }
  } catch(e) {
    const txt = document.getElementById('dbStatusText');
    if (txt) txt.textContent = 'BD Local';
  }
}

let _dbUpdatePoller = null;

async function triggerDbUpdate() {
  const btn = document.getElementById('dbUpdateBtn');
  if (!btn) return;
  try {
    const st = await apiFetch('/api/db-update/status');
    const sd = await st.json();
    if (sd.running) {
      _startDbUpdatePolling();
      return;
    }
  } catch(_) {}

  btn.textContent = 'Iniciando...';
  btn.disabled = true;
  try {
    const res = await apiFetch('/api/db-update', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({source:'all'})
    });
    const d = await res.json();
    if (d.error && res.status !== 409) {
      btn.textContent = '✗ Error: ' + (d.error||'');
      setTimeout(() => { btn.textContent = '↻ Actualizar BD'; btn.disabled = false; }, 4000);
      return;
    }
    _startDbUpdatePolling();
  } catch(e) {
    btn.textContent = '✗ Sin conexión';
    setTimeout(() => { btn.textContent = '↻ Actualizar BD'; btn.disabled = false; }, 3000);
  }
}

function _startDbUpdatePolling() {
  const btn     = document.getElementById('dbUpdateBtn');
  const statusEl = document.getElementById('dbUpdateStatus');
  if (_dbUpdatePoller) clearInterval(_dbUpdatePoller);

  let dots = 0;
  _dbUpdatePoller = setInterval(async () => {
    try {
      const r = await apiFetch('/api/db-update/status');
      const s = await r.json();
      dots = (dots + 1) % 4;
      const dotStr = '.'.repeat(dots + 1);

      if (s.running) {
        if (btn) { btn.textContent = `Actualizando${dotStr}`; btn.disabled = true; }
        if (statusEl) {
          statusEl.style.display = 'block';
          statusEl.innerHTML = `<span style="color:var(--amber)">⏳ ${s.last_message || 'Procesando...'}</span>`;
        }
      } else {
        clearInterval(_dbUpdatePoller);
        _dbUpdatePoller = null;
        if (btn) { btn.textContent = '↻ Actualizar BD'; btn.disabled = false; }
        if (statusEl) {
          const ok = s.last_result === 'ok';
          const delta = s.vulns_after && s.vulns_before
            ? ` (+${Math.max(0, s.vulns_after - s.vulns_before)} CVEs nuevos · ${s.vulns_after} total)`
            : '';
          statusEl.innerHTML = ok
            ? `<span style="color:var(--green)">✓ Completada${delta}</span>`
            : `<span style="color:var(--red)">✗ Error: ${s.last_message||'desconocido'}</span>`;
          setTimeout(() => loadDbStatus(), 1500);
        }
      }
    } catch(_) {
      clearInterval(_dbUpdatePoller);
      _dbUpdatePoller = null;
      if (btn) { btn.textContent = '↻ Actualizar BD'; btn.disabled = false; }
    }
  }, 1800);
}
let _histOffset = 0;
const _HIST_LIMIT = 20;
let _histRows = [];
let _histAbortCtrl = null;  // cancela fetch previo si se lanza otro rápido

async function loadHistory(reset) {
  if (reset) { _histOffset = 0; _histRows = []; }
  if (_histAbortCtrl) { _histAbortCtrl.abort(); }
  _histAbortCtrl = new AbortController();

  const q    = (document.getElementById('histSearch')?.value || '').trim();
  const risk = (document.getElementById('histRiskSel')?.value || '').trim();
  const url = `/api/history?limit=${_HIST_LIMIT}&offset=${_histOffset}` +
              (q    ? `&url=${encodeURIComponent(q)}` : '') +
              (risk ? `&risk_label=${encodeURIComponent(risk)}` : '');
  const bodyEl = document.getElementById('historyBody');
  if (bodyEl && reset) {
    bodyEl.innerHTML = [1,2,3].map(() =>
      '<div class="history-row" style="pointer-events:none">' +
      '<span class="h-risk" style="background:var(--bg-4);border-radius:3px;width:40px;height:14px;display:inline-block"></span>' +
      '<span class="h-url" style="background:var(--bg-4);border-radius:3px;height:12px;display:inline-block;animation:hist-shimmer 1.2s ease-in-out infinite"></span>' +
      '</div>'
    ).join('');
  }
  try {
    const res  = await apiFetch(url, { signal: _histAbortCtrl.signal });
    const json = await res.json();
    const rows  = json.data || json;
    const total = json.total || rows.length;

    _histRows = reset ? rows : [..._histRows, ...rows];
    _histOffset += rows.length;

    const body    = _el('historyBody');
    const empty   = document.getElementById('histEmpty');
    const count   = document.getElementById('histCount');
    const moreBtn = document.getElementById('histLoadMore');

    if (count) count.textContent = total ? `(${total})` : '';

    if (!_histRows.length) {
      if (empty) { empty.textContent = q ? 'Sin resultados para ese filtro.' : 'No hay escaneos previos.'; empty.style.display = ''; }
      if (body) body.innerHTML = '';
      if (moreBtn) moreBtn.style.display = 'none';
      return;
    }

    if (empty) empty.style.display = 'none';
    const riskC = {'CRÍTICO':'#ff4757','ALTO':'#ff6b35','MEDIO':'#ffa502','BAJO':'#2ed573'};
    const frag = document.createDocumentFragment();
    _histRows.forEach(r => {
      const div = document.createElement('div');
      div.className = 'history-row';
      div.setAttribute('data-scan-id', r.id);  // ✅ Usar data attribute para event delegation
      div.innerHTML = `<span class="h-risk" style="color:${riskC[r.risk_label]||'#8b949e'}">${r.risk_score}/100</span>` +
        `<span class="h-url" title="${_esc(r.url)}">${_esc(r.url)}</span>` +
        `<span class="meta-small">${r.vuln_count||0}V · ${r.exposed_count||0}E${r.wpscan_api?' · API':''}</span>` +
        `<span class="h-meta">${r.scanned_at}</span>`;
      frag.appendChild(div);
    });
    if (body) { body.innerHTML = ''; body.appendChild(frag); }

    if (moreBtn) moreBtn.style.display = _histRows.length < total ? 'block' : 'none';
  } catch (e) {
    if (e.name === 'AbortError') return;  // cancelado intencionalmente — no mostrar error
    const empty = document.getElementById('histEmpty');
    if (empty) empty.textContent = 'Error cargando historial.';
  }
}

function loadHistoryMore() { loadHistory(false); }

let _histSearchTimer = null;
function _histSearchDebounce() {
  const inp = document.getElementById('histSearch');
  const clr = document.getElementById('histSearchClear');
  if (clr) clr.style.display = inp.value ? 'block' : 'none';
  clearTimeout(_histSearchTimer);
  _histSearchTimer = setTimeout(() => loadHistory(true), 280);
}

function toggleHistory() {
  const body    = _el('historyBody');
  const chevron = document.getElementById('histChevron');
  const header  = document.getElementById('historyHeader');
  const sw      = document.getElementById('histSearchWrap');
  const isOpen  = body.classList.contains('open');
  body.classList.toggle('open', !isOpen);
  chevron.classList.toggle('open', !isOpen);
  header.classList.toggle('open', !isOpen);
  if (header) header.setAttribute('aria-expanded', !isOpen ? 'true' : 'false');
  if (sw) sw.style.display = !isOpen ? 'block' : 'none';
  if (!isOpen) loadHistory(true);
}

async function loadFromHistory(scanId) {
  try {
    const res  = await apiFetch(`/scan/${scanId}/result`);
    const data = await res.json();
    if (data.result) { currentJobId = scanId; showResults(data.result); }
  } catch (e) { console.error(e); }
}
function saveActiveJob(jobId) { try { localStorage.setItem('wpvuln_active_job', jobId); } catch(e){} }
function clearActiveJob()     { try { localStorage.removeItem('wpvuln_active_job'); } catch(e){} }
function getActiveJob()       { try { return localStorage.getItem('wpvuln_active_job'); } catch(e){ return null; } }

async function tryReconnect() {
  const jobId = getActiveJob();
  if (!jobId) return;
  try {
    const res  = await apiFetch(`/scan/${jobId}/result`);
    const data = await res.json();
    if (data.status === 'running') {
      currentJobId = jobId;
      scanStart = Date.now();
      showProgress();
      addLine('Reconectando a escaneo en curso...', '+0.0s');
      connectStream(jobId);
    } else if (data.status === 'done' && data.result) {
      clearActiveJob();
    } else {
      clearActiveJob();
    }
  } catch(e) { clearActiveJob(); }
}
function downloadExecutivePDF() {
  if (!currentJobId) { 
    showToast('⚠️ Completa un escaneo primero', 'warn'); 
    console.warn('[Export] No currentJobId available');
    return; 
  }
  const btn = document.getElementById('btnExecPDF');
  const original = btn ? btn.innerHTML : '';
  if (btn) { btn.textContent = '⏳ Generando...'; btn.disabled = true; }
  console.log('[Export] Iniciando descarga PDF Ejecutivo:', `/scan/${currentJobId}/executive-pdf`);
  _triggerDownload(`/scan/${currentJobId}/executive-pdf`);
  setTimeout(() => { if (btn) { btn.innerHTML = original; btn.disabled = false; } }, 3000);
}

function downloadPDF() {
  if (!currentJobId) { 
    showToast('⚠️ Completa un escaneo primero', 'warn'); 
    console.warn('[Export] No currentJobId available');
    return; 
  }
  const btn = document.getElementById('btnPDF');
  const original = btn ? btn.innerHTML : '';
  if (btn) { btn.textContent = '⏳ Generando...'; btn.disabled = true; }
  console.log('[Export] Iniciando descarga PDF:', `/scan/${currentJobId}/pdf`);
  _triggerDownload(`/scan/${currentJobId}/pdf`);
  setTimeout(() => { if (btn) { btn.innerHTML = original; btn.disabled = false; } }, 3500);
}
async function startScan() {
  if (_scanStartLocked) {
    showToast('Escaneo ya en curso. Espera a que termine.', 'warn');
    return;
  }
  _scanStartLocked = true;

  const url   = document.getElementById('urlInput').value.trim();
  const legal = document.getElementById('legalCheck').checked;

  if (!url) { flashInput('URL requerida'); _scanStartLocked = false; return; }
  if (!isValidUrl(url)) { flashInput('URL no válida — usa http(s)://dominio.com'); _scanStartLocked = false; return; }
  if (!legal) {
    const box = document.getElementById('legalBox');
    box.style.borderColor = 'var(--red)';
    box.style.background  = 'rgba(255,71,87,.1)';
    box.scrollIntoView({behavior:'smooth',block:'center'});
    setTimeout(() => { box.style.borderColor=''; box.style.background=''; }, 2500);
    _scanStartLocked = false;
    return;
  }
  clearError();
  const btn    = document.getElementById('scanBtn');
  const btnTxt = document.getElementById('btnText');
  const iconEl = document.getElementById('btnIcon');

  btn.disabled = true;
  btnTxt.textContent = 'VERIFICANDO';
  iconEl.innerHTML   = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="width:14px;height:14px;animation:spin .8s linear infinite"><path d="M12 2a10 10 0 0 1 10 10"/></svg>';

  _showWpCheckBadge('checking');

  let wpCheckPassed = false;
  try {
    const ck = await apiFetch('/api/check-wp', {
      method:  'POST',
      headers: {'Content-Type':'application/json'},
      body:    JSON.stringify({url}),
    });
    const cd = await ck.json();

    if (!cd.reachable) {
      _showWpCheckBadge('unreachable', cd.reason);
      btn.disabled   = false;
      btnTxt.textContent = 'ESCANEAR';
      iconEl.innerHTML = '';
      _scanStartLocked = false;
      return;
    }
    if (!cd.is_wordpress) {
      _showWpCheckBadge('not_wp');
      const go = await _confirmNotWP(url);
      if (!go) {
        btn.disabled   = false;
        btnTxt.textContent = 'ESCANEAR';
        iconEl.innerHTML = '';
        _scanStartLocked = false;
        return;
      }
      _showWpCheckBadge('not_wp_continue');
    } else {
      _showWpCheckBadge('ok', cd.wp_version);
      wpCheckPassed = true;
    }
  } catch (_e) {
    _showWpCheckBadge('skip');
  }
  scanStart = Date.now();
  _scanLastProgressPct = 0;
  _scanLastEventAt = Date.now();
  showProgress();
  resetTerminal();
  resetLiveFindings();

  btnTxt.textContent = 'ESCANEANDO';
  iconEl.innerHTML   = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" style="width:14px;height:14px;animation:spin .8s linear infinite"><path d="M12 2a10 10 0 0 1 10 10"/></svg>';

  try {
    const res = await apiFetch('/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, legal_accepted: true}),
    });
    if (res.status === 429) throw new Error('Demasiadas peticiones. Espera un minuto e inténtalo de nuevo.');
    let data;
    try {
      data = await res.json();
    } catch (_) {
      throw new Error(`Error del servidor (${res.status}) — respuesta inesperada. Comprueba que la URL sea accesible.`);
    }
    if (!res.ok || data.error) throw new Error(data.error || `Error del servidor (${res.status})`);
    currentJobId = data.job_id;
    saveActiveJob(currentJobId);
      if (data.deduped) {
        addLine('Escaneo ya en curso detectado. Reutilizando job activo...', elapsed(), true);
      }
      if (data.cached) {
        addLine('⚡ Resultado cargado desde caché (< 1h)', elapsed(), false);
        setProgress(100, 'Cargado desde caché');
        const r2 = await apiFetch(`/scan/${currentJobId}/result`).then(r => r.json());
        hideProgress();
        showResults(r2);
        showCacheBadge(url);
      } else {
        connectStream(currentJobId);
      }
  } catch (err) {
    showError(err.message);
    resetBtn();
    _scanStartLocked = false;
  }
}

function connectStream(jobId) {
  const evtSrc = new EventSource(`/scan/${jobId}/stream`);
  let reconnectAttempts = 0;
  let lastActivity = Date.now();

  evtSrc.onmessage = (e) => {
    lastActivity = Date.now();
    _scanLastEventAt = Date.now();
    let ev;
    try { ev = JSON.parse(e.data); } catch { return; }

    if (ev.type === 'progress') {
      const isWarn = ev.message.includes('⚠') || ev.message.includes('offline');
      addLine(ev.message, elapsed(), isWarn);
      setProgress(ev.percent, ev.message);
    } else if (ev.type === 'finding') {
      addLiveFinding(ev);
    } else if (ev.type === 'heartbeat') {
      const cursor = document.querySelector('.t-cursor');
      if (cursor) cursor.style.opacity = cursor.style.opacity === '0' ? '1' : '0';
    } else if (ev.type === 'done') {
      evtSrc.close();
      clearActiveJob();
      _scanStartLocked = false;
      setProgress(100, ev.partial ? '⚠ Escaneo parcial (timeout)' : '¡Completado!');
      if (ev.partial) addLine('⚠ Timeout: resultado parcial guardado', elapsed(), true);
      setTimeout(() => {
        if (!ev.result) {
          showError('El servidor no devolvió resultado (timeout parcial o error interno)');
          resetBtn();
          return;
        }
        showResults(ev.result);
      }, 400);
      loadHistory(true);
    } else if (ev.type === 'error') {
      evtSrc.close();
      clearActiveJob();
      _scanStartLocked = false;
      showError(ev.message);
      resetBtn();
    }
  };

  let _watchdogTimer = null;
  let _watchdogActive = false;

  function _startWatchdog() {
    if (_watchdogActive) return;
    _watchdogActive = true;
    addLine('⚠ Conexión SSE interrumpida — esperando resultado en background...', elapsed(), true);
    setProgress(null, 'Esperando resultado...');
    let _polls = 0;
    const _maxPolls = 60; // 5 min máximo (60 × 5s)
    _watchdogTimer = setInterval(() => {
      _polls++;
      apiFetch(`/scan/${jobId}/result`)
        .then(r => r.json())
        .then(data => {
          if (data && data.status === 'done' && data.result) {
            clearInterval(_watchdogTimer);
            _watchdogActive = false;
            clearActiveJob();
            setProgress(100, '¡Completado!');
            addLine('✔ Resultado recuperado vía polling', elapsed());
            setTimeout(() => showResults(data.result), 400);
            loadHistory(true);
          } else if (data && data.status === 'error') {
            clearInterval(_watchdogTimer);
            _watchdogActive = false;
            clearActiveJob();
            showError(data.message || 'El escaneo terminó con error.');
            resetBtn();
          } else if (_polls >= _maxPolls) {
            clearInterval(_watchdogTimer);
            _watchdogActive = false;
            clearActiveJob();
            showError('Tiempo de espera agotado. El escaneo puede haber completado — revisa el historial.');
            resetBtn();
            loadHistory(true);
          }
        })
        .catch(() => {
          if (_polls >= _maxPolls) {
            clearInterval(_watchdogTimer);
            _watchdogActive = false;
            showError('No se pudo contactar el servidor. Revisa el historial.');
            resetBtn();
          }
        });
    }, 5000);
  }

  evtSrc.onerror = () => {
    reconnectAttempts++;
    if (reconnectAttempts >= 3) {
      evtSrc.close();
      _startWatchdog();
    }
  };
}
function elapsed() {
  const s = ((Date.now() - (scanStart || Date.now())) / 1000).toFixed(1);
  return `+${s}s`;
}

function _formatSeconds(sec) {
  const n = Math.max(0, Math.round(sec || 0));
  const m = Math.floor(n / 60);
  const s = n % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

function _renderScanRuntime() {
  const elapsedEl = _el('scanElapsed');
  const etaEl = _el('progETA');
  if (!elapsedEl || !etaEl || !scanStart) return;

  const elapsedSec = (Date.now() - scanStart) / 1000;
  elapsedEl.textContent = `${_formatSeconds(elapsedSec)} transcurridos`;

  const pct = Number(_scanLastProgressPct);
  let etaTxt = '';
  if (Number.isFinite(pct) && pct > 3 && pct < 99) {
    const estimatedTotal = elapsedSec / (pct / 100);
    const remaining = Math.max(0, estimatedTotal - elapsedSec);
    etaTxt = `ETA ~${_formatSeconds(remaining)}`;
  }

  const idleSec = _scanLastEventAt ? Math.max(0, Math.round((Date.now() - _scanLastEventAt) / 1000)) : 0;
  if (idleSec >= 8) {
    etaTxt = etaTxt ? `${etaTxt} · sin eventos ${idleSec}s` : `sin eventos ${idleSec}s`;
  }

  etaEl.textContent = etaTxt;
}

function _startScanRuntimeTicker() {
  if (_scanTickerId) clearInterval(_scanTickerId);
  _renderScanRuntime();
  _scanTickerId = setInterval(_renderScanRuntime, 1000);
}

function _stopScanRuntimeTicker(resetText = false) {
  if (_scanTickerId) {
    clearInterval(_scanTickerId);
    _scanTickerId = null;
  }
  if (resetText) {
    const elapsedEl = _el('scanElapsed');
    const etaEl = _el('progETA');
    if (elapsedEl) elapsedEl.textContent = '0s transcurridos';
    if (etaEl) etaEl.textContent = '';
  }
}

const _MAX_TERM_LINES = 120;
function addLine(msg, time, isWarn = false) {
  const body = _el('termBody');
  if (!body) return;
  const cursor = body.querySelector('.t-cursor');
  const line   = document.createElement('div');
  line.className = 't-line';
  line.innerHTML = `<span class="t-time">${time}</span><span class="t-msg${isWarn?' warn':''}">${_esc(String(msg))}</span>`;
  if (cursor) body.insertBefore(line, cursor);
  else body.appendChild(line);
  const lines = body.querySelectorAll('.t-line');
  if (lines.length > _MAX_TERM_LINES) {
    for (let i = 0; i < lines.length - _MAX_TERM_LINES; i++) lines[i].remove();
  }
  const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 40;
  if (atBottom) {
    body.scrollTop = body.scrollHeight;
  } else {
    const sb = document.getElementById('termScrollBtn');
    if (sb) sb.style.display = 'block';
  }
}
function scrollTermToBottom() {
  const body = _el('termBody');
  if (body) body.scrollTop = body.scrollHeight;
  const sb = document.getElementById('termScrollBtn');
  if (sb) sb.style.display = 'none';
}
function resetTerminal() {
  const b = document.getElementById('termBody');
  if (b) { b.innerHTML = '<span class="t-cursor"></span>'; _DOM['termBody'] = b; }
  const sb = document.getElementById('termScrollBtn');
  if (sb) sb.style.display = 'none';
}
const _lfCounts = {critical:0, high:0, medium:0, low:0, info:0, total:0};

function resetLiveFindings() {
  Object.keys(_lfCounts).forEach(k => _lfCounts[k] = 0);
  const body = document.getElementById('lfBody');
  if (body) body.innerHTML = '';
  ['lfCntC','lfCntH','lfCntM','lfCntL'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.style.display = 'none';
  });
  const tot = document.getElementById('lfCntTotal');
  if (tot) tot.textContent = '0 hallazgos';
  const panel = document.getElementById('liveFindingsPanel');
  if (panel) panel.style.display = 'none';
}

function addLiveFinding(f) {
  const panel = document.getElementById('liveFindingsPanel');
  const body  = document.getElementById('lfBody');
  if (!panel || !body) return;

  panel.style.display = 'block';

  const sev = (f.severity || 'info').toLowerCase();
  _lfCounts[sev] = (_lfCounts[sev] || 0) + 1;
  _lfCounts.total++;
  const sevMap = {
    critical: {id:'lfCntC', label:'CRÍTICO'},
    high:     {id:'lfCntH', label:'ALTO'},
    medium:   {id:'lfCntM', label:'MEDIO'},
    low:      {id:'lfCntL', label:'BAJO'}
  };
  if (sevMap[sev]) {
    const el = document.getElementById(sevMap[sev].id);
    if (el) {
      el.style.display = '';
      el.textContent = `${_lfCounts[sev]} ${sevMap[sev].label}`;
    }
  }
  const tot = document.getElementById('lfCntTotal');
  if (tot) tot.textContent = `${_lfCounts.total} hallazgo${_lfCounts.total !== 1 ? 's' : ''}`;
  const card = document.createElement('div');
  card.className = `lf-card sev-${sev}`;

  const cvssHtml = f.cvss
    ? `<span class="lf-cvss">CVSS ${parseFloat(f.cvss).toFixed(1)}</span>` : '';
  const cveHtml  = f.cve
    ? `<span class="lf-cve">${_esc(f.cve)}</span>` : '';
  const compText = f.component
    ? (f.version ? `${f.component} ${f.version}` : f.component) : '';
  const compHtml = compText
    ? `<span class="lf-comp" title="${_esc(compText)}">${_esc(compText)}</span>` : '';

  card.innerHTML =
    `<span class="lf-sev">${sev.toUpperCase()}</span>` +
    `<span class="lf-title" title="${_esc(f.title || '')}">${_esc(f.title || 'Hallazgo sin título')}</span>` +
    `<span class="lf-meta">${cvssHtml}${cveHtml}${compHtml}</span>`;

  body.appendChild(card);
  const atBottom = body.scrollHeight - body.scrollTop - body.clientHeight < 60;
  if (atBottom) body.scrollTop = body.scrollHeight;
}
(function _initTermScroll() {
  document.addEventListener('DOMContentLoaded', function() {
    const body = document.getElementById('termBody');
    if (!body) return;
    body.addEventListener('scroll', function() {
      const sb = document.getElementById('termScrollBtn');
      if (!sb) return;
      sb.style.display = (body.scrollHeight - body.scrollTop - body.clientHeight < 40) ? 'none' : 'block';
    });
  });
})();
const _DOM = {};
function _el(id) { return _DOM[id] || (_DOM[id] = document.getElementById(id)); }

function setProgress(pct, msg) {
  const fill = _el('progFill');
  const pctNum = Number(pct);
  const hasPct = Number.isFinite(pctNum);
  const safePct = hasPct ? Math.max(0, Math.min(100, pctNum)) : null;

  if (fill && hasPct) {
    fill.style.width = safePct + '%';
    fill.setAttribute('aria-valuenow', String(Math.round(safePct)));
  }
  const pctEl = _el('progPct');
  if (pctEl) pctEl.textContent = hasPct ? `${Math.round(safePct)}%` : '—';
  
  const msgEl = _el('progMsg'); 
  if (msg && msgEl) {
    // Agregar spinner visual si no está completado
    const spinner = hasPct && safePct < 100 ? '⏳ ' : '';
    msgEl.textContent = spinner + msg;
    msgEl.style.fontStyle = 'italic';
    msgEl.style.opacity = safePct === 100 ? '1' : '0.85';
  }

  if (hasPct) _scanLastProgressPct = safePct;
  _scanLastEventAt = Date.now();
  _renderScanRuntime();
}
function _renderActionSummary(r) {
  const panel = document.getElementById('actionSummaryPanel');
  if (!panel) return;
  const actions = [];
  const pushAction = (sev, title, detail, step, cve = '') => {
    actions.push({ sev, title, detail, step, cve });
  };
  const vulns = r.vulnerabilities || [];
  const critHigh = vulns.filter(v => v.severity === 'critical' || v.severity === 'high');
  if (critHigh.length) {
    const top = critHigh[0] || {};
    const step = top.recommended_action || (top.fixed_in
      ? `Actualizar ${top.plugin_slug || 'el componente afectado'} a la version ${top.fixed_in}.`
      : 'Aplicar mitigacion temporal y aislar los componentes vulnerables hasta disponer de parche oficial.');
    pushAction(
      'critical',
      `${critHigh.length} vulnerabilidad(es) critica(s)/alta(s) detectada(s)`,
      'Este grupo de hallazgos suele permitir compromiso del sitio si no se corrige con prioridad.',
      step,
      top.cve_id || ''
    );
  }
  if (r.wp_outdated) {
    pushAction(
      'high',
      'WordPress esta desactualizado',
      `Version actual: ${r.wp_version || 'desconocida'} / ultima version: ${r.wp_latest_version || 'no indicada'}.`,
      'Actualizar desde Panel > Actualizaciones y validar compatibilidad de plugins tras el despliegue.'
    );
  }

  if (r.debug_mode?.debug_active) {
    pushAction(
      'high',
      'WP_DEBUG activo en produccion',
      'La salida de debug puede exponer rutas internas, stack traces y configuraciones sensibles.',
      'Editar wp-config.php y establecer WP_DEBUG=false en entorno de produccion.'
    );
  }

  if (r.ssl_info?.expired) {
    pushAction(
      'critical',
      'Certificado SSL expirado',
      'Los visitantes reciben advertencias de seguridad y se degrada la confianza del sitio.',
      'Renovar el certificado TLS inmediatamente y verificar la cadena completa del certificado.'
    );
  }
  const critFiles = (r.exposed_files || []).filter(f => f.severity === 'critical');
  if (critFiles.length) {
    const samplePath = critFiles[0]?.path || 'archivo sensible';
    pushAction(
      'critical',
      `${critFiles.length} archivo(s) critico(s) expuesto(s)`,
      `Se detecto exposicion publica de contenido sensible (ejemplo: ${samplePath}).`,
      'Aplicar denegacion de acceso, mover archivos fuera del webroot y revisar permisos del sistema de archivos.'
    );
  }

  const usersExposed = (r.users || []).length;
  if (usersExposed > 0 || r.xmlrpc_enabled) {
    const vector = [
      usersExposed > 0 ? `${usersExposed} usuario(s) enumerable(s)` : '',
      r.xmlrpc_enabled ? 'XML-RPC habilitado' : '',
    ].filter(Boolean).join(' + ');
    pushAction(
      'medium',
      'Superficie de autenticacion expuesta',
      vector || 'Endpoints de autenticacion accesibles desde Internet.',
      'Limitar enumeracion de usuarios, aplicar 2FA y desactivar XML-RPC si no es imprescindible.'
    );
  }
  const missingHeaders = (r.headers_issues || []).length;
  if (missingHeaders >= 3) {
    pushAction(
      'low',
      `Hardening HTTP incompleto (${missingHeaders} cabeceras faltantes)`,
      'La ausencia de cabeceras reduce defensas del navegador frente a clickjacking y XSS.',
      'Definir HSTS, CSP y X-Frame-Options en la configuracion de nginx/apache.'
    );
  }

  if (!(r.waf_detected || []).length) {
    pushAction(
      'low',
      'No se detecta WAF perimetral',
      'Sin filtrado perimetral disminuye la capacidad de bloqueo temprano de ataques automatizados.',
      'Valorar Cloudflare, Sucuri o Wordfence para agregar capa de proteccion proactiva.'
    );
  }

  if (!actions.length) {
    panel.style.display = 'none';
    return;
  }

  const sevOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  const sevMeta = {
    critical: { icon: 'ic-shield-alert', label: 'Critico' },
    high: { icon: 'ic-warning', label: 'Alto' },
    medium: { icon: 'ic-lock', label: 'Medio' },
    low: { icon: 'ic-check', label: 'Base' },
  };

  actions.sort((a, b) => (sevOrder[a.sev] || 9) - (sevOrder[b.sev] || 9));

  panel.style.display = 'block';
  panel.innerHTML = `
    <div class="action-summary-card">
      <div class="action-summary-head">
        <span class="action-summary-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
            <use href="#ic-dashboard"></use>
          </svg>
          ${actions.length} accion(es) recomendada(s)
        </span>
        <button onclick="document.getElementById('actionSummaryPanel').style.display='none'"
                class="action-summary-close"
                aria-label="Ocultar acciones recomendadas">&times;</button>
      </div>
      <div class="action-summary-body">
        ${actions.map(a => {
          const meta = sevMeta[a.sev] || sevMeta.low;
          return `
          <article class="action-summary-item action-summary-item-${a.sev}">
            <div class="action-summary-icon-wrap" aria-hidden="true">
              <svg class="action-summary-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
                <use href="#${meta.icon}"></use>
              </svg>
            </div>
            <div class="action-summary-copy">
              <div class="action-summary-line">
                <span class="action-summary-level">${meta.label}</span>
                <strong>${_esc(a.title)}</strong>
              </div>
              <div class="action-summary-detail">${_esc(a.detail)}</div>
              <div class="action-summary-step"><span>Accion recomendada:</span> ${_esc(a.step)}</div>
            </div>
            ${a.cve ? `<a class="action-summary-cve" href="https://nvd.nist.gov/vuln/detail/${_esc(a.cve)}" target="_blank" rel="noopener noreferrer">${_esc(a.cve)}</a>` : ''}
          </article>`;
        }).join('')}
      </div>
    </div>`;
}

function showResults(r) {
  _stopScanRuntimeTicker();
  r = _normalizeScanResult(r);
  currentResult = r;
  currentJobId = currentJobId || r.scan_id || null;
  if (currentJobId && (!r.scan_id || r.scan_id !== currentJobId)) {
    r.scan_id = currentJobId;
  }
  _el('progressSection').style.display = 'none';
  const lfp = document.getElementById('liveFindingsPanel');
  if (lfp) lfp.style.display = 'none';
  _el('scanSection').style.display     = 'none';
  _el('resultsSection').style.display  = 'block';

  const resultUrl = r.target_url || r.url || r.site_url || 'URL desconocida';
  const resultId = r.scan_id || currentJobId || 'sin-id';
  const resultDate = r.scanned_at || r.started_at || r.finished_at || '';
  const resultDuration = Number.isFinite(Number(r.duration)) ? `${Number(r.duration)}s` : '';
  document.getElementById('resultMeta').textContent =
    [resultUrl, `ID: ${resultId}`, resultDate, resultDuration].filter(Boolean).join('  ·  ');
  const staleBanner = _el('dbStaleBanner');
  const staleText   = document.getElementById('dbStaleText');
  if (r.db_days_old && r.db_days_old > 7) {
    staleText.textContent = ` La BD lleva ${r.db_days_old} días sin actualizar.`;
    staleBanner.classList.add('show');
  } else {
    staleBanner.classList.remove('show');
  }
  let sslBanner = document.getElementById('sslUnverifiedBanner');
  if (!sslBanner) {
    sslBanner = document.createElement('div');
    sslBanner.id = 'sslUnverifiedBanner';
    sslBanner.className = 'api-error-banner';
    sslBanner.innerHTML = '<strong>⚠ Certificado SSL no verificado.</strong> <span>Este escaneo se ejecutó con validación de SSL deshabilitada. Algunos sitios con certificados autofirmados o inválidos pueden haber sido escaneados, pero verifica los resultados.</span>';
    staleBanner.parentNode.insertBefore(sslBanner, staleBanner.nextSibling);
  }
  if (r.ssl_unverified) {
    sslBanner.classList.add('show');
  } else {
    sslBanner.classList.remove('show');
  }

  const risk = Number.isFinite(Number(r.risk_score)) ? Number(r.risk_score) : 0;
  _el('riskNum').textContent   = 0;
  _el('riskNum').style.color   = r.risk_color;
  _el('riskLabel').textContent = r.risk_label;
  _el('riskLabel').style.color = r.risk_color;
  animateRiskScore(risk, r.risk_color);
  setTimeout(() => updateRiskCallout(r), 200);
  setTimeout(() => {
    const bar = _el('riskBar');
    bar.style.width      = `${risk}%`;
    bar.style.background = r.risk_color;
  }, 100);

  const s = r.summary || {};
  const outdated = Number(s.outdated_plugins || 0) + Number(s.outdated_themes || 0);
  const row1 = [
    {n: s.vulns_found,    l: 'Vulnerabilidades', c: s.vulns_found   > 0 ? 'var(--red)'    : 'var(--green)', bar: '#e5484d'},
    {n: s.critical_vulns, l: 'Críticas',         c: s.critical_vulns> 0 ? 'var(--red)'    : 'var(--text-3)', bar: '#e5484d'},
    {n: s.high_vulns,     l: 'Altas',            c: s.high_vulns    > 0 ? 'var(--orange)' : 'var(--text-3)', bar: '#f4753a'},
    {n: s.malware_found,  l: 'Malware / Spam',   c: s.malware_found > 0 ? 'var(--red)'    : 'var(--text-3)', bar: '#e5484d'},
    {n: s.exposed_files,  l: 'Archivos expuestos',c: s.exposed_files> 0 ? 'var(--orange)' : 'var(--text-3)', bar: '#f4753a'},
  ];
  const row2 = [
    {n: s.plugins_found,  l: 'Plugins',          c: 'var(--blue)',   bar: '#2b7fff'},
    {n: s.themes_found,   l: 'Temas',            c: 'var(--teal)',   bar: '#00c8be'},
    {n: outdated,         l: 'Desactualizados',  c: outdated   > 0 ? 'var(--amber)' : 'var(--text-3)', bar: '#f5a31a'},
    {n: s.users_found,    l: 'Usuarios expuestos',c: s.users_found > 0 ? 'var(--amber)' : 'var(--text-3)', bar: '#f5a31a'},
    {n: s.header_issues,  l: 'Headers faltantes',c: s.header_issues> 0 ? 'var(--amber)' : 'var(--text-3)', bar: '#f5a31a'},
  ];

  function mkStat(st) {
    return `<div class="risk-stat">
      <div class="risk-stat-bar" style="background:${st.bar}"></div>
      <div class="risk-stat-num" style="color:${st.c}">${Number.isFinite(Number(st.n)) ? Number(st.n) : 0}</div>
      <div class="risk-stat-lbl">${st.l}</div>
    </div>`;
  }
  document.getElementById('riskStatsGrid').innerHTML  = row1.map(mkStat).join('');
  document.getElementById('riskStatsGrid2').innerHTML = row2.map(mkStat).join('');
  const legacyStats = [...row1,...row2];
  document.getElementById('statGrid').innerHTML = legacyStats.map(s => `
    <div class="stat-cell"><div class="stat-num" style="color:${s.c}">${Number.isFinite(Number(s.n)) ? Number(s.n) : 0}</div><div class="stat-lbl">${s.l}</div></div>`).join('');
  const tbVulns = document.getElementById('tbVulns');
  const tbComps = document.getElementById('tbComps');
  const tbFiles = document.getElementById('tbFiles');
  const tbDeep  = document.getElementById('tbDeepScan');
  const tbInfo  = document.getElementById('tbInfo');
  const tbSurface = document.getElementById('tbSurface');
  if (tbVulns) tbVulns.textContent = Array.isArray(r.vulnerabilities) ? r.vulnerabilities.length : Number(r.summary?.vulns_found || 0);
  if (tbComps) tbComps.textContent = (Array.isArray(r.plugins) ? r.plugins.length : Number(r.summary?.plugins_found || 0)) + (Array.isArray(r.themes) ? r.themes.length : Number(r.summary?.themes_found || 0));
  if (tbFiles) tbFiles.textContent = Array.isArray(r.exposed_files) ? r.exposed_files.length : Number(r.summary?.exposed_files || 0);
  if (tbSurface) {
    const maxArea = Math.max(
      Number(r.risk_score || 0),
      Number((r.summary || {}).critical_vulns || 0) > 0 ? 80 : 0,
      Number((r.summary || {}).header_issues || 0) >= 3 ? 60 : 0
    );
    const isRed = maxArea >= 70;
    const isAmber = !isRed && maxArea >= 40;
    tbSurface.textContent = isRed ? 'ROJO' : isAmber ? 'AMBAR' : 'VERDE';
    tbSurface.style.color = isRed ? 'var(--red)' : isAmber ? 'var(--amber)' : 'var(--green2)';
    tbSurface.style.background = isRed
      ? 'var(--red-dim)'
      : isAmber
        ? 'var(--amber-dim)'
        : 'var(--green-dim)';
    tbSurface.style.borderColor = isRed
      ? 'rgba(255,69,96,.34)'
      : isAmber
        ? 'rgba(255,184,48,.38)'
        : 'rgba(0,214,143,.34)';
  }
  if (tbInfo) {
    const usersCount = (r.users||[]).length;
    if (usersCount > 0) {
      tbInfo.textContent = usersCount + ' usuarios';
      tbInfo.style.display = '';
      tbInfo.style.background = 'rgba(255,184,48,.15)';
      tbInfo.style.color = 'var(--amber)';
      tbInfo.style.border = '1px solid rgba(255,184,48,.35)';
    } else {
      tbInfo.style.display = 'none';
    }
  }
  if (tbDeep  && r.deep_scan) {
    const ds = r.deep_scan;
    const n  = (ds.rest_deep?.exposed_routes?.length || 0) +
               (ds.uploads?.dangerous_files?.length || 0) +
               (ds.woocommerce?.exposed_paths?.length || 0) +
               (ds.changelog?.found?.length || 0) +
               (ds.ajax_nopriv?.exposed_actions?.length || 0) +
               (ds.login_security?.username_enumerable ? 1 : 0) +
               (ds.pingback?.ssrf_risk ? 1 : 0);
    tbDeep.textContent = n;
  }
  const tools = document.getElementById('tabVulnsTools');
  if (tools) tools.style.display = 'none';
  currentTab = 'vulns';
  document.querySelectorAll('.tab-btn').forEach(b => {
    b.classList.toggle('active', b.dataset.tab === 'vulns');
    b.setAttribute('aria-selected', b.dataset.tab === 'vulns' ? 'true' : 'false');
    b.setAttribute('tabindex', b.dataset.tab === 'vulns' ? '0' : '-1');
  });
  renderTab('vulns', r);
  _updateReconBadge(r);
  if (r.target_url) loadRiskTimeline(r.target_url);
  loadAutoDiff(currentJobId || r.scan_id || '');

  _el('resultsSection').scrollIntoView({behavior:'smooth'});
  _renderActionSummary(r);
}
function section(icon, title, countHtml, countClass, bodyHtml, openByDefault) {
  const id = 'acc_' + Math.random().toString(36).slice(2,8);
  return `
  <div class="acc-section open">
    <div class="acc-header">
      <span class="acc-icon">${icon}</span>
      <span class="acc-title">${title}</span>
      <span class="acc-count ${countClass}">${countHtml}</span>
    </div>
    <div class="acc-body" id="${id}">${bodyHtml}</div>
  </div>`;
}

function toggleAcc(id) {
}

function compCard(p, icon) {
  const c = (p && typeof p === 'object') ? p : { slug: String(p || 'desconocido') };
  const isOutdated = !!c.is_outdated;
  const name = _esc(c.slug || 'desconocido');
  const iconCode = _esc(String(icon || 'CMP').toUpperCase().slice(0, 4));
  const version = _esc(c.version || '?');
  const latestInfo = c.latest_version ? ` -> <span class="comp-latest">${_esc(c.latest_version)}</span>` : '';
  const detectedVia = _esc(c.detected_via || 'deteccion heuristica');
  const confRaw = Number(c.confidence);
  const conf = Number.isFinite(confRaw) ? Math.max(0, Math.min(100, Math.round(confRaw))) : null;
  const confTag = conf === null ? 'conf. n/d' : `conf. ${conf}%`;
  const stateBadge = isOutdated
    ? '<span class="comp-out">DESACTUALIZADO</span>'
    : '<span class="comp-ok">AL DIA</span>';

  return `
  <div class="comp-card ${isOutdated ? 'is-outdated' : 'is-current'}">
    <div class="comp-icon">${iconCode}</div>
    <div class="comp-main" style="flex:1;min-width:0">
      <div class="comp-head">
        <div class="comp-name">${name}</div>
        ${stateBadge}
      </div>
      <div class="comp-meta">
        v<span class="comp-ver">${version}</span>${latestInfo}
      </div>
      <div class="comp-tags">
        <span class="comp-tag">${detectedVia}</span>
        <span class="comp-tag">${confTag}</span>
      </div>
      ${conf === null ? '' : `<div class="conf-bar"><div class="conf-fill" style="width:${conf}%"></div></div>`}
    </div>
  </div>`;
}

function buildAccordion(r) {
  const s = r.summary || {};
  let html = '';
  const ssl = r.ssl_info || {};
  const sslColor = ssl.expired ? 'var(--red)' : !ssl.valid ? 'var(--orange)' : (ssl.days_left < 30 ? 'var(--yellow)' : 'var(--green2)');
  const sslText  = ssl.error && !ssl.valid ? `⚠ ${ssl.error}` : ssl.expired ? 'EXPIRADO'
                 : ssl.valid ? `✓ ${ssl.days_left}d restantes (${ssl.issuer})` : 'No analizado';
  const wpVerHtml = r.wp_version
    ? `<span class="${r.wp_outdated?'wi-bad':'wi-warn'}">${_esc(r.wp_version)}</span>
       ${r.wp_outdated ? `<span style="color:var(--red);font-size:11px"> ⚠ → ${_esc(r.wp_latest_version)}</span>` : ''}
       <span style="color:var(--text3);font-size:11px"> (${r.wp_version_source})</span>`
    : `<span class="wi-ok">No detectada ✓</span>`;

  const wafs = r.waf_detected || [];
  const wafHtml = wafs.length > 0
    ? `<span style="color:var(--green2)">${wafs.join(', ')}</span>`
    : `<span class="wi-warn">Sin WAF/CDN detectado</span>`;
  const dbInfo = r.db_days_old
    ? `<span style="color:${r.db_days_old>14?'var(--red)':r.db_days_old>7?'var(--yellow)':'var(--green2)'}">${r.db_days_old === 0 ? 'Hoy' : 'Hace '+r.db_days_old+'d'} (${r.db_last_update||''})</span>`
    : `<span style="color:var(--text3)">BD local</span>`;

  html += section('', 'Información del sitio', '', 'count-grey', `
    <div class="wp-grid">
      <div class="wp-item"><div class="wi-label">WordPress</div>
        <div class="wi-value ${r.is_wordpress?'wi-ok':'wi-warn'}">${r.is_wordpress?'✓ Detectado':'? No confirmado'}</div></div>
      <div class="wp-item"><div class="wi-label">Versión WP</div>
        <div class="wi-value">${wpVerHtml}</div></div>
      <div class="wp-item"><div class="wi-label">Servidor</div>
        <div class="wi-value">${r.server_info||'<span class="wi-ok">Oculto ✓</span>'}</div></div>
      <div class="wp-item"><div class="wi-label">PHP</div>
        <div class="wi-value">${r.php_version?`<span class="wi-warn">${_esc(r.php_version)}</span>`:'<span class="wi-ok">Oculta ✓</span>'}</div></div>
      <div class="wp-item"><div class="wi-label">XML-RPC</div>
        <div class="wi-value ${r.xmlrpc_enabled?'wi-bad':'wi-ok'}">${r.xmlrpc_enabled?'ACTIVO':'✓ Desactivado'}</div></div>
      <div class="wp-item"><div class="wi-label">Login /wp-login.php</div>
        <div class="wi-value ${r.login_exposed?'wi-warn':'wi-ok'}">${r.login_exposed?'Accesible':'✓ Protegido'}</div></div>
      <div class="wp-item"><div class="wi-label">SSL / HTTPS</div>
        <div class="wi-value" style="color:${sslColor}">${sslText}</div></div>
      <div class="wp-item"><div class="wi-label">WAF / CDN</div>
        <div class="wi-value">${wafHtml}</div></div>
      <div class="wp-item"><div class="wi-label">BD Vulnerabilidades</div>
        <div class="wi-value">${dbInfo}</div></div>
    </div>`, true);
  const vulns = r.vulnerabilities || [];
  const vc = s.critical_vulns>0?'count-red':s.high_vulns>0?'count-orange':vulns.length>0?'count-yellow':'count-green';
  const vulnsHtml = vulns.length === 0
    ? `<div class="no-results"><div class="nr-icon ic-ok"></div><p>No se encontraron vulnerabilidades conocidas</p></div>`
    : vulns.map(v => {
        if (typeof v !== 'object') return '';
        const icon = v.type==='wordpress'?'WP':v.type==='theme'?'TEMA':'PLUGIN';
        const sevLabel = {critical:'CRÍTICO',high:'ALTO',medium:'MEDIO',low:'BAJO',info:'INFO'}[v.severity]||v.severity.toUpperCase();
        return `<div class="vuln-card">
          <div class="vuln-header">
            <span class="sev-badge sev-${v.severity}">${sevLabel}</span>
            <div style="flex:1;min-width:0">
              <div class="vuln-title">${_esc(v.title)}</div>
              <div class="vuln-tags">
                <span class="vtag">${icon} ${_esc(v.plugin_slug)}${v.plugin_version?' v'+_esc(v.plugin_version):''}</span>
                ${v.cvss_score?`<span class="vtag" style="color:${parseFloat(v.cvss_score)>=9?'var(--red)':parseFloat(v.cvss_score)>=7?'var(--orange)':'var(--yellow)'}">CVSS ${v.cvss_score}</span>`:''}
                ${v.cve_id?`<span class="vtag"><a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank" title="Ver en NVD (NIST)" style="color:var(--cyan);font-weight:600">${v.cve_id} ↗</a></span>`:''}
              </div>
            </div>
          </div>
          ${(v.description||v.fixed_in)?`<div class="vuln-body">
            ${v.description?`<p style="line-height:1.55">${_esc(v.description)}</p>`:''}
            ${v.fixed_in?`<span class="fix-tag">✓ Actualizar a v${_esc(v.fixed_in)}</span>`:''}
          </div>`:''}
        </div>`;
      }).join('');
  html += section('⚠', 'Vulnerabilidades', vulns.length, vc, vulnsHtml, vulns.length > 0);
  const plugins = r.plugins || [];
  const outdP   = s.outdated_plugins > 0 ? ` — <span style="color:var(--yellow)">${s.outdated_plugins} desactualizados</span>` : '';
  html += section('', `Plugins${outdP}`, plugins.length, 'count-grey',
    plugins.length === 0
      ? `<div class="no-results"><div class="nr-icon ic-plug"></div><p>No se detectaron plugins</p></div>`
      : `<div class="comp-grid">${plugins.map(p=>compCard(p,'PLG')).join('')}</div>`);
  const themes = r.themes || [];
  const outdT  = s.outdated_themes > 0 ? ` — <span style="color:var(--yellow)">${s.outdated_themes} desactualizados</span>` : '';
  html += section('', `Temas${outdT}`, themes.length, 'count-grey',
    themes.length === 0
      ? `<div class="no-results"><div class="nr-icon ic-theme"></div><p>No se detectaron temas</p></div>`
      : `<div class="comp-grid">${themes.map(t=>compCard(t,'THM')).join('')}</div>`);
  const exposed = r.exposed_files || [];
  const fileCC  = exposed.some(f=>f.severity==='critical') ? 'count-red' : exposed.length > 0 ? 'count-orange' : 'count-green';
  const sevC    = {critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--text2)'};
  html += section('', 'Archivos sensibles expuestos', exposed.length, fileCC,
    exposed.length === 0
      ? `<div class="no-results"><div class="nr-icon ic-ok"></div><p>No se encontraron archivos sensibles expuestos</p></div>`
      : '<div style="margin-top:12px">' + exposed.map(f => {
          if (typeof f === 'string') f = {path:f,description:'',severity:'high',extra:''};
          const c = sevC[f.severity]||'var(--orange)';
          return `<div class="file-item">
            <span class="file-sev" style="color:${c}">${f.severity?.toUpperCase()||'?'}</span>
            <div style="flex:1">
              <code class="file-path"><a href="${(/^https?:\/\//i.test(f.url||''))?f.url:'#'}" target="_blank" rel="noopener noreferrer" style="color:var(--cyan);text-decoration:none">${_esc(f.path)}</a></code>
              <div class="file-desc">${f.description||''}</div>
              ${f.extra?`<div class="file-extra">${f.extra}</div>`:''}
            </div>
          </div>`;
        }).join('') + '</div>', exposed.length > 0);
  const users = r.users || [];
  html += section('', 'Usuarios expuestos', users.length, users.length>0?'count-orange':'count-green',
    users.length === 0
      ? `<div class="no-results"><div class="nr-icon ic-ok"></div><p>No se pudieron enumerar usuarios</p></div>`
      : `<div style="margin-top:12px">
          <p style="font-size:11px;color:var(--yellow);margin-bottom:10px">Facilitan ataques de fuerza bruta contra /wp-login.php</p>
          ${users.map(u => {
            if (typeof u !== 'object') return '';
            return `<div class="list-item">
              <span style="color:var(--orange);font-size:18px"></span>
              <div>
                <div style="font-weight:700">${u.login||u.display_name||'?'}</div>
                <div style="font-size:10px;color:var(--text3)">ID: ${u.id} · ${u.source}${u.display_name?' · '+u.display_name:''}</div>
              </div>
              <span style="margin-left:auto;font-size:10px;color:var(--orange);border:1px solid;border-radius:3px;padding:1px 6px">EXPUESTO</span>
            </div>`;
          }).join('')}
        </div>`, users.length > 0);
  const malware = r.malware_indicators || [];
  html += section('', 'Malware / SEO Spam', malware.length, malware.length>0?'count-red':'count-green',
    malware.length === 0
      ? `<div class="no-results"><div class="nr-icon ic-ok"></div><p>No se detectaron indicadores de malware o SEO spam</p></div>`
      : `<div style="margin-top:12px">${malware.map(m => `
          <div class="list-item">
            <span style="color:var(--red);font-size:18px">☣</span>
            <span style="font-size:12px">${m}</span>
          </div>`).join('')}</div>`, malware.length > 0);
  const hIssues = r.headers_issues || [];
  const hOk     = r.headers_ok || [];
  html += section('', 'Cabeceras de seguridad HTTP', `${hIssues.length} faltan`, hIssues.length>3?'count-yellow':'count-green',
    `<div style="margin-top:12px">
      ${hIssues.map(h => {
        const [name,...rest] = h.split(' — ');
        return `<div class="hdr-item">
          <span class="hdr-icon" style="color:var(--red)">✗</span>
          <div><div class="hdr-name">${name}</div><div class="hdr-detail">${rest.join(' — ')}</div></div>
        </div>`;
      }).join('')}
      ${hOk.map(h => {
        const [name,...rest] = h.split(': ');
        return `<div class="hdr-item">
          <span class="hdr-icon" style="color:var(--green2)">✓</span>
          <div><div class="hdr-name">${name}</div><div class="hdr-detail">${rest.join(': ')}</div></div>
        </div>`;
      }).join('')}
    </div>`);
  const allErrors = r.errors || [];
  const infoMessages = allErrors.filter(e => e.startsWith('ℹ'));
  const warnings = allErrors.filter(e => e.startsWith('⚠'));
  const technicalErrors = allErrors.filter(e => !e.startsWith('ℹ') && !e.startsWith('⚠'));
  
  if (infoMessages.length > 0 || warnings.length > 0 || technicalErrors.length > 0) {
    let notesHtml = '';
    
    if (infoMessages.length > 0) {
      notesHtml += `<div style="margin-bottom:12px">
        <div style="font-size:11px;color:var(--cyan);font-weight:700;margin-bottom:6px">ℹ️ INFORMATIVOS (${infoMessages.length})</div>
        ${infoMessages.map(e => {
          const msg = e.replace(/^ℹ\s*/, '').trim();
          return `<div class="list-item"><span style="color:var(--cyan)">ℹ</span><span style="font-size:11px;color:var(--text2)">${msg}</span></div>`;
        }).join('')}
      </div>`;
    }
    
    if (warnings.length > 0) {
      notesHtml += `<div style="margin-bottom:12px">
        <div style="font-size:11px;color:var(--orange);font-weight:700;margin-bottom:6px">⚠️ ADVERTENCIAS (${warnings.length})</div>
        ${warnings.map(e => {
          const msg = e.replace(/^⚠\s*/, '').trim();
          return `<div class="list-item"><span style="color:var(--orange)">⚠</span><span style="font-size:11px;color:var(--text2)">${msg}</span></div>`;
        }).join('')}
      </div>`;
    }
    
    if (technicalErrors.length > 0) {
      notesHtml += `<div>
        <div style="font-size:11px;color:var(--red);font-weight:700;margin-bottom:6px">❌ ERRORES TÉCNICOS (${technicalErrors.length})</div>
        ${technicalErrors.map(e => {
          const msg = e.trim();
          return `<div class="list-item"><span style="color:var(--red)">❌</span><span style="font-size:11px;color:var(--text2)">${msg}</span></div>`;
        }).join('')}
      </div>`;
    }
    
    const totalCount = infoMessages.length + warnings.length + technicalErrors.length;
    const sectionIcon = technicalErrors.length > 0 ? '❌' : (warnings.length > 0 ? '⚠' : 'ℹ');
    const sectionColor = technicalErrors.length > 0 ? 'count-red' : (warnings.length > 0 ? 'count-orange' : 'count-grey');
    
    html += section(sectionIcon, 'Registro del escaneo', totalCount, sectionColor,
      `<div style="margin-top:12px">${notesHtml}</div>`);
  }
  const rep = r.reputation;
  if (rep) {
    const repColor = {clean:'var(--green2)', suspicious:'var(--yellow)', malicious:'var(--red)'}[rep.risk_level] || 'var(--text2)';
    const repIcon  = {clean:'✅', suspicious:'REVISAR', malicious:'PELIGRO'}[rep.risk_level] || 'ℹ';
    let repHtml = `<div class="wp-grid" style="margin-bottom:12px">
      <div class="wp-item"><div class="wi-label">Dominio</div><div class="wi-value">${rep.domain||'—'}</div></div>
      <div class="wp-item"><div class="wi-label">IP</div><div class="wi-value">${rep.ip||'—'}</div></div>
      <div class="wp-item"><div class="wi-label">Nivel de riesgo</div>
        <div class="wi-value" style="color:${repColor}">${repIcon} ${(rep.risk_level||'').toUpperCase()}</div></div>
      <div class="wp-item"><div class="wi-label">Fuentes verificadas</div>
        <div class="wi-value" style="color:var(--text2)">${(rep.sources_checked||[]).join(', ')||'—'}</div></div>
      ${rep.virustotal_score?`<div class="wp-item"><div class="wi-label">VirusTotal</div>
        <div class="wi-value ${parseInt(rep.virustotal_score, 10)>0?'wi-bad':'wi-ok'}">${rep.virustotal_score} motores</div></div>`:''}
      ${rep.abuseipdb_score!=null?`<div class="wp-item"><div class="wi-label">AbuseIPDB Score</div>
        <div class="wi-value ${rep.abuseipdb_score>=25?'wi-bad':'wi-ok'}">${rep.abuseipdb_score}/100</div></div>`:''}
      ${rep.urlhaus_status?`<div class="wp-item"><div class="wi-label">URLhaus</div>
        <div class="wi-value ${rep.urlhaus_status==='online'||rep.urlhaus_status==='offline'?'wi-bad':'wi-ok'}">${rep.urlhaus_status}</div></div>`:''}
    </div>`;
    if ((rep.threats||[]).length > 0) {
      repHtml += `<div style="margin-top:8px"><strong style="color:var(--red)">Amenazas detectadas:</strong>
        ${rep.threats.map(t=>`<div class="list-item"><span style="color:var(--red)">⚠</span><span>${t}</span></div>`).join('')}
      </div>`;
    }
    const repCount = rep.clean ? 0 : (rep.sources_flagged||[]).length;
    html += section('', 'Reputación del dominio', repCount||'OK', repCount>0?'count-red':'count-green', repHtml, repCount>0);
  }
  const subs = r.subdomains || [];
  if (subs.length > 0) {
    const aliveSubs = subs.filter(s => s.alive);
    const wpSubs    = subs.filter(s => s.is_wordpress);
    let subHtml = `<div style="margin-bottom:8px;color:var(--text2);font-size:11px">
      ${subs.length} subdominios encontrados · ${aliveSubs.length} activos · ${wpSubs.length} con WordPress</div>`;
    subHtml += `<div class="comp-grid">` + subs.map(s => `
      <div class="comp-card" style="${!s.alive?'opacity:.5':''}">
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px">
          <span style="font-size:11px;color:var(--cyan);font-weight:700">${s.subdomain}</span>
          <span style="font-size:10px;color:${s.alive?(s.is_wordpress?'var(--green2)':'var(--text2)'):'var(--text3)'}">
            ${s.alive ? (s.is_wordpress ? 'WordPress' : '✓ Activo') : '○ Inactivo'}
          </span>
        </div>
        <div style="font-size:10px;color:var(--text3)">
          ${s.ip||'—'} · ${s.status_code?'HTTP '+s.status_code:''} · ${s.server||'servidor oculto'}
        </div>
      </div>
    `).join('') + `</div>`;
    html += section('', `Subdominios (${subs.length})`, aliveSubs.length, aliveSubs.length>0?'count-grey':'count-green', subHtml, aliveSubs.length>0);
  }
  const jsThreats = r.js_threats || [];
  const stack = r.server_stack || {};
  const cookieIssues = r.cookie_issues || [];

  if (jsThreats.length > 0 || Object.keys(stack).length > 0 || cookieIssues.length > 0) {
    let stackHtml = '';

    if (Object.keys(stack).length > 0) {
      stackHtml += `<div class="wp-grid" style="margin-bottom:12px">
        ${stack.web_server?`<div class="wp-item"><div class="wi-label">Servidor web</div>
          <div class="wi-value wi-warn">${stack.web_server}${stack.web_server_version?' v'+stack.web_server_version:''}</div></div>`:''}
        ${stack.php_version?`<div class="wp-item"><div class="wi-label">PHP</div>
          <div class="wi-value ${stack.php_vulnerable?'wi-bad':'wi-warn'}">PHP ${stack.php_version}${stack.php_eol?' ('+stack.php_eol+')':''}</div></div>`:''}
        ${stack.cdn?`<div class="wp-item"><div class="wi-label">CDN</div>
          <div class="wi-value wi-ok">${stack.cdn}</div></div>`:''}
        ${stack.os_hint?`<div class="wp-item"><div class="wi-label">Sistema operativo</div>
          <div class="wi-value wi-warn">${stack.os_hint}</div></div>`:''}
        ${(stack.info_leaks||[]).length>0?`<div class="wp-item"><div class="wi-label">Info expuesta</div>
          <div class="wi-value wi-warn">${stack.info_leaks.join('<br>')}</div></div>`:''}
      </div>`;
    }

    if (jsThreats.length > 0) {
      stackHtml += `<div style="margin-top:8px"><strong style="color:var(--red)">Scripts JS externos sospechosos:</strong>
        ${jsThreats.map(t=>`<div class="list-item"><span style="color:var(--orange)">⚠</span><span style="font-size:11px">${t}</span></div>`).join('')}
      </div>`;
    }

    if (cookieIssues.length > 0) {
      stackHtml += `<div style="margin-top:8px"><strong style="color:var(--yellow)">Problemas en cookies:</strong>
        ${cookieIssues.map(c=>`<div class="list-item"><span style="color:var(--yellow)">⚠</span><span style="font-size:11px">${c}</span></div>`).join('')}
      </div>`;
    }

    const issues11 = jsThreats.length + cookieIssues.length + (stack.php_vulnerable?1:0);
    html += section('', 'Stack tecnológico y JS', issues11||'', issues11>0?'count-orange':'count-grey', stackHtml, issues11>0);
  }
  const csp   = r.csp_analysis  || {};
  const hsts  = r.hsts_analysis || {};
  if (Object.keys(csp).length > 0 || Object.keys(hsts).length > 0) {
    let deepHtml = `<div class="wp-grid" style="margin-bottom:12px">`;
    if (csp.present != null) {
      const cspScore = csp.score != null ? csp.score : 0;
      const cspColor = cspScore>=80?'var(--green2)':cspScore>=50?'var(--yellow)':'var(--red)';
      deepHtml += `<div class="wp-item"><div class="wi-label">CSP Score</div>
        <div class="wi-value" style="color:${cspColor}">${csp.present?cspScore+'/100':'Ausente'}</div></div>`;
      if ((csp.issues||[]).length > 0) {
        deepHtml += `<div class="wp-item" style="grid-column:span 2"><div class="wi-label">Problemas CSP</div>
          <div class="wi-value">${csp.issues.map(i=>`<div style="color:var(--orange);font-size:11px">${i}</div>`).join('')}</div></div>`;
      }
    }
    if (hsts.present != null) {
      const hstsColor = hsts.max_age_ok?'var(--green2)':'var(--orange)';
      deepHtml += `<div class="wp-item"><div class="wi-label">HSTS</div>
        <div class="wi-value" style="color:${hstsColor}">
          ${hsts.present?'✓ Configurado':'Ausente'}
          ${hsts.max_age?` (${Math.round(hsts.max_age/86400)}d)`:''}
          ${hsts.include_subdomains?' + subdomains':''}
        </div></div>`;
      if ((hsts.issues||[]).length > 0) {
        deepHtml += `<div class="wp-item"><div class="wi-label">Problemas HSTS</div>
          <div class="wi-value">${hsts.issues.map(i=>`<div style="color:var(--yellow);font-size:11px">${i}</div>`).join('')}</div></div>`;
      }
    }
    deepHtml += '</div>';
    const deepIssues = (csp.issues||[]).length + (hsts.issues||[]).length;
    html += section('', 'Análisis profundo CSP/HSTS', deepIssues||'', deepIssues>0?'count-yellow':'count-green', deepHtml, deepIssues>0);
  }

  return html;
}
function showProgress() {
  _el('progressSection').style.display = 'block';
  _el('resultsSection').style.display  = 'none';
  _el('scanSection').style.display     = 'none';
  _startScanRuntimeTicker();
}

function hideProgress() {
  _stopScanRuntimeTicker();
  _el('progressSection').style.display = 'none';
  _el('scanSection').style.display     = 'block';
  _scanStartLocked = false;
  resetBtn();
}

function showCacheBadge(url) {
  const meta = document.getElementById('resultsMeta');
  if (meta && !document.getElementById('cacheBadge')) {
    const badge = document.createElement('span');
    badge.id = 'cacheBadge';
    badge.style.cssText = 'display:inline-flex;align-items:center;gap:5px;font-size:10px;'
      + 'background:rgba(0,200,192,.1);color:var(--teal);border:1px solid rgba(0,200,192,.25);'
      + 'border-radius:4px;padding:2px 8px;font-family:var(--mono);cursor:pointer;margin-left:8px';
    badge.title = 'Resultado de caché (< 1h). Haz clic para forzar re-scan.';
    badge.innerHTML = '⚡ caché';
    badge.onclick = () => rescanTarget();
    meta.appendChild(badge);
  }
}

function showError(msg) {
  _stopScanRuntimeTicker();
  const el = _el('errorState');
  el.classList.add('show');
  _el('errorMsg').textContent = msg;
  _el('scanSection').style.display    = 'block';
  _el('progressSection').style.display = 'none';
  _scanStartLocked = false;
}

function clearError() { _el('errorState').classList.remove('show'); }

function flashInput(msg) {
  const wrap = document.getElementById('urlWrap');
  wrap.style.borderColor = 'var(--red)';
  const input = document.getElementById('urlInput');
  const orig  = input.placeholder;
  input.placeholder = msg || 'URL requerida';
  setTimeout(() => { wrap.style.borderColor = ''; input.placeholder = orig; }, 2000);
  input.focus();
}

function resetBtn() {
  const btn = document.getElementById('scanBtn');
  btn.disabled = false;
  document.getElementById('btnText').textContent = 'ESCANEAR';
  document.getElementById('btnIcon').textContent = '▶';
}

function newScan() {
  _stopScanRuntimeTicker(true);
  _el('resultsSection').style.display  = 'none';
  _el('progressSection').style.display = 'none';
  _el('scanSection').style.display     = 'block';
  currentResult = null; currentJobId = null;
  _scanStartLocked = false;
  renderTab._cache = null;
  _aiPlanCache = null; _aiPlanJobId = null;
  _chatHistory = []; _chatJobId = null; _chatSystemCtx = null; _chatLoadedFor = null;
  window.scrollTo({top:0, behavior:'smooth'});
  resetBtn();
  document.getElementById('urlInput')?.focus();
  loadHistory(true);
}
function tabKeyNav(e) {
  const tabs = Array.from(document.querySelectorAll('[role="tab"]'));
  const idx  = tabs.indexOf(e.target);
  let next = -1;
  if      (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
  else if (e.key === 'ArrowLeft')  next = (idx - 1 + tabs.length) % tabs.length;
  else if (e.key === 'Home')       next = 0;
  else if (e.key === 'End')        next = tabs.length - 1;
  else return;
  e.preventDefault();
  tabs[next].focus();
  tabs[next].click();
}

function _menuItems(menu) {
  if (!menu) return [];
  return Array.from(menu.querySelectorAll('[role="menuitem"]')).filter(el => !el.disabled && el.offsetParent !== null);
}

function _trapFocusIn(container, e) {
  if (!container || e.key !== 'Tab') return;
  const focusables = Array.from(container.querySelectorAll(
    'button,[href],input,select,textarea,[tabindex]:not([tabindex="-1"])'
  )).filter(el => !el.disabled && el.offsetParent !== null);
  if (!focusables.length) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  if (e.shiftKey && document.activeElement === first) {
    e.preventDefault();
    last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault();
    first.focus();
  }
}

document.addEventListener('click', function(e) {
  const menu = document.getElementById('exportMenu');
  const btn  = document.getElementById('exportDropBtn');
  if (!menu || !btn) return;
  const clickedOnBtn = btn.contains(e.target) || btn === e.target;
  const clickedOnMenu = menu.contains(e.target) || menu === e.target;
  if (!clickedOnBtn && !clickedOnMenu) {
    closeExportMenu();
  }
});
document.addEventListener('keydown', function(e) { if (e.key === 'Escape') closeExportMenu(); });
function exportJSON() {
  if (!currentResult) { 
    showToast('⚠️ Completa un escaneo primero', 'warn'); 
    return; 
  }
  try {
    const json = JSON.stringify(currentResult, null, 2);
    const blob = new Blob([json], {type:'application/json'});
    const url  = URL.createObjectURL(blob);
    const domain = (currentResult.target_url||'').replace(/https?:\/\//, '').split('/')[0];
    const filename = `wpvuln-${domain||currentJobId||'report'}.json`;
    console.log('[Export] Exportando JSON:', filename);
    _triggerDownload(url, filename);
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  } catch (err) {
    console.error('[Export] Error en exportJSON:', err);
    showToast('❌ Error al exportar JSON', 'err');
  }
}

function copyJSON() {
  if (!currentResult) { showToast('Primero realiza un escaneo', 'warn'); return; }
  navigator.clipboard.writeText(JSON.stringify(currentResult, null, 2))
    .then(() => showToast('JSON copiado al portapapeles', 'ok'))
    .catch(() => showToast('Error al copiar — usa Exportar JSON', 'err'));
}
function downloadHTMLReport() {
  if (!currentJobId) { 
    showToast('⚠️ Completa un escaneo primero', 'warn'); 
    return; 
  }
  console.log('[Export] Iniciando descarga HTML:', `/scan/${currentJobId}/html`);
  _triggerDownload(`/scan/${currentJobId}/html`);
}
function exportHTML() { downloadHTMLReport(); }
async function rescanTarget() {
  if (!currentJobId && !currentResult) return;
  const url = currentResult?.target_url;
  if (!url) return;
  const btn = document.getElementById('btnRescan');
  if (btn) { btn.textContent = 'Iniciando...'; btn.disabled = true; }
  try {
    const res  = await apiFetch('/api/rescan', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({ job_id: currentJobId, url, legal_accepted: true }),
    });
    const data = await res.json();
    if (data.error) { showToast('Error: ' + data.error, 'err'); return; }
    currentJobId = data.job_id;
    scanStart = Date.now();
    _scanLastProgressPct = 0;
    _scanLastEventAt = Date.now();
    _el('resultsSection').style.display = 'none';
    _el('progressSection').style.display = 'block';
    _el('termBody').innerHTML = '<span class="t-cursor"></span>';
    _el('progFill').style.width = '0%';
    _startScanRuntimeTicker();
    startStream(data.job_id);
  } catch(e) {
    showToast('Error de conexión: ' + e.message, 'err');
  } finally {
    if (btn) { btn.textContent = 'Re-scan'; btn.disabled = false; }
  }
}
let termFullscreen = false;
function toggleTermFullscreen() {
  const wrap = document.getElementById('terminalWrap');
  const btn  = document.getElementById('termFullBtn');
  termFullscreen = !termFullscreen;
  wrap.classList.toggle('fullscreen', termFullscreen);
  btn.textContent = termFullscreen ? '✕' : '⛶';
  btn.title = termFullscreen ? 'Salir de pantalla completa' : 'Pantalla completa';
  if (termFullscreen) {
    document.addEventListener('keydown', _termEsc);
  } else {
    document.removeEventListener('keydown', _termEsc);
  }
}
function _termEsc(e) { if (e.key === 'Escape') toggleTermFullscreen(); }
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    const m = document.getElementById('cveModal');
    if (m && m.style.display !== 'none') closeCVEModal();
  }
});
let currentTab = 'surface';

function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab-btn').forEach(b => {
    const isActive = b.dataset.tab === tab;
    b.classList.toggle('active', isActive);
    b.setAttribute('aria-selected', isActive ? 'true' : 'false');
    b.setAttribute('tabindex', isActive ? '0' : '-1');
  });
  const tools = document.getElementById('tabVulnsTools');
  if (tools) tools.style.display = tab === 'vulns' ? 'flex' : 'none';

  if (tab === 'vulns' && currentResult) {
    _vulnRaw = currentResult.vulnerabilities || [];
    _vulnPage = 0;
    _vulnFiltered = _vulnRaw;
    _populateComponentFilter(_vulnRaw);
    filterVulns();
  } else {
    const pag = document.getElementById('vulnPagination');
    if (pag) pag.style.display = 'none';
    renderTab(tab, currentResult);
  }
}

function renderTab(tab, r) {
  if (!r) return;
  const el = _el('tabContent');
  if (!el) return;
  el.className = 'tab-content';
  const _cacheKey = `${tab}::${r.scan_id || r.target_url || ''}`;
  if (renderTab._cache && renderTab._cache.key === _cacheKey && tab !== 'vulns') {
    el.innerHTML = renderTab._cache.html;
    return;
  }

  let html = '';
  switch (tab) {
    case 'vulns':     el.innerHTML = buildVulnsTab(r); return;  // vulns usa paginación propia
    case 'surface':   html = buildSurfaceTab(r);   break;
    case 'info':      html = buildInfoTab(r);      break;
    case 'comps':     html = buildCompsTab(r);     break;
    case 'files':     html = buildFilesTab(r);     break;
    case 'technical': html = buildInfoTab(r);      break;
    case 'action':    html = buildActionTab(r);    break;
    case 'deepscan':  html = buildDeepScanTab(r);  break;
    case 'compliance':  html = buildComplianceTab(r);  break;
    case 'aiplan':      buildAIPlanTab(r, el); return;
    case 'aichat':      buildChatTab(r, el); return;
    case 'recon':      html = buildReconTab(r); break;
  }
  el.innerHTML = html;
  if (html.length < 500000) {
    renderTab._cache = { key: _cacheKey, html };
  }
}

function _surfaceHost(rawUrl) {
  try {
    return new URL(String(rawUrl || '').startsWith('http') ? rawUrl : `https://${rawUrl}`).hostname;
  } catch (_) {
    return String(rawUrl || '').replace(/^https?:\/\//i, '').split('/')[0];
  }
}

function _surfaceClamp(n, min = 0, max = 100) {
  const v = Number(n);
  if (!Number.isFinite(v)) return min;
  return Math.max(min, Math.min(max, v));
}

function _surfaceRiskPill(score) {
  const s = _surfaceClamp(score);
  if (s >= 70) return { tone: 'ROJO', label: 'Alto', color: 'var(--red)', bg: 'rgba(229,72,77,.14)' };
  if (s >= 40) return { tone: 'AMBAR', label: 'Medio', color: 'var(--amber)', bg: 'rgba(245,163,26,.14)' };
  return { tone: 'VERDE', label: 'Controlado', color: 'var(--green2)', bg: 'rgba(46,213,115,.14)' };
}

const _surfaceHeaderImpactHints = {
  'Content-Security-Policy': 'Sin CSP aumenta el riesgo de XSS y carga de scripts maliciosos.',
  'Strict-Transport-Security': 'Sin HSTS se facilita downgrade a HTTP y secuestro de sesion.',
  'X-Frame-Options': 'Sin esta cabecera es mas facil ejecutar clickjacking.',
  'X-Content-Type-Options': 'Sin nosniff el navegador puede interpretar tipos peligrosos.',
  'Referrer-Policy': 'Sin politica de referrer se filtra informacion sensible en enlaces salientes.',
  'Permissions-Policy': 'Sin restricciones se amplian capacidades del navegador para terceros.',
  'Cross-Origin-Opener-Policy': 'Sin COOP aumenta el riesgo de aislamiento insuficiente entre ventanas.',
  'Cross-Origin-Resource-Policy': 'Sin CORP se facilita uso no autorizado de recursos cross-origin.',
};

function _normalizeHeaderName(name) {
  const raw = String(name || '').trim();
  const low = raw.toLowerCase();
  if (low.includes('content-security-policy') || low.includes('csp')) return 'Content-Security-Policy';
  if (low.includes('strict-transport-security') || low.includes('hsts')) return 'Strict-Transport-Security';
  if (low.includes('x-frame-options')) return 'X-Frame-Options';
  if (low.includes('x-content-type-options')) return 'X-Content-Type-Options';
  if (low.includes('referrer-policy')) return 'Referrer-Policy';
  if (low.includes('permissions-policy')) return 'Permissions-Policy';
  if (low.includes('cross-origin-opener-policy')) return 'Cross-Origin-Opener-Policy';
  if (low.includes('cross-origin-resource-policy')) return 'Cross-Origin-Resource-Policy';
  if (low.includes('x-xss-protection')) return 'X-XSS-Protection';
  return raw || 'Header no identificado';
}

function _headerRiskWeight(headerName) {
  const weights = {
    'Content-Security-Policy': 22,
    'Strict-Transport-Security': 18,
    'X-Frame-Options': 12,
    'X-Content-Type-Options': 10,
    'Referrer-Policy': 8,
    'Permissions-Policy': 8,
    'Cross-Origin-Opener-Policy': 7,
    'Cross-Origin-Resource-Policy': 7,
    'X-XSS-Protection': 4,
  };
  return weights[headerName] || 6;
}

function _buildSurfaceHeaderGrade(r) {
  const rawIssues = Array.isArray(r.headers_issues) ? r.headers_issues : [];
  const rawOk = Array.isArray(r.headers_ok) ? r.headers_ok : [];

  const parsedIssues = rawIssues.map(issue => {
    const parts = String(issue).split(' — ');
    const head = _normalizeHeaderName(parts[0] || issue);
    return {
      name: head,
      detail: parts.slice(1).join(' — ') || '',
      impact: _surfaceHeaderImpactHints[head] || 'Aumenta la superficie de ataque del navegador cliente.',
    };
  });

  const uniqueMissing = Array.from(new Map(parsedIssues.map(i => [i.name, i])).values());
  let score = 100;
  uniqueMissing.forEach(i => { score -= _headerRiskWeight(i.name); });

  const csp = r.csp_analysis || {};
  const hsts = r.hsts_analysis || {};
  if (csp.unsafe_inline) score -= 8;
  if (csp.unsafe_eval) score -= 8;
  if (hsts.present && !hsts.max_age_ok) score -= 6;

  const cookieIssues = Array.isArray(r.cookie_issues) ? r.cookie_issues.length : 0;
  score -= Math.min(12, cookieIssues * 3);
  score = _surfaceClamp(Math.round(score));

  const grade = score >= 90 ? 'A' : score >= 75 ? 'B' : score >= 60 ? 'C' : score >= 40 ? 'D' : 'E';

  return {
    score,
    grade,
    issues: uniqueMissing,
    okCount: rawOk.length,
    missingCount: uniqueMissing.length,
  };
}

function _buildSurfaceAreas(r, headerGrade) {
  const s = r.summary || {};
  const recon = r.recon || {};
  const shodan = recon.shodan || {};
  const ssl = r.ssl_info || {};
  const rep = r.reputation || {};

  const nmapPorts = Array.isArray(recon.nmap && recon.nmap.ports) ? recon.nmap.ports.length : 0;
  const shodanPorts = Array.isArray(shodan.ports) ? shodan.ports.length : 0;
  const shodanVulns = Array.isArray(shodan.vulns) ? shodan.vulns.length : 0;
  const criticalFiles = (r.exposed_files || []).filter(f => f && typeof f === 'object' && f.severity === 'critical').length;
  const exposedFiles = (r.exposed_files || []).length;
  const users = (r.users || []).length;
  const activeSubs = (r.subdomains || []).filter(sd => sd && sd.alive).length;

  const areas = {
    infraestructura: { key: 'infraestructura', title: 'Infraestructura', icon: '🌐', score: 0, reasons: [] },
    aplicacion: { key: 'aplicacion', title: 'Aplicacion', icon: '🧩', score: 0, reasons: [] },
    configuracion: { key: 'configuracion', title: 'Configuracion', icon: '⚙️', score: 0, reasons: [] },
    exposicion: { key: 'exposicion', title: 'Exposicion Externa', icon: '📡', score: 0, reasons: [] },
  };

  if (nmapPorts > 0) {
    areas.infraestructura.score += nmapPorts > 8 ? 28 : nmapPorts > 3 ? 18 : 10;
    areas.infraestructura.reasons.push(`${nmapPorts} puerto(s) abierto(s) en reconocimiento activo.`);
  }
  if (shodanPorts > 0) {
    areas.infraestructura.score += Math.min(16, shodanPorts * 2);
    areas.infraestructura.reasons.push(`${shodanPorts} puerto(s) visibles desde Shodan.`);
  }
  if (shodanVulns > 0) {
    areas.infraestructura.score += Math.min(40, 20 + shodanVulns * 4);
    areas.infraestructura.reasons.push(`${shodanVulns} CVE asociadas a servicios expuestos.`);
  }
  if (ssl.expired || (ssl.valid === false && !ssl.error)) {
    areas.infraestructura.score += 20;
    areas.infraestructura.reasons.push('TLS con problemas de validez o certificado expirado.');
  }
  if (!(r.waf_detected || []).length) {
    areas.infraestructura.score += 10;
    areas.infraestructura.reasons.push('No se detecta WAF/CDN perimetral.');
  }

  areas.aplicacion.score += Math.min(50, Number(s.critical_vulns || 0) * 22 + Number(s.high_vulns || 0) * 8 + Number(s.medium_vulns || 0) * 3);
  if (Number(s.critical_vulns || 0) > 0) {
    areas.aplicacion.reasons.push(`${s.critical_vulns} vulnerabilidad(es) critica(s) en componentes WordPress.`);
  }
  if (Number(s.high_vulns || 0) > 0) {
    areas.aplicacion.reasons.push(`${s.high_vulns} vulnerabilidad(es) alta(s) pendientes de corregir.`);
  }
  if (r.wp_outdated) {
    areas.aplicacion.score += 12;
    areas.aplicacion.reasons.push(`WordPress desactualizado (${r.wp_version || '?'}) frente a ${r.wp_latest_version || 'ultima version'}.`);
  }
  if (Number(s.outdated_plugins || 0) > 0 || Number(s.outdated_themes || 0) > 0) {
    const stale = Number(s.outdated_plugins || 0) + Number(s.outdated_themes || 0);
    areas.aplicacion.score += Math.min(20, stale * 3);
    areas.aplicacion.reasons.push(`${stale} componente(s) con version desactualizada.`);
  }

  areas.configuracion.score += _surfaceClamp(100 - headerGrade.score, 0, 65);
  if (headerGrade.missingCount > 0) {
    areas.configuracion.reasons.push(`${headerGrade.missingCount} cabecera(s) HTTP de seguridad ausente(s).`);
  }
  if (r.debug_mode && r.debug_mode.debug_active) {
    areas.configuracion.score += 18;
    areas.configuracion.reasons.push('WP_DEBUG activo en produccion.');
  }
  if (r.cors_issues && r.cors_issues.vulnerable) {
    areas.configuracion.score += 16;
    areas.configuracion.reasons.push(`CORS vulnerable (${(r.cors_issues.findings || []).length} hallazgo(s)).`);
  }
  if (r.tls_analysis && r.tls_analysis.deprecated_protocol) {
    areas.configuracion.score += 12;
    areas.configuracion.reasons.push('Protocolos TLS deprecados detectados.');
  }

  areas.exposicion.score += Math.min(50, criticalFiles * 20 + Math.max(0, exposedFiles - criticalFiles) * 6);
  if (criticalFiles > 0) {
    areas.exposicion.reasons.push(`${criticalFiles} archivo(s) critico(s) expuesto(s) publicamente.`);
  } else if (exposedFiles > 0) {
    areas.exposicion.reasons.push(`${exposedFiles} archivo(s) expuesto(s) con informacion sensible.`);
  }
  if (users > 0) {
    areas.exposicion.score += Math.min(20, users * 4);
    areas.exposicion.reasons.push(`${users} usuario(s) enumerable(s) para ataques de credenciales.`);
  }
  if (r.xmlrpc_enabled) {
    areas.exposicion.score += 10;
    areas.exposicion.reasons.push('XML-RPC habilitado y accesible.');
  }
  if (r.login_exposed || (r.custom_login && r.custom_login.original_accessible)) {
    areas.exposicion.score += 8;
    areas.exposicion.reasons.push('Endpoint de login principal accesible para fuerza bruta.');
  }
  if (activeSubs > 3) {
    areas.exposicion.score += 8;
    areas.exposicion.reasons.push(`${activeSubs} subdominios activos amplian la superficie de ataque.`);
  }
  if (rep.risk_level === 'malicious' || rep.blacklisted) {
    areas.exposicion.score += 20;
    areas.exposicion.reasons.push('Reputacion externa negativa o presencia en listas de bloqueo.');
  } else if (rep.risk_level === 'suspicious') {
    areas.exposicion.score += 10;
    areas.exposicion.reasons.push('Reputacion sospechosa en fuentes de inteligencia.');
  }

  Object.values(areas).forEach(area => {
    area.score = _surfaceClamp(Math.round(area.score));
    if (!area.reasons.length) area.reasons.push('Sin señales criticas destacables en este bloque.');
  });

  return areas;
}

function _surfaceAreaCard(area) {
  const sem = _surfaceRiskPill(area.score);
  const reasons = (area.reasons || []).slice(0, 2).map(msg => `<li style="color:var(--text-2);font-size:11px;line-height:1.45">${_esc(msg)}</li>`).join('');
  return `
    <div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
      <div style="display:flex;align-items:center;gap:8px;justify-content:space-between;margin-bottom:8px">
        <div style="display:flex;align-items:center;gap:8px">
          <span style="font-size:16px">${area.icon}</span>
          <strong style="font-size:12px;color:var(--text)">${_esc(area.title)}</strong>
        </div>
        <span style="font-size:10px;font-weight:700;letter-spacing:.6px;padding:3px 7px;border-radius:999px;color:${sem.color};background:${sem.bg};border:1px solid ${sem.color}">${sem.tone}</span>
      </div>
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">
        <span style="font-family:var(--head);font-size:18px;font-weight:800;color:${sem.color}">${area.score}</span>
        <span style="font-size:11px;color:var(--text-3)">riesgo ${_esc(sem.label.toLowerCase())}</span>
      </div>
      <div style="height:6px;border-radius:999px;background:var(--bg-2);overflow:hidden;margin-bottom:8px">
        <div style="height:100%;width:${area.score}%;background:${sem.color};transition:width .4s ease"></div>
      </div>
      <div style="font-size:10px;color:var(--text-3);font-family:var(--head);letter-spacing:.7px;text-transform:uppercase;margin-bottom:6px">Qué mirar primero</div>
      <ul style="margin:0;padding-left:16px;display:grid;gap:4px">${reasons}</ul>
    </div>`;
}

function _surfaceSubdomainGraph(r) {
  const rootHost = _surfaceHost(r.target_url || r.url || 'objetivo.local') || 'objetivo.local';
  let nodes = [];

  if (Array.isArray(r.subdomains) && r.subdomains.length) {
    nodes = r.subdomains.map(sd => {
      if (typeof sd === 'string') return { host: sd, alive: null, isWordPress: false };
      return {
        host: sd.subdomain || sd.host || '',
        alive: typeof sd.alive === 'boolean' ? sd.alive : null,
        isWordPress: !!sd.is_wordpress,
      };
    });
  }

  const crt = r.recon && r.recon.crtsh;
  if (!nodes.length && crt && Array.isArray(crt.subdomains) && crt.subdomains.length) {
    nodes = crt.subdomains.map(sd => ({ host: String(sd), alive: null, isWordPress: false }));
  }

  const uniq = Array.from(new Map(
    nodes
      .filter(n => n && n.host)
      .map(n => [String(n.host).toLowerCase(), n])
  ).values());

  if (!uniq.length) {
    return `<div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">Mapa de subdominios</div>
      <div style="font-size:12px;color:var(--text-2)">No se detectaron subdominios en este escaneo.</div>
    </div>`;
  }

  const shown = uniq.slice(0, 14);
  const hidden = Math.max(0, uniq.length - shown.length);
  const width = 760;
  const height = 300;
  const cx = width / 2;
  const cy = height / 2;
  const radius = 105;

  let edgeSvg = '';
  let nodeSvg = '';
  let labelSvg = '';

  shown.forEach((n, idx) => {
    const angle = (Math.PI * 2 * idx) / Math.max(1, shown.length) - Math.PI / 2;
    const x = cx + radius * Math.cos(angle);
    const y = cy + radius * Math.sin(angle);
    const color = n.alive === false ? '#6e7681' : (n.isWordPress ? '#2ed573' : '#00c8be');
    const rootPattern = new RegExp(`\\.?${rootHost.replace(/\./g, '\\.')}$`, 'i');
    const shortLabel = String(n.host).replace(rootPattern, '') || n.host;
    const label = shortLabel.length > 16 ? `${shortLabel.slice(0, 16)}...` : shortLabel;

    edgeSvg += `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" stroke="rgba(139,148,158,.25)" stroke-width="1" />`;
    nodeSvg += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="8" fill="${color}" fill-opacity="0.95" stroke="rgba(255,255,255,.08)"/>`;
    labelSvg += `<text x="${x.toFixed(1)}" y="${(y + 18).toFixed(1)}" text-anchor="middle" fill="#8b949e" style="font-size:10px;font-family:var(--mono)">${_esc(label)}</text>`;
  });

  return `<div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3)">Mapa de subdominios</div>
      <div style="font-size:11px;color:var(--text-2)">${shown.length} nodo(s)${hidden > 0 ? ` · +${hidden} ocultos` : ''}</div>
    </div>
    <svg viewBox="0 0 ${width} ${height}" style="width:100%;height:auto;border-radius:6px;background:linear-gradient(180deg,rgba(15,20,29,.7),rgba(15,20,29,.35));border:1px solid var(--border)">
      ${edgeSvg}
      <circle cx="${cx}" cy="${cy}" r="20" fill="rgba(43,127,255,.2)" stroke="#2b7fff" stroke-width="1.2"/>
      <text x="${cx}" y="${cy + 4}" text-anchor="middle" fill="#2b7fff" style="font-size:11px;font-family:var(--head);font-weight:700">ROOT</text>
      ${nodeSvg}
      ${labelSvg}
    </svg>
    <div style="margin-top:8px;font-size:10px;color:var(--text-3)">Dominio base: ${_esc(rootHost)} · Verde: responde WordPress · Cian: activo</div>
  </div>`;
}

function _surfaceTimelineSvg(r) {
  const host = _surfaceHost(r.target_url || r.url || '');
  const timeline = host ? _riskTimelineDataCache[host] : null;

  if (!timeline || !Array.isArray(timeline.scores) || timeline.scores.length < 2) {
    return `<div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">Linea de tiempo de riesgo</div>
      <div style="font-size:12px;color:var(--text-2)">No hay suficiente historico todavia. Ejecuta mas de un escaneo para visualizar tendencia.</div>
    </div>`;
  }

  const scores = timeline.scores.map(v => _surfaceClamp(v));
  const labels = timeline.labels || [];
  const w = 740;
  const h = 190;
  const padX = 28;
  const padY = 16;
  const xSpan = w - (padX * 2);
  const ySpan = h - (padY * 2);
  const step = scores.length > 1 ? xSpan / (scores.length - 1) : 0;
  const points = scores.map((score, idx) => {
    const x = padX + (idx * step);
    const y = h - padY - ((score / 100) * ySpan);
    return { x, y, score, label: labels[idx] || '' };
  });

  const polyline = points.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ');
  const circles = points.map(p => `<circle cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="2.8" fill="#39ff14"/>`).join('');
  const grid = [0, 25, 50, 75, 100].map(v => {
    const gy = h - padY - ((v / 100) * ySpan);
    return `<line x1="${padX}" y1="${gy.toFixed(1)}" x2="${(w - padX).toFixed(1)}" y2="${gy.toFixed(1)}" stroke="rgba(139,148,158,.18)" stroke-width="1"/>`;
  }).join('');

  const first = scores[0] || 0;
  const last = scores[scores.length - 1] || 0;
  const delta = Math.round(last - first);
  const trendColor = delta < 0 ? 'var(--green2)' : delta > 0 ? 'var(--red)' : 'var(--text-2)';
  const trendText = delta === 0 ? 'Sin cambios relevantes' : (delta < 0 ? `Mejora ${Math.abs(delta)} pts` : `Empeora +${delta} pts`);

  return `<div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3)">Linea de tiempo de riesgo</div>
      <div style="font-size:11px;color:${trendColor};font-weight:700">${_esc(trendText)}</div>
    </div>
    <svg viewBox="0 0 ${w} ${h}" style="width:100%;height:auto;border-radius:6px;background:linear-gradient(180deg,rgba(15,20,29,.7),rgba(15,20,29,.35));border:1px solid var(--border)">
      ${grid}
      <polyline points="${polyline}" fill="none" stroke="#39ff14" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round"/>
      ${circles}
    </svg>
    <div style="display:flex;justify-content:space-between;margin-top:8px;gap:10px;flex-wrap:wrap">
      <span style="font-size:11px;color:var(--text-2)">Escaneos: ${scores.length}</span>
      <span style="font-size:11px;color:var(--text-2)">Inicial: ${first}</span>
      <span style="font-size:11px;color:var(--text-2)">Actual: ${last}</span>
    </div>
  </div>`;
}

function _surfaceAutoDiffSnapshot(r) {
  const scanId = r.scan_id || currentJobId || '';
  const payload = scanId ? _autoDiffCache[scanId] : null;
  if (!payload || !payload.has_previous || !payload.diff) {
    return `<div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">Cambio frente al escaneo anterior</div>
      <div style="font-size:12px;color:var(--text-2)">Sin comparativa disponible. Se habilita automaticamente cuando exista un escaneo previo del mismo objetivo.</div>
    </div>`;
  }

  const d = payload.diff || {};
  const s = d.summary || {};
  const riskDelta = Number(d.risk_delta || 0);
  const status = String(d.status || (riskDelta < 0 ? 'MEJORADO' : riskDelta > 0 ? 'EMPEORADO' : 'SIN CAMBIOS'));
  const statusColor = d.status_color || (riskDelta < 0 ? 'var(--green2)' : riskDelta > 0 ? 'var(--red)' : 'var(--text-2)');

  return `<div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:8px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3)">Cambio frente al escaneo anterior</div>
      <span style="font-size:10px;padding:3px 7px;border-radius:999px;color:${statusColor};background:rgba(139,148,158,.13);border:1px solid ${statusColor};font-weight:700">${_esc(status)}</span>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:8px">
      <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px">
        <div style="font-size:10px;color:var(--text-3)">Delta riesgo</div>
        <div style="font-size:14px;font-weight:700;color:${riskDelta <= 0 ? 'var(--green2)' : 'var(--red)'}">${riskDelta > 0 ? '+' : ''}${riskDelta}</div>
      </div>
      <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px">
        <div style="font-size:10px;color:var(--text-3)">Vulns nuevas</div>
        <div style="font-size:14px;font-weight:700;color:${Number(s.new_vulns || 0) > 0 ? 'var(--red)' : 'var(--text-2)'}">${Number(s.new_vulns || 0)}</div>
      </div>
      <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px">
        <div style="font-size:10px;color:var(--text-3)">Vulns corregidas</div>
        <div style="font-size:14px;font-weight:700;color:var(--green2)">${Number(s.fixed_vulns || 0)}</div>
      </div>
      <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px">
        <div style="font-size:10px;color:var(--text-3)">Archivos expuestos</div>
        <div style="font-size:14px;font-weight:700;color:var(--text-2)">+${Number(s.new_files || 0)} / -${Number(s.fixed_files || 0)}</div>
      </div>
    </div>
  </div>`;
}

function _surfaceShodanCard(r) {
  const sh = (r.recon && r.recon.shodan) || {};
  const hasData = sh && Object.keys(sh).length > 0;
  const shodanReason = String(sh.reason || sh.error || '');
  const isInvalidTarget = /invalid ip|name resolution|could not resolve|host not found|no address associated/i.test(shodanReason);

  if (!hasData) {
    return `<div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">2) Shodan</div>
      <div style="font-size:12px;color:var(--text-2)">No hay datos de Shodan en este resultado. Si activas la API key, verás qué servicios del sitio son visibles desde Internet.</div>
    </div>`;
  }

  if (sh.error || sh.skipped) {
    const friendly = isInvalidTarget
      ? 'No se pudo consultar Shodan porque el host no se resolvió correctamente.'
      : (sh.skipped
        ? 'Shodan no se ejecutó en este escaneo.'
        : 'No se pudo consultar Shodan en este escaneo.');
    const detail = isInvalidTarget
      ? 'Revisa que el dominio esté bien escrito y que tenga una IP pública resoluble.'
      : (sh.reason || sh.error || 'Activa la API key de Shodan para ver este bloque.');

    return `<div style="background:var(--bg-3);border:1px solid rgba(245,163,26,.35);border-radius:8px;padding:12px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">2) Shodan</div>
      <div style="font-size:12px;color:var(--amber);font-weight:700">${_esc(friendly)}</div>
      <div style="font-size:11px;color:var(--text-2);margin-top:4px">${_esc(detail)}</div>
    </div>`;
  }

  const ports = Array.isArray(sh.ports) ? sh.ports : [];
  const vulns = Array.isArray(sh.vulns) ? sh.vulns : [];
  const tags = Array.isArray(sh.tags) ? sh.tags.slice(0, 4) : [];
  const hostnames = Array.isArray(sh.hostnames) ? sh.hostnames.slice(0, 2) : [];
  const cveSample = vulns.slice(0, 3).map(v => `<code style="font-size:10px;color:var(--orange)">${_esc(v)}</code>`).join(' ');

  return `<div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
    <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:8px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.7px;text-transform:uppercase;color:var(--text-3)">2) Shodan</div>
      <div style="font-size:11px;color:${vulns.length ? 'var(--red)' : 'var(--green2)'}">${vulns.length ? `${vulns.length} CVE expuestas` : 'Sin CVE reportadas'}</div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin-bottom:8px">
      <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px"><div style="font-size:10px;color:var(--text-3)">Puertos</div><div style="font-size:14px;font-weight:700;color:${ports.length ? 'var(--amber)' : 'var(--green2)'}">${ports.length}</div></div>
      <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px"><div style="font-size:10px;color:var(--text-3)">Vulnerabilidades</div><div style="font-size:14px;font-weight:700;color:${vulns.length ? 'var(--red)' : 'var(--green2)'}">${vulns.length}</div></div>
      <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px"><div style="font-size:10px;color:var(--text-3)">Org/ISP</div><div style="font-size:12px;font-weight:700;color:var(--text-2)">${_esc(sh.org || sh.isp || 'N/D')}</div></div>
      <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px"><div style="font-size:10px;color:var(--text-3)">Ultima actualizacion</div><div style="font-size:12px;font-weight:700;color:var(--text-2)">${_esc(sh.last_update || 'N/D')}</div></div>
    </div>
    <div style="font-size:10px;color:var(--text-3);font-family:var(--head);letter-spacing:.7px;text-transform:uppercase;margin-bottom:4px">Lo que ve un atacante</div>
    ${ports.length ? `<div style="font-size:11px;color:var(--text-2);margin-bottom:6px">Puertos visibles: ${ports.slice(0, 10).map(p => `<code style="font-size:10px">${_esc(String(p))}</code>`).join(' ')}</div>` : ''}
    ${cveSample ? `<div style="font-size:11px;color:var(--text-2);margin-bottom:6px">CVE de muestra: ${cveSample}</div>` : ''}
    ${hostnames.length ? `<div style="font-size:11px;color:var(--text-3)">Hostnames expuestos: ${hostnames.map(h => _esc(h)).join(', ')}</div>` : ''}
    ${tags.length ? `<div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">${tags.map(t => `<span style="font-size:10px;padding:2px 6px;border-radius:999px;background:rgba(0,200,190,.12);color:var(--teal);border:1px solid rgba(0,200,190,.3)">${_esc(t)}</span>`).join('')}</div>` : ''}
  </div>`;
}

function _buildSurfaceImpactList(r, areas, headerGrade) {
  const impacts = [];
  const shV = (((r.recon || {}).shodan || {}).vulns || []).length;
  const crit = Number((r.summary || {}).critical_vulns || 0);
  const users = (r.users || []).length;
  const expFiles = (r.exposed_files || []).length;

  if (crit > 0) impacts.push('Un atacante podría tomar el sitio si explota una vulnerabilidad crítica.');
  if (expFiles > 0) impacts.push('Archivos expuestos pueden revelar credenciales, rutas internas o copias de configuración.');
  if (users > 0 || r.xmlrpc_enabled) impacts.push('Aumenta el riesgo de acceso a cuentas por fuerza bruta o password spraying.');
  if (headerGrade.score < 70) impacts.push('El navegador del visitante queda más expuesto a XSS, clickjacking y filtrado de datos.');
  if (shV > 0) impacts.push('Shodan muestra al exterior servicios y vulnerabilidades que un atacante puede aprovechar.');

  const worst = Object.values(areas).sort((a, b) => b.score - a.score)[0];
  if (worst && worst.score >= 70) {
    impacts.unshift(`El bloque más expuesto ahora es ${worst.title} (${worst.score}/100). Empieza por aquí para bajar el riesgo más rápido.`);
  }

  return impacts.slice(0, 4);
}

function buildSurfaceTab(r) {
  const headerGrade = _buildSurfaceHeaderGrade(r);
  const areas = _buildSurfaceAreas(r, headerGrade);
  const areaList = Object.values(areas);
  const peak = areaList.reduce((m, a) => Math.max(m, a.score), 0);
  const peakSem = _surfaceRiskPill(peak);
  const impacts = _buildSurfaceImpactList(r, areas, headerGrade);
  const headerColor = headerGrade.score >= 85 ? 'var(--green2)' : headerGrade.score >= 65 ? 'var(--amber)' : 'var(--red)';
  const quickOrder = [
    { n: '1', t: 'Cabeceras HTTP' },
    { n: '2', t: 'Shodan' },
    { n: '3', t: 'Áreas por impacto' },
  ];

  const missingHeaders = headerGrade.issues.length
    ? headerGrade.issues.slice(0, 6).map(h => `
      <div style="display:flex;gap:8px;align-items:flex-start;padding:8px 10px;border:1px solid rgba(245,163,26,.22);border-radius:6px;background:rgba(245,163,26,.06)">
        <span style="color:var(--orange);font-weight:700">!</span>
        <div>
          <div style="font-size:12px;color:var(--text);font-weight:700">${_esc(h.name)}</div>
          <div style="font-size:11px;color:var(--text-2)">${_esc(h.detail || h.impact)}</div>
          <div style="font-size:10px;color:var(--text-3)">${_esc(h.impact)}</div>
        </div>
      </div>`).join('')
    : '<div style="font-size:12px;color:var(--green2)">No hay cabeceras criticas faltantes en este escaneo.</div>';

  return `<div class="tab-content" style="display:grid;gap:12px">
    <div style="background:linear-gradient(135deg,rgba(43,127,255,.16),rgba(0,200,190,.08));border:1px solid var(--border-2);border-radius:10px;padding:14px 16px">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap">
        <div>
          <div style="font-size:10px;font-family:var(--head);letter-spacing:1px;text-transform:uppercase;color:var(--text-3)">Superficie de Ataque</div>
          <div style="font-size:18px;font-weight:800;color:var(--text);margin-top:2px">Resumen ejecutivo en 10 segundos</div>
          <div style="font-size:12px;color:var(--text-2);margin-top:4px">Empieza por cabeceras HTTP, sigue con Shodan y termina en el panel por áreas.</div>
          <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:8px">${quickOrder.map(item => `<span style="font-size:10px;padding:3px 8px;border-radius:999px;background:var(--bg-3);border:1px solid var(--border);color:var(--text-2);font-family:var(--head);font-weight:700;letter-spacing:.6px">${item.n}. ${item.t}</span>`).join('')}</div>
        </div>
        <div style="display:flex;align-items:center;gap:8px;padding:6px 10px;border-radius:999px;background:${peakSem.bg};border:1px solid ${peakSem.color}">
          <span style="font-size:11px;color:${peakSem.color};font-weight:700">Riesgo global ${peakSem.tone}</span>
          <span style="font-size:16px;color:${peakSem.color};font-weight:800">${peak}</span>
        </div>
      </div>
    </div>

    <div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:8px">
        <div>
          <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--text-3)">1) Cabeceras HTTP</div>
          <div style="font-size:11px;color:var(--text-2);margin-top:3px">Si solo arreglas una cosa hoy, empieza por aquí: protege el navegador del visitante.</div>
        </div>
        <div style="display:flex;align-items:baseline;gap:8px">
          <span style="font-size:26px;font-family:var(--head);font-weight:800;color:${headerColor}">${headerGrade.score}</span>
          <span style="font-size:12px;color:var(--text-2)">/100 · grado ${headerGrade.grade}</span>
        </div>
      </div>
      <div style="height:8px;border-radius:999px;background:var(--bg-2);overflow:hidden;margin-bottom:10px">
        <div style="height:100%;width:${headerGrade.score}%;background:${headerColor}"></div>
      </div>
      <div style="font-size:11px;color:var(--text-3);margin-bottom:10px">Faltan ${headerGrade.missingCount} cabecera(s). Las tarjetas siguientes te dicen qué pasa y por qué importa.</div>
      <div style="display:grid;gap:8px">${missingHeaders}</div>
    </div>

    ${_surfaceShodanCard(r)}

    <div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--text-3);margin-bottom:4px">3) Panel unificado por area</div>
      <div style="font-size:11px;color:var(--text-2);margin-bottom:8px">Aquí ves el bloque que conviene corregir primero y la razón resumida en lenguaje simple.</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px">${areaList.map(_surfaceAreaCard).join('')}</div>
    </div>

    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(310px,1fr));gap:10px">
      ${_surfaceTimelineSvg(r)}
      ${_surfaceAutoDiffSnapshot(r)}
    </div>

    ${_surfaceSubdomainGraph(r)}

    <div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:12px">
      <div style="font-size:11px;font-family:var(--head);font-weight:700;letter-spacing:.8px;text-transform:uppercase;color:var(--text-3);margin-bottom:8px">Impacto para negocio y usuarios</div>
      ${impacts.length
        ? `<ul style="margin:0;padding-left:18px;display:grid;gap:6px">${impacts.map(i => `<li style="font-size:12px;color:var(--text-2);line-height:1.45">${_esc(i)}</li>`).join('')}</ul>`
        : '<div style="font-size:12px;color:var(--green2)">No se identifican impactos criticos inmediatos con la evidencia actual.</div>'}
    </div>
  </div>`;
}
function buildReconTab(r) {
  const rec = r.recon || {};
  if (!rec.hostname && !rec.domain) {
    return '<div class="tab-content"><p style="color:var(--text-3);font-size:12px;padding:24px">No hay datos de reconocimiento pasivo para este escaneo.</p></div>';
  }

  const e = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const na = v => v ? e(v) : '<span style="color:var(--text-3)">—</span>';
  const ip = rec.target_ip || '';
  const geo = rec.geoip || {};
  const flag = geo.country_code ? `<span title="${e(geo.country)}" style="margin-left:6px">${countryFlag(geo.country_code)}</span>` : '';
  const asnInfo = rec.asn && rec.asn.asns && rec.asn.asns.length ? rec.asn.asns[0] : {};

  let html = `
  <div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:var(--radius);padding:16px 20px;margin-bottom:14px;display:flex;flex-wrap:wrap;gap:20px;align-items:flex-start">
    <div style="flex:1;min-width:200px">
      <div style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">Objetivo</div>
      <div style="font-family:var(--mono);font-size:15px;color:var(--text);font-weight:600">${e(rec.hostname||rec.domain)}${flag}</div>
      <div style="font-size:11px;color:var(--text-3);margin-top:3px">${e(rec.domain)} · IP: <span style="color:var(--teal)">${na(ip)}</span></div>
      ${rec.rdns ? `<div style="font-size:10px;color:var(--text-3);font-family:var(--mono);margin-top:2px">PTR: ${e(rec.rdns)}</div>` : ''}
    </div>
    <div style="flex:1;min-width:160px">
      <div style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">Geolocalización</div>
      <div style="font-size:12px;color:var(--text)">${geo.city ? e(geo.city)+', ' : ''}${na(geo.country)}</div>
      <div style="font-size:11px;color:var(--text-3);margin-top:2px">${na(geo.isp)}</div>
      ${geo.lat ? `<div style="font-size:10px;color:var(--text-3);font-family:var(--mono)">${geo.lat}, ${geo.lon}</div>` : ''}
    </div>
    <div style="flex:1;min-width:180px">
      <div style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">ASN / Red</div>
      <div style="font-size:12px;color:var(--text)">${na(asnInfo.name || geo.org)}</div>
      <div style="font-size:11px;color:var(--text-3);margin-top:2px">${na(asnInfo.asn || geo.asn)}</div>
      ${asnInfo.prefix ? `<div style="font-size:10px;color:var(--text-3);font-family:var(--mono)">${e(asnInfo.prefix)}</div>` : ''}
    </div>
    <div style="text-align:right;min-width:100px">
      <div style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1.5px;text-transform:uppercase;color:var(--text-3);margin-bottom:6px">Duración recon</div>
      <div style="font-size:22px;font-family:var(--head);font-weight:700;color:var(--blue)">${rec.duration||'?'}s</div>
      <div style="font-size:10px;color:var(--text-3);font-family:var(--mono)">${(rec.timestamp||'').slice(0,16).replace('T',' ')}</div>
    </div>
  </div>`;
  const w = rec.whois || {};
  const whoisFields = [
    ['Registrador', w.registrar],
    ['Titular / Org', w.org || w.registrant_name],
    ['País', w.country],
    ['Creación', w.creation_date],
    ['Expiración', w.expiration_date],
    ['Actualización', w.updated_date],
    ['DNSSEC', w.dnssec],
    ['Estado', Array.isArray(w.status) ? w.status[0] : w.status],
  ].filter(([,v]) => v);

  const nsRows = (w.name_servers||[]).map(ns =>
    `<span style="display:inline-block;background:var(--bg-4);border:1px solid var(--border);border-radius:3px;padding:1px 7px;font-family:var(--mono);font-size:10px;margin:2px">${e(ns)}</span>`
  ).join('');

  const expiry = w.expiration_date ? new Date(w.expiration_date) : null;
  const daysLeft = expiry ? Math.round((expiry - Date.now()) / 86400000) : null;
  const expiryAlert = daysLeft !== null && daysLeft < 60
    ? `<span style="color:var(--red);font-weight:600"> ⚠ vence en ${daysLeft} días</span>` : '';

  let whoisBody = whoisFields.length ? `
    <div class="wp-grid" style="margin-bottom:10px">
      ${whoisFields.map(([label, val]) =>
        `<div class="wp-item"><div class="wi-label">${label}</div><div class="wi-value">${e(String(val||''))}${label==='Expiración'?expiryAlert:''}</div></div>`
      ).join('')}
    </div>` : '<p style="color:var(--text-3);font-size:12px">Sin datos WHOIS</p>';

  if (nsRows) whoisBody += `<div style="margin-top:6px"><span style="font-size:10px;color:var(--text-3);font-family:var(--head);letter-spacing:1px;text-transform:uppercase">Name Servers: </span>${nsRows}</div>`;
  if (w.emails && w.emails.length) {
    whoisBody += `<div style="margin-top:8px"><span style="font-size:10px;color:var(--text-3);font-family:var(--head);letter-spacing:1px;text-transform:uppercase">Emails WHOIS: </span>${(w.emails||[]).map(em=>`<span style="color:var(--amber);font-family:var(--mono);font-size:11px;margin-right:8px">${e(em)}</span>`).join('')}</div>`;
  }
  if (w.raw) {
    whoisBody += `<details style="margin-top:10px"><summary style="font-size:11px;color:var(--text-3);cursor:pointer;font-family:var(--head);letter-spacing:.5px">Ver WHOIS raw</summary><pre style="margin-top:8px;font-size:10px;color:var(--text-2);font-family:var(--mono);white-space:pre-wrap;word-break:break-all;background:var(--bg);padding:10px;border-radius:4px;border:1px solid var(--border);max-height:300px;overflow-y:auto">${e(w.raw)}</pre></details>`;
  }
  html += _reconSection('🔍', 'WHOIS', whoisBody);
  const dns = rec.dns || {};
  const dnsTypes = [
    { type: 'A',     records: dns.A    || [], color: 'var(--teal)' },
    { type: 'AAAA',  records: dns.AAAA || [], color: 'var(--blue)' },
    { type: 'MX',    records: dns.MX   || [], color: 'var(--amber)' },
    { type: 'NS',    records: dns.NS   || [], color: 'var(--green)' },
    { type: 'TXT',   records: dns.TXT  || [], color: 'var(--text-2)' },
    { type: 'CNAME', records: dns.CNAME ? [dns.CNAME] : [], color: 'var(--orange)' },
  ].filter(t => t.records.length);

  let dnsBody = dnsTypes.length ? dnsTypes.map(({type, records, color}) => `
    <div style="margin-bottom:10px">
      <span style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1px;color:${color};text-transform:uppercase;background:var(--bg-4);padding:1px 8px;border-radius:3px;border:1px solid var(--border)">${type}</span>
      <div style="margin-top:5px">
        ${records.map(r => `<div style="font-family:var(--mono);font-size:11px;color:var(--text-2);padding:2px 0;border-bottom:1px solid var(--border)">${e(r)}</div>`).join('')}
      </div>
    </div>`).join('') : '<p style="color:var(--text-3);font-size:12px">Sin registros DNS</p>';

  if (dns.SOA && dns.SOA.mname) {
    dnsBody += `<div style="margin-top:8px;padding:8px 12px;background:var(--bg-4);border:1px solid var(--border);border-radius:4px;font-size:11px">
      <span style="font-family:var(--head);font-size:10px;color:var(--text-3);letter-spacing:1px;text-transform:uppercase">SOA</span>
      <span style="font-family:var(--mono);color:var(--text-2);margin-left:10px">${e(dns.SOA.mname)}</span>
      <span style="color:var(--text-3);font-family:var(--mono);font-size:10px;margin-left:8px">serial: ${dns.SOA.serial||''}</span>
    </div>`;
  }
  html += _reconSection('🌐', 'Registros DNS', dnsBody);
  const nmap = rec.nmap || {};
  let nmapBody = '';
  if (nmap.error) {
    nmapBody = `<p style="color:var(--amber);font-size:12px">⚠ ${e(nmap.error)}</p>`;
  } else if (!nmap.ports || !nmap.ports.length) {
    nmapBody = '<p style="color:var(--text-3);font-size:12px">Sin puertos abiertos detectados (o nmap no disponible)</p>';
  } else {
    const portRows = nmap.ports.map(p => {
      const svcColor = p.port === 22 ? 'var(--amber)' : p.port === 3306 || p.port === 5432 ? 'var(--red)' : 'var(--text-2)';
      const svcBadge = p.port === 443 || p.port === 80 ? '' : p.port === 22 ? ' <span style="color:var(--amber);font-size:10px">SSH</span>' : p.port === 3306 ? ' <span style="color:var(--red);font-size:10px">DB</span>' : p.port === 6379 ? ' <span style="color:var(--red);font-size:10px">REDIS</span>' : p.port === 9200 ? ' <span style="color:var(--orange);font-size:10px">ELASTIC</span>' : '';
      return `<tr>
        <td style="font-family:var(--mono);font-size:12px;font-weight:700;color:${svcColor};padding:6px 10px;border-bottom:1px solid var(--border)">${p.port}/${p.proto}</td>
        <td style="font-size:11px;color:var(--green);padding:6px 10px;border-bottom:1px solid var(--border)">${e(p.state)}</td>
        <td style="font-family:var(--mono);font-size:11px;color:var(--text-2);padding:6px 10px;border-bottom:1px solid var(--border)">${e(p.service)}${svcBadge}</td>
        <td style="font-size:11px;color:var(--text-3);padding:6px 10px;border-bottom:1px solid var(--border);word-break:break-all">${e(p.version)}</td>
      </tr>`;
    }).join('');
    nmapBody = `<table style="width:100%;border-collapse:collapse">
      <thead><tr style="background:var(--bg-4)">
        <th style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1px;color:var(--text-3);text-transform:uppercase;padding:7px 10px;text-align:left;border-bottom:1px solid var(--border)">Puerto</th>
        <th style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1px;color:var(--text-3);text-transform:uppercase;padding:7px 10px;text-align:left;border-bottom:1px solid var(--border)">Estado</th>
        <th style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1px;color:var(--text-3);text-transform:uppercase;padding:7px 10px;text-align:left;border-bottom:1px solid var(--border)">Servicio</th>
        <th style="font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:1px;color:var(--text-3);text-transform:uppercase;padding:7px 10px;text-align:left;border-bottom:1px solid var(--border)">Versión</th>
      </tr></thead>
      <tbody>${portRows}</tbody>
    </table>`;
    if (nmap.os_guess) nmapBody += `<div style="margin-top:8px;font-size:11px;color:var(--text-2)">OS detectado: <span style="color:var(--teal)">${e(nmap.os_guess)}</span></div>`;
    if (nmap.latency) nmapBody += `<div style="font-size:10px;color:var(--text-3);margin-top:3px">Latencia: ${e(nmap.latency)}</div>`;
  }
  if (nmap.raw && nmap.raw.length > 10) {
    nmapBody += `<details style="margin-top:10px">
      <summary style="font-size:11px;color:var(--text-3);cursor:pointer;font-family:var(--head);letter-spacing:.5px;padding:8px 0">Ver salida raw de Nmap</summary>
      <pre style="margin-top:8px;font-size:10px;color:var(--green);font-family:var(--mono);white-space:pre-wrap;word-break:break-all;background:var(--bg);padding:14px;border-radius:4px;border:1px solid var(--border);max-height:400px;overflow-y:auto">${e(nmap.raw)}</pre>
    </details>`;
  }
  const nmapCount = nmap.ports ? nmap.ports.length : 0;
  html += _reconSection('🔌', `Nmap — Puertos Abiertos <span style="font-family:var(--mono);font-weight:400;font-size:11px">(${nmapCount})</span>`, nmapBody);
  const crt = rec.crtsh || {};
  let crtBody = '';
  if (crt.skipped) {
    crtBody = `<div style="padding:12px;background:var(--bg-4);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-2)">
      <span style="color:var(--amber)">⚙</span> ${e(crt.reason || 'Servicio CT temporalmente no disponible')}
      <div style="margin-top:6px;font-size:11px;color:var(--text-3)">Intenta de nuevo en unos minutos. El resto del reconocimiento se ha completado normalmente.</div>
    </div>`;
  } else if (crt.error) {
    crtBody = `<div style="padding:12px;background:var(--bg-4);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-2)">
      <span style="color:var(--amber)">⚠</span> Servicio de Certificate Transparency no disponible en este momento.
      <details style="margin-top:6px"><summary style="cursor:pointer;color:var(--text-3);font-size:11px">Detalle tecnico</summary><pre style="margin-top:6px;font-size:10px;color:var(--text-3);font-family:var(--mono);white-space:pre-wrap">${e(crt.error)}</pre></details>
    </div>`;
  } else if (!crt.subdomains || !crt.subdomains.length) {
    crtBody = '<p style="color:var(--text-3);font-size:12px">Sin subdominios encontrados en CT logs</p>';
  } else {
    crtBody = `<div style="display:flex;flex-wrap:wrap;gap:5px;margin-bottom:10px">
      ${crt.subdomains.map(sd =>
        `<span style="font-family:var(--mono);font-size:10px;background:var(--bg-4);border:1px solid var(--border);border-radius:3px;padding:2px 8px;color:var(--teal)">${e(sd)}</span>`
      ).join('')}
    </div>`;
    if (crt.total_certs) crtBody += `<div style="font-size:10px;color:var(--text-3)">Certificados analizados: ${crt.total_certs} · Subdominios únicos: ${crt.subdomains.length}</div>`;
  }
  html += _reconSection('📜', 'Certificate Transparency (crt.sh)', crtBody);
  const sh = rec.shodan || {};
  let shodanBody = '';
  if (sh.skipped) {
    shodanBody = `<div style="padding:14px;background:var(--bg-4);border:1px solid var(--border);border-radius:var(--radius);font-size:12px;color:var(--text-3)">
      <span style="color:var(--amber)">⚙</span> ${e(sh.reason || 'Shodan no configurado')}
      <div style="margin-top:6px;font-size:11px">Añade <code style="color:var(--teal)">SHODAN_API_KEY=xxx</code> en el archivo <code>.env</code> para activar este módulo.</div>
    </div>`;
  } else if (sh.error) {
    shodanBody = `<p style="color:var(--amber);font-size:12px">⚠ ${e(sh.error)}</p>`;
  } else if (sh.ip) {
    const vulnBadges = (sh.vulns||[]).map(v =>
      `<span style="font-size:10px;font-family:var(--mono);background:var(--red-dim);color:var(--red);border:1px solid rgba(255,69,96,.22);border-radius:3px;padding:1px 6px;margin:2px">${e(v)}</span>`
    ).join('');
    shodanBody = `
    <div class="wp-grid" style="margin-bottom:10px">
      ${[['ISP', sh.isp],['Organización',sh.org],['País',sh.country],['Ciudad',sh.city],['OS',sh.os],['Última actualización',sh.last_update]].filter(([,v])=>v).map(([l,v])=>
        `<div class="wp-item"><div class="wi-label">${l}</div><div class="wi-value">${e(String(v))}</div></div>`
      ).join('')}
    </div>`;
    if (sh.ports && sh.ports.length) shodanBody += `<div style="margin-bottom:8px"><span style="font-size:10px;color:var(--text-3);letter-spacing:1px;text-transform:uppercase;font-family:var(--head)">Puertos: </span>${sh.ports.map(p=>`<span style="font-family:var(--mono);font-size:11px;margin-right:6px;color:var(--text-2)">${p}</span>`).join('')}</div>`;
    if (sh.vulns && sh.vulns.length) shodanBody += `<div style="margin-bottom:8px"><span style="font-size:10px;color:var(--red);letter-spacing:1px;text-transform:uppercase;font-family:var(--head)">CVEs Shodan: </span>${vulnBadges}</div>`;
    if (sh.banners && sh.banners.length) {
      shodanBody += `<div style="margin-top:8px"><div style="font-size:10px;color:var(--text-3);font-family:var(--head);letter-spacing:1px;text-transform:uppercase;margin-bottom:6px">Banners</div>` +
        sh.banners.map(b=>`<div style="font-size:11px;padding:7px 10px;border-bottom:1px solid var(--border);display:flex;gap:14px">
          <span style="font-family:var(--mono);color:var(--teal);min-width:50px">${b.port}/${b.transport}</span>
          <span style="color:var(--text-2)">${e(b.product||'')} ${e(b.version||'')}</span>
          ${b.banner ? `<span style="color:var(--text-3);font-family:var(--mono);font-size:10px;flex:1;word-break:break-all">${e(b.banner.slice(0,120))}</span>` : ''}
        </div>`).join('') + '</div>';
    }
  } else {
    shodanBody = '<p style="color:var(--text-3);font-size:12px">Sin datos Shodan</p>';
  }
  html += _reconSection('☁️', 'Shodan', shodanBody);

  return html;
}

function _reconSection(icon, title, bodyHtml) {
  return `
  <div class="module-section" style="margin-bottom:10px">
    <div class="module-header" onclick="this.nextElementSibling.classList.toggle('open');this.querySelector('.module-chevron').classList.toggle('open')">
      <div class="module-header-icon" style="background:var(--bg-4);border:1px solid var(--border)">${icon}</div>
      <div class="module-header-text">
        <div class="module-header-title">${title}</div>
      </div>
      <span class="module-chevron">▾</span>
    </div>
    <div class="module-body open" style="padding:14px 16px">${bodyHtml}</div>
  </div>`;
}

function countryFlag(code) {
  if (!code || code.length !== 2) return '';
  const c = code.toUpperCase();
  return String.fromCodePoint(...[...c].map(ch => 127397 + ch.charCodeAt(0)));
}
function _updateReconBadge(r) {
  const el = document.getElementById('reconBadge');
  if (!el) return;
  const recon = r.recon || {};
  const ports = (recon.nmap && recon.nmap.ports) ? recon.nmap.ports.length : 0;
  const vulns = (recon.shodan && recon.shodan.vulns) ? recon.shodan.vulns.length : 0;
  const total = ports + vulns;
  if (total > 0) {
    el.textContent = total > 99 ? '99+' : String(total);
    el.className = 'tab-badge' + (vulns > 0 ? ' red' : ' orange');
    el.style.display = '';
  }
}
let _vulnSev = 'all';
let _vulnRaw = [];
const VULN_PAGE_SIZE = 25;
let _vulnPage = 0;
let _vulnFiltered = [];

function setVulnSev(sev) {
  _vulnSev = sev;
  _vulnPage = 0;
  document.querySelectorAll('.sev-tab').forEach(b => {
    b.classList.toggle('active', b.dataset.sev === sev);
  });
  filterVulns();
}

function _populateComponentFilter(vulns) {
  const sel = document.getElementById('vulnComponentSel');
  if (!sel) return;
  const current = sel.value;
  const slugs = [...new Set(vulns.map(v => v.plugin_slug).filter(Boolean))].sort();
  sel.innerHTML = '<option value="">Todos los componentes</option>' +
    slugs.map(s => `<option value="${_esc(s)}"${s===current?' selected':''}>${_esc(s)}</option>`).join('');
}

function filterVulns() {
  const q    = (document.getElementById('vulnSearch')?.value || '').toLowerCase();
  const sort = document.getElementById('vulnSort')?.value || 'sev';
  const comp = document.getElementById('vulnComponentSel')?.value || '';
  let vulns  = [..._vulnRaw];

  if (_vulnSev !== 'all') vulns = vulns.filter(v => v.severity === _vulnSev);
  if (comp) vulns = vulns.filter(v => (v.plugin_slug||'')=== comp);
  if (q) vulns = vulns.filter(v =>
    (v.title||'').toLowerCase().includes(q) ||
    (v.cve_id||'').toLowerCase().includes(q) ||
    (v.plugin_slug||'').toLowerCase().includes(q) ||
    (v.description||'').toLowerCase().includes(q)
  );

  const sevO = {critical:0,high:1,medium:2,low:3,info:4};
  if (sort === 'sev')    vulns.sort((a,b) => (sevO[a.severity]||9)-(sevO[b.severity]||9));
  if (sort === 'cvss')   vulns.sort((a,b) => (b.cvss_score||0)-(a.cvss_score||0));
  if (sort === 'plugin') vulns.sort((a,b) => (a.plugin_slug||'').localeCompare(b.plugin_slug||'')); 
  if (sort === 'kev')    vulns.sort((a,b) => {
    const ka = a.kev?2:(a.epss||0)>0.5?1:0;
    const kb = b.kev?2:(b.epss||0)>0.5?1:0;
    return kb-ka||(sevO[a.severity]||9)-(sevO[b.severity]||9);
  });

  _vulnFiltered = vulns;
  _vulnPage = 0;
  _renderVulnPage();

  const cntEl = document.getElementById('vulnCount');
  if (cntEl) cntEl.textContent = vulns.length !== _vulnRaw.length
    ? `${vulns.length} / ${_vulnRaw.length}` : `${_vulnRaw.length} total`;
}

function _renderVulnPage() {
  const total    = _vulnFiltered.length;
  const pages    = Math.ceil(total / VULN_PAGE_SIZE) || 1;
  _vulnPage      = Math.max(0, Math.min(_vulnPage, pages-1));
  const start    = _vulnPage * VULN_PAGE_SIZE;
  const pageVulns = _vulnFiltered.slice(start, start + VULN_PAGE_SIZE);
  const el = _el('tabContent');
  if (el) el.innerHTML = renderVulnsList(pageVulns);
  const pag  = document.getElementById('vulnPagination');
  const info = document.getElementById('vulnPageInfo');
  const prev = document.getElementById('vulnPrevBtn');
  const next = document.getElementById('vulnNextBtn');
  if (pag) {
    pag.style.display = total > VULN_PAGE_SIZE ? 'flex' : 'none';
    if (info) info.textContent = `Página ${_vulnPage+1} de ${pages} · ${total} vulnerabilidades`;
    if (prev) prev.disabled = (_vulnPage === 0);
    if (next) next.disabled = (_vulnPage >= pages-1);
  }
}

function vulnPageChange(dir) {
  _vulnPage += dir;
  _renderVulnPage();
  _el('tabContent')?.scrollIntoView({behavior:'smooth',block:'start'});
}
function buildVulnsTab(r) {
  _vulnRaw = r.vulnerabilities || [];
  _vulnPage = 0;
  _vulnFiltered = _vulnRaw;
  _populateComponentFilter(_vulnRaw);
  const pf = r.passive_fingerprints || {};
  const pfFindings = Array.isArray(pf.findings) ? pf.findings : [];
  const pfEmails = Array.isArray(r.exposed_emails) && r.exposed_emails.length
    ? r.exposed_emails
    : (Array.isArray(pf.exposed_emails) ? pf.exposed_emails : []);
  const pfKeys = Array.isArray(pf.hardcoded_keys) ? pf.hardcoded_keys : [];
  const hasOffline = _vulnRaw.some(v => !v.source || v.source === 'offline');
  const hasOnline  = _vulnRaw.some(v => v.source && v.source !== 'offline');
  let banner = '';
  if (hasOffline && !hasOnline) {
    banner = `<div style="background:var(--bg-2);border:1px solid var(--border);border-left:3px solid var(--blue);border-radius:6px;padding:10px 14px;margin-bottom:14px;font-size:11px;color:var(--text-3);font-family:var(--sans);display:flex;align-items:center;gap:10px">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:14px;height:14px;flex-shrink:0;color:var(--blue)"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
      <span>CVEs de <strong style="color:var(--text-2)">base de datos local</strong>. Para verificación exacta haz clic en <strong>NVD ↗</strong> en cada vulnerabilidad o configura una API key de WPScan para datos en tiempo real.</span>
    </div>`;
  } else if (hasOnline) {
    banner = `<div style="background:var(--green-dim);border:1px solid rgba(0,214,143,.2);border-radius:6px;padding:8px 14px;margin-bottom:14px;font-size:11px;color:var(--green);font-family:var(--sans)">
      ✓ Vulnerabilidades verificadas en tiempo real vía WPScan API
    </div>`;
  }

  let passiveBanner = '';
  if (pfFindings.length || pfEmails.length || pfKeys.length) {
    const sevColor = s => ({critical:'var(--red)',high:'var(--orange)',medium:'var(--amber)',low:'var(--text-2)',info:'var(--blue)'})[s] || 'var(--blue)';
    const rows = pfFindings.slice(0, 6).map(f => {
      const color = sevColor(f.severity);
      const sev = String(f.severity || 'info').toUpperCase();
      return `<div style="display:flex;gap:8px;align-items:flex-start;padding:7px 0;border-bottom:1px solid var(--border)">
        <span style="font-size:10px;font-weight:700;padding:1px 6px;border:1px solid ${color}66;background:${color}22;color:${color};border-radius:3px;min-width:52px;text-align:center">${_esc(sev)}</span>
        <div style="font-size:11px;color:var(--text-2)">${_esc(f.issue || '')}${f.detail ? `<div style="margin-top:2px;color:var(--text-3)">${_esc(f.detail)}</div>` : ''}</div>
      </div>`;
    }).join('');

    passiveBanner = `<div style="background:var(--bg-2);border:1px solid var(--border);border-left:3px solid var(--teal);border-radius:6px;padding:10px 14px;margin-bottom:14px">
      <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-bottom:8px">
        <div style="font-size:11px;color:var(--teal);font-family:var(--head);font-weight:700;letter-spacing:.5px">HALLAZGOS PASIVOS (NO-CVE)</div>
        <div style="font-size:11px;color:var(--text-3)">${pfFindings.length} finding(s) · ${pfEmails.length} email(s) · ${pfKeys.length} key(s)</div>
      </div>
      ${rows || '<div style="font-size:11px;color:var(--text-3)">Sin detalle de findings, pero hay señales pasivas relevantes.</div>'}
      ${pfEmails.length ? `<div style="margin-top:8px;font-size:11px;color:var(--amber)">Emails expuestos: ${pfEmails.slice(0, 5).map(e => `<code>${_esc(e)}</code>`).join(' ')}</div>` : ''}
      ${pfKeys.length ? `<div style="margin-top:6px;font-size:11px;color:var(--red)">Posibles claves expuestas: ${pfKeys.slice(0, 5).map(k => `<code>${_esc(k)}</code>`).join(' ')}</div>` : ''}
    </div>`;
  }

  let listHtml = '';
  if (_vulnRaw.length) {
    listHtml = renderVulnsList(_vulnRaw.slice(0, VULN_PAGE_SIZE));
  } else if (pfFindings.length || pfEmails.length || pfKeys.length) {
    listHtml = '<div class="no-results"><div class="nr-icon ic-ok"></div><p>No hay CVEs de WordPress en este resultado, pero sí hallazgos pasivos relevantes.</p></div>';
  } else {
    listHtml = '<div class="no-results"><div class="nr-icon ic-ok"></div><p>No se encontraron vulnerabilidades con los filtros actuales</p></div>';
  }
  return banner + passiveBanner + listHtml;
}

function copyCVE(cveId, btn) {
  if (!cveId) return;
  const origHtml = `⎘ ${cveId}`;
  navigator.clipboard.writeText(cveId).then(() => {
    btn.classList.add('copied'); btn.textContent = '✓ Copiado';
    setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = origHtml; }, 1600);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = cveId; ta.style.position='fixed'; ta.style.opacity='0';
    document.body.appendChild(ta); ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
    btn.classList.add('copied'); btn.textContent = '✓ Copiado';
    setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = origHtml; }, 1600);
  });
}
let _vulnStore = [];

function _openVulnCard(el) {
  const idx = parseInt(el.dataset.vi, 10);
  const v = _vulnStore[idx];
  if (v) openCVEModal(JSON.stringify(v));
}
document.addEventListener('click', function(e) {
  const btn = e.target.closest('.copy-cve-btn[data-cve]');
  if (!btn) return;
  e.stopPropagation();
  const cveId = btn.dataset.cve;
  if (!cveId) return;
  const origHtml = btn.innerHTML;
  navigator.clipboard.writeText(cveId).then(() => {
    btn.classList.add('copied'); btn.textContent = '✓ Copiado';
    setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = origHtml; }, 1600);
  }).catch(() => {
    try {
      const ta = document.createElement('textarea');
      ta.value = cveId; ta.style.cssText = 'position:fixed;opacity:0;top:0;left:0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy');
      document.body.removeChild(ta);
    } catch(_) {}
    btn.classList.add('copied'); btn.textContent = '✓ Copiado';
    setTimeout(() => { btn.classList.remove('copied'); btn.innerHTML = origHtml; }, 1600);
  });
});

function renderVulnsList(vulns) {
  _vulnStore = [];  // limpiar store en cada render
  if (!vulns.length) return '<div class="no-results"><div class="nr-icon ic-ok"></div><p>No se encontraron vulnerabilidades con los filtros actuales</p></div>';
  return vulns.map(v => {
    const sevLabel = {critical:'CRÍTICO',high:'ALTO',medium:'MEDIO',low:'BAJO',info:'INFO'}[v.severity]||v.severity?.toUpperCase();
    const icon = v.type==='wordpress'?'WP':v.type==='theme'?'TEMA':'PLUGIN';
    const cvssVal = parseFloat(v.cvss_score);
    const cvssColor = cvssVal>=9?'var(--red)':cvssVal>=7?'var(--orange)':'var(--yellow)';
    const cveBtn = v.cve_id
      ? `<button class="copy-cve-btn" data-cve="${v.cve_id}" onclick="event.stopPropagation()" title="Copiar CVE al portapapeles">⎘ ${v.cve_id}</button>`
      : '';
    const cveLinks = v.cve_id
      ? `<span class="vtag"><a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank" onclick="event.stopPropagation()" style="color:var(--cyan);font-weight:700;letter-spacing:.3px" title="Ver ${v.cve_id} en NVD/NIST">${v.cve_id} ↗</a></span>`
      : '';
    const srcBadge = v.source === 'offline' || !v.source
      ? `<span class="vtag" style="color:var(--text-3);font-size:9px">BD local</span>`
      : `<span class="vtag" style="color:var(--green);font-size:9px">online</span>`;
    const kev  = v.kev  ? '<span class="vtag" style="color:var(--red);font-weight:700;white-space:nowrap">🚨 CISA KEV</span>' : '';
    const unconf = v.version_unconfirmed ? '<span class="vtag" style="color:var(--amber);font-size:9px" title="Versión no detectada — resultado no confirmado">⚠ NO CONF.</span>' : ''
    const epss = v.epss > 0.5 ? `<span class="vtag" style="color:var(--orange)">EPSS ${Math.round(v.epss*100)}%</span>` : '';
    const action  = v.recommended_action ? `<div class="action-tag">💡 ${_esc(v.recommended_action)}</div>` : '';
    const fixTag  = v.fixed_in && !v.recommended_action ? `<span class="fix-tag">✓ Actualizar a v${_esc(v.fixed_in)}</span>` : '';
    const noFix   = !v.fixed_in && v.severity !== 'info' ? '<span style="font-size:10px;color:var(--red)">⚠ Sin fix conocido — considerar desactivar</span>' : '';
    const _vKey = _vulnStore.push(v) - 1;
    return `<div class="vuln-card" style="cursor:pointer" data-vi="${_vKey}" onclick="_openVulnCard(this)">
      <div class="vuln-header">
        <span class="sev-badge sev-${v.severity}">${sevLabel}</span>
        <div style="flex:1;min-width:0">
          <div class="vuln-title">${_esc(v.title)}</div>
          <div class="vuln-tags">
            <span class="vtag">${icon} ${_esc(v.plugin_slug)}${v.plugin_version?' v'+_esc(v.plugin_version):''}</span>
            ${v.cvss_score?`<span class="vtag" style="color:${cvssColor}">CVSS ${v.cvss_score}</span>`:''}
            ${cveBtn}${cveLinks}${srcBadge}${kev}${epss}${unconf}
          </div>
        </div>
      </div>
      ${(fixTag||action||noFix)?`<div class="vuln-body">${fixTag}${action}${noFix}</div>`:''}
    </div>`;
  }).join('');
}

function buildInfoTab(r) {
  const ssl = r.ssl_info || {};
  const sslColor = ssl.expired ? 'var(--red)' : !ssl.valid ? 'var(--orange)' : (ssl.days_left < 30 ? 'var(--yellow)' : 'var(--green2)');
  const sslText  = ssl.error && !ssl.valid ? `⚠ ${ssl.error}` : ssl.expired ? 'EXPIRADO'
                 : ssl.valid ? `✓ ${ssl.days_left}d restantes (${ssl.issuer})` : 'No analizado';
  const tls = r.tls_analysis || {};
  const cors = r.cors_issues || {};
  const debug = r.debug_mode || {};
  const cron = r.wp_cron_abuse || {};
  const login = r.custom_login || {};
  const redir = r.redirect_chain || {};
  const rest = r.rest_api_issues || {};
  const ms = r.multisite_info || {};

  const infoRow = (label, val) => `
    <div class="wp-item">
      <div class="wi-label">${label}</div>
      <div class="wi-value">${val}</div>
    </div>`;
  const users = r.users || [];
  const usersHtml = users.length === 0
    ? `<div style="color:var(--green2);font-size:12px;padding:8px 0">✓ No se pudieron enumerar usuarios</div>`
    : `<div style="margin-top:6px">
        <div style="font-size:11px;color:var(--amber);margin-bottom:8px">⚠ ${users.length} usuario${users.length>1?'s':''} enumerable${users.length>1?'s':''} — facilitan ataques de fuerza bruta contra /wp-login.php</div>
        ${users.map(u => {
          if (typeof u !== 'object') return '';
          return `<div style="display:flex;align-items:center;gap:10px;padding:7px 10px;background:rgba(255,184,48,.06);border:1px solid rgba(255,184,48,.2);border-radius:4px;margin-bottom:6px">
            <div style="width:30px;height:30px;border-radius:50%;background:rgba(255,138,80,.15);display:flex;align-items:center;justify-content:center;font-family:var(--head);font-weight:800;color:var(--orange);font-size:14px;flex-shrink:0">${(u.login||u.display_name||'?')[0].toUpperCase()}</div>
            <div style="flex:1;min-width:0">
              <div style="font-weight:700;font-size:13px;color:var(--text)">${u.login||u.display_name||'?'}</div>
              <div style="font-size:10px;color:var(--text-2)">ID: ${u.id||'?'} · ${u.source||''}${u.display_name && u.display_name!==u.login?' · '+u.display_name:''}</div>
            </div>
            <span style="font-size:10px;font-family:var(--head);font-weight:700;color:var(--amber);background:rgba(255,184,48,.1);border:1px solid rgba(255,184,48,.3);border-radius:3px;padding:2px 8px;letter-spacing:.5px">EXPUESTO</span>
          </div>`;
        }).join('')}
      </div>`;

  const csp  = r.csp_analysis  || {};
  const hsts = r.hsts_analysis || {};
  const jst  = r.js_threats   || [];
  const postInj = r.post_injections || [];
  const rep  = r.reputation    || {};
  const stack= r.server_stack  || {};
  return `<div style="display:grid;gap:12px">
    
    <div class="acc-section open">
      <div class="acc-header">
        <span class="acc-icon">📋</span>
        <span class="acc-title">Informacion General</span>
        <span class="acc-chevron">▼</span>
      </div>
      <div class="acc-body">
        <div class="wp-grid">
    ${infoRow('WordPress', r.wp_version
      ? `<span class="${r.wp_outdated?'wi-bad':'wi-warn'}">${_esc(r.wp_version)}</span>${r.wp_outdated?` <span style="color:var(--red);font-size:11px">→ ${_esc(r.wp_latest_version)}</span>`:''}`
      : '<span class="wi-ok">No detectada ✓</span>')}
    ${infoRow('Servidor', r.server_info||'<span class="wi-ok">Oculto ✓</span>')}
    ${infoRow('PHP', r.php_version?`<span class="wi-warn">${r.php_version}</span>`:'<span class="wi-ok">Oculta ✓</span>')}
    ${infoRow('XML-RPC', `<span class="${r.xmlrpc_enabled?'wi-bad':'wi-ok'}">${r.xmlrpc_enabled?'ACTIVO':'✓ Desactivado'}</span>`)}
    ${infoRow('SSL/HTTPS', `<span style="color:${sslColor}">${sslText}</span>`)}
    ${infoRow('WAF/CDN', (r.waf_detected||[]).length?`<span style="color:var(--green2)">${r.waf_detected.join(', ')}</span>`:'<span class="wi-warn">Sin WAF detectado</span>')}
    ${infoRow('CORS REST API', cors.vulnerable?`<span class="wi-bad">${cors.severity?.toUpperCase()} — ${cors.findings?.length||0} hallazgos</span>`:'<span class="wi-ok">✓ OK</span>')}
    ${infoRow('WP_DEBUG', debug.debug_active?'<span class="wi-bad">ACTIVO en producción</span>':'<span class="wi-ok">✓ Desactivado</span>')}
    ${infoRow('TLS', tls.deprecated_protocol?`<span class="wi-bad">Protocolo deprecado: ${(tls.weak_protocol_list||[]).join(', ')}</span>`:tls.tls_version?`<span class="wi-ok">✓ ${tls.tls_version}</span>`:'<span class="wi-warn">No analizado</span>')}
    ${infoRow('wp-cron externo', cron.abusable?`<span class="wi-bad">Abusable (${cron.response_time_ms}ms)</span>`:'<span class="wi-ok">✓ No accesible</span>')}
    ${infoRow('Login URL', login.custom_url?`<span class="wi-warn">Personalizado: ${login.custom_url}</span>`:login.original_accessible?'<span class="wi-warn">/wp-login.php accesible</span>':'<span class="wi-ok">✓ No detectado</span>')}
    ${infoRow('REST API auth', rest.allows_edit_context?'<span class="wi-bad badge-danger">Sin auth sin auth</span>':rest.exposes_emails?'<span class="wi-bad">Expone emails</span>':rest.exposes_private_posts?'<span class="wi-warn">Posts privados expuestos</span>':'<span class="wi-ok">✓ OK</span>')}
    ${infoRow('Multisite', ms.is_multisite?`<span class="wi-warn">Multisite detectado (${(ms.indicators||[]).length} indicadores)</span>`:'<span class="wi-ok">✓ Instalación simple</span>')}
    ${infoRow('Redirección UA', redir.suspicious?'<span class="wi-bad badge-danger">Redirección sospechosa sospechosa (posible malware)</span>':'<span class="wi-ok">✓ Sin anomalías</span>')}
  </div>
  <div style="margin-top:16px">
    <div class="acc-section open">
      <div class="acc-header">
        <span class="acc-icon">👤</span>
        <span class="acc-title">Usuarios expuestos</span>
        ${users.length>0?`<span class="acc-count count-orange">${users.length}</span>`:`<span class="acc-count count-green">0</span>`}
        <span class="acc-chevron">▼</span>
      </div>
      <div class="acc-body">${usersHtml}</div>
    </div>
    <div class="acc-section open">
      <div class="acc-header">
        <span class="acc-icon"></span><span class="acc-title">Cabeceras de seguridad</span>
        <span class="acc-chevron">▼</span>
      </div>
      <div class="acc-body" style="">
        ${(r.headers_issues||[]).map(h=>`<div style="padding:4px 0;font-size:12px;color:var(--yellow)">${h}</div>`).join('')}
        ${(r.headers_ok||[]).map(h=>`<div style="padding:4px 0;font-size:12px;color:var(--green2)">✓ ${h}</div>`).join('')}
        ${!(r.headers_issues||[]).length && !(r.headers_ok||[]).length ? '<div style="color:var(--text3);font-size:12px">No analizado</div>' : ''}
      </div>
    </div>
  </div>`;
}

function buildCompsTab(r) {
  const plugins = [...(r.plugins || [])];
  const themes  = [...(r.themes || [])];
  const timing  = [...(r.timing_plugins || [])];

  const sorter = (a, b) => {
    const aOut = a && a.is_outdated ? 1 : 0;
    const bOut = b && b.is_outdated ? 1 : 0;
    if (bOut !== aOut) return bOut - aOut;

    const aConf = Number.isFinite(Number(a && a.confidence)) ? Number(a.confidence) : -1;
    const bConf = Number.isFinite(Number(b && b.confidence)) ? Number(b.confidence) : -1;
    if (bConf !== aConf) return bConf - aConf;

    return String((a && a.slug) || '').localeCompare(String((b && b.slug) || ''), 'es', { sensitivity: 'base' });
  };

  plugins.sort(sorter);
  themes.sort(sorter);
  timing.sort((a, b) => {
    const aConf = Number(a && a.confidence) || 0;
    const bConf = Number(b && b.confidence) || 0;
    if (bConf !== aConf) return bConf - aConf;
    return (Number(b && b.avg_response_ms) || 0) - (Number(a && a.avg_response_ms) || 0);
  });

  const all = plugins.concat(themes);
  const total = all.length;
  const outdated = all.filter(c => c && c.is_outdated).length;
  const upToDate = Math.max(0, total - outdated);
  const unknownVer = all.filter(c => !c || !c.version || c.version === '?').length;
  const avgConf = total
    ? Math.round(all.reduce((acc, c) => acc + (Number(c && c.confidence) || 0), 0) / total)
    : 0;

  const coreLabel = r.wp_version
    ? `WP ${_esc(r.wp_version)}${r.wp_outdated && r.wp_latest_version ? ` -> ${_esc(r.wp_latest_version)}` : ''}`
    : 'No detectada';

  let html = `
    <div class="comps-hero">
      <div class="comps-hero-head">
        <div class="comps-hero-title">Inventario de componentes</div>
        <div class="comps-hero-sub">Vista de plugins, temas y señales por timing detectadas en el objetivo.</div>
      </div>
      <div class="comps-kpis">
        <div class="comps-kpi"><span class="comps-kpi-lbl">Total</span><span class="comps-kpi-val">${total}</span></div>
        <div class="comps-kpi warn"><span class="comps-kpi-lbl">Desactualizados</span><span class="comps-kpi-val">${outdated}</span></div>
        <div class="comps-kpi ok"><span class="comps-kpi-lbl">Al dia</span><span class="comps-kpi-val">${upToDate}</span></div>
        <div class="comps-kpi"><span class="comps-kpi-lbl">Version n/d</span><span class="comps-kpi-val">${unknownVer}</span></div>
        <div class="comps-kpi"><span class="comps-kpi-lbl">Confianza media</span><span class="comps-kpi-val">${avgConf}%</span></div>
      </div>
      <div class="comps-core-row">
        <span class="comps-core-label">WordPress Core</span>
        <span class="comps-core-val ${r.wp_outdated ? 'is-outdated' : 'is-ok'}">${coreLabel}</span>
      </div>
    </div>`;

  if (!plugins.length && !themes.length && !timing.length) {
    return html + '<div class="no-results"><div class="nr-icon ic-plug"></div><p>No se detectaron componentes</p></div>';
  }

  if (plugins.length) {
    html += `
      <div class="comps-section">
        <div class="comps-section-head">
          <h4 class="comps-section-title">Plugins</h4>
          <span class="comps-section-count">${plugins.length}</span>
        </div>
        <div class="comp-grid comps-grid">${plugins.map(p => compCard(p, 'PLG')).join('')}</div>
      </div>`;
  }

  if (themes.length) {
    html += `
      <div class="comps-section">
        <div class="comps-section-head">
          <h4 class="comps-section-title">Temas</h4>
          <span class="comps-section-count">${themes.length}</span>
        </div>
        <div class="comp-grid comps-grid">${themes.map(t => compCard(t, 'THM')).join('')}</div>
      </div>`;
  }

  if (timing.length) {
    html += `
      <div class="comps-section comps-section-timing">
        <div class="comps-section-head">
          <h4 class="comps-section-title">Plugins detectados por timing</h4>
          <span class="comps-section-count">${timing.length}</span>
        </div>
        <div class="comp-grid comps-grid">
          ${timing.map(p => {
            const conf = Number.isFinite(Number(p && p.confidence)) ? Math.max(0, Math.min(100, Math.round(Number(p.confidence)))) : 0;
            return `<div class="comp-card comp-card-timing">
              <div class="comp-icon">TMG</div>
              <div style="flex:1;min-width:0">
                <div class="comp-head">
                  <div class="comp-name">${_esc((p && p.slug) || 'desconocido')}</div>
                  <span class="comp-timing-badge">TIMING</span>
                </div>
                <div class="comp-meta">avg: ${Number(p && p.avg_response_ms) || 0}ms · baseline: ${Number(p && p.baseline_ms) || 0}ms</div>
                <div class="comp-tags"><span class="comp-tag">conf. ${conf}%</span></div>
                <div class="conf-bar"><div class="conf-fill" style="width:${conf}%"></div></div>
              </div>
            </div>`;
          }).join('')}
        </div>
      </div>`;
  }

  return html;
}

function buildFilesTab(r) {
  const files = r.exposed_files || [];
  if (!files.length) return '<div class="no-results"><div class="nr-icon ic-ok"></div><p>No se encontraron archivos expuestos</p></div>';
  return files.map(f => {
    if (typeof f === 'string') f = {path:f, description:'', severity:'high', extra:''};
    const sColor = {critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',
                    low:'var(--green2)',info:'var(--cyan)'}[f.severity]||'var(--text2)';
    return `<div class="file-item" style="border-left-color:${sColor}">
      <div style="display:flex;align-items:center;gap:8px">
        <span class="sev-badge sev-${f.severity}" style="font-size:11px">${f.severity?.toUpperCase()}</span>
        <code style="color:var(--cyan);font-size:12px">${_esc(f.path)}</code>
        ${f.extra?`<span style="color:var(--yellow);font-size:11px">${f.extra}</span>`:''}
      </div>
      ${f.description?`<div style="color:var(--text2);font-size:11px;margin-top:4px">${_esc(f.description)}</div>`:''}
    </div>`;
  }).join('');
}
function buildTechTab(r) {
  const csp  = r.csp_analysis  || {};
  const hsts = r.hsts_analysis || {};
  const tls  = r.tls_analysis  || {};
  const cors = r.cors_issues   || {};
  const debug= r.debug_mode    || {};
  const rest = r.rest_api_issues || {};
  const redir= r.redirect_chain || {};
  const jst  = r.js_threats   || [];
  const stack= r.server_stack  || {};
  const postInj = r.post_injections || [];
  const rep  = r.reputation    || {};

  const statusDot = (ok, trueLabel='✓ OK', falseLabel='No') =>
    ok ? `<span class="wi-ok">${trueLabel}</span>` : `<span class="wi-warn">${falseLabel}</span>`;

  return `
  <div class="wp-grid" style="margin-bottom:18px">
    <div class="wp-item"><div class="wi-label">CSP</div>
      <div class="wi-value">${statusDot(csp.present,'✓ Presente','Ausente')}
        ${csp.unsafe_inline?'<span class="wi-bad" style="font-size:10px"> unsafe-inline</span>':''}
        ${csp.unsafe_eval?'<span class="wi-bad" style="font-size:10px"> unsafe-eval</span>':''}
      </div></div>
    <div class="wp-item"><div class="wi-label">HSTS</div>
      <div class="wi-value">${statusDot(hsts.present,`✓ max-age=${hsts.max_age||'?'}${hsts.include_subdomains?' includeSubDomains':''}`,
        'Ausente')}</div></div>
    <div class="wp-item"><div class="wi-label">TLS cipher</div>
      <div class="wi-value">${tls.cipher_suite||'<span class="wi-warn">N/D</span>'}
        ${tls.weak_cipher?'<span class="wi-bad" style="font-size:10px"> DÉBIL</span>':''}
      </div></div>
    <div class="wp-item"><div class="wi-label">HSTS Preload</div>
      <div class="wi-value">${statusDot(tls.hsts_preload,'✓ En lista preload','No en preload')}</div></div>
    <div class="wp-item"><div class="wi-label">Amenazas JS</div>
      <div class="wi-value">${jst.length?`<span class="wi-bad">${jst.length} detectadas</span>`:'<span class="wi-ok">✓ Limpias</span>'}</div></div>
    <div class="wp-item"><div class="wi-label">Reputación</div>
      <div class="wi-value">${rep.risk_level==='malicious'?'<span class="wi-bad badge-danger">MALICIOSO</span>':rep.risk_level==='suspicious'?'<span class="wi-warn">Sospechoso</span>':rep.risk_level?'<span class="wi-ok">✓ Limpio</span>':'<span class="wi-warn">No analizado</span>'}</div></div>
    <div class="wp-item"><div class="wi-label">Inyec. POST</div>
      <div class="wi-value">${postInj.length?`<span class="wi-bad">${postInj.length} hallazgos</span>`:'<span class="wi-ok">✓ Sin hallazgos</span>'}</div></div>
  </div>

  ${stack && Object.keys(stack).length ? `
  <div style="margin-bottom:14px">
    <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Stack tecnológico</div>
    <div class="wp-grid">${Object.entries(stack).filter(([,v])=>v).map(([k,v])=>`
      <div class="wp-item"><div class="wi-label">${k}</div><div class="wi-value">${v}</div></div>`).join('')}
    </div>
  </div>` : ''}

  ${jst.length ? `
  <div style="margin-bottom:14px">
    <div style="font-size:11px;color:var(--red);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Amenazas JS detectadas</div>
    ${jst.map(t=>`<div style="background:rgba(255,71,87,.1);border:1px solid rgba(255,71,87,.2);border-radius:4px;padding:8px 12px;margin:4px 0;font-size:12px;color:var(--text2)">${t}</div>`).join('')}
  </div>` : ''}

  ${postInj.length ? `
  <div>
    <div style="font-size:11px;color:var(--orange);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Inyecciones POST encontradas</div>
    ${postInj.map(i=>`<div style="background:rgba(255,107,53,.1);border:1px solid rgba(255,107,53,.2);border-radius:4px;padding:8px 12px;margin:4px 0;font-size:12px">
      <span class="sev-badge sev-high" style="font-size:11px">ALTO</span>
      <span style="margin-left:8px">${i.type||i.description||''}</span>
      <div style="color:var(--text3);font-size:10px;margin-top:4px">URL: ${i.url||''} | Field: ${i.field||''}</div>
    </div>`).join('')}
  </div>` : ''}`;
}
function buildActionTab(r) {
  const s = r.summary || {};
  const plan = [];
  const addPlan = (window, sev, title, detail, action) => {
    plan.push({ window, sev, title, detail, action });
  };

  const crit = s.critical_vulns || 0;
  const high = s.high_vulns || 0;

  if (crit > 0) addPlan(
    'ahora',
    'critical',
    'Corregir vulnerabilidades criticas',
    `${crit} hallazgo(s) critico(s) con riesgo elevado de explotacion.`,
    'Actualizar de inmediato plugins/tema/core afectados y aplicar mitigaciones temporales hasta verificar el parche.'
  );

  if (r.ssl_info?.expired) addPlan(
    'ahora',
    'critical',
    'Restaurar confianza TLS',
    'El certificado SSL esta expirado y puede provocar bloqueos en navegadores.',
    'Renovar certificado, recargar el servidor web y validar la cadena completa con un test externo.'
  );

  if (r.debug_mode?.debug_active) addPlan(
    'ahora',
    'high',
    'Desactivar modo debug en produccion',
    'WP_DEBUG activo expone informacion interna util para un atacante.',
    'Editar wp-config.php y establecer WP_DEBUG=false en el entorno publico.'
  );

  if (r.redirect_chain?.suspicious) addPlan(
    'ahora',
    'high',
    'Investigar redireccion sospechosa',
    'Se detecto un patron compatible con inyeccion o secuestro de trafico.',
    'Revisar .htaccess, wp-config.php y archivos PHP recientes antes de mantener el sitio en linea.'
  );

  if (r.rest_api_issues?.allows_edit_context) addPlan(
    'semana',
    'high',
    'Restringir REST API sensible',
    'El endpoint REST permite acceso a contexto de edicion sin controles suficientes.',
    'Limitar permisos por rol, restringir endpoints y bloquear acceso anonimo a rutas sensibles.'
  );

  if (high > 0) addPlan(
    'semana',
    'high',
    'Resolver vulnerabilidades altas',
    `${high} hallazgo(s) de severidad alta requieren cierre en esta ventana de trabajo.`,
    'Actualizar componentes afectados y revisar logs para confirmar que no hubo explotacion previa.'
  );

  if (r.cors_issues?.vulnerable) addPlan(
    'semana',
    'medium',
    'Corregir politica CORS',
    `Configuracion CORS vulnerable detectada en /wp-json/ (${r.cors_issues?.severity || 'high'}).`,
    'Definir allowlist de origenes validos y limitar metodos/cabeceras en el servidor web.'
  );

  if (r.tls_analysis?.deprecated_protocol) addPlan(
    'semana',
    'medium',
    'Retirar protocolos TLS obsoletos',
    `Se detectaron protocolos debiles: ${(r.tls_analysis.weak_protocol_list || []).join(', ') || 'TLS heredado'}.`,
    'Mantener solo TLS modernos (1.2/1.3) y cifrados robustos segun hardening de Apache/nginx.'
  );

  if (r.rest_api_issues?.exposes_emails) addPlan(
    'semana',
    'medium',
    'Evitar exposicion de correos por API',
    'El endpoint /wp-json/wp/v2/users expone datos personales que facilitan phishing.',
    'Aplicar plugin o filtro de WordPress para ocultar email y metadatos de usuarios.'
  );

  const outdatedCount = (s.outdated_plugins || 0) + (s.outdated_themes || 0);
  if (outdatedCount > 0) addPlan(
    'mes',
    'medium',
    'Completar ciclo de actualizacion funcional',
    `${outdatedCount} componente(s) estan fuera de version recomendada.`,
    `Actualizar ${s.outdated_plugins || 0} plugin(s) y ${s.outdated_themes || 0} tema(s) tras validar en staging.`
  );

  if (r.xmlrpc_enabled) addPlan(
    'mes',
    'medium',
    'Reducir superficie XML-RPC',
    'XML-RPC habilitado puede facilitar abuso automatizado y amplificacion de trafico.',
    'Desactivar XML-RPC si no es necesario o limitarlo a IPs de confianza.'
  );

  if (r.wp_cron_abuse?.abusable) addPlan(
    'mes',
    'medium',
    'Controlar ejecucion remota de wp-cron',
    'wp-cron accesible externamente permite disparo abusivo de tareas.',
    'Bloquear acceso publico a /wp-cron.php y mover la ejecucion a cron del sistema.'
  );

  if ((s.header_issues || 0) >= 3) addPlan(
    'seguimiento',
    'low',
    'Completar hardening de cabeceras HTTP',
    `${s.header_issues} cabecera(s) de seguridad faltante(s) detectada(s).`,
    'Configurar HSTS, CSP, X-Frame-Options y Referrer-Policy en el servidor.'
  );

  if ((s.users_found || 0) > 0) addPlan(
    'seguimiento',
    'low',
    'Reducir enumeracion de usuarios',
    `${s.users_found} usuario(s) se pueden enumerar desde endpoints publicos.`,
    'Ocultar login publico, aplicar 2FA y limitar respuestas de endpoints de autores.'
  );

  if (!(r.waf_detected || []).length) addPlan(
    'seguimiento',
    'low',
    'Incorporar capa WAF',
    'No se detecto proteccion perimetral contra bots y patrones de ataque comunes.',
    'Implementar WAF administrado o plugin con reglas actualizadas y modo bloqueo.'
  );

  if (!plan.length) {
    addPlan(
      'seguimiento',
      'low',
      'Mantener postura de seguridad',
      'No se identificaron riesgos inmediatos en este escaneo.',
      'Programar escaneo recurrente, backups verificados y revision mensual de plugins.'
    );
  }

  const windowOrder = { ahora: 0, semana: 1, mes: 2, seguimiento: 3 };
  const windowLabel = {
    ahora: 'Hoy (0-24h)',
    semana: 'Esta semana',
    mes: 'Este mes',
    seguimiento: 'Mejora continua',
  };
  const sevLabel = { critical: 'Critico', high: 'Alto', medium: 'Medio', low: 'Base' };

  plan.sort((a, b) => (windowOrder[a.window] || 9) - (windowOrder[b.window] || 9));
  const urgent = plan.filter(p => p.sev === 'critical' || p.sev === 'high').length;
  const improvements = plan.filter(p => p.sev === 'low').length;

  return `
  <div class="action-guide">
    <div class="action-guide-hero">
      <div class="action-guide-title">Plan guiado para nuevos usuarios</div>
      <div class="action-guide-sub">Sigue los pasos en orden. Cada tarjeta indica plazo, impacto y accion concreta.</div>
      <div class="action-guide-kpis">
        <div class="action-guide-kpi">
          <span>Pasos urgentes</span>
          <strong>${urgent}</strong>
        </div>
        <div class="action-guide-kpi">
          <span>Total de tareas</span>
          <strong>${plan.length}</strong>
        </div>
        <div class="action-guide-kpi">
          <span>Mejoras base</span>
          <strong>${improvements}</strong>
        </div>
      </div>
    </div>
    ${plan.map((item, idx) => `
    <div class="plan-item plan-item--${item.sev}">
      <div class="plan-priority-wrap">
        <div class="plan-priority">${windowLabel[item.window] || _esc(item.window)}</div>
        <span class="plan-step-id">Paso ${idx + 1}</span>
      </div>
      <div class="plan-main">
        <div class="plan-title">${_esc(item.title)} <span class="plan-sev-badge plan-sev-${item.sev}">${sevLabel[item.sev] || 'Info'}</span></div>
        <div class="plan-text">${_esc(item.detail)}</div>
        <div class="plan-step"><span>Accion recomendada:</span> ${_esc(item.action)}</div>
      </div>
    </div>`).join('')}
  </div>`;
}
function openCVEModal(vJson) {
  let v;
  try {
    v = (typeof vJson === 'object' && vJson !== null) ? vJson : JSON.parse(vJson);
  } catch(e) { return; }

  const sevLabel = {critical:'CRÍTICO',high:'ALTO',medium:'MEDIO',low:'BAJO',info:'INFO'}[v.severity]||v.severity?.toUpperCase();
  const cvss = parseFloat(v.cvss_score) || 0;
  let cvssVectors = [];
  if (v.cvss_vector) {
    const parts = v.cvss_vector.replace('CVSS:3.1/','').split('/');
    const labels = {
      'AV':'Attack Vector', 'AC':'Attack Complexity', 'PR':'Privileges Required',
      'UI':'User Interaction', 'S':'Scope', 'C':'Confidentiality', 'I':'Integrity', 'A':'Availability',
    };
    const values = {'N':'None','L':'Low','H':'High','P':'Physical','R':'Required','C':'Changed','U':'Unchanged','A':'Adjacent'};
    parts.forEach(p => {
      const [k, val] = p.split(':');
      if (labels[k]) cvssVectors.push({label: labels[k], value: values[val]||val, key: k, raw: val});
    });
  }

  const cvssColor = cvss >= 9 ? 'var(--red)' : cvss >= 7 ? 'var(--orange)' : cvss >= 4 ? 'var(--yellow)' : 'var(--green2)';
  const cvssBar = cvss > 0 ? `
    <div style="display:flex;align-items:center;gap:10px;margin:12px 0">
      <div style="flex:1;height:8px;background:var(--bg3);border-radius:4px;overflow:hidden">
        <div style="width:${cvss*10}%;height:100%;background:${cvssColor};border-radius:4px;transition:width 1s ease-out"></div>
      </div>
      <span style="color:${cvssColor};font-weight:700;font-size:16px">${cvss}</span>
    </div>` : '';

  const cvssGridHtml = cvssVectors.length ? `
    <div class="cvss-grid">${cvssVectors.map(c=>`
      <div class="cvss-component">
        <div class="cvss-label">${c.label}</div>
        <div class="cvss-value" style="color:${c.raw==='H'||c.raw==='C'?'var(--red)':c.raw==='L'||c.raw==='U'?'var(--yellow)':'var(--text)'}">${c.value}</div>
      </div>`).join('')}
    </div>` : '';

  document.getElementById('cveModalTitle').innerHTML =
    `<span class="sev-badge sev-${v.severity}">${sevLabel}</span>&nbsp; ${v.title}`;

  document.getElementById('cveModalBody').innerHTML = `
    <div style="color:var(--text2);font-size:12px;margin-bottom:12px">
      <span style="color:var(--cyan)">${_esc(v.plugin_slug)}</span>${v.plugin_version?' v'+_esc(v.plugin_version):''} &nbsp;·&nbsp;
      ${v.type==='wordpress'?'WordPress Core':v.type==='theme'?'Tema':'Plugin'}
    </div>

    ${cvss > 0 ? `<div style="font-size:13px;color:var(--text2);margin-bottom:4px">CVSS Score</div>${cvssBar}` : ''}
    ${cvssGridHtml}

    ${(v.kev || v.epss > 0) ? `
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin:10px 0">
      ${v.kev ? `<span style="background:rgba(255,69,96,.12);border:1px solid rgba(255,69,96,.35);border-radius:4px;
                             padding:4px 10px;font-size:11px;font-weight:700;color:var(--red)">
        🚨 CISA KEV — Explotada activamente en la naturaleza
      </span>` : ''}
      ${v.epss > 0 ? `<span style="background:rgba(255,122,61,.10);border:1px solid rgba(255,122,61,.28);border-radius:4px;
                             padding:4px 10px;font-size:11px;color:var(--orange)">
        EPSS ${Math.round(v.epss*100)}% — probabilidad de explotación en 30 días
      </span>` : ''}
      ${v.version_unconfirmed ? `<span style="background:rgba(255,184,48,.08);border:1px solid rgba(255,184,48,.3);border-radius:4px;
                             padding:4px 10px;font-size:11px;color:var(--amber)">
        ⚠ Versión no detectada — resultado no confirmado
      </span>` : ''}
    </div>` : ''}

    ${v.description ? `
    <div style="margin-top:14px">
      <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">Descripción</div>
      <div style="background:var(--bg3);border-radius:6px;padding:12px;font-size:12px;line-height:1.6;color:var(--text2)">${_esc(v.description)}</div>
    </div>` : ''}

    ${v.fixed_in ? `
    <div style="margin-top:12px;background:rgba(46,204,64,.08);border:1px solid rgba(46,204,64,.2);
                border-radius:6px;padding:10px 14px">
      <span style="color:var(--green2);font-weight:700">✓ Solución:</span>
      <span style="font-size:12px;margin-left:8px">Actualizar a versión ${_esc(v.fixed_in)} o superior</span>
    </div>` : `
    <div style="margin-top:12px;background:rgba(255,69,96,.06);border:1px solid rgba(255,69,96,.2);
                border-radius:6px;padding:10px 14px">
      <span style="color:var(--red);font-weight:700">⚠ Sin fix conocido.</span>
      <span style="font-size:12px;margin-left:8px">Considerar desactivar el componente hasta que el proveedor publique un parche.</span>
    </div>`}

    ${v.recommended_action ? `
    <div style="margin-top:10px;background:rgba(0,212,255,.06);border:1px solid rgba(0,212,255,.18);
                border-radius:6px;padding:10px 14px;display:flex;gap:10px;align-items:flex-start">
      <span style="font-size:16px">💡</span>
      <div>
        <div style="font-size:10px;font-weight:700;color:var(--cyan);text-transform:uppercase;letter-spacing:.8px;margin-bottom:3px">Acción recomendada</div>
        <div style="font-size:12px;color:var(--text);line-height:1.5">${_esc(v.recommended_action)}</div>
      </div>
    </div>` : ''}

    <div style="margin-top:14px">
      <div style="font-size:11px;color:var(--text3);text-transform:uppercase;letter-spacing:1px;margin-bottom:8px">Referencias</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${v.cve_id ? `
          <a href="https://nvd.nist.gov/vuln/detail/${v.cve_id}" target="_blank"
             style="background:rgba(0,190,255,.10);border:1px solid rgba(0,190,255,.28);border-radius:4px;
                    padding:5px 10px;font-size:11px;color:var(--cyan);text-decoration:none;font-weight:600">
            ${_esc(v.cve_id)} — NVD
          </a>
          <a href="https://github.com/advisories?query=${v.cve_id}" target="_blank"
             style="background:rgba(120,120,180,.10);border:1px solid rgba(120,120,180,.28);border-radius:4px;
                    padding:5px 10px;font-size:11px;color:var(--text-2);text-decoration:none;font-weight:600">
            GitHub Advisory
          </a>` : ''}
        ${(v.references||[]).map(ref=>`
          <a href="${ref}" target="_blank"
             style="background:var(--bg3);border:1px solid var(--bd2);border-radius:4px;
                    padding:5px 10px;font-size:11px;color:var(--text2);text-decoration:none">
            → ${ref.replace('https://','').slice(0,40)}...
          </a>`).join('')}
      </div>
    </div>`;
  const nvdBtn = document.getElementById('cveNVDBtn');
  const ghBtn = document.getElementById('cveGHBtn');
  const exploitBtn = document.getElementById('cveExploitBtn');
  if (v.cve_id) {
    nvdBtn.onclick   = () => window.open(`https://nvd.nist.gov/vuln/detail/${v.cve_id}`, '_blank');
    ghBtn.onclick    = () => window.open(`https://github.com/advisories?query=${v.cve_id}`, '_blank');
    exploitBtn.onclick = () => window.open(`https://www.exploit-db.com/search?cve=${v.cve_id}`, '_blank');
    nvdBtn.style.display = ghBtn.style.display = exploitBtn.style.display = '';
  } else {
    nvdBtn.style.display = ghBtn.style.display = 'none';
    exploitBtn.onclick = () => window.open(`https://www.exploit-db.com/search?q=${encodeURIComponent(v.plugin_slug+' '+v.title)}`, '_blank');
  }

  const modal = document.getElementById('cveModal');
  document._lastCveFocus = document.activeElement;
  modal.style.display = 'flex';
  modal.setAttribute('aria-hidden', 'false');
  setTimeout(() => {
    document.getElementById('closeCveModalBtn')?.focus();
  }, 0);
}

function closeCVEModal() {
  const modal = document.getElementById('cveModal');
  modal.style.display = 'none';
  modal.setAttribute('aria-hidden', 'true');
  if (document._lastCveFocus && typeof document._lastCveFocus.focus === 'function') {
    document._lastCveFocus.focus();
    document._lastCveFocus = null;
  }
}
function showToast(msg, type = 'ok', duration = 4500) {
  const container = document.getElementById('wpvs-toast-container');
  if (!container) return;
  const existing = container.querySelectorAll('.wpvs-toast');
  if (existing.length >= 3) existing[0].remove();
  const t = document.createElement('div');
  t.className = `wpvs-toast ${type}`;
  t.setAttribute('role', 'status');
  t.setAttribute('aria-live', type === 'err' ? 'assertive' : 'polite');
  t.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:10px';
  const txt = document.createElement('span');
  txt.textContent = msg;
  const cls = document.createElement('button');
  cls.textContent = '×';
  cls.setAttribute('aria-label', 'Cerrar notificación');
  cls.style.cssText = 'background:none;border:none;cursor:pointer;font-size:16px;line-height:1;padding:0;color:inherit;opacity:.7;flex-shrink:0';
  cls.onclick = () => dismissToast(t);
  t.appendChild(txt);
  t.appendChild(cls);
  container.appendChild(t);
  const timer = setTimeout(() => dismissToast(t), duration);
  t._timer = timer;
}
function dismissToast(t) {
  clearTimeout(t._timer);
  t.classList.add('out');
  setTimeout(() => { if (t.parentNode) t.remove(); }, 320);
}
function toggleTheme() {
  const isLight = document.documentElement.classList.toggle('light');
  try { localStorage.setItem('wpvs_theme', isLight ? 'light' : 'dark'); } catch(e){}
  const dark  = document.getElementById('themeIconDark');
  const light = document.getElementById('themeIconLight');
  if (dark)  dark.style.display  = isLight ? 'none'  : '';
  if (light) light.style.display = isLight ? ''      : 'none';
}
(function applyTheme(){
  try {
    const saved = localStorage.getItem('wpvs_theme');
    if (saved === 'light') {
      document.documentElement.classList.add('light');
      const dark  = document.getElementById('themeIconDark');
      const light = document.getElementById('themeIconLight');
      if (dark)  dark.style.display  = 'none';
      if (light) light.style.display = '';
    }
  } catch(e){}
})();
function animateRiskScore(targetScore, color) {
  const el = _el('riskNum');
  if (!el) return;
  el.classList.add('animating');
  const duration = 1200;
  const start    = performance.now();
  const from     = 0;

  function step(now) {
    const progress = Math.min((now - start) / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);  // ease-out cubic
    const current  = Math.round(from + (targetScore - from) * eased);
    el.textContent = current;
    el.style.color = color;
    if (progress < 1) requestAnimationFrame(step);
    else el.classList.remove('animating');
  }
  requestAnimationFrame(step);
}
async function loadRiskTimeline(targetUrl) {
  try {
    const domain  = new URL(targetUrl.startsWith('http') ? targetUrl : 'https://'+targetUrl).hostname;
    const res     = await apiFetch(`/api/history/by-url?url=${encodeURIComponent(domain)}&limit=10`);
    if (!res.ok) return;
    const history = await res.json();
    if (!Array.isArray(history)) return;

    const ordered = history.slice().reverse();
    const scores = ordered.map(h => h.risk_score || 0);
    const labels = ordered.map(h => (h.scanned_at || '').slice(5, 10));
    _riskTimelineDataCache[domain] = { scores, labels, ordered };

    if (currentTab === 'surface' && currentResult) {
      renderTab._cache = null;
      renderTab('surface', currentResult);
    }

    if (ordered.length < 2) return;

    const el = document.getElementById('riskTimeline');
    if (!el) return;
    el.style.display = 'block';

    const canvas = document.getElementById('riskTimelineChart');
    if (typeof Chart === 'undefined') return;
    if (canvas._chart) canvas._chart.destroy();
    canvas._chart = new Chart(canvas.getContext('2d'), {
      type: 'line',
      data: {
        labels,
        datasets: [{
          data: scores,
          borderColor: '#39ff14',
          backgroundColor: 'rgba(57,255,20,.08)',
          borderWidth: 2,
          pointBackgroundColor: '#39ff14',
          pointRadius: 3,
          fill: true,
          tension: 0.3,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#8b949e', font: { size: 9 } }, grid: { color: '#21262d' } },
          y: { min: 0, max: 100, ticks: { color: '#8b949e', font: { size: 9 } }, grid: { color: '#21262d' } }
        }
      }
    });
  } catch(e) {
  }
}

function _renderAutoDiffCard(payload) {
  const panel = document.getElementById('autoDiffPanel');
  if (!panel) return;

  if (!payload || !payload.has_previous || !payload.diff) {
    panel.style.display = 'none';
    panel.innerHTML = '';
    return;
  }

  const d = payload.diff || {};
  const s = d.summary || {};
  const riskDelta = Number(d.risk_delta || 0);
  const status = String(d.status || (riskDelta < 0 ? 'MEJORADO' : riskDelta > 0 ? 'EMPEORADO' : 'SIN CAMBIOS'));
  const statusColor = d.status_color || (riskDelta < 0 ? 'var(--green2)' : riskDelta > 0 ? 'var(--red)' : 'var(--text-3)');
  const oldId = payload.previous_scan_id || d.scan_old_id || '';
  const newId = payload.scan_id || d.scan_new_id || currentJobId || '';
  const oldDate = payload.previous_scanned_at || d.scan_old_date || 'escaneo anterior';
  const riskDeltaTxt = riskDelta === 0 ? '0' : `${riskDelta > 0 ? '+' : ''}${riskDelta}`;

  panel.style.display = 'block';
  panel.innerHTML = `
    <div style="background:var(--bg-3);border:1px solid var(--border-2);border-radius:8px;padding:10px 12px">
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">
        <span style="font-size:10px;font-family:var(--head);letter-spacing:.7px;text-transform:uppercase;color:var(--text-3)">Auto-Diff</span>
        <strong style="font-size:12px;color:${statusColor}">${_esc(status)}</strong>
        <span style="font-size:11px;color:var(--text-3)">vs ${_esc(oldDate)}</span>
        ${oldId && newId ? `<a href="/compare?id1=${encodeURIComponent(oldId)}&id2=${encodeURIComponent(newId)}" style="margin-left:auto;font-size:11px;color:var(--cyan);text-decoration:none">Abrir comparativa completa ↗</a>` : ''}
      </div>
      <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px">
        <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px">
          <div style="font-size:10px;color:var(--text-3)">Delta de riesgo</div>
          <div style="font-size:14px;font-weight:700;color:${riskDelta <= 0 ? 'var(--green2)' : 'var(--red)'}">${_esc(riskDeltaTxt)}</div>
        </div>
        <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px">
          <div style="font-size:10px;color:var(--text-3)">Vulns corregidas</div>
          <div style="font-size:14px;font-weight:700;color:var(--green2)">${Number(s.fixed_vulns || 0)}</div>
        </div>
        <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px">
          <div style="font-size:10px;color:var(--text-3)">Vulns nuevas</div>
          <div style="font-size:14px;font-weight:700;color:${Number(s.new_vulns || 0) > 0 ? 'var(--red)' : 'var(--text-2)'}">${Number(s.new_vulns || 0)}</div>
        </div>
        <div style="background:var(--bg-2);border:1px solid var(--border);border-radius:6px;padding:8px">
          <div style="font-size:10px;color:var(--text-3)">Archivos expuestos</div>
          <div style="font-size:14px;font-weight:700;color:var(--text-2)">+${Number(s.new_files || 0)} / -${Number(s.fixed_files || 0)}</div>
        </div>
      </div>
    </div>`;
}

async function loadAutoDiff(scanId) {
  const panel = document.getElementById('autoDiffPanel');
  if (!panel) return;

  panel.style.display = 'none';
  panel.innerHTML = '';
  if (!scanId) return;

  if (_autoDiffCache[scanId]) {
    _renderAutoDiffCard(_autoDiffCache[scanId]);
    if (currentTab === 'surface' && currentResult) {
      renderTab._cache = null;
      renderTab('surface', currentResult);
    }
    return;
  }

  try {
    const res = await apiFetch(`/api/history/auto-diff?scan_id=${encodeURIComponent(scanId)}`);
    if (!res.ok) return;
    const payload = await res.json();
    _autoDiffCache[scanId] = payload;
    _renderAutoDiffCard(payload);
    if (currentTab === 'surface' && currentResult) {
      renderTab._cache = null;
      renderTab('surface', currentResult);
    }
  } catch (_) {
  }
}
function downloadExcel() {
  if (!currentJobId) { showToast('⚠️ Completa un escaneo primero', 'warn'); return; }
  console.log('[Export] Iniciando descarga Excel:', `/scan/${currentJobId}/excel`);
  _triggerDownload(`/scan/${currentJobId}/excel`);
}

function downloadCSV() {
  if (!currentJobId) { showToast('⚠️ Completa un escaneo primero', 'warn'); return; }
  console.log('[Export] Iniciando descarga CSV:', `/scan/${currentJobId}/csv`);
  _triggerDownload(`/scan/${currentJobId}/csv`);
}

function downloadSARIF() {
  if (!currentJobId) { showToast('⚠️ Completa un escaneo primero', 'warn'); return; }
  console.log('[Export] Iniciando descarga SARIF:', `/scan/${currentJobId}/sarif`);
  _triggerDownload(`/scan/${currentJobId}/sarif`);
}

function downloadMarkdown() {
  if (!currentJobId) { showToast('⚠️ Completa un escaneo primero', 'warn'); return; }
  console.log('[Export] Iniciando descarga Markdown:', `/scan/${currentJobId}/markdown`);
  _triggerDownload(`/scan/${currentJobId}/markdown`);
  showToast('Markdown descargado — listo para Notion, Confluence o GitHub', 'ok');
}

function copyPermalink(btn) {
  if (!currentJobId) { showToast('Primero realiza un escaneo', 'warn'); return; }
  const url = `${location.origin}/r/${currentJobId}`;
  navigator.clipboard.writeText(url).then(() => {
    showToast('Enlace permanente copiado', 'ok');
    if (btn) {
      const orig = btn.innerHTML;
      btn.textContent = '✓ Copiado';
      setTimeout(() => { btn.innerHTML = orig; }, 2000);
    }
  }).catch(() => {
    prompt('Copia este enlace:', url);
  });
}


function openAttackMap() {
  if (!currentJobId) { showToast('Primero realiza un escaneo', 'warn'); return; }
  const overlay = document.getElementById('mapOverlay');
  const iframe  = document.getElementById('mapIframe');
  document._lastMapFocus = document.activeElement;
  iframe.src = `/attack-map/${currentJobId}`;
  overlay.classList.add('open');
  overlay.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  setTimeout(() => {
    document.getElementById('mapCloseBtn')?.focus();
  }, 0);
  document._mapEscHandler = e => {
    if (e.key === 'Escape') {
      closeAttackMap();
      return;
    }
    _trapFocusIn(overlay, e);
  };
  document.addEventListener('keydown', document._mapEscHandler);
  document._mapMsgHandler = e => { if (e.data === 'closeAttackMap') closeAttackMap(); };
  window.addEventListener('message', document._mapMsgHandler);
}

function closeAttackMap() {
  const overlay = document.getElementById('mapOverlay');
  const iframe  = document.getElementById('mapIframe');
  overlay.classList.remove('open');
  overlay.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
  setTimeout(() => { iframe.src = ''; }, 300); // clear after animation
  if (document._mapEscHandler) document.removeEventListener('keydown', document._mapEscHandler);
  if (document._mapMsgHandler) window.removeEventListener('message', document._mapMsgHandler);
  if (document._lastMapFocus && typeof document._lastMapFocus.focus === 'function') {
    document._lastMapFocus.focus();
    document._lastMapFocus = null;
  }
}
function startStream(jobId) { connectStream(jobId); }

function _sevColor(sev) {
  return {critical:'var(--red)',high:'var(--orange)',medium:'var(--amber)',low:'var(--text-2)',none:'var(--text-3)'}[sev] || 'var(--text-2)';
}
function _sevBg(sev) {
  return {critical:'rgba(229,72,77,.15)',high:'rgba(244,117,58,.15)',medium:'rgba(245,163,26,.12)',low:'rgba(136,144,176,.1)',none:'transparent'}[sev] || 'transparent';
}
function _sevLabel(sev) {
  return {critical:'CRÍTICO',high:'ALTO',medium:'MEDIO',low:'BAJO',none:'INFO'}[sev] || (sev||'').toUpperCase();
}

function renderCoreIntegrity(r) {
  const ci = r.core_integrity || {};
  const forbidden = ci.forbidden_files || [];
  const malware   = ci.malware_in_core || [];
  const mismatches= ci.checksum_mismatches || [];
  const total     = forbidden.length + malware.length + mismatches.length;
  if (total === 0 && !ci.official_checksums) return '';

  const sev = ci.severity || 'none';
  const iconColor = _sevColor(sev);

  let body = '';

  if (malware.length > 0) {
    body += `<div style="margin:12px 0 6px;font-size:11px;font-weight:700;color:var(--red);letter-spacing:.5px;font-family:var(--head)">PATRONES DE MALWARE EN ARCHIVOS CORE</div>`;
    body += malware.map(m => `
      <div class="finding-row">
        <span class="finding-sev" style="background:rgba(229,72,77,.15);color:var(--red)">CRÍTICO</span>
        <div class="finding-text">
          <div class="finding-title">${m.pattern}</div>
          <div class="finding-url">${m.url}</div>
        </div>
      </div>`).join('');
  }

  if (mismatches.length > 0) {
    body += `<div style="margin:12px 0 6px;font-size:11px;font-weight:700;color:var(--orange);letter-spacing:.5px;font-family:var(--head)">CHECKSUMS DIFERENTES AL OFICIAL</div>`;
    body += mismatches.map(m => `
      <div class="finding-row">
        <span class="finding-sev" style="background:rgba(244,117,58,.15);color:var(--orange)">ALTO</span>
        <div class="finding-text">
          <div class="finding-title">${m.file}</div>
          <div class="integrity-hash">Esperado: <span class="integrity-ok">${m.expected}</span></div>
          <div class="integrity-hash">Actual: <span class="integrity-fail">${m.actual}</span></div>
          <div class="finding-note">${m.note}</div>
        </div>
      </div>`).join('');
  }

  if (forbidden.length > 0) {
    body += `<div style="margin:12px 0 6px;font-size:11px;font-weight:700;color:var(--text-2);letter-spacing:.5px;font-family:var(--head)">ARCHIVOS SENSIBLES ACCESIBLES</div>`;
    body += forbidden.map(f => `
      <div class="finding-row">
        <span class="finding-sev" style="background:${_sevBg(f.severity)};color:${_sevColor(f.severity)}">${_sevLabel(f.severity)}</span>
        <div class="finding-text">
          <div class="finding-title"><a href="${(/^https?:\/\//i.test(f.url||''))?f.url:'#'}" target="_blank" rel="noopener noreferrer" style="color:var(--blue)">${_esc(f.path)}</a></div>
          <div class="finding-note">${_esc(f.description)}</div>
        </div>
      </div>`).join('');
  }

  if (total === 0) {
    body = `<div class="no-findings"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>Integridad del core verificada correctamente${ci.official_checksums ? ' (checksums oficiales)' : ''}</div>`;
  }

  return `<div class="module-section">
    <div class="module-header" onclick="this.nextElementSibling.classList.toggle('open');this.querySelector('.module-chevron').classList.toggle('open')">
      <div class="module-header-icon" style="background:${_sevBg(sev)};color:${iconColor}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg>
      </div>
      <div class="module-header-text">
        <div class="module-header-title">Integridad del Core</div>
        <div class="module-header-sub">WordPress core · ${total} hallazgo${total!==1?'s':''} · ${ci.wp_version_checked||'versión desconocida'}</div>
      </div>
      ${total > 0 ? `<span class="module-badge" style="background:${_sevBg(sev)};color:${iconColor}">${total}</span>` : ''}
      <span class="module-chevron">▾</span>
    </div>
    <div class="module-body ${total>0?'open':''}">${body}</div>
  </div>`;
}

function renderBackupFiles(r) {
  const bf = r.backup_files || {};
  const exposed = bf.exposed || [];
  if (exposed.length === 0) return '';

  const sev = bf.severity || 'none';
  let body = exposed.map(f => `
    <div class="finding-row">
      <span class="finding-sev" style="background:${_sevBg(f.severity)};color:${_sevColor(f.severity)}">${_sevLabel(f.severity)}</span>
      <div class="finding-text">
        <div class="finding-title"><a href="${(/^https?:\/\//i.test(f.url||''))?f.url:'#'}" target="_blank" rel="noopener noreferrer" style="color:var(--blue)">${_esc(f.path)}</a></div>
        ${f.note ? `<div class="finding-note">${f.note}</div>` : ''}
      </div>
    </div>`).join('');

  return `<div class="module-section">
    <div class="module-header" onclick="this.nextElementSibling.classList.toggle('open');this.querySelector('.module-chevron').classList.toggle('open')">
      <div class="module-header-icon" style="background:${_sevBg(sev)};color:${_sevColor(sev)}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><polyline points="21 8 21 21 3 21 3 8"/><rect x="1" y="3" width="22" height="5"/><line x1="10" y1="12" x2="14" y2="12"/></svg>
      </div>
      <div class="module-header-text">
        <div class="module-header-title">Backups y Archivos Sensibles</div>
        <div class="module-header-sub">${exposed.length} archivo${exposed.length!==1?'s':''} accesible${exposed.length!==1?'s':''}${bf.git_exposed?' · Git expuesto':''}${bf.sql_dump_exposed?' · Dump SQL expuesto':''}</div>
      </div>
      <span class="module-badge" style="background:${_sevBg(sev)};color:${_sevColor(sev)}">${exposed.length}</span>
      <span class="module-chevron open">▾</span>
    </div>
    <div class="module-body open">${body}</div>
  </div>`;
}

function renderJsAnalysis(r) {
  const js = r.js_analysis || {};
  const libs    = js.vulnerable_libs  || [];
  const unknown = js.unknown_cdn_srcs || [];
  const noSri   = js.missing_sri      || [];
  const total   = libs.length + unknown.length;
  if (total === 0 && noSri.length === 0) return '';

  const sev = js.severity || 'none';
  let body = '';

  if (libs.length > 0) {
    body += `<div style="margin:12px 0 6px;font-size:11px;font-weight:700;color:var(--text-2);letter-spacing:.5px;font-family:var(--head)">LIBRERÍAS JS VULNERABLES</div>`;
    body += libs.map(l => `
      <div class="js-lib-row">
        <div class="js-lib-name">${l.library}</div>
        <span class="js-lib-ver">${l.version}</span>
        <span class="finding-sev" style="background:${_sevBg(l.severity)};color:${_sevColor(l.severity)}">${_sevLabel(l.severity)}</span>
        <div class="js-lib-cves">${l.cves}</div>
      </div>
      <div style="font-size:11px;color:var(--text-2);padding:2px 0 8px">${l.description}</div>`).join('');
  }

  if (unknown.length > 0) {
    body += `<div style="margin:12px 0 6px;font-size:11px;font-weight:700;color:var(--text-2);letter-spacing:.5px;font-family:var(--head)">CDNs NO RECONOCIDOS</div>`;
    body += unknown.map(u => `
      <div class="finding-row">
        <span class="finding-sev" style="background:rgba(136,144,176,.1);color:var(--text-2)">BAJO</span>
        <div class="finding-text">
          <div class="finding-title">${u.domain}</div>
          <div class="finding-url">${u.url}</div>
        </div>
      </div>`).join('');
  }

  if (noSri.length > 0) {
    body += `<div style="margin:12px 0 6px;font-size:11px;font-weight:700;color:var(--text-2);letter-spacing:.5px;font-family:var(--head)">SCRIPTS SIN INTEGRIDAD (SRI)</div>`;
    body += noSri.slice(0,5).map(s => `
      <div class="finding-row">
        <span class="finding-sev" style="background:rgba(245,163,26,.12);color:var(--amber)">MEDIO</span>
        <div class="finding-text">
          <div class="finding-url">${s.url}</div>
          <div class="finding-note">${s.note}</div>
        </div>
      </div>`).join('');
  }

  return `<div class="module-section">
    <div class="module-header" onclick="this.nextElementSibling.classList.toggle('open');this.querySelector('.module-chevron').classList.toggle('open')">
      <div class="module-header-icon" style="background:${_sevBg(sev)};color:${_sevColor(sev)}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg>
      </div>
      <div class="module-header-text">
        <div class="module-header-title">Dependencias JavaScript</div>
        <div class="module-header-sub">${libs.length} librería${libs.length!==1?'s':''} vulnerable${libs.length!==1?'s':''} · ${noSri.length} sin SRI · ${unknown.length} CDN desconocido${unknown.length!==1?'s':''}</div>
      </div>
      ${libs.length > 0 ? `<span class="module-badge" style="background:${_sevBg(sev)};color:${_sevColor(sev)}">${libs.length}</span>` : ''}
      <span class="module-chevron ${libs.length>0?'open':''}">▾</span>
    </div>
    <div class="module-body ${libs.length>0?'open':''}">${body}</div>
  </div>`;
}

function renderAdvancedUsers(r) {
  const ua = r.users_advanced || {};
  const users = ua.users || [];
  const techniques = ua.techniques_used || [];
  if (users.length === 0 && !ua.login_enumerable) return '';

  const sev = ua.severity || 'none';
  let body = '';

  if (ua.login_enumerable) {
    body += `<div class="finding-row" style="margin-bottom:4px">
      <span class="finding-sev" style="background:rgba(244,117,58,.15);color:var(--orange)">ALTO</span>
      <div class="finding-text">
        <div class="finding-title">Login enumerable por mensajes de error diferenciados</div>
        <div class="finding-note">El formulario de login devuelve mensajes distintos para usuario válido vs inválido</div>
      </div>
    </div>`;
  }

  if (users.length > 0) {
    body += `<div style="margin:12px 0 6px;font-size:11px;color:var(--text-3);letter-spacing:.5px;font-family:var(--head)">USUARIOS ENUMERADOS · técnicas: ${techniques.join(', ')||'N/A'}</div>`;
    body += users.map(u => `
      <div class="user-row">
        <div class="user-avatar">${(u.login||'?')[0].toUpperCase()}</div>
        <div>
          <div class="user-login">${_esc(u.login)}</div>
          ${u.display_name && u.display_name !== u.login ? `<div class="user-display">${_esc(u.display_name)}</div>` : ''}
          ${u.email ? `<div class="user-email">${u.email}</div>` : ''}
        </div>
        <span class="user-source">${u.source||''}</span>
      </div>`).join('');
  }

  return `<div class="module-section">
    <div class="module-header" onclick="this.nextElementSibling.classList.toggle('open');this.querySelector('.module-chevron').classList.toggle('open')">
      <div class="module-header-icon" style="background:${_sevBg(sev)};color:${_sevColor(sev)}">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
      </div>
      <div class="module-header-text">
        <div class="module-header-title">Enumeración Avanzada de Usuarios</div>
        <div class="module-header-sub">${users.length} usuario${users.length!==1?'s':''} detectado${users.length!==1?'s':''}${ua.login_enumerable?' · login enumerable':''}${ua.author_archive_enumerable?' · author archive expuesto':''}</div>
      </div>
      ${users.length > 0 ? `<span class="module-badge" style="background:${_sevBg(sev)};color:${_sevColor(sev)}">${users.length}</span>` : ''}
      <span class="module-chevron ${users.length>0?'open':''}">▾</span>
    </div>
    <div class="module-body ${users.length>0?'open':''}">${body}</div>
  </div>`;
}
const _origBuildInfoTab = buildInfoTab;
buildInfoTab = function(r) {
  let html = _origBuildInfoTab(r);
  html += renderCoreIntegrity(r);
  html += renderBackupFiles(r);
  html += renderJsAnalysis(r);
  html += renderAdvancedUsers(r);
  html += renderPassiveFingerprints(r);  // v5.9: passive fingerprinting
  return html;
};
function renderPassiveFingerprints(r) {
  const pf = r.passive_fingerprints || {};
  const findings = pf.findings || [];
  const emails = r.exposed_emails || pf.exposed_emails || [];
  const keys = pf.hardcoded_keys || [];

  if (!findings.length && !emails.length && !keys.length) return '';

  const sevClr = {
    critical: 'var(--red)',   high:   'var(--orange)',
    medium:   'var(--amber)', low:    'var(--text-2)',
    info:     'var(--blue)',  none:   'var(--text-3)',
  };

  const rows = findings.map(f => {
    const clr = sevClr[f.severity] || sevClr.info;
    const sevLabel = (f.severity || 'info').toUpperCase();
    return `<div class="finding-row">
      <span class="finding-sev" style="background:${clr}22;color:${clr};border:1px solid ${clr}44">${_esc(sevLabel)}</span>
      <div class="finding-text">
        <div class="finding-title">${_esc(f.issue || '')}</div>
        ${f.detail ? `<div class="finding-note">${_esc(f.detail)}</div>` : ''}
      </div>
    </div>`;
  }).join('');

  const emailsHtml = emails.length
    ? `<div style="margin-top:10px;padding:10px 12px;background:var(--amber-dim);border:1px solid rgba(255,184,48,.2);border-radius:var(--radius)">
        <div style="font-size:10px;font-family:var(--head);font-weight:700;letter-spacing:.5px;color:var(--amber);margin-bottom:6px">EMAILS EXPUESTOS EN HTML</div>
        ${emails.map(e => `<code style="display:inline-block;margin:2px;font-size:11px;color:var(--amber)">${_esc(e)}</code>`).join('')}
        <div style="font-size:10px;color:var(--text-2);margin-top:6px;font-family:var(--sans)">Pueden usarse para phishing o ataques de fuerza bruta al login.</div>
      </div>` : '';

  const totalBadge = findings.length + emails.length;
  const hasCrit = findings.some(f => f.severity === 'critical');

  return `<div class="module-section" id="modPassive">
    <div class="module-header" onclick="this.nextElementSibling.classList.toggle('open');this.querySelector('.module-chevron').classList.toggle('open')">
      <div class="module-header-icon" style="background:rgba(0,200,190,.1)">
        <svg viewBox="0 0 24 24" fill="none" stroke="var(--teal)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
        </svg>
      </div>
      <div class="module-header-text">
        <div class="module-header-title">Fingerprinting pasivo</div>
        <div class="module-header-sub">Información sensible detectada en cabeceras y HTML sin peticiones activas</div>
      </div>
      <span class="module-badge" style="background:${hasCrit ? 'var(--red-dim)' : 'rgba(0,200,190,.12)'};color:${hasCrit ? 'var(--red)' : 'var(--teal)'}">${totalBadge}</span>
      <span class="module-chevron">▾</span>
    </div>
    <div class="module-body">
      ${rows}
      ${emailsHtml}
    </div>
  </div>`;
}
function renderRemediationSteps(v) {
  const action = v.recommended_action || '';
  if (!action) return '';
  const urgencyMatch = action.match(/^\[([^\]]+)\]\s*/);
  const urgency = urgencyMatch ? urgencyMatch[1] : null;
  const stepsRaw = urgency ? action.slice(urgencyMatch[0].length) : action;
  const steps = stepsRaw.split(' → ').filter(Boolean);

  if (steps.length <= 1) {
    return `<div class="action-tag">💡 ${_esc(action)}</div>`;
  }

  const urgencyClr = urgency && urgency.includes('INMEDIATA') ? 'var(--red)'
    : urgency && urgency.includes('SEMANA') ? 'var(--orange)'
    : 'var(--amber)';

  return `<div style="margin-top:8px;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden">
    ${urgency ? `<div style="padding:5px 10px;background:${urgencyClr}22;border-bottom:1px solid var(--border);font-family:var(--head);font-size:10px;font-weight:700;letter-spacing:.5px;color:${urgencyClr}">⏱ ${_esc(urgency)}</div>` : ''}
    ${steps.map((s, i) => `
      <div style="display:flex;gap:10px;align-items:flex-start;padding:7px 10px;${i < steps.length - 1 ? 'border-bottom:1px solid var(--border);' : ''}background:var(--bg-3)">
        <span style="font-family:var(--head);font-size:10px;font-weight:700;color:var(--blue);min-width:18px;flex-shrink:0">${i + 1}</span>
        <span style="font-size:11px;color:var(--text-2);font-family:var(--sans);line-height:1.5">${_esc(s)}</span>
      </div>`).join('')}
  </div>`;
}
let _pwaPrompt = null;

window.addEventListener('beforeinstallprompt', (e) => {
  e.preventDefault();
  _pwaPrompt = e;
  const btn = document.getElementById('pwaInstallBtn');
  if (btn) btn.classList.add('visible');
});

function installPWA() {
  if (!_pwaPrompt) return;
  _pwaPrompt.prompt();
  _pwaPrompt.userChoice.then(choice => {
    if (choice.outcome === 'accepted') {
      const btn = document.getElementById('pwaInstallBtn');
      if (btn) btn.classList.remove('visible');
    }
    _pwaPrompt = null;
  });
}
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/static/sw.js').catch(e => {
      console.warn('[PWA] SW registration failed:', e);
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  const _apiKeyMeta = document.getElementById('__wpvs_api_key');
  if (_apiKeyMeta && _apiKeyMeta.value) {
    try { localStorage.setItem('wpvs_api_key', _apiKeyMeta.value); } catch(e) {}
  }
  const urlInput = document.getElementById('urlInput');
  if (urlInput) {
    urlInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') startScan();
    });
    urlInput.addEventListener('input', _detectWordPressDebounce);
  }
  const historyHeader = document.getElementById('historyHeader');
  if (historyHeader) {
    historyHeader.addEventListener('click', toggleHistory);
    historyHeader.addEventListener('keydown', e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        toggleHistory();
      }
    });
  }
  // ✅ Event delegation para history rows (previene memory leak de listeners)
  const historyBody = document.getElementById('historyBody');
  if (historyBody) {
    historyBody.addEventListener('click', (e) => {
      const row = e.target.closest('.history-row[data-scan-id]');
      if (row) {
        const scanId = row.getAttribute('data-scan-id');
        if (scanId) loadFromHistory(scanId);
      }
    });
  }
  const histSearch = document.getElementById('histSearch');
  if (histSearch) histSearch.addEventListener('input', _histSearchDebounce);
  const histRiskSel = document.getElementById('histRiskSel');
  if (histRiskSel) histRiskSel.addEventListener('change', () => loadHistory(true));
  const histSearchClear = document.getElementById('histSearchClear');
  if (histSearchClear) {
    histSearchClear.addEventListener('click', () => {
      if (histSearch) histSearch.value = '';
      loadHistory(true);
    });
  }
  const histLoadMoreBtn = document.getElementById('histLoadMoreBtn');
  if (histLoadMoreBtn) histLoadMoreBtn.addEventListener('click', loadHistoryMore);
  const retryBtn = document.getElementById('scanRetryBtn');
  if (retryBtn) retryBtn.addEventListener('click', startScan);
  const termToggleBtn = document.getElementById('termToggleBtn');
  if (termToggleBtn) termToggleBtn.addEventListener('click', toggleTerminal);
  const termFullBtn = document.getElementById('termFullBtn');
  if (termFullBtn) termFullBtn.addEventListener('click', toggleTermFullscreen);
  const termScrollBtn = document.getElementById('termScrollBtn');
  if (termScrollBtn) termScrollBtn.addEventListener('click', scrollTermToBottom);
  document.getElementById('scanBtn')?.addEventListener('click', startScan);
  document.getElementById('dbUpdateBtn')?.addEventListener('click', triggerDbUpdate);
  document.getElementById('legalCheck')?.addEventListener('change', e => onLegalChange(e.target));
  document.getElementById('onboardDismissBtn')?.addEventListener('click', dismissOnboard);
  document.getElementById('mapCloseBtn')?.addEventListener('click', closeAttackMap);
  document.getElementById('newScanBtn')?.addEventListener('click', newScan);
  document.getElementById('btnRescan')?.addEventListener('click', rescanTarget);
  document.getElementById('openAttackMapBtn')?.addEventListener('click', openAttackMap);
  document.getElementById('downloadExecutivePdfBtn')?.addEventListener('click', downloadExecutivePDF);
  const exportBtn = document.getElementById('exportDropBtn');
  const exportMenu = document.getElementById('exportMenu');
  exportBtn?.addEventListener('keydown', e => {
    if (e.key === 'ArrowDown' || e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      if (exportMenu?.style.display !== 'block') toggleExportMenu();
    }
  });
  exportMenu?.addEventListener('keydown', e => {
    const items = _menuItems(exportMenu);
    if (!items.length) return;
    const idx = items.indexOf(document.activeElement);
    if (e.key === 'Escape') {
      e.preventDefault();
      closeExportMenu();
      return;
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      items[(idx + 1 + items.length) % items.length].focus();
      return;
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault();
      items[(idx - 1 + items.length) % items.length].focus();
      return;
    }
    if (e.key === 'Home') {
      e.preventDefault();
      items[0].focus();
      return;
    }
    if (e.key === 'End') {
      e.preventDefault();
      items[items.length - 1].focus();
      return;
    }
    if (e.key === 'Tab') {
      e.preventDefault();
      const step = e.shiftKey ? -1 : 1;
      items[(idx + step + items.length) % items.length].focus();
    }
  });
  document.getElementById('riskCalloutPlanBtn')?.addEventListener('click', () => switchTab('plan'));
  document.getElementById('vulnPrevBtn')?.addEventListener('click', () => vulnPageChange(-1));
  document.getElementById('vulnNextBtn')?.addEventListener('click', () => vulnPageChange(1));
  document.getElementById('copyJsonBtn')?.addEventListener('click', copyJSON);
  document.getElementById('vulnSearch')?.addEventListener('input', filterVulns);
  document.getElementById('vulnComponentSel')?.addEventListener('change', filterVulns);
  document.getElementById('vulnSort')?.addEventListener('change', filterVulns);
  document.getElementById('closeCveModalBtn')?.addEventListener('click', closeCVEModal);
  const cveModal = document.getElementById('cveModal');
  if (cveModal) {
    cveModal.addEventListener('click', e => {
      if (e.target === cveModal) closeCVEModal();
    });
    cveModal.addEventListener('keydown', e => {
      if (e.key === 'Escape') {
        e.preventDefault();
        closeCVEModal();
        return;
      }
      _trapFocusIn(cveModal, e);
    });
  }
  document.querySelectorAll('.tab-btn[data-tab]').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    btn.addEventListener('keydown', tabKeyNav);
  });
  document.querySelectorAll('.sev-tab[data-sev]').forEach(btn => {
    btn.addEventListener('click', () => setVulnSev(btn.dataset.sev));
  });
  document.querySelectorAll('#exportMenu .btn-export-item[data-export-action]').forEach(btn => {
    btn.addEventListener('click', () => {
      const action = btn.dataset.exportAction;
      if (action === 'pdf') downloadPDF();
      else if (action === 'executive-pdf') downloadExecutivePDF();
      else if (action === 'excel') downloadExcel();
      else if (action === 'csv') downloadCSV();
      else if (action === 'json') exportJSON();
      else if (action === 'html') downloadHTMLReport();
      else if (action === 'markdown') downloadMarkdown();
      else if (action === 'sarif') downloadSARIF();
      else if (action === 'permalink') copyPermalink(btn);
      closeExportMenu();
    });
  });

  loadHistory(true);
  loadDbStatus();
  tryReconnect();
  const _permalinkMeta = document.getElementById('__wpvs_permalink');
  if (_permalinkMeta && _permalinkMeta.value) {
    currentJobId = _permalinkMeta.value;
    apiFetch(`/scan/${currentJobId}/result`)
      .then(r => r.json())
      .then(d => { if (d.result) displayResults(d.result, currentJobId); })
      .catch(e => console.error('Permalink load error:', e));
  }
  const _permalinkErrMeta = document.getElementById('__wpvs_permalink_error');
  if (_permalinkErrMeta && _permalinkErrMeta.value) {
    const banner = document.createElement('div');
    banner.style.cssText = 'background:var(--red);color:#fff;padding:12px 20px;text-align:center;font-size:13px';
    banner.textContent = _permalinkErrMeta.value;
    document.body.prepend(banner);
  }
});
function buildDeepScanTab(r) {
  const ds = r.deep_scan || {};
  if (!Object.keys(ds).length) {
    return `<div class="info-block" style="padding:24px;text-align:center;color:var(--text3)">
      <div style="font-size:22px;margin-bottom:8px">🔭</div>
      Deep scan no disponible en este resultado (requiere v5.5+)
    </div>`;
  }

  const SEV_CLR = {critical:'var(--red)',high:'var(--orange)',medium:'var(--yellow)',low:'var(--text3)',info:'var(--cyan)'};
  const SEV_LBL = {critical:'CRÍT',high:'ALTO',medium:'MEDIO',low:'BAJO',info:'INFO'};

  function badge(sev) {
    const c = SEV_CLR[sev]||'var(--text3)';
    return `<span style="font-size:11px;font-weight:700;letter-spacing:.5px;padding:1px 6px;border:1px solid ${c};border-radius:2px;color:${c};background:${c}1a">${SEV_LBL[sev]||sev.toUpperCase()}</span>`;
  }

  function section(title, icon, content) {
    return `<div class="info-block" style="margin-bottom:12px">
      <div style="font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--text2);margin-bottom:10px;display:flex;align-items:center;gap:6px">
        <span style="font-size:14px">${icon}</span>${title}
      </div>
      ${content}
    </div>`;
  }

  function noIssues(msg='Sin problemas detectados') {
    return `<div style="font-size:11px;color:var(--green2);font-family:var(--sans)">✓ ${msg}</div>`;
  }

  function itemRow(sev, text, extra='') {
    return `<div style="display:flex;align-items:flex-start;gap:8px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,.04)">
      ${badge(sev)}
      <div style="flex:1;font-size:11px;font-family:var(--sans);color:var(--text2)">${text}</div>
      ${extra ? `<div style="font-size:10px;color:var(--text3)">${extra}</div>` : ''}
    </div>`;
  }

  let html = `<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:0;margin-top:4px">`;
  const rest = ds.rest_deep || {};
  {
    let content = '';
    if (!rest.available) {
      content = `<div style="font-size:11px;color:var(--text3)">REST API no disponible o desactivada</div>`;
    } else {
      const routes = rest.exposed_routes || [];
      if (!routes.length) content += noIssues('REST API disponible sin rutas críticas expuestas');
      else routes.forEach(rt => {
        content += itemRow(rt.severity, `<code style="font-family:var(--mono)">${rt.path}</code><br><span style="color:var(--text3)">${rt.desc}</span>`,
                           rt.count > 1 ? `${rt.count} items` : '');
      });
      if (rest.users_via_rest?.length) {
        content += `<div style="margin-top:8px;font-size:11px;color:var(--orange)">👤 Usuarios via REST: ${rest.users_via_rest.map(u => `<code>${_esc(u.login)}</code>`).join(', ')}</div>`;
      }
      if (rest.emails_found?.length) {
        content += `<div style="margin-top:6px;font-size:11px;color:var(--orange)">✉ Emails expuestos: ${rest.emails_found.slice(0,3).join(', ')}</div>`;
      }
      if (rest.woocommerce_rest) {
        content += `<div style="margin-top:6px;font-size:11px;color:var(--yellow)">🛒 WooCommerce REST API activo</div>`;
      }
    }
    html += section('REST API', '🔌', content);
  }
  const login = ds.login_security || {};
  {
    let content = '';
    if (!login.login_accessible) {
      content = `<div style="font-size:11px;color:var(--text3)">wp-login.php no accesible</div>`;
    } else {
      if (!login.username_enumerable && login.rate_limit_detected) {
        content += noIssues('Sin enumeración de usuarios detectada · Rate limiting activo');
      }
      if (login.username_enumerable) {
        content += itemRow('high', `Username enumerable: <em style="color:var(--text2)">${login.enum_method||''}</em>`);
      }
      if (login.lost_password_enumerable) {
        content += itemRow('medium', 'Lost password enumeration activo');
      }
      if (!login.rate_limit_detected) {
        content += itemRow('high', 'Sin rate limiting en wp-login.php — fuerza bruta sin obstáculos');
      } else {
        content += `<div style="font-size:11px;color:var(--green2);padding:6px 0">✓ Rate limiting detectado</div>`;
      }
      if (login.captcha_detected) {
        content += `<div style="font-size:11px;color:var(--green2);padding:6px 0">✓ CAPTCHA detectado en formulario de login</div>`;
      }
      if (login.login_page_info?.security_plugins?.length) {
        content += `<div style="font-size:11px;color:var(--green2);padding:4px 0">🛡 Plugins de seguridad: ${login.login_page_info.security_plugins.join(', ')}</div>`;
      }
    }
    html += section('Seguridad de Login', '🔑', content);
  }
  const feed = ds.feed_enum || {};
  {
    let content = '';
    const authors = [...(feed.authors_via_redirect||[]), ...(feed.authors_via_feed||[])];
    if (!feed.author_enum_possible && !feed.emails_in_feeds?.length) {
      content = noIssues('Sin enumeración de usuarios ni emails via feeds');
    } else {
      if (feed.author_enum_possible) {
        content += itemRow('medium',
          `Enumeración via ?author=N: <strong>${feed.authors_via_redirect.join(', ')}</strong>`);
      }
      if (feed.emails_in_feeds?.length) {
        content += itemRow('medium', `Emails en feed RSS: ${feed.emails_in_feeds.slice(0,5).join(', ')}`);
      }
      if (feed.comment_authors?.length) {
        content += `<div style="font-size:11px;color:var(--text3);padding:4px 0">Autores en comentarios: ${feed.comment_authors.slice(0,5).join(', ')}</div>`;
      }
    }
    html += section('Feed & Enumeración', '📡', content);
  }
  const woo = ds.woocommerce || {};
  {
    let content = '';
    if (!woo.detected) {
      content = `<div style="font-size:11px;color:var(--text3)">WooCommerce no detectado</div>`;
    } else {
      content += `<div style="font-size:11px;color:var(--cyan);margin-bottom:8px">🛒 WooCommerce detectado${woo.version ? ` v${woo.version}` : ''}</div>`;
      const paths = woo.exposed_paths || [];
      if (!paths.length) content += noIssues('Sin endpoints WooCommerce expuestos');
      else paths.forEach(p => {
        content += itemRow(p.severity, `<code style="font-family:var(--mono)">${p.path}</code><br><span style="color:var(--text3)">${p.desc}</span>`,
                           p.count > 1 ? `${p.count} items` : '');
      });
    }
    html += section('WooCommerce', '🛒', content);
  }

  html += '</div><div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px">';
  const clog = ds.changelog || {};
  {
    let content = '';
    const found = clog.found || [];
    if (!found.length) content = noIssues('Sin archivos de changelog/versión expuestos');
    else found.forEach(f => {
      content += itemRow(f.severity,
        `<code style="font-family:var(--mono)">${_esc(f.path)}</code><br><span style="color:var(--text3)">${_esc(f.desc)}</span>`,
        f.version ? `v${f.version}` : '');
    });
    html += section('Changelog & Versiones', '📋', content);
  }
  const ajax = ds.ajax_nopriv || {};
  {
    let content = '';
    const actions = ajax.exposed_actions || [];
    if (!actions.length) content = noIssues('Sin acciones admin-ajax sin auth con datos');
    else actions.forEach(a => {
      content += itemRow(a.severity,
        `<code style="font-family:var(--mono)">${a.action}</code><br><span style="color:var(--text3)">${a.desc}</span>`,
        `${a.response_size} bytes`);
    });
    html += section('Admin-AJAX nopriv', '⚡', content);
  }
  const ping = ds.pingback || {};
  {
    let content = '';
    if (!ping.xmlrpc_accessible) {
      content = `<div style="font-size:11px;color:var(--green2)">✓ XML-RPC no accesible</div>`;
    } else if (!ping.pingback_enabled) {
      content = `<div style="font-size:11px;color:var(--yellow)">⚠ XML-RPC activo pero pingback.ping no disponible</div>`;
    } else {
      content += itemRow('critical', '🚨 pingback.ping activo — vector SSRF/amplificación DDoS');
    }
    if (ping.issues?.length) {
      ping.issues.forEach(i => {
        if (!content.includes(i)) {
          content += `<div style="font-size:10px;color:var(--text3);padding:3px 0">• ${i}</div>`;
        }
      });
    }
    html += section('Pingback / SSRF', '🎯', content);
  }
  const ups = ds.uploads || {};
  {
    let content = '';
    if (ups.directory_listing) {
      content += itemRow('high', 'Directory listing activo en /wp-content/uploads/');
    }
    const dangerous = ups.dangerous_files || [];
    if (!dangerous.length && !ups.directory_listing) {
      content = noIssues('Sin archivos peligrosos detectados en uploads/');
    } else {
      dangerous.forEach(f => {
        content += itemRow(f.severity,
          `<code style="font-family:var(--mono)">${_esc(f.path)}</code><br><span style="color:var(--text3)">${_esc(f.desc)}</span>`,
          `${f.size} bytes`);
      });
    }
    html += section('Uploads Scanner', '📁', content);
  }
  const appPw = ds.app_passwords || {};
  {
    let content = '';
    if (!appPw.feature_enabled) {
      content = `<div style="font-size:11px;color:var(--text3)">Application Passwords no activo o no detectado</div>`;
    } else if (appPw.basic_auth_accepted) {
      content += itemRow('high', 'Application Passwords activo con auth básica aceptada en REST API');
    } else {
      content += `<div style="font-size:11px;color:var(--yellow)">ℹ️ Application Passwords (WP 5.6+) activo — acceso API via Basic Auth disponible</div>`;
    }
    html += section('Application Passwords', '🗝', content);
  }

  html += '</div>';
  const stg = ds.staging || {};
  if (stg.is_staging || stg.staging_signals?.length || stg.hosting_platform) {
    let content = '';
    if (stg.is_staging) {
      content += itemRow('medium', 'Entorno staging/desarrollo accesible públicamente');
    }
    if (stg.staging_signals?.length) {
      stg.staging_signals.forEach(s => {
        content += `<div style="font-size:11px;color:var(--text2);padding:4px 0;font-family:var(--sans)">• ${s}</div>`;
      });
    }
    if (stg.hosting_platform) {
      content += `<div style="font-size:11px;color:var(--cyan);padding:4px 0">🌐 Hosting: ${stg.hosting_platform}</div>`;
    }
    if (stg.cdn_detected) {
      content += `<div style="font-size:11px;color:var(--teal);padding:4px 0">⚡ CDN: ${stg.cdn_detected}</div>`;
    }
    html += `<div style="margin-top:12px">` + section('Entorno / Staging', '🌍', content) + `</div>`;
  }

  return html;
}
function buildComplianceTab(r) {
  const comp = r.compliance || {};
  const byFw = comp.by_framework || {};

  if (comp.error) {
    return `<div class="compliance-state compliance-state-error">
      <div class="compliance-state-title">Error en modulo de cumplimiento</div>
      <div class="compliance-state-msg">${_esc(comp.error)}</div>
    </div>`;
  }

  // ✅ NUEVA GUÍA DE REGULACIONES CON PENAS
  let html = `<div style="background:var(--bg-4);border-radius:8px;padding:14px;margin-bottom:16px;border-left:5px solid var(--blue)">
    <div style="font-weight:700;color:var(--text);margin-bottom:8px;display:flex;align-items:center;gap:6px">
      <span style="font-size:16px">📋</span> Marcos de Cumplimiento — Penas por Incumplimiento
    </div>
    <div style="font-size:11px;color:var(--text-2);line-height:1.6">
      Cada hallazgo está mapeado a regulaciones que pueden resultar en sanciones. 
      <strong style="color:var(--text)">Lee las penas abajo para entender el impacto</strong>.
    </div>
  </div>`;

  // ✅ TABLA DE REGULACIONES CON PENAS
  const regulationsGuide = `
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:12px;margin-bottom:16px">
      <!-- GDPR -->
      <div class="compliance-penalty-box">
        <div class="compliance-penalty-title">🇪🇺 GDPR (UE)</div>
        <div class="compliance-penalty-content">
          <strong>Aplicable a:</strong> Sitios con usuarios en UE, datos personales<br>
          <strong style="color:var(--red)">⚠️ PENAS:</strong>
          <ul class="compliance-penalty-list">
            <li>Multas hasta <strong>€20,000,000</strong> o <strong>4% ingresos anuales</strong></li>
            <li>Ejemplo: Sitio €10M ingresos = €400k multa mínima</li>
            <li>Incidentes: Notificar en <strong>72 horas</strong></li>
            <li>Consentimiento: Acción de usuario, no pre-checked</li>
          </ul>
        </div>
      </div>
      
      <!-- PCI-DSS -->
      <div class="compliance-penalty-box">
        <div class="compliance-penalty-title">💳 PCI-DSS</div>
        <div class="compliance-penalty-content">
          <strong>Aplicable a:</strong> Procesamiento de tarjetas de crédito<br>
          <strong style="color:var(--red)">⚠️ PENAS:</strong>
          <ul class="compliance-penalty-list">
            <li>Multas hasta <strong>$100,000 USD / mes</strong></li>
            <li>Pérdida capacidad procesar pagos (VISA/Mastercard)</li>
            <li>Responsabilidad civil sin límite por fraude</li>
            <li>Breach: Pérdida del 2-4% en transacciones</li>
          </ul>
        </div>
      </div>
      
      <!-- OWASP -->
      <div class="compliance-penalty-box">
        <div class="compliance-penalty-title">🛡️ OWASP Top 10</div>
        <div class="compliance-penalty-content">
          <strong>Aplicable a:</strong> Todos los sitios (estándar de facto)<br>
          <strong style="color:var(--orange)">⚠️ RESPONSABILIDAD CIVIL:</strong>
          <ul class="compliance-penalty-list">
            <li>No cumplir OWASP = <strong>negligencia probada</strong></li>
            <li>Demandas por pérdidas: €100k - €1M+ por hackeo</li>
            <li>Más vulnerable si hay SQLi, RCE o XSS sin parchear</li>
            <li>Ej: SQL Injection = responsabilidad de 100% a cliente</li>
          </ul>
        </div>
      </div>
      
      <!-- ISO 27001 -->
      <div class="compliance-penalty-box">
        <div class="compliance-penalty-title">📊 ISO 27001</div>
        <div class="compliance-penalty-content">
          <strong>Aplicable a:</strong> Empresas certificadas o requeridas<br>
          <strong style="color:var(--amber)">⚠️ CONSECUENCIAS:</strong>
          <ul class="compliance-penalty-list">
            <li>Pérdida de certificación = exclusión de licitaciones</li>
            <li>Primas de seguro aumentan 300-500%</li>
            <li>Multas contractuales con clientes: sin límite</li>
            <li>Reputación: pérdida de confianza de partners</li>
          </ul>
        </div>
      </div>
    </div>
  `;
  html += regulationsGuide;

  if (!Object.keys(byFw).length) {
    const vulns = r.vulnerabilities || [];
    const headers = r.headers_issues || [];
    const users = r.users || [];
    const malware = r.malware_indicators || [];
    const noVulnsAtAll = vulns.length === 0 && headers.length === 0 && users.length === 0 && malware.length === 0;

    if (noVulnsAtAll) {
      return `<div class="compliance-state compliance-state-ok">
        <div class="compliance-state-title">Sin hallazgos de cumplimiento</div>
        <div class="compliance-state-msg">El escaneo no detectó brechas que impacten GDPR, PCI-DSS, OWASP o ISO 27001.</div>
      </div>`;
    }
    let details = '';
    if (vulns.length) details += `<div>🔎 Vulnerabilidades detectadas: <strong>${vulns.length}</strong></div>`;
    if (headers.length) details += `<div>🛡️ Cabeceras inseguras: <strong>${headers.length}</strong></div>`;
    if (users.length) details += `<div>👥 Usuarios expuestos: <strong>${users.length}</strong></div>`;
    if (malware.length) details += `<div>☠️ Indicadores malware: <strong>${malware.length}</strong></div>`;

    details += `<div style="margin-top:8px;font-size:12px;color:var(--muted)">El mapeo normativo no se generó para este escaneo. Puedes ejecutar un nuevo escaneo o re-ejecutar el proceso de mapeo en el servidor para obtener el informe completo.</div>`;

    return `<div class="compliance-state compliance-state-empty">
      <div class="compliance-state-title">Datos de cumplimiento no disponibles</div>
      <div class="compliance-state-msg">${details}</div>
    </div>`;
  }

  const statusMeta = {
    critical: { color: 'var(--red)', bg: 'rgba(255,93,108,.12)', icon: 'ic-shield-alert', label: 'Critico' },
    high: { color: 'var(--orange)', bg: 'rgba(255,154,69,.12)', icon: 'ic-warning', label: 'Alto' },
    medium: { color: 'var(--amber)', bg: 'rgba(255,193,74,.12)', icon: 'ic-lock', label: 'Medio' },
    low: { color: 'var(--blue)', bg: 'rgba(47,131,255,.12)', icon: 'ic-check', label: 'Bajo' },
    ok: { color: 'var(--green)', bg: 'rgba(37,197,138,.12)', icon: 'ic-check', label: 'Correcto' },
  };
  const sevOrder = { critical: 4, high: 3, medium: 2, low: 1, ok: 0 };
  const remediationHint = {
    critical: 'Aplicar correccion en menos de 24 horas y validar en produccion.',
    high: 'Aplicar correccion esta semana con seguimiento en logs.',
    medium: 'Programar ajuste tecnico en el siguiente sprint.',
    low: 'Incluir en ciclo de hardening y verificaciones periodicas.',
  };

  const fwEntries = Object.entries(byFw);
  const allFindings = [];
  fwEntries.forEach(([, fw]) => {
    (fw.findings || []).forEach(f => allFindings.push(f));
  });

  const affectedFrameworks = fwEntries.filter(([, fw]) => (fw.findings_count || 0) > 0).length;
  const controlsTouched = new Set(allFindings.map(f => f.control).filter(Boolean)).size;
  const topSeverity = allFindings.reduce((acc, f) => {
    const sev = String(f.severity || 'low').toLowerCase();
    return (sevOrder[sev] || 0) > (sevOrder[acc] || 0) ? sev : acc;
  }, 'ok');
  const topMeta = statusMeta[topSeverity] || statusMeta.ok;

  let html = `<div class="compliance-guide">
    <div class="compliance-guide-head">
      <div class="compliance-guide-icon" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round">
          <use href="#ic-check"></use>
        </svg>
      </div>
      <div>
        <div class="compliance-guide-title">Cumplimiento explicado para accion inmediata</div>
        <div class="compliance-guide-sub">Este panel traduce hallazgos tecnicos a impacto normativo para que sepas por donde empezar.</div>
      </div>
    </div>
    <div class="compliance-guide-steps">
      <div class="compliance-guide-step"><span>1</span> Prioriza marcos con estado critico o alto.</div>
      <div class="compliance-guide-step"><span>2</span> Corrige primero controles con mayor severidad.</div>
      <div class="compliance-guide-step"><span>3</span> Vuelve a escanear para evidenciar mejora.</div>
    </div>
  </div>`;

  html += `<div class="compliance-overview-grid">
    <div class="compliance-metric">
      <div class="compliance-metric-lbl">Hallazgos normativos</div>
      <div class="compliance-metric-val">${comp.total_findings || allFindings.length}</div>
    </div>
    <div class="compliance-metric">
      <div class="compliance-metric-lbl">Marcos afectados</div>
      <div class="compliance-metric-val">${affectedFrameworks}/${fwEntries.length}</div>
    </div>
    <div class="compliance-metric">
      <div class="compliance-metric-lbl">Controles impactados</div>
      <div class="compliance-metric-val">${controlsTouched || 0}</div>
    </div>
    <div class="compliance-metric">
      <div class="compliance-metric-lbl">Severidad maxima</div>
      <div class="compliance-metric-val" style="color:${topMeta.color}">${topMeta.label}</div>
    </div>
  </div>`;
  const totalFindings = allFindings.length;
  const findingsByStatus = { ok: 0, low: 0, medium: 0, high: 0, critical: 0 };
  allFindings.forEach(f => {
    const sev = String(f.severity || 'low').toLowerCase();
    if (Object.prototype.hasOwnProperty.call(findingsByStatus, sev)) findingsByStatus[sev] += 1;
  });
  
  const complianceScore = totalFindings === 0 ? 100 : Math.max(0, 100 - Math.round((findingsByStatus.critical * 50 + findingsByStatus.high * 25 + findingsByStatus.medium * 10 + findingsByStatus.low * 5) / totalFindings));
  
  html += `<div style="margin-top:20px;padding:16px;background:var(--bg-4);border-radius:6px">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <span style="font-size:12px;font-weight:700;color:var(--text)">Indice de cumplimiento</span>
      <span style="font-size:14px;font-weight:700;color:${complianceScore >= 80 ? 'var(--green2)' : complianceScore >= 60 ? 'var(--amber)' : 'var(--red)'}">${complianceScore}%</span>
    </div>
    <div style="height:8px;background:var(--bg-3);border-radius:4px;overflow:hidden">
      <div style="width:${complianceScore}%;height:100%;background:${complianceScore >= 80 ? 'linear-gradient(90deg,var(--green2),var(--teal))' : complianceScore >= 60 ? 'linear-gradient(90deg,var(--amber),var(--orange))' : 'linear-gradient(90deg,var(--red),var(--orange))'};border-radius:4px;transition:width .6s ease-out"></div>
    </div>
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px;margin-top:12px;font-size:11px">
      ${findingsByStatus.critical > 0 ? `<div style="padding:6px;background:rgba(255,93,108,.1);border-left:3px solid var(--red);border-radius:2px"><span style="color:var(--red);font-weight:700">${findingsByStatus.critical}</span> critico` : ''}
      ${findingsByStatus.high > 0 ? `<div style="padding:6px;background:rgba(255,154,69,.1);border-left:3px solid var(--orange);border-radius:2px"><span style="color:var(--orange);font-weight:700">${findingsByStatus.high}</span> alto` : ''}
      ${findingsByStatus.medium > 0 ? `<div style="padding:6px;background:rgba(255,193,74,.1);border-left:3px solid var(--amber);border-radius:2px"><span style="color:var(--amber);font-weight:700">${findingsByStatus.medium}</span> medio` : ''}
      ${findingsByStatus.low > 0 ? `<div style="padding:6px;background:rgba(47,131,255,.1);border-left:3px solid var(--blue);border-radius:2px"><span style="color:var(--blue);font-weight:700">${findingsByStatus.low}</span> bajo` : ''}
    </div>
  </div>`;

  html += `<div class="compliance-framework-grid">`;
  fwEntries.forEach(([id, fw]) => {
    const status = String(fw.status || 'medium').toLowerCase();
    const meta = statusMeta[status] || statusMeta.medium;
    const anchorId = `fw-${String(id).replace(/[^a-zA-Z0-9_-]/g, '-')}`;
    html += `<button type="button" class="compliance-fw-card status-${status}" onclick="document.getElementById('${anchorId}').scrollIntoView({behavior:'smooth', block:'start'})">
      <div class="compliance-fw-card-title">${_esc(fw.name || String(id).toUpperCase())}</div>
      <div class="compliance-fw-card-meta">${fw.findings_count || 0} hallazgo(s)</div>
      <div class="compliance-fw-card-status" style="color:${meta.color}">${_esc(fw.status_label || meta.label)}</div>
    </button>`;
  });
  html += `</div>`;

  fwEntries.forEach(([id, fw]) => {
    const status = String(fw.status || 'medium').toLowerCase();
    const meta = statusMeta[status] || statusMeta.medium;
    const fwFindings = fw.findings || [];
    const anchorId = `fw-${String(id).replace(/[^a-zA-Z0-9_-]/g, '-')}`;

    const sevSummary = { critical: 0, high: 0, medium: 0, low: 0 };
    fwFindings.forEach(f => {
      const sev = String(f.severity || 'medium').toLowerCase();
      if (Object.prototype.hasOwnProperty.call(sevSummary, sev)) sevSummary[sev] += 1;
    });

    const sevSummaryText = Object.entries(sevSummary)
      .filter(([, count]) => count > 0)
      .map(([sev, count]) => `${count} ${statusMeta[sev].label.toLowerCase()}`)
      .join(' · ') || 'Sin hallazgos';

    html += `<section id="${anchorId}" class="compliance-fw compliance-fw-${status}">
      <div class="compliance-fw-head" style="background:${meta.bg}">
        <div class="compliance-fw-title-wrap">
          <div class="compliance-fw-title">${_esc(fw.name || String(id).toUpperCase())}</div>
          <div class="compliance-fw-full">${_esc(fw.full_name || '')}</div>
        </div>
        <span class="compliance-fw-status" style="color:${meta.color};border-color:${meta.color}">${_esc(fw.status_label || meta.label)}</span>
      </div>
      <div class="compliance-fw-meta">${fwFindings.length} hallazgo(s) · ${_esc(sevSummaryText)}</div>`;

    if (!fwFindings.length) {
      html += `<div class="compliance-fw-ok">No se detectaron brechas relevantes en este marco.</div>`;
    } else {
      html += `<div class="compliance-findings">`;
      fwFindings.forEach(f => {
        const sev = String(f.severity || 'medium').toLowerCase();
        const sevMeta = statusMeta[sev] || statusMeta.medium;
        const controlDesc = (fw.controls_desc && f.control) ? fw.controls_desc[f.control] : '';
        html += `<article class="compliance-finding compliance-finding-${sev}">
          <div class="compliance-control">${_esc(f.control || 'CONTROL')}</div>
          <div class="compliance-finding-copy">
            <div class="compliance-risk">${_esc(f.risk || 'Riesgo identificado')}</div>
            ${f.detail ? `<div class="compliance-detail">${_esc(f.detail)}</div>` : ''}
            ${controlDesc ? `<div class="compliance-detail compliance-detail-note">${_esc(controlDesc)}</div>` : ''}
            <div class="compliance-hint"><span>Accion sugerida:</span> ${remediationHint[sev] || remediationHint.medium}</div>
          </div>
          <span class="compliance-sev" style="color:${sevMeta.color}">${_esc((f.severity || 'medium').toUpperCase())}</span>
        </article>`;
      });
      html += `</div>`;
    }
    html += `</section>`;
  });

  html += `<div class="compliance-note">
    Este analisis es orientativo. Para auditorias oficiales, complementa este resultado con revision legal y de cumplimiento especializada.
  </div>`;

  return html;
}
let _aiPlanCache = null;
let _aiPlanJobId = null;

function buildAIPlanTab(r, el) {
  if (_aiPlanCache && _aiPlanJobId === currentJobId) {
    el.innerHTML = _aiPlanCache;
    return;
  }

  el.innerHTML = `
    <div style="text-align:center;padding:24px 0 16px">
      <div style="font-size:13px;color:var(--text);font-family:var(--sans);margin-bottom:6px">
        Plan de remediación personalizado generado por IA
      </div>
      <div style="font-size:11px;color:var(--text-3);font-family:var(--sans);max-width:480px;margin:0 auto 20px">
        La IA analiza todos los hallazgos del escaneo y genera un plan concreto, priorizado y contextualizado para <strong style="color:var(--cyan)">${_esc(r.target_url)}</strong>
      </div>
      <button onclick="generateAIPlan()" id="btnGenAI"
        style="background:linear-gradient(135deg,var(--blue),var(--teal));border:none;color:#fff;
               border-radius:8px;padding:12px 28px;font-family:var(--head);font-size:13px;
               font-weight:700;letter-spacing:.5px;cursor:pointer;transition:opacity .2s">
        ✦ Generar Plan con IA
      </button>
      <div style="margin-top:12px;font-size:10px;color:var(--text-3);font-family:var(--mono)">
        Modo auto: Gemini → Claude (si hay claves) y fallback a Ollama local (<code style="color:var(--cyan);background:var(--bg-4);padding:1px 5px;border-radius:3px">AI_PROVIDER=ollama</code>)
      </div>
    </div>
    <div id="aiPlanOutput" style="display:none"></div>`;
}

async function generateAIPlan() {
  const r = currentResult;
  if (!r) return;

  const btn = document.getElementById('btnGenAI');
  const out = document.getElementById('aiPlanOutput');
  if (btn) { btn.textContent = '⟳ Analizando con IA...'; btn.disabled = true; btn.style.opacity = '.6'; }
  const SYSTEM = `Eres un consultor senior de ciberseguridad especializado en WordPress con más de 15 años de experiencia. \
Conoces en profundidad el ecosistema de plugins, themes, la API REST de WP, WP-CLI, y las bases de datos CVE/NVD/CISA KEV. \
Tu objetivo es proporcionar planes de remediación accionables, técnicamente precisos y priorizados por impacto real. \
Respondes EXCLUSIVAMENTE en español técnico y en formato Markdown limpio. \
Reglas obligatorias: \
1) No inventes CVEs, versiones, rutas, servicios o herramientas no presentes en el informe. \
2) Si un dato no está en el informe, indica explícitamente "No verificado en el escaneo". \
3) Evita acciones destructivas o ambiguas (renombrar/borrar masivo, chmod globales peligrosos). Prioriza mitigaciones seguras, reversibles y verificables. \
4) Los comandos deben ir en bloques \`\`\`bash\`\`\` válidos, nunca como texto roto ni pseudo-comandos. \
5) No uses placeholders genéricos tipo /path/to sin explicar que debe sustituirse por una ruta real.`;
  const vulns     = r.vulnerabilities || [];
  const kevVulns  = vulns.filter(v => v.kev);
  const critVulns = vulns.filter(v => v.severity === 'critical');
  const highVulns = vulns.filter(v => v.severity === 'high');
  const plugins   = (r.plugins || []);
  const outdated  = plugins.filter(p => p.is_outdated);
  const vulnLines = vulns.slice(0, 20).map(v => {
    const tags = [
      v.kev         ? '🚨CISA-KEV'                           : null,
      v.epss > 0.7  ? `EPSS:${Math.round(v.epss*100)}%`      : null,
      v.epss > 0.3 && v.epss <= 0.7 ? `EPSS:${Math.round(v.epss*100)}%` : null,
      v.version_unconfirmed ? '⚠NO-CONF'                    : null,
    ].filter(Boolean).join(' ');
    return `  [${(v.severity||'').toUpperCase()}] ${v.title}` +
           `${v.cve_id ? ' (' + v.cve_id + ')' : ''}` +
           `${tags ? ' ' + tags : ''}` +
           `\n    Plugin: ${v.plugin_slug} v${v.plugin_version||'?'}` +
           `${v.fixed_in ? ' → fix disponible: v' + v.fixed_in : ' → SIN FIX CONOCIDO'}` +
           `${v.cvss_score ? ' | CVSS:' + v.cvss_score : ''}` +
           `${v.description ? '\n    Descripción: ' + v.description.slice(0, 160) : ''}`;
  }).join('\n');
  const outdatedLines = outdated.slice(0, 15).map(p =>
    `  - ${p.slug} v${p.version||'?'} → última: v${p.latest_version||'?'}`
  ).join('\n');
  const exposedFiles = (r.exposed_files || []).slice(0, 12).map(f =>
    `  [${(f.severity||'').toUpperCase()}] ${f.path} — ${f.description||''}`
  ).join('\n');
  const headersInfo = r.security_headers || {};
  const missingHeaders = Object.entries(headersInfo)
    .filter(([,v]) => v === false || v === null || v === 'missing')
    .map(([k]) => k).join(', ') || 'N/A';
  const compLines = Object.entries(r.compliance?.by_framework || {})
    .map(([id, fw]) => `  [${fw.status_label||fw.status}] ${fw.name}: ${fw.findings_count} hallazgos`)
    .join('\n') || '  Sin datos de compliance';
  const repInfo = r.reputation || {};
  const blacklisted = repInfo.blacklisted ? `BLACKLISTED en: ${(repInfo.blacklists||[]).join(', ')}` : 'Limpio';
  const sslInfo = r.ssl_info || {};
  const sslStatus = sslInfo.expired ? `EXPIRADO (${sslInfo.expires_at||''})` :
                    sslInfo.valid === false ? 'INVÁLIDO' :
                    sslInfo.days_until_expiry < 30 ? `Expira en ${sslInfo.days_until_expiry} días` : 'OK';

  const PROMPT = `Analiza el siguiente informe de seguridad de WordPress y genera un plan de remediación DETALLADO, TÉCNICO y PRIORIZADO.

═══════════════════════════════════════════════════════
INFORME DE SEGURIDAD — ${r.target_url}
═══════════════════════════════════════════════════════
RISK SCORE:     ${r.risk_score}/100 (${r.risk_label})
WordPress:      ${r.wp_version||'desconocido'}${r.wp_outdated?' → DESACTUALIZADO (latest: v'+r.wp_latest_version+')':' (actualizado)'}
PHP:            ${r.php_version||'desconocida'}
Servidor:       ${r.server_info?.web_server||'desconocido'}
Usuarios exp.:  ${(r.users||[]).length > 0 ? (r.users||[]).map(u=>u.login||u.display_name).join(', ') : 'Ninguno'}
XML-RPC:        ${r.xmlrpc_enabled ? '⚠ ACTIVO — vector de ataque abierto' : 'Desactivado'}
WP_DEBUG:       ${r.debug_mode?.debug_active ? '🚨 ACTIVO EN PRODUCCIÓN' : 'OK'}
WAF detectado:  ${(r.waf_detected||[]).length > 0 ? (r.waf_detected||[]).join(', ') : 'Ninguno'}
Reputación:     ${blacklisted}
SSL:            ${sslStatus}

───────────────────────────────────────────────────────
VULNERABILIDADES (${vulns.length} total: ${critVulns.length} críticas, ${highVulns.length} altas, ${kevVulns.length} en CISA KEV)
───────────────────────────────────────────────────────
${vulnLines || '  Ninguna detectada'}

───────────────────────────────────────────────────────
PLUGINS/TEMAS DESACTUALIZADOS (${outdated.length})
───────────────────────────────────────────────────────
${outdatedLines || '  Todos actualizados'}

───────────────────────────────────────────────────────
ARCHIVOS Y RUTAS EXPUESTAS
───────────────────────────────────────────────────────
${exposedFiles || '  Ninguno'}

───────────────────────────────────────────────────────
CABECERAS DE SEGURIDAD HTTP FALTANTES
───────────────────────────────────────────────────────
${missingHeaders}

───────────────────────────────────────────────────────
CUMPLIMIENTO NORMATIVO
───────────────────────────────────────────────────────
${compLines}

═══════════════════════════════════════════════════════
INSTRUCCIONES PARA EL PLAN:
═══════════════════════════════════════════════════════
Genera el plan con EXACTAMENTE este formato. Cada acción debe ser específica para ESTE sitio (usa los nombres reales de plugins, CVEs, versiones y rutas del informe):

## 🚨 CRÍTICO — Actuar ahora mismo (riesgo de compromiso activo)
Incluye únicamente vulnerabilidades CRITICAL o CISA-KEV. Para cada una:
- Nombre del plugin + versión afectada + CVE
- Impacto real si se explota (qué puede hacer un atacante)
- Comando exacto de corrección (WP-CLI preferiblemente)
- Verificación: cómo confirmar que la corrección funcionó

## ⚡ URGENTE — Esta semana (reducir superficie de ataque)
Vulnerabilidades HIGH, plugins muy desactualizados, XML-RPC activo, WP_DEBUG activo, usuarios expuestos. Pasos concretos para cada punto.

## 📅 IMPORTANTE — Este mes (hardening y cumplimiento)
Vulnerabilidades MEDIUM, cabeceras HTTP faltantes, SSL próximo a expirar, compliance gaps. Incluye snippets de código o configuración donde aplique.

## 🛡️ HARDENING PROACTIVO (recomendaciones avanzadas)
5 medidas de seguridad proactiva específicas para el stack detectado (${r.server_info?.web_server||'servidor'}, PHP ${r.php_version||'?'}, plugins activos). Incluye configuración de WAF si no hay ninguno.

## 📊 ANÁLISIS DE RIESGO RESIDUAL
- Risk score actual: ${r.risk_score}/100
- Risk score estimado tras implementar el plan: [calcula]
- Amenaza principal para este sitio específico y por qué
- Una frase de contexto sobre el estado de seguridad general

RECUERDA: Cero generalidades. Cada punto referencia datos reales del informe.`;

  const QUALITY_RULES = `

REGLAS DE CALIDAD DE SALIDA (OBLIGATORIAS):
- Usa SOLO Markdown estándar.
- Encabezados con ## y ###.
- Listas solo con "-" o "1." (no uses viñetas Unicode como •).
- Todos los comandos en bloques de código con \`\`\`bash.
- Para cambios de configuración, usa bloques \`\`\`apache, \`\`\`nginx o \`\`\`php según corresponda.
- No mezcles comando y explicación en la misma línea.
- No propongas versiones "objetivo" si no aparecen en el informe; en su lugar indica cómo verificarlas.
- Si detectas archivos sensibles expuestos, incluye primero mitigación inmediata (bloqueo de acceso + rotación de secretos) antes de cambios estructurales.
`;

  const FINAL_PROMPT = `${PROMPT}${QUALITY_RULES}`;

  try {
    const resp = await apiFetch('/api/ai-plan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ prompt: FINAL_PROMPT, body: { system: SYSTEM, prompt: FINAL_PROMPT } }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(()=>({error:'Error de API'}));
      if (resp.status === 503) throw new Error(err.hint || 'No hay proveedor IA disponible. Configura GEMINI_API_KEY/ANTHROPIC_API_KEY o activa Ollama local.');
      if (resp.status === 401) throw new Error('API key inválida — revisa GEMINI_API_KEY o ANTHROPIC_API_KEY en .env');
      if (resp.status === 429) throw new Error(err.error || 'Proveedor IA con rate limit/cuota temporal. Puedes usar Ollama local gratis.');
      if (resp.status === 504) throw new Error(err.hint || err.error || 'Ollama tardó demasiado en responder.');
      throw new Error(err.hint || err.error || `HTTP ${resp.status}`);
    }

    const data = await resp.json();
    const text = data.text || '';
    if (currentResult && text) {
      currentResult.ai_plan = text;
      if (currentJobId) {
        apiFetch(`/scan/${currentJobId}/ai-plan`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({ai_plan: text}),
        }).catch(() => {}); // silencioso — no crítico
      }
    }

    const rendered = _renderMd(text);

    const providerLabel = data.provider === 'ollama'
      ? 'Ollama local'
      : data.provider === 'claude'
        ? 'Claude (Anthropic)'
        : 'Gemini';
    const modelLabel = data.model
      ? data.model
          .replace(/^gemini-/i,'Gemini ')
          .replace(/^ollama:/i,'')
          .replace(/^claude:/i,'')
          .replace(/-/g,' ')
      : 'modelo desconocido';
    const fallbackLabel = data.fallback_from
      ? `<span style="font-size:10px;color:var(--text-3);font-family:var(--mono)">fallback desde ${_esc(String(data.fallback_from))}</span>`
      : '';

    const html = `
      <div style="background:rgba(61,142,255,.06);border:1px solid rgba(61,142,255,.2);border-radius:8px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:10px;flex-wrap:wrap">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><circle cx="12" cy="16" r=".5" fill="var(--blue)"/></svg>
        <span style="font-size:11px;color:var(--blue);font-family:var(--sans)">Plan generado por <strong>${providerLabel} · ${_esc(modelLabel)}</strong></span>
        ${fallbackLabel}
        <span style="font-size:10px;color:var(--text-3);font-family:var(--mono);margin-left:auto">${new Date().toLocaleString('es-ES')}</span>
      </div>
      <div style="font-size:12px;line-height:1.75;font-family:var(--sans);color:var(--text-2)">${rendered}</div>
      <div style="margin-top:18px;padding:10px 14px;background:var(--bg-2);border-radius:6px;border:1px solid var(--border);font-size:10px;color:var(--text-3);font-family:var(--sans);display:flex;gap:8px;align-items:flex-start">
        <span>⚠</span><span>Este plan es orientativo. Valida siempre los cambios en un entorno de staging antes de aplicarlos en producción. Los CVEs y versiones se basan en la BD local — verifica en NVD para confirmación.</span>
      </div>
      <button onclick="generateAIPlan()" style="margin-top:12px;background:var(--bg-4);border:1px solid var(--border);color:var(--text-3);border-radius:6px;padding:6px 16px;font-size:11px;font-family:var(--sans);cursor:pointer">
        ↻ Regenerar análisis
      </button>`;

    if (out) { out.innerHTML = html; out.style.display = 'block'; }
    if (btn) btn.style.display = 'none';
    _aiPlanCache = _el('tabContent')?.innerHTML || html;
    _aiPlanJobId = currentJobId;

  } catch (e) {
    if (btn) { btn.textContent = '✦ Generar Plan con IA'; btn.disabled = false; btn.style.opacity = '1'; }
    if (out) {
      out.innerHTML = `<div style="background:rgba(255,69,96,.08);border:1px solid rgba(255,69,96,.2);border-radius:8px;padding:14px 18px;color:var(--red);font-size:12px;font-family:var(--sans)">
        ⚠ Error al generar el plan: ${_esc(e.message)}<br>
        <span style="font-size:11px;color:var(--text-3)">Comprueba la conexión e inténtalo de nuevo.</span>
      </div>`;
      out.style.display = 'block';
    }
  }
}
let _chatHistory   = [];   // [{role, content}]
let _chatJobId     = null;
let _chatSystemCtx = null; // system prompt cacheado con el contexto del escaneo
let _chatStreaming  = false;
let _chatLoadedFor  = null;
function _buildChatSystem(r) {
  if (_chatSystemCtx && _chatJobId === currentJobId) return _chatSystemCtx;

  const vulns   = r.vulnerabilities || [];
  const plugins = r.plugins || [];
  const themes  = r.themes  || [];

  const vulnSummary = vulns.slice(0, 30).map(v =>
    `- [${(v.severity||'').toUpperCase()}] ${v.title}` +
    `${v.cve_id ? ' (' + v.cve_id + ')' : ''}` +
    `${v.kev ? ' 🚨CISA-KEV' : ''}` +
    `${v.epss > 0.3 ? ' EPSS:' + Math.round(v.epss*100) + '%' : ''}` +
    `\n  Plugin: ${v.plugin_slug} v${v.plugin_version||'?'}` +
    `${v.fixed_in ? ' → fix: v' + v.fixed_in : ' → sin fix'}` +
    `${v.cvss_score ? ' | CVSS:' + v.cvss_score : ''}` +
    `${v.description ? '\n  Desc: ' + v.description.slice(0,200) : ''}`
  ).join('\n');

  const pluginSummary = plugins.slice(0,20).map(p =>
    `- ${p.slug} v${p.version||'?'}${p.is_outdated?' (DESACTUALIZADO → v'+p.latest_version+')':''}`
  ).join('\n');

  const exposedSummary = (r.exposed_files||[]).slice(0,10).map(f =>
    `- [${f.severity}] ${f.path}: ${f.description||''}`
  ).join('\n');

  const userSummary = (r.users||[]).map(u =>
    `- login: ${u.login||'?'}, display: ${u.display_name||'?'}`
  ).join('\n');

  _chatSystemCtx = `Eres un experto en ciberseguridad WordPress asistiendo al equipo de seguridad que acaba de escanear un sitio web.

Tienes acceso COMPLETO al informe de seguridad del escaneo. Responde SIEMPRE en español, con precisión técnica, citando los datos reales del informe cuando sea relevante. Sé directo y concreto — nada de respuestas genéricas. Usa comandos WP-CLI, PHP snippets o configuraciones específicas cuando aplique.

════════════════════════════════════════════════════
INFORME DE SEGURIDAD COMPLETO
════════════════════════════════════════════════════
SITIO:          ${r.target_url}
RISK SCORE:     ${r.risk_score}/100 (${r.risk_label})
WordPress:      ${r.wp_version||'desconocido'}${r.wp_outdated?' [DESACTUALIZADO — latest v'+r.wp_latest_version+']':''}
PHP:            ${r.php_version||'desconocida'}
Servidor:       ${r.server_info?.web_server||'desconocido'}
SSL:            ${r.ssl_info?.expired?'EXPIRADO':r.ssl_info?.valid===false?'INVÁLIDO':'OK'}
XML-RPC:        ${r.xmlrpc_enabled?'ACTIVO':'Desactivado'}
WP_DEBUG:       ${r.debug_mode?.debug_active?'ACTIVO EN PRODUCCIÓN':'OK'}
WAF:            ${(r.waf_detected||[]).length>0?(r.waf_detected||[]).join(', '):'Ninguno detectado'}
Reputación:     ${r.reputation?.blacklisted?'BLACKLISTED en '+(r.reputation?.blacklists||[]).join(', '):'Limpia'}

VULNERABILIDADES (${vulns.length} total: ${vulns.filter(v=>v.severity==='critical').length} críticas, ${vulns.filter(v=>v.severity==='high').length} altas, ${vulns.filter(v=>v.kev).length} CISA-KEV):
${vulnSummary||'Ninguna'}

PLUGINS/TEMAS DETECTADOS (${plugins.length+themes.length}):
${pluginSummary||'Ninguno'}

ARCHIVOS EXPUESTOS:
${exposedSummary||'Ninguno'}

USUARIOS EXPUESTOS (${(r.users||[]).length}):
${userSummary||'Ninguno'}

CABECERAS HTTP FALTANTES: ${Object.entries(r.security_headers||{}).filter(([,v])=>!v).map(([k])=>k).join(', ')||'Todas presentes'}

════════════════════════════════════════════════════
El usuario puede preguntarte cualquier cosa sobre este informe: detalles de CVEs específicos, cómo explotar o parchear una vulnerabilidad, qué significa una métrica, cómo priorizar, etc.`;

  _chatJobId = currentJobId;
  return _chatSystemCtx;
}
function _renderMd(raw) {
  const source = _escHtml(String(raw || '').replace(/\r\n/g, '\n'));
  const codeBlocks = [];

  let s = source
    .replace(/^[ \t]*[•●▪]\s+/gm, '- ')
    .replace(/```([a-zA-Z0-9_-]*)\n?([\s\S]*?)```/g, (_, lang, code) => {
      const token = `__CODEBLOCK_${codeBlocks.length}__`;
      const langLabel = lang
        ? `<div style="font-size:10px;color:var(--text-3);font-family:var(--mono);margin:0 0 4px">${_escHtml(String(lang).toUpperCase())}</div>`
        : '';
      codeBlocks.push(
        `<div style="margin:10px 0">${langLabel}<pre style="background:var(--bg);border:1px solid var(--border-2);border-radius:6px;padding:10px 14px;overflow-x:auto"><code style="font-family:var(--mono);font-size:11px;color:var(--cyan);line-height:1.6">${code.trim()}</code></pre></div>`
      );
      return token;
    });

  s = s
    .replace(/^#### (.+)$/gm, '<div style="font-family:var(--head);font-size:11px;font-weight:700;color:var(--text);margin:12px 0 5px;letter-spacing:.25px">$1</div>')
    .replace(/^### (.+)$/gm, '<div style="font-family:var(--head);font-size:12px;font-weight:700;color:var(--text);margin:14px 0 6px;letter-spacing:.3px">$1</div>')
    .replace(/^## (.+)$/gm, '<div style="font-family:var(--head);font-size:13px;font-weight:700;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--border)">$1</div>')
    .replace(/`([^`\n]+)`/g, '<code style="background:var(--bg-4);color:var(--cyan);padding:1px 6px;border-radius:3px;font-size:11px;font-family:var(--mono)">$1</code>')
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong style="color:var(--text)">$1</strong>')
    .replace(/\[CISA[\.-]?KEV\]/gi, '<span style="background:rgba(255,69,96,.15);color:var(--red);border:1px solid rgba(255,69,96,.3);border-radius:3px;padding:1px 5px;font-size:10px;font-weight:700">CISA KEV</span>')
    .replace(/CVE-(\d{4}-\d{4,7})/g, '<a href="https://nvd.nist.gov/vuln/detail/CVE-$1" target="_blank" style="color:var(--cyan);text-decoration:none;font-weight:600" title="Ver en NVD">CVE-$1 ↗</a>')
    .replace(/^- (.+)$/gm, '<div style="display:flex;gap:8px;padding:3px 0"><span style="color:var(--blue);flex-shrink:0">•</span><span>$1</span></div>')
    .replace(/^\d+\. (.+)$/gm, '<div style="display:flex;gap:8px;padding:3px 0"><span style="color:var(--blue);flex-shrink:0">›</span><span>$1</span></div>')
    .replace(/\n{3,}/g, '\n\n')
    .replace(/\n\n/g, '<br><br>')
    .replace(/\n/g, '<br>');

  codeBlocks.forEach((block, idx) => {
    s = s.replace(new RegExp(`__CODEBLOCK_${idx}__`, 'g'), block);
  });

  return s;
}

function _escHtml(s) {
  const str = String(s ?? '');
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}
function buildChatTab(r, el) {
  el.innerHTML = `
  <div id="chatWrap" style="display:flex;flex-direction:column;height:auto;max-height:70vh;background:var(--bg-2);border-radius:var(--radius);overflow:hidden;border:1px solid var(--border)">

  
  <div style="display:flex;align-items:center;gap:10px;padding:11px 16px;background:var(--bg-3);border-bottom:1px solid var(--border);flex-shrink:0">
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="var(--blue)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
    <span style="font-family:var(--head);font-size:11px;font-weight:700;letter-spacing:1px;text-transform:uppercase;color:var(--text)">Asistente de Seguridad</span>
    <span style="font-size:10px;color:var(--text-3);font-family:var(--mono)">Asistente IA · contexto del escaneo incluido</span>
    <button onclick="_chatClear()" title="Limpiar conversación"
      style="margin-left:auto;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text-3);font-size:10px;font-family:var(--mono);padding:3px 8px;cursor:pointer;transition:all .12s"
      onmouseover="this.style.color='var(--text)'" onmouseout="this.style.color='var(--text-3)'">
      Limpiar
    </button>
  </div>

  <div style="padding:10px 14px;border-bottom:1px solid var(--border);background:var(--bg-3);flex-shrink:0">
    <span style="font-size:10px;color:var(--text-3);font-family:var(--sans);">Asistente IA listo — escribe tu consulta.</span>
  </div>

  
  <div id="chatMessages" style="flex:1;overflow-y:auto;padding:14px 16px;display:flex;flex-direction:column;gap:12px;scroll-behavior:smooth"></div>

  
  <div style="display:flex;gap:8px;padding:10px 14px;background:var(--bg-3);border-top:1px solid var(--border);flex-shrink:0;align-items:flex-end">
    <textarea id="chatInput" placeholder="Pregunta sobre el escaneo de ${_esc(r.target_url||'')}…"
      rows="2"
      style="flex:1;background:var(--bg-2);border:1px solid var(--border-2);border-radius:6px;color:var(--text);font-family:var(--sans);font-size:12px;padding:8px 10px;outline:none;resize:none;line-height:1.5;transition:border-color .15s;max-height:120px"
      onfocus="this.style.borderColor='var(--blue)'" onblur="this.style.borderColor='var(--border-2)'"
      onkeydown="if((event.ctrlKey||event.metaKey)&&event.key==='Enter'){event.preventDefault();_chatSend();}"
      oninput="this.style.height='auto';this.style.height=Math.min(this.scrollHeight,120)+'px'"></textarea>
    <button id="chatSendBtn" onclick="_chatSend()"
      style="background:var(--blue);border:none;border-radius:6px;color:#fff;padding:9px 16px;font-family:var(--head);font-size:11px;font-weight:700;letter-spacing:.5px;cursor:pointer;flex-shrink:0;transition:opacity .15s;height:36px"
      onmouseover="this.style.opacity='.85'" onmouseout="this.style.opacity='1'">
      Enviar
    </button>
  </div>
</div>`;

  const activeScanId = currentJobId || r.scan_id || null;
  if (activeScanId && _chatJobId !== activeScanId) {
    _chatHistory = [];
    _chatJobId = activeScanId;
    _chatSystemCtx = null;
  }
  if (_chatHistory.length) {
    _chatRepaint();
  } else {
    _chatAddBubble('assistant',
      `**Hola.** Soy tu asistente de seguridad para el escaneo de **${_esc(r.target_url)}**.

Conozco todos los detalles del informe: ${(r.vulnerabilities||[]).length} vulnerabilidades detectadas (${(r.vulnerabilities||[]).filter(v=>v.severity==='critical').length} críticas), ${(r.plugins||[]).length} plugins, archivos expuestos, compliance y más.

Puedes preguntarme cualquier cosa sobre el resultado. Por ejemplo:
- *¿Cuál es la vuln más peligrosa y cómo la parcheo?*
- *¿Qué comandos WP-CLI necesito ejecutar ahora mismo?*
- *Explícame qué significa CVE-XXXX-XXXX*
- *¿Este sitio cumple con GDPR?*

**Ctrl+Enter** para enviar rápido.`, false);
  }

  _chatLoadHistoryFromServer(r).catch(() => {});
}

function _chatRepaint() {
  const box = document.getElementById('chatMessages');
  if (!box) return;
  box.innerHTML = '';
  _chatHistory.forEach(m => {
    if (m.role === 'user')
      _chatAddBubble('user', m.content, false);
    else
      _chatAddBubble('assistant', m.content, false);
  });
}

async function _chatLoadHistoryFromServer(r) {
  const sid = currentJobId || r?.scan_id || '';
  if (!sid) return;
  if (_chatLoadedFor === sid) return;

  _chatLoadedFor = sid;
  try {
    const resp = await apiFetch(`/api/ai-chat/history?scan_id=${encodeURIComponent(sid)}&limit=120`);
    if (!resp.ok) return;
    const payload = await resp.json();
    const msgs = Array.isArray(payload.messages)
      ? payload.messages
          .map(m => ({
            role: m?.role === 'assistant' ? 'assistant' : 'user',
            content: String(m?.content || '').trim(),
          }))
          .filter(m => m.content)
      : [];

    if ((currentJobId || r?.scan_id || '') !== sid) return;

    if (msgs.length) {
      _chatHistory = msgs;
      _chatJobId = sid;
      _chatRepaint();
    }
  } catch (_) {
  }
}

function _chatClear() {
  _chatHistory = [];
  const box = document.getElementById('chatMessages');
  if (box) box.innerHTML = '';
  const sid = currentJobId || '';
  _chatLoadedFor = sid || null;
  if (sid) {
    apiFetch(`/api/ai-chat/history?scan_id=${encodeURIComponent(sid)}`, {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
    }).catch(() => {});
  }
  if (currentResult) buildChatTab(currentResult, document.getElementById('tabContent'));
}

function _chatSuggest(q) {
  const inp = document.getElementById('chatInput');
  if (inp) { inp.value = q; inp.focus(); }
  _chatSend();
}

function _chatAddBubble(role, text, streaming) {
  const box = document.getElementById('chatMessages');
  if (!box) return null;

  const isUser = role === 'user';
  const id = 'cb-' + Date.now() + '-' + Math.random().toString(36).slice(2);

  const bubble = document.createElement('div');
  bubble.id = id;
  bubble.style.cssText = `display:flex;flex-direction:column;align-items:${isUser?'flex-end':'flex-start'};gap:4px`;

  const inner = document.createElement('div');
  inner.style.cssText = isUser
    ? 'background:var(--blue);color:#fff;border-radius:12px 12px 2px 12px;padding:9px 13px;max-width:78%;font-size:12px;font-family:var(--sans);line-height:1.6;white-space:pre-wrap'
    : 'background:var(--bg-3);border:1px solid var(--border);border-radius:2px 12px 12px 12px;padding:11px 14px;max-width:90%;font-size:12px;font-family:var(--sans);line-height:1.7;color:var(--text-2)';

  if (isUser) {
    inner.textContent = text;
  } else {
    inner.innerHTML = streaming ? '<span class="t-cursor"></span>' : _renderMd(text);
  }

  bubble.appendChild(inner);
  box.appendChild(bubble);
  box.scrollTop = box.scrollHeight;
  return { id, inner };
}

async function _chatSend() {
  if (_chatStreaming) return;
  const inp = document.getElementById('chatInput');
  const btn = document.getElementById('chatSendBtn');
  if (!inp || !currentResult) return;

  const userText = inp.value.trim();
  if (!userText) return;

  inp.value = '';
  inp.style.height = 'auto';
  _chatStreaming = true;
  if (btn) { btn.textContent = '…'; btn.disabled = true; btn.style.opacity = '.5'; }
  const sugg = document.getElementById('chatSuggestions');
  if (sugg) sugg.style.display = 'none';
  _chatHistory.push({ role: 'user', content: userText });
  _chatAddBubble('user', userText, false);
  const _orphan = document.querySelector('#chatMessages [data-pending="1"]');
  if (_orphan) _orphan.remove();
  const { id: bubbleId, inner: bubbleEl } = _chatAddBubble('assistant', '', true);
  bubbleEl.closest('[id^="cb-"]').dataset.pending = '1';

  const system = _buildChatSystem(currentResult);
  let accumulated = '';

  try {
    const resp = await apiFetch('/api/ai-chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system,
        messages: _chatHistory,
        stream: true,
        scan_id: currentJobId || currentResult?.scan_id || '',
        session_id: 'default',
        persist_chat: true,
      }),
    });

    if (!resp.ok) {
      const err = await resp.json().catch(() => ({ error: `HTTP ${resp.status}` }));
      throw new Error(err.error || `HTTP ${resp.status}`);
    }

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buf = '';

    const applySseLine = (line) => {
      const trimmed = String(line || '').trim();
      if (!trimmed || !trimmed.startsWith('data: ')) return false;
      const payload = trimmed.slice(6);
      if (payload === '[DONE]') return true;

      try {
        const evt = JSON.parse(payload);
        if (evt.error) throw new Error(evt.error);
        if (evt.text) {
          accumulated += String(evt.text);
          bubbleEl.innerHTML = _renderMd(accumulated) + '<span class="t-cursor"></span>';
          const box = document.getElementById('chatMessages');
          if (box) box.scrollTop = box.scrollHeight;
        }
      } catch (pe) {
        if (pe.message && !pe.message.includes('JSON')) throw pe;
      }
      return false;
    };

    let streamDone = false;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buf += decoder.decode(value, { stream: true });
      const lines = buf.split('\n');
      buf = lines.pop(); // guardar línea incompleta

      for (const line of lines) {
        if (applySseLine(line)) { buf = ''; streamDone = true; break; }
      }
      if (streamDone) break;
    }
    if (!streamDone && buf.trim()) {
      streamDone = applySseLine(buf) || streamDone;
      buf = '';
    }
    const finalText = (accumulated || '').trim();
    if (!finalText) {
      bubbleEl.innerHTML = '<span style="color:var(--amber)">⚠ La IA devolvió una respuesta vacía. Reintenta en unos segundos o cambia el modelo de Ollama.</span>';
      if (bubbleEl.closest) { const p = bubbleEl.closest('[data-pending]'); if (p) delete p.dataset.pending; }
      return;
    }
    bubbleEl.innerHTML = _renderMd(accumulated);
    if (bubbleEl.closest) { const p = bubbleEl.closest('[data-pending]'); if (p) delete p.dataset.pending; }
    _chatHistory.push({ role: 'assistant', content: accumulated });

  } catch (e) {
    bubbleEl.innerHTML = `<span style="color:var(--red)">⚠ ${_escHtml(e.message)}</span>`;
    _chatHistory.pop();
  } finally {
    _chatStreaming = false;
    if (btn) { btn.textContent = 'Enviar'; btn.disabled = false; btn.style.opacity = '1'; }
    if (inp) inp.focus();
  }
}
(function initUrlValidation() {
  const input = document.getElementById('urlInput');
  const wrap  = document.getElementById('urlWrap');
  if (!input || !wrap) return;
  let _t = null;
  input.addEventListener('input', () => {
    clearTimeout(_t);
    const val = input.value.trim();
    wrap.classList.remove('url-valid','url-invalid');
    if (!val) return;
    _t = setTimeout(() => {
      const ok = isValidUrl(val);
      wrap.classList.add(ok ? 'url-valid' : 'url-invalid');
    }, 320);
  });
})();
(function initOnboarding() {
  try {
    if (localStorage.getItem('wpvs_welcomed')) return;
    const banner = document.getElementById('onboardBanner');
    if (banner) banner.style.display = 'flex';
  } catch(e) {}
})();

function dismissOnboard() {
  try { localStorage.setItem('wpvs_welcomed','1'); } catch(e) {}
  const b = document.getElementById('onboardBanner');
  if (b) { b.style.opacity='0'; b.style.transform='translateY(-8px)'; setTimeout(() => b.remove(), 300); }
}
(function initTerminalCollapse() {
  const wrap = document.getElementById('terminalWrap');
  if (!wrap) return;
  wrap.classList.add('term-collapsed');
  const bar = wrap.querySelector('.terminal-bar');
  if (!bar) return;
  const tog = document.createElement('button');
  tog.className = 'term-toggle-btn';
  tog.title = 'Mostrar / ocultar log';
  tog.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><polyline points="18 15 12 9 6 15"/></svg>';
  tog.onclick = () => {
    wrap.classList.toggle('term-collapsed');
    tog.querySelector('svg').style.transform = wrap.classList.contains('term-collapsed') ? '' : 'rotate(180deg)';
  };
  bar.appendChild(tog);
})();
function updateRiskCallout(r) {
  const el = document.getElementById('riskCallout');
  if (!el) return;
  const s = r.summary || {};
  const crit = s.critical_vulns || 0;
  const high = s.high_vulns    || 0;
  const total = s.vulns_found  || 0;
  const score = r.risk_score   || 0;

  let icon, msg, clr;
  if (crit > 0) {
    icon = '🚨'; clr = 'var(--red)';
    msg = `Tienes <strong>${crit} vulnerabilidad${crit>1?'es':''} crítica${crit>1?'s':''}</strong> — requieren acción inmediata antes de que tu sitio sea comprometido.`;
  } else if (high > 0) {
    icon = '⚠️'; clr = 'var(--orange)';
    msg = `<strong>${high} problema${high>1?'s':''} de severidad alta</strong> detectado${high>1?'s':''}. Corríjelos pronto para reducir el riesgo significativamente.`;
  } else if (total > 0) {
    icon = '💡'; clr = 'var(--amber)';
    msg = `<strong>${total} vulnerabilidad${total>1?'es':''}</strong> de severidad media o baja. Revisa el <em>Plan de Acción</em> para las correcciones recomendadas.`;
  } else if (score < 20) {
    icon = '✅'; clr = 'var(--green)';
    msg = '<strong>Buen estado de seguridad.</strong> No se encontraron vulnerabilidades conocidas. Mantén los plugins actualizados.';
  } else {
    icon = '🔍'; clr = 'var(--teal)';
    msg = 'Revisa los hallazgos en las pestañas de abajo para ver los detalles completos.';
  }
  el.style.display = 'flex';
  el.querySelector('.rca-icon').textContent = icon;
  el.querySelector('.rca-msg').innerHTML = msg;
  el.style.setProperty('--rca-clr', clr);
}
const _origLoadHistory = loadHistory;  // no redefine — parchea el render inline
const _histEmptyHTML = `
<div class="hist-empty-state">
  <div class="hist-empty-icon">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
      <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
      <line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/>
    </svg>
  </div>
  <div class="hist-empty-title">Aún no has escaneado ningún sitio</div>
  <div class="hist-empty-sub">Escribe una URL arriba y pulsa <strong>Escanear</strong> para empezar tu primer análisis</div>
</div>`;
const __loadHistOrig = window.loadHistory;
window.loadHistory = async function(reset) {
  await __loadHistOrig(reset);
  const empty = document.getElementById('histEmpty');
  if (empty && empty.style.display !== 'none') {
    const q = (document.getElementById('histSearch')?.value || '').trim();
    if (!q) empty.innerHTML = _histEmptyHTML;
  }
};
function toggleTerminal() {
  const wrap = document.getElementById('terminalWrap');
  const btn  = document.getElementById('termToggleBtn');
  if (!wrap) return;
  const collapsed = wrap.classList.toggle('term-collapsed');
  if (btn) btn.querySelector('svg').style.transform = collapsed ? '' : 'rotate(180deg)';
}

function _showWpCheckBadge(state, extra) {
  let badge = document.getElementById('wpCheckBadge');
  if (!badge) {
    const wrap = document.getElementById('urlWrap');
    if (!wrap) return;
    badge = document.createElement('div');
    badge.id = 'wpCheckBadge';
    badge.className = 'wp-check-badge';
    wrap.parentNode.insertBefore(badge, wrap.nextSibling);
  }

  const states = {
    checking:       { icon: '⟳', text: 'Verificando sitio…',                        cls: 'wpcb-checking' },
    ok:             { icon: '✓', text: extra ? `WordPress ${extra} detectado`
                                             : 'WordPress detectado',                cls: 'wpcb-ok'       },
    not_wp:         { icon: '⚠', text: 'No parece WordPress — confirma para continuar', cls: 'wpcb-warn'  },
    not_wp_continue:{ icon: '→', text: 'Escaneando igualmente…',                     cls: 'wpcb-warn'     },
    unreachable:    { icon: '✕', text: `Sitio no alcanzable${extra?': '+String(extra).slice(0,70):''}`, cls: 'wpcb-err' },
    skip:           { icon: '·', text: 'Verificación omitida — escaneando…',         cls: 'wpcb-skip'     },
  };

  const s = states[state] || states.skip;
  badge.className = `wp-check-badge ${s.cls}`;
  badge.innerHTML = `<span class="wpcb-icon">${s.icon}</span><span class="wpcb-text">${s.text}</span>`;
  badge.style.display = 'flex';
  if (state === 'ok') setTimeout(() => { if (badge) badge.style.opacity = '0'; }, 4000);
  if (state === 'checking') badge.querySelector('.wpcb-icon').style.animation = 'spin .8s linear infinite';
}

function _confirmNotWP(url) {
  return new Promise(resolve => {
    const prev = document.getElementById('notWpModal');
    if (prev) prev.remove();

    const modal = document.createElement('div');
    modal.id = 'notWpModal';
    modal.className = 'not-wp-modal-overlay';
    modal.innerHTML = `
      <div class="not-wp-modal">
        <div class="nwm-icon">⚠</div>
        <div class="nwm-title">Sitio no identificado como WordPress</div>
        <div class="nwm-body">
          No se han encontrado indicadores de WordPress en
          <strong>${_esc(url.replace(/https?:\/\//,'').split('/')[0])}</strong>.<br><br>
          Puede que WordPress esté oculto, use un path personalizado,
          o que el sitio no sea WordPress en absoluto.
          El escáner puede dar resultados incompletos o incorrectos.
        </div>
        <div class="nwm-actions">
          <button class="nwm-btn nwm-cancel" id="nwmCancel">✕ Cancelar</button>
          <button class="nwm-btn nwm-continue" id="nwmContinue">Escanear igualmente →</button>
        </div>
      </div>`;
    document.body.appendChild(modal);
    requestAnimationFrame(() => modal.classList.add('nwm-visible'));

    function close(result) {
      modal.classList.remove('nwm-visible');
      setTimeout(() => modal.remove(), 250);
      resolve(result);
    }

    document.getElementById('nwmCancel').onclick   = () => close(false);
    document.getElementById('nwmContinue').onclick = () => close(true);
    modal.addEventListener('click', e => { if (e.target === modal) close(false); });
  });
}
