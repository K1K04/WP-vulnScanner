
const API_KEY_HEADER = { 'X-API-Key': '' };

let catalog = [];
let savedKeys = [];
let envStatus = {};

const ENV_PURPOSE = {
  VT_API_KEY: 'Consulta reputacion de dominios y URLs detectadas.',
  ABUSEIPDB_API_KEY: 'Consulta reputacion de IPs y rangos sospechosos.',
  GSB_API_KEY: 'Comprueba URLs contra listas de phishing y malware.',
  WPSCAN_API_TOKEN: 'Sincroniza vulnerabilidades de WordPress con WPScan.',
  GITHUB_TOKEN: 'Aumenta limites al actualizar advisories desde GitHub.',
  SMTP_HOST: 'Servidor SMTP usado para enviar notificaciones.',
  SMTP_PASS: 'Contrasena SMTP para enviar notificaciones por email.',
  GEMINI_API_KEY: 'Activa Chat IA y Plan IA de remediacion.',
  ANTHROPIC_API_KEY: 'Clave de Anthropic para usar Claude en chat/plan.',
  AI_PROVIDER: 'Selecciona proveedor IA: auto, gemini, claude u ollama.',
  GEMINI_MODEL: 'Modelo de Gemini usado por las funciones IA.',
  CLAUDE_MODEL: 'Modelo de Claude usado por las funciones IA.',
  OLLAMA_BASE_URL: 'URL del servidor Ollama local o remoto.',
  OLLAMA_MODEL: 'Modelo principal de Ollama para chat/plan.',
  OLLAMA_MODEL_FALLBACKS: 'Modelos alternativos si el principal no existe.',
  GEMINI_TIMEOUT_SECONDS: 'Timeout de peticiones no-stream a Gemini (segundos).',
  GEMINI_STREAM_TIMEOUT_SECONDS: 'Timeout de peticiones stream a Gemini (segundos).',
  CLAUDE_TIMEOUT_SECONDS: 'Timeout de peticiones no-stream a Claude (segundos).',
  CLAUDE_STREAM_TIMEOUT_SECONDS: 'Timeout de peticiones stream a Claude (segundos).',
  OLLAMA_TIMEOUT_SECONDS: 'Timeout general de Ollama en respuestas no-stream (segundos).',
  OLLAMA_STREAM_TIMEOUT_SECONDS: 'Timeout de Ollama en respuestas stream (segundos).',
  OLLAMA_PLAN_TIMEOUT_SECONDS: 'Timeout especifico para generar planes IA (segundos).',
  OLLAMA_TAGS_TIMEOUT_SECONDS: 'Timeout al consultar modelos instalados en /api/tags.',
  AI_PLAN_MAX_TOKENS: 'Tokens maximos para el plan IA.',
  AI_PLAN_RETRY_MAX_TOKENS: 'Tokens usados en reintento del plan tras timeout.',
  OLLAMA_PLAN_RETRY_TIMEOUT_SECONDS: 'Timeout del reintento del plan tras timeout inicial.',
  UI_BASIC_AUTH_USER: 'Usuario para proteger la UI web con HTTP Basic Auth.',
  UI_BASIC_AUTH_PASS: 'Contrasena para proteger la UI web con HTTP Basic Auth.',
};

const VALUE_PLACEHOLDERS = {
  VT_API_KEY: 'ej: 7b8f... (API key de VirusTotal)',
  ABUSEIPDB_API_KEY: 'ej: abcd1234... (Key de AbuseIPDB)',
  GSB_API_KEY: 'ej: AIza... (Google Safe Browsing key)',
  WPSCAN_API_TOKEN: 'ej: 123abc... (Token personal de WPScan)',
  SMTP_PASS: 'Contrasena SMTP de la cuenta remitente',
  GEMINI_API_KEY: 'ej: AIza... (API key de Gemini)',
  ANTHROPIC_API_KEY: 'ej: sk-ant-... (API key de Anthropic)',
  GITHUB_TOKEN: 'ej: ghp_... (token personal de GitHub)',
};

document.addEventListener('DOMContentLoaded', async () => {
  const urlKey = new URLSearchParams(location.search).get('key');
  if (urlKey) {
    API_KEY_HEADER['X-API-Key'] = urlKey;
    localStorage.setItem('wpvs_api_key', urlKey);
  } else {
    API_KEY_HEADER['X-API-Key'] = localStorage.getItem('wpvs_api_key') || '';
  }

  await loadKeys();
});

async function apiFetch(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...API_KEY_HEADER, ...(opts.headers || {}) },
  });
  if (!res.ok && res.status === 401) {
    showToast('API Key no valida. Anade ?key=TU_API_KEY a la URL.', 'err');
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const msg = await res.text().catch(() => '');
    throw new Error(msg || `HTTP ${res.status}`);
  }
  return res.json();
}

async function loadKeys() {
  try {
    const data = await apiFetch('/api/settings/keys');
    catalog = data.catalog || [];
    savedKeys = data.keys || [];
    envStatus = data.env_status || {};

    renderApiGuide();
    renderKeysGrid();
    renderCatalogSelect();
    renderEnvTable();
  } catch (e) {
    const keysGrid = document.getElementById('keysGrid');
    const envTableBody = document.getElementById('envTableBody');
    if (keysGrid) {
      keysGrid.innerHTML = `<div style="color:var(--red);font-size:12px;padding:12px">Error al cargar claves: ${e.message}</div>`;
    }
    if (envTableBody) {
      envTableBody.innerHTML = `<tr><td colspan="5" style="color:var(--red);font-size:11px;padding:12px">Error cargando estado: ${e.message}</td></tr>`;
    }
  }
}

function renderApiGuide() {
  const grid = document.getElementById('apiGuideGrid');
  if (!grid) return;

  if (!catalog.length) {
    grid.innerHTML = `<div style="color:var(--text-3);font-size:12px;padding:12px;font-family:var(--sans)">No hay servicios disponibles en el catalogo.</div>`;
    return;
  }

  const sorted = [...catalog].sort((a, b) => {
    const ap = a.priority === 'recommended' ? 1 : 0;
    const bp = b.priority === 'recommended' ? 1 : 0;
    if (ap !== bp) return bp - ap;
    return (a.label || '').localeCompare(b.label || '', 'es');
  });

  grid.innerHTML = sorted.map((s) => {
    const isRecommended = s.priority === 'recommended';
    const badgeLabel = isRecommended ? 'Recomendada' : 'Opcional';
    return `<article class="api-guide-card">
      <div class="api-guide-top">
        <div class="api-guide-label">${s.label}</div>
        <span class="api-guide-priority ${isRecommended ? 'recommended' : ''}">${badgeLabel}</span>
      </div>
      <div class="api-guide-desc">${s.description || 'Sin descripcion'}</div>
      <div class="api-guide-env">${s.env_var || s.service}</div>
    </article>`;
  }).join('');
}

function renderKeysGrid() {
  const grid = document.getElementById('keysGrid');
  const testAllBtn = document.getElementById('btnTestAll');
  if (!grid) return;
  if (testAllBtn) testAllBtn.disabled = !savedKeys.length;

  if (!savedKeys.length) {
    grid.innerHTML = `<div style="color:var(--text-3);font-size:12px;padding:12px;font-family:var(--sans)">No hay claves configuradas. Usa el formulario de abajo para anadir la primera.</div>`;
    return;
  }

  grid.innerHTML = savedKeys.map((k) => {
    const isEnvOnly = k.source === 'env';
    const testDate = k.last_tested ? new Date(k.last_tested).toLocaleDateString('es-ES', { day: '2-digit', month: 'short' }) : null;
    const testStatus = k.test_ok === null
      ? { dot: '', label: 'Sin probar' }
      : k.test_ok
        ? { dot: 'ok', label: `OK · ${testDate || ''}` }
        : { dot: 'fail', label: `Fallo · ${testDate || ''}` };

    const sourceTag = isEnvOnly
      ? '<span class="key-mask" style="letter-spacing:.2px">Solo .env</span>'
      : '';

    const actionsHtml = isEnvOnly
      ? `<button class="btn btn-secondary btn-sm" onclick="toggleEdit('${k.service}')">Guardar en BD</button>
         <button class="btn btn-success btn-sm" onclick="testKey('${k.service}', this)">Test</button>`
      : `<button class="btn btn-secondary btn-sm" onclick="toggleEdit('${k.service}')">Editar</button>
         <button class="btn btn-success btn-sm" onclick="testKey('${k.service}', this)">Test</button>
         <button class="btn btn-danger btn-sm" onclick="deleteKey('${k.service}')">Eliminar</button>`;

    return `<div class="key-card" id="card-${k.service}">
      <div class="key-card-top">
        <div class="key-icon ${k.active ? 'configured' : ''}">${iconSvg(k.icon)}</div>
        <div class="key-info">
          <div class="key-label">${k.label}</div>
          <div class="key-desc">${k.description}</div>
          <div class="key-status">
            <span class="status-dot ${testStatus.dot}"></span>
            <span class="status-label">${testStatus.label}</span>
            &nbsp;&nbsp;
            <span class="key-mask">${k.value_mask}</span>
            &nbsp;&nbsp;
            ${sourceTag}
          </div>
        </div>
        <div class="key-actions">
          ${actionsHtml}
        </div>
      </div>
      <div class="key-form" id="form-${k.service}">
        <div class="form-row">
          <div class="form-input-wrap">
            <input type="password" id="input-${k.service}" placeholder="Nueva clave API..." autocomplete="off">
            <button class="show-toggle" onclick="toggleVisibility('${k.service}')">👁</button>
          </div>
          <button class="btn btn-primary btn-sm" onclick="updateKey('${k.service}')">Actualizar</button>
          <button class="btn btn-secondary btn-sm" onclick="toggleEdit('${k.service}')">Cancelar</button>
        </div>
        ${k.docs_url ? `<div class="form-hint">Obtener clave: <a href="${k.docs_url}" target="_blank">${k.docs_url}</a></div>` : ''}
        <div class="test-result" id="test-${k.service}"></div>
      </div>
    </div>`;
  }).join('');
}

function renderCatalogSelect() {
  const sel = document.getElementById('addService');
  if (!sel) return;
  const configured = new Set(savedKeys.map((k) => k.service));
  sel.innerHTML = '<option value="">Seleccionar servicio...</option>';
  catalog.forEach((s) => {
    const opt = document.createElement('option');
    opt.value = s.service;
    const priority = s.priority === 'recommended' ? 'Recomendada' : 'Opcional';
    const action = configured.has(s.service) ? ' (actualizar)' : '';
    opt.textContent = `${s.label} · ${priority}${action}`;
    sel.appendChild(opt);
  });
}

function renderEnvTable() {
  const ENV_VARS = [
    'VT_API_KEY', 'ABUSEIPDB_API_KEY', 'GSB_API_KEY',
    'WPSCAN_API_TOKEN', 'GITHUB_TOKEN',
    'SMTP_HOST', 'SMTP_PASS', 'GEMINI_API_KEY', 'ANTHROPIC_API_KEY',
    'AI_PROVIDER', 'GEMINI_MODEL', 'CLAUDE_MODEL', 'OLLAMA_BASE_URL', 'OLLAMA_MODEL',
    'OLLAMA_MODEL_FALLBACKS',
    'GEMINI_TIMEOUT_SECONDS', 'GEMINI_STREAM_TIMEOUT_SECONDS',
    'CLAUDE_TIMEOUT_SECONDS', 'CLAUDE_STREAM_TIMEOUT_SECONDS',
    'OLLAMA_TIMEOUT_SECONDS', 'OLLAMA_STREAM_TIMEOUT_SECONDS',
    'OLLAMA_PLAN_TIMEOUT_SECONDS', 'OLLAMA_TAGS_TIMEOUT_SECONDS',
    'AI_PLAN_MAX_TOKENS', 'AI_PLAN_RETRY_MAX_TOKENS',
    'OLLAMA_PLAN_RETRY_TIMEOUT_SECONDS',
    'UI_BASIC_AUTH_USER', 'UI_BASIC_AUTH_PASS',
  ];

  const configuredInDb = new Set(savedKeys.filter((k) => k.source !== 'env').map((k) => k.service));
  const tbody = document.getElementById('envTableBody');
  if (!tbody) return;

  tbody.innerHTML = ENV_VARS.map((v) => {
    const svc = catalog.find((s) => s.service === v);
    const inDb = configuredInDb.has(v);
    const inEnv = !inDb && (envStatus[v] === true);
    const usage = svc?.description || ENV_PURPOSE[v] || 'Variable tecnica interna';

    let status = '';
    let source = '';

    if (inDb) {
      status = '<span style="color:var(--green)">BD cifrada</span>';
      source = '<span style="color:var(--teal)">BD</span>';
    } else if (inEnv) {
      status = '<span style="color:var(--blue)">.env</span>';
      source = '<span style="color:var(--text-3)">.env</span>';
    } else {
      status = '<span style="color:var(--text-3)">No configurada</span>';
      source = '<span style="color:var(--text-3)">.env</span>';
    }

    return `<tr>
      <td style="color:var(--blue)">${v}</td>
      <td style="color:var(--text-2)">${svc?.label || '—'}</td>
      <td style="color:var(--text-2);font-family:var(--sans)">${usage}</td>
      <td>${status}</td>
      <td>${source}</td>
    </tr>`;
  }).join('');
}

function toggleEdit(service) {
  const form = document.getElementById(`form-${service}`);
  if (!form) return;
  form.classList.toggle('open');
  if (form.classList.contains('open')) {
    document.getElementById(`input-${service}`)?.focus();
  }
}

function toggleVisibility(service) {
  const inp = document.getElementById(`input-${service}`);
  if (!inp) return;
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

function toggleAddVisibility() {
  const inp = document.getElementById('addValue');
  if (!inp) return;
  inp.type = inp.type === 'password' ? 'text' : 'password';
}

async function updateKey(service) {
  const inp = document.getElementById(`input-${service}`);
  const val = inp?.value?.trim() || '';
  if (!val) {
    showToast('El valor no puede estar vacio', 'err');
    return;
  }

  try {
    await apiFetch('/api/settings/keys', {
      method: 'POST',
      body: JSON.stringify({ service, value: val }),
    });
    inp.value = '';
    showToast(`Clave ${service} actualizada correctamente`, 'ok');
    await loadKeys();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'err');
  }
}

async function saveKey() {
  const service = document.getElementById('addService')?.value || '';
  const val = document.getElementById('addValue')?.value?.trim() || '';
  if (!service) {
    showToast('Selecciona un servicio', 'err');
    return;
  }
  if (!val) {
    showToast('El valor no puede estar vacio', 'err');
    return;
  }

  const btn = document.getElementById('btnSave');
  if (btn) btn.disabled = true;
  try {
    await apiFetch('/api/settings/keys', {
      method: 'POST',
      body: JSON.stringify({ service, value: val }),
    });
    const addValue = document.getElementById('addValue');
    const addService = document.getElementById('addService');
    const docsHint = document.getElementById('docsHint');
    if (addValue) {
      addValue.value = '';
      addValue.placeholder = 'sk-··· o tu clave API';
    }
    if (addService) addService.value = '';
    if (docsHint) docsHint.innerHTML = '';
    showToast(`Clave ${service} guardada cifrada`, 'ok');
    await loadKeys();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'err');
  } finally {
    if (btn) btn.disabled = false;
  }
}

async function deleteKey(service) {
  if (!confirm(`¿Eliminar la clave de ${service}? Esta accion no se puede deshacer.`)) return;
  try {
    await apiFetch(`/api/settings/keys/${service}`, { method: 'DELETE' });
    showToast(`Clave ${service} eliminada`, 'info');
    await loadKeys();
  } catch (e) {
    showToast(`Error: ${e.message}`, 'err');
  }
}

async function testAllKeys() {
  if (!savedKeys.length) {
    showToast('No hay claves guardadas para probar', 'info');
    return;
  }

  const btn = document.getElementById('btnTestAll');
  const original = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = 'Probando...';
  }

  let okCount = 0;
  let failCount = 0;
  for (const k of savedKeys) {
    try {
      const res = await apiFetch(`/api/settings/keys/test/${k.service}`, { method: 'POST' });
      if (res?.ok) okCount += 1;
      else failCount += 1;
    } catch (_) {
      failCount += 1;
    }
  }

  await loadKeys();
  showToast(`Prueba completada: ${okCount} OK · ${failCount} con error`, failCount ? 'info' : 'ok');
  if (btn) {
    btn.innerHTML = original;
    btn.disabled = false;
  }
}

async function testKey(service, btn) {
  const origHtml = btn ? btn.innerHTML : '';
  if (btn) {
    btn.disabled = true;
    btn.innerHTML = 'Probando...';
  }

  try {
    const res = await apiFetch(`/api/settings/keys/test/${service}`, { method: 'POST' });
    const resultEl = document.getElementById(`test-${service}`);
    if (resultEl) {
      resultEl.className = `test-result ${res.ok ? 'ok' : 'fail'}`;
      resultEl.textContent = res.ok
        ? `Conexion correcta · ${res.message || '200 OK'}`
        : `Error: ${res.error || res.message || 'Respuesta inesperada'}`;
      resultEl.style.display = 'block';
      const form = document.getElementById(`form-${service}`);
      if (form) form.classList.add('open');
      setTimeout(() => { resultEl.style.display = 'none'; }, 8000);
    }
    showToast(res.ok ? `${service}: conexion OK` : `${service}: ${res.error || 'fallo'}`, res.ok ? 'ok' : 'err');
  } catch (e) {
    showToast(`Error al probar ${service}: ${e.message}`, 'err');
  } finally {
    if (btn) {
      btn.innerHTML = origHtml;
      btn.disabled = false;
    }
  }
}

function updateDocsLink() {
  const service = document.getElementById('addService')?.value || '';
  const svc = catalog.find((s) => s.service === service);
  const hint = document.getElementById('docsHint');
  const valueInput = document.getElementById('addValue');

  if (!hint || !valueInput) return;
  hint.innerHTML = '';
  valueInput.placeholder = 'sk-··· o tu clave API';

  if (!svc) return;

  if (VALUE_PLACEHOLDERS[service]) {
    valueInput.placeholder = VALUE_PLACEHOLDERS[service];
  }

  const priority = svc.priority === 'recommended' ? '<strong>Recomendada.</strong> ' : '<strong>Opcional.</strong> ';

  if (svc.docs_url) {
    hint.innerHTML = `${priority}${svc.description || ''} Obtener clave en: <a href="${svc.docs_url}" target="_blank" rel="noopener noreferrer">${svc.docs_url}</a>`;
  } else if (svc.description) {
    hint.innerHTML = `${priority}${svc.description}`;
  }
}

function iconSvg(name) {
  const icons = {
    globe: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>`,
    server: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>`,
    shield: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2L3 6.5v5.5c0 4.8 3.8 9.3 9 10.5 5.2-1.2 9-5.7 9-10.5V6.5L12 2z"/><polyline points="9 12 11 14 15 10"/></svg>`,
    key: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"/></svg>`,
    lock: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>`,
  };
  return icons[name] || icons.key;
}

function showToast(msg, type = 'ok') {
  const t = document.getElementById('toast');
  if (!t) return;
  t.textContent = msg;
  t.className = `toast ${type}`;
  t.style.display = 'block';
  clearTimeout(t._timer);
  t._timer = setTimeout(() => { t.style.display = 'none'; }, 5000);
}

window.toggleEdit = toggleEdit;
window.toggleVisibility = toggleVisibility;
window.toggleAddVisibility = toggleAddVisibility;
window.updateKey = updateKey;
window.saveKey = saveKey;
window.deleteKey = deleteKey;
window.testAllKeys = testAllKeys;
window.testKey = testKey;
window.updateDocsLink = updateDocsLink;
