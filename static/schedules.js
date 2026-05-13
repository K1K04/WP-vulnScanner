

const HDR = {
  'Content-Type': 'application/json',
  'X-API-Key': localStorage.getItem('wpvs_api_key') || '',
};
const API_KEY_QP = new URLSearchParams(location.search).get('key');
if (API_KEY_QP) {
  HDR['X-API-Key'] = API_KEY_QP;
  localStorage.setItem('wpvs_api_key', API_KEY_QP);
}


function showToast(msg, type = 'ok') {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className   = `toast ${type}`;
  t.style.display = 'block';
  clearTimeout(t._t);
  t._t = setTimeout(() => { t.style.display = 'none'; }, 5000);
}


async function loadSchedules() {
  const list = document.getElementById('scheduleList');
  try {
    const res  = await fetch('/api/schedules', { headers: HDR });
    const data = await res.json();

    if (!Array.isArray(data)) {
      const errMsg = document.createElement('div');
      errMsg.className = 'empty-state';
      errMsg.style.color = 'var(--red)';
      errMsg.textContent = data.error || 'Error al cargar';
      list.innerHTML = '';
      list.appendChild(errMsg);
      return;
    }
    if (!data.length) {
      list.innerHTML = `<div class="empty-state">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/></svg>
        <p>No hay escaneos programados. Usa el formulario de arriba para crear el primero.</p>
      </div>`;
      return;
    }

    list.innerHTML = data.map(s => {
      const freqClass = {daily:'badge-daily', weekly:'badge-weekly', monthly:'badge-monthly'}[s.cron_expr] || 'badge-weekly';
      const freqLabel = {daily:'Diario', weekly:'Semanal', monthly:'Mensual'}[s.cron_expr] || s.cron_expr;
      const domain    = (s.url || '').replace(/https?:\/\//, '').split('/')[0];
      const lastRun   = s.last_run
        ? new Date(s.last_run).toLocaleString('es-ES', {day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'})
        : 'Nunca';

      return `<div class="sched-card ${s.active ? '' : 'inactive'}">
        <div class="sched-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/></svg>
        </div>
        <div class="sched-info">
          <div class="sched-url" title="${s.url}">${domain}</div>
          <div class="sched-meta">
            <span class="sched-badge ${freqClass}">${freqLabel}</span>
            <span class="sched-badge ${s.active ? 'badge-active' : 'badge-inactive'}">${s.active ? 'Activo' : 'Inactivo'}</span>
            <span class="sched-date">Último: ${lastRun}</span>
            ${s.last_scan_id ? `<a href="/scan/${s.last_scan_id}/result" style="font-size:10px;color:var(--blue);text-decoration:none;border:1px solid rgba(77,159,255,.35);border-radius:2px;padding:1px 6px">Ver resultado</a>` : ''}
            ${s.notify_email ? `<span class="sched-email"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>${s.notify_email}</span>` : ''}
          </div>
        </div>
        <div class="sched-actions">
          <button class="btn btn-run btn-sm" onclick="runNow('${s.id}', this)">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><polygon points="5 3 19 12 5 21 5 3"/></svg>
            Ahora
          </button>
          <button class="btn btn-danger btn-sm" onclick="deleteSchedule('${s.id}')">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14H6L5 6"/><path d="M10 11v6M14 11v6"/></svg>
          </button>
        </div>
      </div>`;
    }).join('');
  } catch(e) {
    list.innerHTML = `<div class="empty-state" style="color:var(--red)">Error: ${e.message}</div>`;
  }
}

async function createSchedule() {
  const url      = document.getElementById('newUrl').value.trim();
  const cron     = document.getElementById('newCron').value;
  const email    = document.getElementById('newEmail').value.trim();
  const callback = document.getElementById('newCallback').value.trim();

  if (!url) { showToast('Introduce una URL', 'err'); return; }

  const btn = document.getElementById('btnCreate');
  btn.disabled = true;
  try {
    const res  = await fetch('/api/schedules', {
      method: 'POST', headers: HDR,
      body: JSON.stringify({ url, cron_expr: cron, notify_email: email, callback_url: callback }),
    });
    const data = await res.json();
    if (data.error) { showToast(data.error, 'err'); return; }
    showToast(`Escaneo programado creado para ${url}`, 'ok');
    document.getElementById('newUrl').value    = '';
    document.getElementById('newEmail').value  = '';
    document.getElementById('newCallback').value = '';
    await loadSchedules();
  } catch(e) {
    showToast('Error al crear escaneo: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

async function runNow(schedId, btn) {
  const origHTML = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" class="spinning"><line x1="12" y1="2" x2="12" y2="6"/><line x1="12" y1="18" x2="12" y2="22"/><line x1="4.9" y1="4.9" x2="7.8" y2="7.8"/><line x1="16.2" y1="16.2" x2="19.1" y2="19.1"/><line x1="2" y1="12" x2="6" y2="12"/><line x1="18" y1="12" x2="22" y2="12"/></svg>`;
  try {
    const res  = await fetch(`/api/schedules/${schedId}/run`, { method: 'POST', headers: HDR });
    const data = await res.json();
    if (data.error) { showToast(data.error, 'err'); return; }
    showToast(`Escaneo lanzado — job ${data.job_id}`, 'ok');
    await loadSchedules();
  } catch(e) {
    showToast('Error al lanzar escaneo: ' + e.message, 'err');
  } finally {
    btn.innerHTML = origHTML;
    btn.disabled  = false;
  }
}

async function deleteSchedule(schedId) {
  if (!confirm('¿Desactivar este escaneo programado? Se puede reactivar más adelante.')) return;
  try {
    const res  = await fetch(`/api/schedules/${schedId}`, { method: 'DELETE', headers: HDR });
    const data = await res.json();
    if (data.error) { showToast(data.error, 'err'); return; }
    showToast('Escaneo programado desactivado', 'info');
    await loadSchedules();
  } catch(e) {
    showToast('Error: ' + e.message, 'err');
  }
}


let _pushSubscription = null;

async function initPush() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    document.getElementById('pushStatusText').textContent = 'No soportado en este navegador';
    return;
  }

  const reg = await navigator.serviceWorker.ready;
  _pushSubscription = await reg.pushManager.getSubscription();

  if (_pushSubscription) {
    setPushUI(true);
  } else {
    setPushUI(false);
  }
}

function setPushUI(active) {
  const dot  = document.getElementById('pushDot');
  const text = document.getElementById('pushStatusText');
  const icon = document.getElementById('pushIcon');
  const sub  = document.getElementById('btnSubscribe');
  const unsub= document.getElementById('btnUnsubscribe');

  dot.className   = `status-dot ${active ? 'on' : 'off'}`;
  text.textContent = active ? 'Notificaciones activas' : 'No activadas';
  text.style.color = active ? 'var(--green)' : 'var(--text-3)';
  icon.className   = `pwa-icon ${active ? 'enabled' : ''}`;
  sub.style.display   = active ? 'none' : '';
  unsub.style.display = active ? '' : 'none';
}

async function subscribePush() {
  if (!('serviceWorker' in navigator) || !('PushManager' in window)) {
    showToast('Tu navegador no soporta push notifications', 'err');
    return;
  }

  const btn = document.getElementById('btnSubscribe');
  btn.disabled = true;

  try {
    const keyRes = await fetch('/api/pwa/vapid-public-key');
    const keyData = await keyRes.json();

    if (!keyData.vapid_public_key) {
      showToast('VAPID_PUBLIC_KEY no configurada en el servidor — configúrala en .env', 'err');
      btn.disabled = false;
      return;
    }

    const perm = await Notification.requestPermission();
    if (perm !== 'granted') {
      showToast('Permiso de notificaciones denegado', 'err');
      btn.disabled = false;
      return;
    }

    const reg  = await navigator.serviceWorker.ready;
    const sub  = await reg.pushManager.subscribe({
      userVisibleOnly:      true,
      applicationServerKey: urlBase64ToUint8Array(keyData.vapid_public_key),
    });
    await fetch('/api/pwa/subscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        endpoint: sub.endpoint,
        keys: {
          p256dh: btoa(String.fromCharCode(...new Uint8Array(sub.getKey('p256dh')))),
          auth:   btoa(String.fromCharCode(...new Uint8Array(sub.getKey('auth')))),
        },
      }),
    });

    _pushSubscription = sub;
    setPushUI(true);
    showToast('Notificaciones push activadas', 'ok');
  } catch(e) {
    showToast('Error al activar: ' + e.message, 'err');
  } finally {
    btn.disabled = false;
  }
}

async function unsubscribePush() {
  if (!_pushSubscription) { setPushUI(false); return; }
  try {
    await fetch('/api/pwa/unsubscribe', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ endpoint: _pushSubscription.endpoint }),
    });
    await _pushSubscription.unsubscribe();
    _pushSubscription = null;
    setPushUI(false);
    showToast('Notificaciones desactivadas', 'info');
  } catch(e) {
    showToast('Error al desactivar: ' + e.message, 'err');
  }
}

async function testPush() {
  try {
    const res  = await fetch('/api/pwa/notify', {
      method:  'POST',
      headers: { ...HDR },
      body:    JSON.stringify({
        title: 'Test — WP VulnScanner',
        body:  'Las notificaciones push funcionan correctamente.',
        url:   '/dashboard',
      }),
    });
    const data = await res.json();
    if (data.warning) { showToast(data.warning, 'info'); return; }
    showToast(`Push enviado a ${data.sent} dispositivo(s)`, 'ok');
  } catch(e) {
    showToast('Error: ' + e.message, 'err');
  }
}


function urlBase64ToUint8Array(base64String) {
  const padding = '='.repeat((4 - base64String.length % 4) % 4);
  const base64  = (base64String + padding).replace(/-/g, '+').replace(/_/g, '/');
  const raw     = window.atob(base64);
  return Uint8Array.from([...raw].map((c) => c.charCodeAt(0)));
}
function toggleTheme() {
  const isLight = document.documentElement.classList.toggle('light');
  try { localStorage.setItem('wpvs_theme', isLight ? 'light' : 'dark'); } catch(e){}
  const dark  = document.getElementById('themeIconDark');
  const light = document.getElementById('themeIconLight');
  if (dark)  dark.style.display  = isLight ? 'none' : '';
  if (light) light.style.display = isLight ? ''     : 'none';
}
(function syncThemeIcons(){
  try {
    if (document.documentElement.classList.contains('light')) {
      const dark  = document.getElementById('themeIconDark');
      const light = document.getElementById('themeIconLight');
      if (dark)  dark.style.display  = 'none';
      if (light) light.style.display = '';
    }
  } catch(e){}
})();


document.addEventListener('DOMContentLoaded', () => {
  loadSchedules();
  initPush();
});


  list.dataset.loading = '1';
  const loadingTimeout = setTimeout(() => {
    if (list.dataset.loading === '1') {
        <p>No se pudo cargar la lista a tiempo. Pulsa "Actualizar lista" para reintentar.</p>
  }, 9000);
      list.dataset.loading = '0';
      clearTimeout(loadingTimeout);
      list.dataset.loading = '0';
      clearTimeout(loadingTimeout);
    list.dataset.loading = '0';
    clearTimeout(loadingTimeout);
    list.dataset.loading = '0';
    clearTimeout(loadingTimeout);
  if (!_validateScheduleForm(true)) return;
function _setFieldValidation(el, ok) {
  if (!el) return;
  el.classList.remove('input-valid', 'input-invalid');
  if (ok === true) el.classList.add('input-valid');
  if (ok === false) el.classList.add('input-invalid');
function _isValidUrlLoose(v) {
  if (!v) return false;
  const t = String(v).trim();
  return /^https?:\/\/.+/i.test(t) || /^[a-z0-9.-]+\.[a-z]{2,}.*$/i.test(t);
function _validateScheduleForm(showToastOnError = false) {
  const urlEl = document.getElementById('newUrl');
  const emailEl = document.getElementById('newEmail');
  const callbackEl = document.getElementById('newCallback');
  const url = (urlEl?.value || '').trim();
  const email = (emailEl?.value || '').trim();
  const callback = (callbackEl?.value || '').trim();
  const urlOk = _isValidUrlLoose(url);
  const emailOk = !email || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
  const callbackOk = !callback || _isValidUrlLoose(callback);
  _setFieldValidation(urlEl, url ? urlOk : null);
  _setFieldValidation(emailEl, email ? emailOk : null);
  _setFieldValidation(callbackEl, callback ? callbackOk : null);
  if (showToastOnError) {
    if (!urlOk) { showToast('URL inválida. Usa dominio o URL completa.', 'err'); return false; }
    if (!emailOk) { showToast('Email de notificación inválido.', 'err'); return false; }
    if (!callbackOk) { showToast('Webhook callback URL inválida.', 'err'); return false; }
  return urlOk && emailOk && callbackOk;
  document.getElementById('refreshSchedulesBtn')?.addEventListener('click', loadSchedules);
  document.getElementById('btnCreate')?.addEventListener('click', createSchedule);
  document.getElementById('btnSubscribe')?.addEventListener('click', subscribePush);
  document.getElementById('btnUnsubscribe')?.addEventListener('click', unsubscribePush);
  document.getElementById('btnTestPush')?.addEventListener('click', testPush);
  ['newUrl','newEmail','newCallback'].forEach(id => {
    document.getElementById(id)?.addEventListener('input', () => _validateScheduleForm(false));
  });
  document.getElementById('copyVapidCmdBtn')?.addEventListener('click', () => {
    const cmd = document.getElementById('vapidCommand')?.textContent || '';
    if (!cmd) return;
    navigator.clipboard.writeText(cmd)
      .then(() => showToast('Comando VAPID copiado', 'ok'))
      .catch(() => showToast('No se pudo copiar el comando', 'err'));
  });
