// ============================================
// Admin Panel — versión light
// Solo: Número principal vigente + reportes (refunds + ingresos)
// ============================================

const API_URL = '';

// Sesiones separadas: el admin general usa `adminToken`, el panel de
// /cierresgeneral (URL con ?only=closings) usa `closingsToken`. Así las
// dos sesiones coexisten sin pisarse.
const _IS_CLOSINGS_MODE = (function() {
    try { return new URLSearchParams(location.search).get('only') === 'closings'; }
    catch { return false; }
})();
const _TOKEN_KEY = _IS_CLOSINGS_MODE ? 'closingsToken' : 'adminToken';
const _USER_KEY = _IS_CLOSINGS_MODE ? 'closingsUser' : 'adminUser';

let currentToken = localStorage.getItem(_TOKEN_KEY) || null;
let currentAdmin = null;

// Máximo de slots permitidos por el backend (USER_LINES_MAX_SLOTS).
// Lo descubrimos del response de GET /api/admin/user-lines y lo guardamos acá.
let USER_LINES_MAX = 30;

// ============================================
// HELPERS
// ============================================
function escapeHtml(str) {
    if (str == null) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Devuelve el valor escapado para inyectar como argumento string en un
// onclick="...(arg)..." con `"`-quotes. Combina JSON.stringify (para JS)
// + escapeHtml (para HTML attr). Si el ID o weekKey trae chars raros,
// queda como dato (no escape al contexto JS).
function escapeJsArg(v) {
    return escapeHtml(JSON.stringify(String(v == null ? '' : v)));
}

function formatMoney(n) {
    const v = Number(n) || 0;
    return '$' + v.toLocaleString('es-AR');
}

function formatDate(iso) {
    if (!iso) return '';
    try {
        const d = new Date(iso);
        return d.toLocaleString('es-AR', { timeZone: 'America/Argentina/Buenos_Aires' });
    } catch (_) {
        return String(iso);
    }
}

function todayISO() {
    const d = new Date();
    // ART = UTC-3
    const offsetMs = 3 * 60 * 60 * 1000;
    return new Date(d.getTime() - offsetMs).toISOString().slice(0, 10);
}

function isoDaysAgo(days) {
    const d = new Date();
    d.setDate(d.getDate() - days);
    const offsetMs = 3 * 60 * 60 * 1000;
    return new Date(d.getTime() - offsetMs).toISOString().slice(0, 10);
}

function showToast(msg, type) {
    const c = document.getElementById('toastContainer');
    if (!c) { console.log('[toast]', msg); return; }
    const t = document.createElement('div');
    t.className = 'toast ' + (type || 'info');
    t.textContent = msg;
    c.appendChild(t);
    setTimeout(() => {
        t.style.opacity = '0';
        t.style.transition = 'opacity 0.25s';
        setTimeout(() => t.remove(), 280);
    }, 3200);
}

// Ruteo de section-pin tokens — si el endpoint corresponde a una sección
// protegida, adjuntamos el token JWT corto que emitió /section-pins/verify.
// Sin esto, el backend devuelve 403 PIN_REQUIRED aunque el admin tenga
// sesión válida.
function _getSectionPinTokenForUrl(url) {
    try {
        // Endpoints que requieren token de 'numero'
        if (/^\/api\/admin\/user-lines(\?|$|\/)/.test(url) && !/lookup|import|history/.test(url)) {
            const raw = sessionStorage.getItem('sectionPinTokens') || '{}';
            return (JSON.parse(raw) || {}).numero || '';
        }
        // Endpoints que requieren token de 'backupPhones'
        if (/^\/api\/admin\/backup-phones(\.csv)?(\?|$)/.test(url)) {
            const raw = sessionStorage.getItem('sectionPinTokens') || '{}';
            return (JSON.parse(raw) || {}).backupPhones || '';
        }
        // Endpoints que requieren token de 'teams' — solo /stats (el detalle).
        // /names (solo nombres) NO requiere PIN para no romper líneas caídas
        // y refund-reminders que usan el selector de equipos.
        if (/^\/api\/admin\/teams\/stats(\?|$)/.test(url)) {
            const raw = sessionStorage.getItem('sectionPinTokens') || '{}';
            return (JSON.parse(raw) || {}).teams || '';
        }
    } catch (_) {}
    return '';
}

async function authFetch(url, opts) {
    const o = opts || {};
    o.headers = Object.assign({}, o.headers || {}, {
        'Authorization': 'Bearer ' + currentToken
    });
    if (o.body && !o.headers['Content-Type']) {
        o.headers['Content-Type'] = 'application/json';
    }
    const pinTok = _getSectionPinTokenForUrl(url);
    if (pinTok) o.headers['X-Section-Pin-Token'] = pinTok;
    const r = await fetch(API_URL + url, o);
    if (r.status === 401) {
        // Token expiró — forzar logout
        handleLogout();
        throw new Error('Sesión expirada');
    }
    // 403 PIN_REQUIRED — el token de sección expiró o nunca se obtuvo.
    // Limpiamos el unlock para que el siguiente intento abra el modal.
    if (r.status === 403) {
        try {
            const clone = r.clone();
            const d = await clone.json();
            if (d && d.error === 'PIN_REQUIRED' && d.section) {
                const raw = sessionStorage.getItem(_SECTION_PIN_UNLOCK_KEY) || '{}';
                const u = JSON.parse(raw); delete u[d.section];
                sessionStorage.setItem(_SECTION_PIN_UNLOCK_KEY, JSON.stringify(u));
                const t = sessionStorage.getItem('sectionPinTokens') || '{}';
                const tt = JSON.parse(t); delete tt[d.section];
                sessionStorage.setItem('sectionPinTokens', JSON.stringify(tt));
            }
        } catch (_) {}
    }
    return r;
}

// ============================================
// AUTH
// ============================================
async function handleLogin(e) {
    e.preventDefault();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errEl = document.getElementById('loginError');
    errEl.textContent = '';

    if (!username || !password) {
        errEl.textContent = 'Completá usuario y contraseña';
        return;
    }

    try {
        const r = await fetch(API_URL + '/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username, password })
        });
        const data = await r.json();

        if (!r.ok || !data.token) {
            errEl.textContent = data.error || data.message || 'Credenciales inválidas';
            return;
        }

        const adminRoles = ['admin', 'depositor', 'withdrawer', 'closings_viewer'];
        if (!adminRoles.includes(data.user && data.user.role)) {
            errEl.textContent = 'Tu cuenta no tiene permisos de administrador';
            return;
        }

        currentToken = data.token;
        currentAdmin = data.user;
        localStorage.setItem(_TOKEN_KEY, currentToken);
        if (data.user) localStorage.setItem(_USER_KEY, JSON.stringify(data.user));
        showApp();
    } catch (err) {
        console.error('Login error:', err);
        errEl.textContent = 'Error de conexión';
    }
}

function handleLogout() {
    currentToken = null;
    currentAdmin = null;
    localStorage.removeItem(_TOKEN_KEY);
    localStorage.removeItem(_USER_KEY);
    document.getElementById('app').classList.add('hidden');
    document.getElementById('loginScreen').classList.remove('hidden');
}

// Badge verde con count de usuarios activos al lado del adminName.
// Pollea /api/admin/active-users-count cada 10s mientras la pestaña está
// visible. Cuando la pestaña se oculta, pausa el polling para no gastar
// requests. Vuelve a arrancar cuando se vuelve a enfocar.
let _activeUsersTimer = null;
async function _fetchActiveUsersCount() {
    try {
        const r = await authFetch('/api/admin/active-users-count');
        if (!r.ok) return;
        const d = await r.json().catch(() => null);
        if (!d || !d.success) return;
        const badge = document.getElementById('activeUsersBadge');
        const counter = document.getElementById('activeUsersCount');
        if (badge && counter) {
            counter.textContent = String(d.count || 0);
            badge.style.display = 'inline-flex';
            badge.title = 'Usuarios activos ahora: ' + (d.count || 0) + ' · Admins: ' + (d.admins || 0);
        }
    } catch (_) { /* silent — no rompemos nada por esto */ }
}
function startActiveUsersBadge() {
    if (_activeUsersTimer) return;
    _fetchActiveUsersCount();
    _activeUsersTimer = setInterval(() => {
        if (document.visibilityState === 'visible') _fetchActiveUsersCount();
    }, 10000);
}

function showApp() {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('app').classList.remove('hidden');
    const nameEl = document.getElementById('adminName');
    if (nameEl) nameEl.textContent = (currentAdmin && currentAdmin.username) || 'Admin';

    // Arranca el polling del badge "users activos" al lado del adminName.
    try { startActiveUsersBadge(); } catch (_) {}

    // Modo "vista reducida" (?only=<sectionKey>): saltar a esa sección y nada más.
    const onlySection = document.documentElement.dataset.onlySection;
    if (onlySection) {
        try { showSection(onlySection); } catch (_) {}
        return;
    }

    // Cargar los nombres de sectores antes de renderizar, así Cierres y
    // Empleados muestran los nombres personalizados desde el primer render.
    // Luego abre la sección por defecto (Cierres general, protegida con PIN).
    _loadSectorNames().finally(() => {
        try { showSection('closings'); } catch (_) {}
    });
}

// ============================================
// PIN GATE — secciones protegidas (CENTRAL, Números vigentes)
// ============================================
// Cada sección protegida tiene su propio PIN. Cuando el admin tilda una
// nav-item protegida, mostramos el modal de PIN. Si lo acierta, marcamos
// la sección como desbloqueada en sessionStorage (vive solo mientras la
// pestaña esté abierta). Si recarga, vuelve a pedir.
const _SECTION_PIN_UNLOCK_KEY = 'sectionPinsUnlocked';

function _isSectionUnlocked(sectionKey) {
    try {
        const raw = sessionStorage.getItem(_SECTION_PIN_UNLOCK_KEY) || '{}';
        const u = JSON.parse(raw);
        if (!u[sectionKey]) return false;
        // Después del deploy del PIN backend, además del flag de unlock
        // necesitamos un token vivo. Si no hay token, forzamos re-ingreso
        // del PIN — el backend igual devolvería 403 sin token.
        const t = sessionStorage.getItem('sectionPinTokens') || '{}';
        const tt = JSON.parse(t);
        return !!tt[sectionKey];
    } catch (_) { return false; }
}

function _markSectionUnlocked(sectionKey) {
    try {
        const raw = sessionStorage.getItem(_SECTION_PIN_UNLOCK_KEY) || '{}';
        const u = JSON.parse(raw);
        u[sectionKey] = true;
        sessionStorage.setItem(_SECTION_PIN_UNLOCK_KEY, JSON.stringify(u));
    } catch (_) {}
}

// Abre el modal de PIN para una sección. Si el admin lo acierta, llama al cb.
function _promptSectionPin(sectionKey, sectionLabel, callback) {
    const modalId = 'sectionPinModal';
    document.getElementById(modalId)?.remove();
    const overlay = document.createElement('div');
    overlay.id = modalId;
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;';
    overlay.innerHTML = '<div style="background:#1a0033;border:1.5px solid #d4af37;border-radius:14px;padding:22px;max-width:380px;width:100%;color:#fff;box-shadow:0 0 40px rgba(212,175,55,0.30);">' +
        '<div style="text-align:center;margin-bottom:14px;">' +
        '<div style="font-size:32px;margin-bottom:6px;">🔐</div>' +
        '<h3 style="margin:0;color:#d4af37;font-size:16px;">' + escapeHtml(sectionLabel) + '</h3>' +
        '<div style="color:#aaa;font-size:11.5px;margin-top:4px;">Esta sección está protegida. Ingresá la clave para acceder.</div>' +
        '</div>' +
        '<input type="password" inputmode="numeric" maxlength="8" id="sectionPinInput" placeholder="••••" style="width:100%;background:#0a0a0a;color:#fff;border:1.5px solid rgba(212,175,55,0.40);padding:10px 14px;border-radius:8px;font-size:18px;text-align:center;letter-spacing:6px;font-weight:900;box-sizing:border-box;font-family:monospace;">' +
        '<div id="sectionPinErr" style="color:#ff8080;font-size:12px;text-align:center;min-height:14px;margin-top:6px;"></div>' +
        '<div style="display:flex;gap:8px;margin-top:14px;">' +
        '<button type="button" onclick="document.getElementById(\'sectionPinModal\').remove()" style="flex:1;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.20);color:#fff;padding:9px;border-radius:8px;font-weight:700;cursor:pointer;">Cancelar</button>' +
        '<button type="button" id="sectionPinSubmit" style="flex:2;background:linear-gradient(135deg,#d4af37,#f4d966);color:#1a0033;border:none;padding:9px;border-radius:8px;font-weight:900;cursor:pointer;">Entrar</button>' +
        '</div>' +
        '<div style="margin-top:10px;text-align:center;"><a href="#" onclick="event.preventDefault();_changeSectionPin(\'' + sectionKey + '\',\'' + escapeHtml(sectionLabel) + '\');" style="color:#888;font-size:10.5px;text-decoration:underline;">🔧 Cambiar la clave</a></div>' +
        '</div>';
    document.body.appendChild(overlay);
    const input = document.getElementById('sectionPinInput');
    const submit = document.getElementById('sectionPinSubmit');
    const errBox = document.getElementById('sectionPinErr');
    setTimeout(() => input && input.focus(), 50);
    const tryUnlock = async () => {
        const pin = input ? input.value : '';
        if (!pin) { errBox.textContent = 'Falta la clave'; return; }
        errBox.textContent = '⏳ Verificando...';
        try {
            const r = await authFetch('/api/admin/section-pins/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ section: sectionKey, pin })
            });
            const d = await r.json();
            if (!r.ok || !d.valid) {
                errBox.textContent = '❌ Clave incorrecta';
                input.value = '';
                input.focus();
                return;
            }
            _markSectionUnlocked(sectionKey);
            // Guardamos el JWT corto que emite el backend — authFetch lo
            // inyecta como X-Section-Pin-Token en cada request a endpoints
            // de la sección. Sin esto, los endpoints devuelven 403.
            if (d.token) {
                try {
                    const t = sessionStorage.getItem('sectionPinTokens') || '{}';
                    const tt = JSON.parse(t);
                    tt[sectionKey] = d.token;
                    sessionStorage.setItem('sectionPinTokens', JSON.stringify(tt));
                } catch (_) {}
            }
            overlay.remove();
            if (typeof callback === 'function') callback();
        } catch (e) {
            errBox.textContent = 'Error de conexión';
        }
    };
    if (submit) submit.onclick = tryUnlock;
    if (input) input.addEventListener('keydown', (e) => { if (e.key === 'Enter') tryUnlock(); });
}

// Modal para cambiar el PIN de una sección. Pide PIN actual + nuevo.
function _changeSectionPin(sectionKey, sectionLabel) {
    document.getElementById('sectionPinModal')?.remove();
    const modalId = 'sectionPinChangeModal';
    document.getElementById(modalId)?.remove();
    const overlay = document.createElement('div');
    overlay.id = modalId;
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;';
    overlay.innerHTML = '<div style="background:#1a0033;border:1.5px solid #d4af37;border-radius:14px;padding:22px;max-width:380px;width:100%;color:#fff;box-shadow:0 0 40px rgba(212,175,55,0.30);">' +
        '<div style="text-align:center;margin-bottom:14px;">' +
        '<div style="font-size:32px;margin-bottom:6px;">🔧</div>' +
        '<h3 style="margin:0;color:#d4af37;font-size:16px;">Cambiar clave · ' + escapeHtml(sectionLabel) + '</h3>' +
        '<div style="color:#aaa;font-size:11px;margin-top:4px;">Ingresá la clave actual y la nueva (4-8 dígitos).</div>' +
        '</div>' +
        '<label style="display:block;color:#aaa;font-size:10.5px;margin-bottom:3px;text-transform:uppercase;letter-spacing:0.5px;">Clave actual</label>' +
        '<input type="password" inputmode="numeric" maxlength="8" id="pinChangeCurrent" style="width:100%;background:#0a0a0a;color:#fff;border:1.5px solid rgba(212,175,55,0.40);padding:8px 12px;border-radius:8px;font-size:15px;text-align:center;letter-spacing:5px;font-weight:900;box-sizing:border-box;font-family:monospace;margin-bottom:10px;">' +
        '<label style="display:block;color:#aaa;font-size:10.5px;margin-bottom:3px;text-transform:uppercase;letter-spacing:0.5px;">Clave nueva</label>' +
        '<input type="password" inputmode="numeric" maxlength="8" id="pinChangeNew" style="width:100%;background:#0a0a0a;color:#fff;border:1.5px solid rgba(212,175,55,0.40);padding:8px 12px;border-radius:8px;font-size:15px;text-align:center;letter-spacing:5px;font-weight:900;box-sizing:border-box;font-family:monospace;margin-bottom:10px;">' +
        '<label style="display:block;color:#aaa;font-size:10.5px;margin-bottom:3px;text-transform:uppercase;letter-spacing:0.5px;">Repetir clave nueva</label>' +
        '<input type="password" inputmode="numeric" maxlength="8" id="pinChangeNew2" style="width:100%;background:#0a0a0a;color:#fff;border:1.5px solid rgba(212,175,55,0.40);padding:8px 12px;border-radius:8px;font-size:15px;text-align:center;letter-spacing:5px;font-weight:900;box-sizing:border-box;font-family:monospace;">' +
        '<div id="pinChangeErr" style="color:#ff8080;font-size:12px;text-align:center;min-height:14px;margin-top:6px;"></div>' +
        '<div style="display:flex;gap:8px;margin-top:12px;">' +
        '<button type="button" onclick="document.getElementById(\'sectionPinChangeModal\').remove()" style="flex:1;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.20);color:#fff;padding:9px;border-radius:8px;font-weight:700;cursor:pointer;">Cancelar</button>' +
        '<button type="button" id="pinChangeSubmit" style="flex:2;background:linear-gradient(135deg,#d4af37,#f4d966);color:#1a0033;border:none;padding:9px;border-radius:8px;font-weight:900;cursor:pointer;">Guardar</button>' +
        '</div>' +
        '</div>';
    document.body.appendChild(overlay);
    setTimeout(() => document.getElementById('pinChangeCurrent')?.focus(), 50);
    document.getElementById('pinChangeSubmit').onclick = async () => {
        const cur = document.getElementById('pinChangeCurrent').value || '';
        const n1 = document.getElementById('pinChangeNew').value || '';
        const n2 = document.getElementById('pinChangeNew2').value || '';
        const errBox = document.getElementById('pinChangeErr');
        if (!cur || !n1 || !n2) { errBox.textContent = 'Completá todos los campos'; return; }
        if (n1 !== n2) { errBox.textContent = 'Las claves nuevas no coinciden'; return; }
        if (!/^\d{4,8}$/.test(n1)) { errBox.textContent = 'La clave debe ser 4-8 dígitos'; return; }
        errBox.textContent = '⏳ Guardando...';
        try {
            const r = await authFetch('/api/admin/section-pins/change', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ section: sectionKey, currentPin: cur, newPin: n1 })
            });
            const d = await r.json();
            if (!r.ok) { errBox.textContent = '❌ ' + (d.error || 'Error'); return; }
            showToast('✅ Clave de ' + sectionLabel + ' cambiada', 'success');
            overlay.remove();
            // Forzar re-unlock con la nueva clave
            try {
                const raw = sessionStorage.getItem(_SECTION_PIN_UNLOCK_KEY) || '{}';
                const u = JSON.parse(raw);
                delete u[sectionKey];
                sessionStorage.setItem(_SECTION_PIN_UNLOCK_KEY, JSON.stringify(u));
            } catch (_) {}
        } catch (e) {
            errBox.textContent = 'Error de conexión';
        }
    };
}

// ============================================
// NAVEGACIÓN ENTRE SECCIONES
// ============================================
function showSection(sectionKey) {
    // Pin gate: si la sección está protegida y no está desbloqueada, pedir PIN.
    // Excepción: en modo ?only=closings (usuario cierresgeneral) NO pedimos PIN
    // porque ese rol no es admin full y no puede llamar a /section-pins/verify.
    // Su autenticación ya pasa por el login dedicado de /cierresgeneral.
    const navEl = document.querySelector('.nav-item[data-section="' + sectionKey + '"]');
    const protectedKey = navEl && navEl.getAttribute('data-protected-pin');
    if (protectedKey && !_IS_CLOSINGS_MODE && !_isSectionUnlocked(protectedKey)) {
        const label = navEl.textContent.trim().split(/\s+/).slice(0, 3).join(' ');
        _promptSectionPin(protectedKey, label, () => showSection(sectionKey));
        return;
    }
    document.querySelectorAll('.section').forEach((s) => s.classList.remove('active'));
    document.querySelectorAll('.nav-item').forEach((n) => n.classList.remove('active'));

    const map = {
        closings: 'closingsSection',
        cotizaciones: 'cotizacionesSection',
        cotizacionesExterno: 'cotizacionesExternoSection',
        historialBuffalo: 'historialBuffaloSection',
        historialCotizacion: 'historialCotizacionSection',
        empleados: 'empleadosSection',
        publicidad: 'publicidadSection'
    };
    const sectionId = map[sectionKey];
    if (sectionId) {
        const sec = document.getElementById(sectionId);
        if (sec) sec.classList.add('active');
    }
    // Reuso navEl declarado al inicio de la función para el pin-gate.
    if (navEl) navEl.classList.add('active');

    // Lazy-load por seccion
    if (sectionKey === 'closings') {
        loadClosings();
    } else if (sectionKey === 'cotizaciones') {
        loadCotizaciones();
    } else if (sectionKey === 'cotizacionesExterno') {
        loadCotizacionesExterno();
    } else if (sectionKey === 'historialBuffalo') {
        loadHistorialBuffalo();
    } else if (sectionKey === 'historialCotizacion') {
        loadHistorialCotizacion();
    } else if (sectionKey === 'empleados') {
        loadEmpleados();
    } else if (sectionKey === 'publicidad') {
        loadPublicistas();
    }
}

document.addEventListener('DOMContentLoaded', function () {
    // Login form
    const loginForm = document.getElementById('loginForm');
    if (loginForm) loginForm.addEventListener('submit', handleLogin);

    // Logout
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);

    // Sidebar nav
    document.querySelectorAll('.nav-item').forEach((el) => {
        el.addEventListener('click', function (e) {
            e.preventDefault();
            const key = el.getAttribute('data-section');
            if (key) showSection(key);
        });
    });

    // (bindings de notificaciones removidos)

    // Si ya hay token guardado, intentar entrar directo
    if (currentToken) {
        // Verificar token contra /api/users/me — si responde 200 y rol válido, mostrar app
        fetch(API_URL + '/api/users/me', {
            headers: { 'Authorization': 'Bearer ' + currentToken }
        }).then(async (r) => {
            if (!r.ok) throw new Error('invalid');
            const data = await r.json();
            const adminRoles = ['admin', 'depositor', 'withdrawer', 'closings_viewer'];
            if (!adminRoles.includes(data.role)) throw new Error('not admin');
            currentAdmin = data;
            showApp();
        }).catch(() => {
            currentToken = null;
            localStorage.removeItem(_TOKEN_KEY);
            localStorage.removeItem(_USER_KEY);
        });
    }
});

// ============================================
// CIERRES GENERAL — estado y configuración
// ============================================
// Cantidad de equipos por sector en los cierres (slots 0..N-1).
const BUFFALO_TEAM_SLOTS = 10;
const CLOSING_SECTORS_UI = [
    { key: 'ganamos',    label: '💼 GANAMOS',    color: '#25d366', individual: true,  slots: BUFFALO_TEAM_SLOTS },
    { key: 'publicidad', label: '📢 PUBLICIDAD', color: '#00d4ff', individual: true,  slots: BUFFALO_TEAM_SLOTS },
    { key: 'buffalo',    label: '🐃 BUFFALO',    color: '#ffd700', individual: true,  slots: BUFFALO_TEAM_SLOTS }
];

// ============================================
// NOMBRES DE SECTORES — editables por el usuario `crazy`
// ============================================
// La clave interna (ganamos/publicidad/buffalo) es fija; el emoji también.
// Lo editable es el texto, que se guarda en el backend (Config sector_names)
// y se aplica a CLOSING_SECTORS_UI y EMP_SECTORS_UI (Cierres y Empleados).
const _SECTOR_EMOJI = { ganamos: '💼', publicidad: '📢', buffalo: '🐃' };
let _sectorNames = { ganamos: 'GANAMOS', publicidad: 'PUBLICIDAD', buffalo: 'BUFFALO' };

function _sectorLabel(key) {
    return (_SECTOR_EMOJI[key] || '') + ' ' + (_sectorNames[key] || String(key || '').toUpperCase());
}

// Vuelca los nombres recibidos sobre las arrays de UI (muta los .label).
function _applySectorNames(names) {
    if (names && typeof names === 'object') {
        ['ganamos', 'publicidad', 'buffalo'].forEach((k) => {
            if (typeof names[k] === 'string' && names[k].trim()) _sectorNames[k] = names[k].trim();
        });
    }
    [CLOSING_SECTORS_UI, EMP_SECTORS_UI].forEach((arr) => {
        if (!Array.isArray(arr)) return;
        arr.forEach((s) => { if (s && _SECTOR_EMOJI[s.key]) s.label = _sectorLabel(s.key); });
    });
}

async function _loadSectorNames() {
    try {
        const r = await authFetch('/api/admin/sector-names');
        const d = await r.json();
        if (r.ok && d && d.names) _applySectorNames(d.names);
    } catch (_) {}
}

// Modal para renombrar los 3 sectores desde el panel (botón en Cierres).
async function _openSectorRenameModal() {
    document.getElementById('sectorRenameModal')?.remove();
    let names = Object.assign({}, _sectorNames);
    try {
        const r = await authFetch('/api/admin/sector-names');
        const d = await r.json();
        if (r.ok && d && d.names) names = d.names;
    } catch (_) {}
    const overlay = document.createElement('div');
    overlay.id = 'sectorRenameModal';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;';
    const row = (k, n) => '<div style="margin-bottom:12px;">' +
        '<label style="display:block;color:#aaa;font-size:10.5px;text-transform:uppercase;letter-spacing:0.6px;margin-bottom:4px;">' + _SECTOR_EMOJI[k] + ' Sector ' + n + '</label>' +
        '<input type="text" id="secRename_' + k + '" maxlength="24" value="' + escapeHtml(names[k] || '') + '" style="width:100%;background:#0a0a0a;color:#fff;border:1.5px solid rgba(212,175,55,0.40);padding:9px 12px;border-radius:8px;font-size:14px;font-weight:800;box-sizing:border-box;">' +
        '</div>';
    overlay.innerHTML = '<div style="background:#1a0033;border:1.5px solid #d4af37;border-radius:14px;padding:22px;max-width:380px;width:100%;color:#fff;box-shadow:0 0 40px rgba(212,175,55,0.30);">' +
        '<div style="text-align:center;margin-bottom:14px;">' +
        '<div style="font-size:30px;">🏷️</div>' +
        '<h3 style="margin:4px 0 2px;color:#d4af37;font-size:16px;">Renombrar sectores</h3>' +
        '<div style="color:#999;font-size:11px;">Cambia el nombre que se muestra en Cierres y Empleados.</div>' +
        '</div>' +
        row('ganamos', '1') + row('publicidad', '2') + row('buffalo', '3') +
        '<div id="secRenameMsg" style="min-height:15px;font-size:12px;text-align:center;margin:2px 0 10px;"></div>' +
        '<div style="display:flex;gap:8px;">' +
        '<button type="button" onclick="document.getElementById(\'sectorRenameModal\').remove()" style="flex:1;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.20);color:#fff;padding:9px;border-radius:8px;font-weight:700;cursor:pointer;">Cancelar</button>' +
        '<button type="button" id="secRenameSave" style="flex:2;background:linear-gradient(135deg,#d4af37,#f4d966);color:#1a0033;border:none;padding:9px;border-radius:8px;font-weight:900;cursor:pointer;">💾 Guardar</button>' +
        '</div></div>';
    document.body.appendChild(overlay);
    document.getElementById('secRenameSave').onclick = async () => {
        const msg = document.getElementById('secRenameMsg');
        const payload = {
            ganamos:    (document.getElementById('secRename_ganamos').value || '').trim(),
            publicidad: (document.getElementById('secRename_publicidad').value || '').trim(),
            buffalo:    (document.getElementById('secRename_buffalo').value || '').trim()
        };
        if (!payload.ganamos || !payload.publicidad || !payload.buffalo) {
            msg.style.color = '#ff8080'; msg.textContent = 'Completá los 3 nombres'; return;
        }
        msg.style.color = '#aaa'; msg.textContent = '⏳ Guardando...';
        try {
            const r = await authFetch('/api/admin/sector-names', {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ names: payload })
            });
            const d = await r.json();
            if (!r.ok || !d.success) { msg.style.color = '#ff8080'; msg.textContent = '❌ ' + (d.error || 'Error'); return; }
            _applySectorNames(d.names || payload);
            overlay.remove();
            try { showToast('✅ Nombres actualizados', 'success'); } catch (_) {}
            // Re-render de la sección activa para reflejar los nombres nuevos.
            try {
                const active = document.querySelector('.nav-item.active');
                const key = active && active.getAttribute('data-section');
                if (key) showSection(key);
            } catch (_) {}
        } catch (e) {
            msg.style.color = '#ff8080'; msg.textContent = 'Error de conexión';
        }
    };
}

let _closingsRowsCache = [];      // historial completo (últimos N días) para la selección activa
let _closingsTodayKey = null;
// Selección actual: qué sector + (opcional) equipo Buffalo + día activo del editor
// + filtro de estado (all/draft/confirmed) para el historial.
let _closingsView = { sector: 'ganamos', teamSlot: null, date: null, filter: 'all' };
const CLOSINGS_HISTORY_DAYS = 60;

function closingsSetFilter(f) {
    _closingsView.filter = f;
    _renderClosings();
}

// Stubs vacíos para compat con render histórico (botón 🔑 PIN no se usa más)
function _changeClosingsPin() { /* no-op: PIN removido */ }

function _closingFmt(n) {
    return '$' + Number(n || 0).toLocaleString('es-AR', { maximumFractionDigits: 0 });
}

// Resta 1 día a un dateKey YYYY-MM-DD (UTC para evitar drift por DST).
function _prevDateKey(dateKey) {
    const m = String(dateKey || '').match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (!m) return null;
    const dt = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
    dt.setUTCDate(dt.getUTCDate() - 1);
    const yy = dt.getUTCFullYear();
    const mm = String(dt.getUTCMonth() + 1).padStart(2, '0');
    const dd = String(dt.getUTCDate()).padStart(2, '0');
    return yy + '-' + mm + '-' + dd;
}

// Devuelve el saldo de CVU a las 00 hs del día anterior — ese es el monto
// REAL que arrastró al nuevo día. Antes usábamos el pendiente calculado,
// pero eso siempre daba faltante por las diferencias entre lo esperado y
// lo que el banco realmente mostró. Tomamos el CVU 00 hs real porque es
// la verdad de cuánta plata hay disponible al arrancar el día.
function _autoPendienteAnterior(date, sectorKey) {
    const prev = _prevDateKey(date);
    if (!prev) return 0;
    const row = (_closingsRowsCache || []).find(r => r.dateKey === prev && r.sector === sectorKey);
    if (!row) return 0;
    // CVU 00 hs del día anterior — saldo bancario real al cierre.
    // Redondear a peso entero — evita decimales feos en el input.
    return Math.round(Number(row.cvuMidnightARS || 0));
}

// Botón inline para adjuntar foto al cierre. Aparece pegado a un campo
// concreto (depósito de un equipo, bajada, gastos, etc.). Cuenta cuántas
// fotos ya tiene de ese kind+teamSlot y lo muestra arriba.
//   rid       — id del cierre (si empieza con "new_" el botón pide guardar)
//   row       — row del cierre actual (para contar fotos ya subidas)
//   kind      — categoría ('deposito', 'bajada', 'ingreso', etc.)
//   teamSlot  — slot del equipo (0..9) o null si general
//   label     — texto del botón ('📷 Foto', etc.)
//   locked    — si el cierre está bloqueado, deshabilita
function _inlineUploadBtn(rid, row, kind, teamSlot, label, locked) {
    const isNew = String(rid).startsWith('new_');
    const comps = (row && row.comprobantes) || [];
    const count = comps.filter(c => c.kind === kind && (teamSlot == null ? (c.teamSlot == null) : Number(c.teamSlot) === Number(teamSlot))).length;
    const disabled = locked || isNew;
    const bg = disabled ? 'rgba(255,255,255,0.04)' : 'rgba(0,212,255,0.10)';
    const color = disabled ? '#666' : '#00d4ff';
    const border = disabled ? 'rgba(255,255,255,0.10)' : 'rgba(0,212,255,0.45)';
    const cursor = disabled ? 'not-allowed' : 'pointer';
    const tsArg = teamSlot != null ? Number(teamSlot) : 'null';
    const onClick = disabled
        ? (isNew ? 'showToast(\'Guardá el cierre primero\',\'info\')' : '')
        : ('openClosingUpload(\'' + rid + '\',\'' + kind + '\',' + tsArg + ')');
    // Wrapper con data-* atributos para que el listener global de drop
    // pueda saber a qué (rid, kind, teamSlot) van las fotos arrastradas.
    // Aplica también al pegar (paste de screenshot ya copiado).
    const dropAttrs = disabled ? ''
        : ' data-cls-drop="1" data-cls-rid="' + rid + '" data-cls-kind="' + kind + '" data-cls-teamslot="' + (teamSlot != null ? Number(teamSlot) : '') + '"';
    const hint = disabled ? '' : ' · tocá para pegar (Ctrl+V) o elegir archivo · o arrastrá la foto';
    let html = '<span' + dropAttrs + ' style="display:inline-flex;align-items:center;gap:4px;padding:2px;border-radius:6px;transition:background 0.12s;">';
    html += '<button type="button" onclick="' + onClick + '" title="' + (isNew ? 'Guardá primero el cierre' : 'Adjuntar foto · ' + count + '/' + COMP_MAX_PER_KIND_DISPLAY + hint) + '" style="background:' + bg + ';border:1px dashed ' + border + ';color:' + color + ';padding:3px 8px;border-radius:5px;font-size:10px;font-weight:700;cursor:' + cursor + ';display:inline-flex;align-items:center;gap:4px;white-space:nowrap;">' + label + (count > 0 ? ' <span style="background:rgba(0,212,255,0.30);color:#fff;border-radius:8px;padding:0 5px;font-size:9.5px;">' + count + '</span>' : '') + '</button>';
    html += '</span>';
    return html;
}
const COMP_MAX_PER_KIND_DISPLAY = 50;

// Lista mini de fotos ya adjuntadas para un kind+teamSlot — muestra
// thumbnails clicables (abren en otra tab) con botón ✕ para eliminar.
// Usado al lado de los inputs para que el owner vea/saque las fotos
// SIN abrir el panel grande de comprobantes.
function _inlineUploadList(rid, row, kind, teamSlot, locked) {
    const comps = (row && row.comprobantes) || [];
    const matches = comps
        .map((c, idx) => ({ ...c, idx }))
        .filter(c => c.kind === kind && (teamSlot == null ? (c.teamSlot == null) : Number(c.teamSlot) === Number(teamSlot)));
    if (matches.length === 0) return '';
    let html = '<div style="display:inline-flex;flex-wrap:wrap;gap:3px;align-items:center;margin-left:4px;">';
    for (const m of matches) {
        html += '<a href="' + escapeHtml(m.url) + '" target="_blank" rel="noopener" style="display:inline-flex;align-items:center;gap:2px;background:rgba(0,212,255,0.10);border:1px solid rgba(0,212,255,0.35);color:#00d4ff;text-decoration:none;padding:1px 5px;border-radius:4px;font-size:9.5px;font-weight:700;">📷' + (m.idx + 1);
        if (!locked) html += '<span onclick="event.preventDefault();event.stopPropagation();removeClosingComprobante(\'' + rid + '\',' + m.idx + ')" style="color:#ff8080;cursor:pointer;margin-left:2px;">✕</span>';
        html += '</a>';
    }
    html += '</div>';
    return html;
}

// Busca los nombres de equipo más recientes para un sector. Recorre el
// cache de cierres (orden cronológico inverso) y para CADA slot toma el
// primer nombre no vacío que encuentra. Así si en un día puntual no se
// llenó el nombre, hereda el del cierre anterior. Devuelve array[BUFFALO_TEAM_SLOTS].
function _latestTeamNames(sectorKey, excludeId) {
    const out = Array.from({ length: BUFFALO_TEAM_SLOTS }, () => '');
    const rows = (_closingsRowsCache || [])
        .filter(r => r && r.sector === sectorKey && Array.isArray(r.teams) && r.id !== excludeId)
        .sort((a, b) => b.dateKey.localeCompare(a.dateKey)); // más reciente primero
    for (const r of rows) {
        for (let i = 0; i < BUFFALO_TEAM_SLOTS; i++) {
            if (out[i]) continue;
            const t = r.teams.find(tt => Number(tt.slot) === i);
            if (t && String(t.name || '').trim()) {
                out[i] = String(t.name).trim();
            }
        }
        if (out.every(n => n)) break;
    }
    return out;
}

function _closingsTodayART() {
    return new Intl.DateTimeFormat('en-CA', {
        timeZone: 'America/Argentina/Buenos_Aires',
        year: 'numeric', month: '2-digit', day: '2-digit'
    }).format(new Date());
}

function closingsSelectSector(sectorKey) {
    _closingsView.sector = sectorKey;
    _closingsView.teamSlot = null;
    loadClosings();
}

function closingsSelectDate(dateStr) {
    _closingsView.date = dateStr;
    _renderClosings();
    loadClosingsSummary(dateStr);
}

async function loadClosings() {
    const body = document.getElementById('closingsBody');
    if (!body) return;
    body.innerHTML = '<div style="color:#aaa;text-align:center;padding:24px;">⏳ Cargando…</div>';

    if (!_closingsView.date) {
        _closingsView.date = _closingsTodayART();
    }
    const today = _closingsTodayART();
    const fromDate = new Date(today);
    fromDate.setDate(fromDate.getDate() - CLOSINGS_HISTORY_DAYS);
    const fromKey = fromDate.toISOString().slice(0, 10);

    try {
        const params = new URLSearchParams({
            from: fromKey,
            to: today,
            sector: _closingsView.sector,
            // lite=1 → el server NO manda las urls base64 de comprobantes
            // (puede ser MB cada uno). Las pedimos on-demand al abrir
            // "Analizar". Si no, el browser se freezea al cargar la lista.
            lite: '1'
        });
        const r = await authFetch('/api/admin/closings?' + params.toString());
        const d = await r.json();
        if (!r.ok || !d.success) {
            body.innerHTML = '<div style="color:#ff8080;padding:14px;">❌ ' + escapeHtml(d.error || 'Error') + '</div>';
            return;
        }
        // Todas las entradas son teamSlot=null ahora (incluso buffalo, que usa teams[]).
        const rows = (d.rows || []).filter(r => r.teamSlot == null);
        _closingsRowsCache = rows;
        _closingsTodayKey = d.today;
        _renderClosings();
        loadClosingsSummary(_closingsView.date);
        loadClosingsAnalysis();
    } catch (e) {
        body.innerHTML = '<div style="color:#ff8080;padding:14px;">Error: ' + escapeHtml(e.message || '') + '</div>';
    }
}

let _closingsAnalysisPeriod = 'month';

function closingsSetAnalysisPeriod(p) {
    _closingsAnalysisPeriod = p;
    loadClosingsAnalysis();
}

async function loadClosingsAnalysis() {
    const box = document.getElementById('closingsAnalysisBox');
    if (!box) return;
    try {
        const params = new URLSearchParams({
            period: _closingsAnalysisPeriod,
            sector: _closingsView.sector
        });
        if (_closingsView.sector === 'buffalo' && _closingsView.teamSlot != null) {
            params.set('teamSlot', String(_closingsView.teamSlot));
        }
        const r = await authFetch('/api/admin/closings/analysis?' + params.toString());
        const d = await r.json();
        if (!r.ok || !d.success) return;

        const fmtPct = (n) => (n >= 0 ? '+' : '') + n.toFixed(1) + '%';
        const arrow = (n) => n > 0.5 ? '▲' : (n < -0.5 ? '▼' : '·');
        const arrowColor = (n, goodIfUp) => {
            if (Math.abs(n) < 0.5) return '#888';
            const isUp = n > 0;
            return (isUp === goodIfUp) ? '#aaffaa' : '#ff8080';
        };
        const periodLabel = { day: 'HOY vs AYER', week: 'ÚLT 7 DÍAS vs PREV 7', month: 'ÚLT 30 DÍAS vs PREV 30' }[d.period];

        let html = '<div style="background:linear-gradient(135deg,rgba(155,48,255,0.08),rgba(0,212,255,0.06));border:1.5px solid rgba(155,48,255,0.40);border-radius:11px;padding:13px;">';
        html += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:10px;">';
        html += '<div style="color:#c89bff;font-weight:900;font-size:13px;letter-spacing:0.6px;">📊 ANÁLISIS COMPARATIVO · ' + periodLabel + '</div>';
        html += '<div style="display:flex;gap:4px;">';
        for (const p of [['day','Día'],['week','Semana'],['month','Mes']]) {
            const active = p[0] === _closingsAnalysisPeriod;
            html += '<button type="button" onclick="closingsSetAnalysisPeriod(\'' + p[0] + '\')" style="background:' + (active ? '#c89bff' : 'rgba(0,0,0,0.40)') + ';color:' + (active ? '#000' : '#c89bff') + ';border:1px solid rgba(155,48,255,0.50);padding:4px 11px;border-radius:6px;font-weight:800;font-size:11px;cursor:pointer;">' + p[1] + '</button>';
        }
        html += '</div></div>';

        // Cards de KPIs con delta
        const kpis = [
            ['📥 Depósitos', d.current.depositsARS, d.deltas.depositsARS, true, 'ars'],
            ['🛒 Ventas', d.current.ventasARS, d.deltas.ventasARS, false, 'ars'],
            ['🏃 Bajadas', d.current.bajadaARS, d.deltas.bajadaARS, false, 'ars'],
            ['🎁 Bonos $', d.current.bonusARS, d.deltas.bonusARS, false, 'ars'],
            ['📐 Neto sector', d.current.netoSector, d.deltas.netoSector, true, 'ars'],
            ['🔢 Transacciones', d.current.transactionsCount, d.deltas.transactionsCount, true, 'count'],
            ['📤 Descargas (cant.)', d.current.withdrawalsCount, d.deltas.withdrawalsCount, false, 'count'],
            ['🎁 Bonos (cant.)', d.current.bonusCount, d.deltas.bonusCount, false, 'count'],
            ['🎯 Ticket prom.', d.current.avgTicket, d.deltas.avgTicket, true, 'ars'],
            ['📤 Descarga prom.', d.current.avgWithdrawal, d.deltas.avgWithdrawal, false, 'ars'],
            ['🎁 Bono prom.', d.current.avgBonus, d.deltas.avgBonus, false, 'ars'],
            ['💸 % Costo bonos', d.current.bonusCostPct, d.deltas.bonusCostPct, false, 'pct']
        ];
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:7px;margin-bottom:10px;">';
        for (const [label, value, delta, goodIfUp, kind] of kpis) {
            let valStr;
            if (kind === 'count') valStr = Number(value || 0).toLocaleString('es-AR');
            else if (kind === 'pct') valStr = Number(value || 0).toFixed(1) + '%';
            else valStr = _closingFmt(value);
            const deltaColor = arrowColor(delta.pct, goodIfUp);
            const ar = arrow(delta.pct);
            let deltaAbs;
            if (kind === 'count') deltaAbs = (delta.abs >= 0 ? '+' : '') + Math.round(delta.abs).toLocaleString('es-AR');
            else if (kind === 'pct') deltaAbs = (delta.abs >= 0 ? '+' : '') + delta.abs.toFixed(1) + 'pp';
            else deltaAbs = (delta.abs >= 0 ? '+' : '−') + _closingFmt(Math.abs(delta.abs));
            html += '<div style="background:rgba(0,0,0,0.35);border:1px solid rgba(255,255,255,0.08);border-radius:8px;padding:8px 10px;">';
            html += '<div style="color:#aaa;font-size:10.5px;font-weight:700;letter-spacing:0.3px;margin-bottom:2px;">' + label + '</div>';
            html += '<div style="color:#fff;font-size:15px;font-weight:900;line-height:1.1;">' + valStr + '</div>';
            html += '<div style="color:' + deltaColor + ';font-size:10.5px;font-weight:800;margin-top:2px;">' + ar + ' ' + fmtPct(delta.pct) + ' · ' + deltaAbs + '</div>';
            html += '</div>';
        }
        html += '</div>';

        // Comparativa lado a lado
        html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;font-size:11px;">';
        html += '<div style="background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.35);border-radius:7px;padding:7px 9px;">';
        html += '<div style="color:#00d4ff;font-weight:800;font-size:10.5px;margin-bottom:3px;">PERÍODO ACTUAL · ' + escapeHtml(d.current.from) + ' → ' + escapeHtml(d.current.to) + '</div>';
        html += '<div style="color:#fff;">' + d.current.days + ' días · ' + d.current.entries + ' cierres · neto/día <strong>' + _closingFmt(d.current.avgNetoDiario) + '</strong></div>';
        html += '</div>';
        html += '<div style="background:rgba(155,48,255,0.06);border:1px solid rgba(155,48,255,0.35);border-radius:7px;padding:7px 9px;">';
        html += '<div style="color:#c89bff;font-weight:800;font-size:10.5px;margin-bottom:3px;">PERÍODO ANTERIOR · ' + escapeHtml(d.previous.from) + ' → ' + escapeHtml(d.previous.to) + '</div>';
        html += '<div style="color:#fff;">' + d.previous.days + ' días · ' + d.previous.entries + ' cierres · neto/día <strong>' + _closingFmt(d.previous.avgNetoDiario) + '</strong></div>';
        html += '</div>';
        html += '</div>';

        // Alertas
        const a = d.alerts;
        if (a.rojos > 0 || a.faltantes > 0 || a.sobrepagos > 0 || a.pendOK > 0) {
            html += '<div style="margin-top:10px;display:flex;gap:6px;flex-wrap:wrap;font-size:11px;">';
            if (a.faltantes > 0) html += '<span style="background:rgba(255,80,80,0.15);border:1px solid #ff5050;color:#ff5050;padding:3px 9px;border-radius:5px;font-weight:800;">🚨 ' + a.faltantes + ' plata faltante</span>';
            if (a.rojos > 0)     html += '<span style="background:rgba(255,128,128,0.10);border:1px solid #ff8080;color:#ff8080;padding:3px 9px;border-radius:5px;font-weight:800;">📉 ' + a.rojos + ' en rojo</span>';
            if (a.sobrepagos > 0) html += '<span style="background:rgba(255,170,102,0.10);border:1px solid #ffaa66;color:#ffaa66;padding:3px 9px;border-radius:5px;font-weight:800;">⚠️ ' + a.sobrepagos + ' sobre-pago</span>';
            if (a.pendOK > 0)    html += '<span style="background:rgba(255,170,102,0.06);border:1px solid rgba(255,170,102,0.40);color:#ffd0a0;padding:3px 9px;border-radius:5px;font-weight:700;">⏳ ' + a.pendOK + ' pendientes respaldados</span>';
            html += '</div>';
        }
        html += '</div>';
        box.innerHTML = html;
    } catch (_) {}
}

// Estado del rango de fechas del resumen (default: día activo).
function _closingsSummaryRange() {
    const today = _closingsTodayART();
    return {
        from: _closingsView.summaryFrom || _closingsView.date || today,
        to: _closingsView.summaryTo || _closingsView.date || today
    };
}

function closingsSetSummaryRange(from, to) {
    _closingsView.summaryFrom = from;
    _closingsView.summaryTo = to;
    loadClosingsSummary(_closingsView.date);
}

async function loadClosingsSummary(date) {
    try {
        const range = _closingsSummaryRange();
        const params = new URLSearchParams({ from: range.from, to: range.to });
        // Filtrar por el sector activo — el resumen del día NO debe mezclar
        // sectores. Cada sector tiene su propio análisis.
        if (_closingsView.sector) params.set('sector', _closingsView.sector);
        const r = await authFetch('/api/admin/closings/summary?' + params.toString());
        const d = await r.json();
        if (!r.ok || !d.success) return;
        const box = document.getElementById('closingsSummaryBox');
        if (!box) return;
        const t = d.totals;
        const sectorEmoji = { ganamos: '💼', publicidad: '📢', buffalo: '🐃' };

        // Promedio del % comisión sobre los depósitos del rango
        const avgCommissionPct = (t.depositsARS > 0)
            ? (t.commission * 100 / t.depositsARS)
            : 0;
        const sameDay = range.from === range.to;
        const rangeLabel = sameDay
            ? range.from
            : (range.from + ' → ' + range.to);

        let html = '';

        // ===== Selector de rango de fechas para este panel =====
        html += '<div style="background:rgba(155,48,255,0.06);border:1px solid rgba(155,48,255,0.30);border-radius:8px;padding:8px 11px;margin-bottom:10px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:11.5px;">';
        html += '<span style="color:#c89bff;font-weight:800;letter-spacing:0.5px;">📅 Resumen del:</span>';
        html += '<label style="color:#aaa;font-size:10.5px;">Desde</label>';
        html += '<input type="date" id="closingsSummaryFrom" value="' + escapeHtml(range.from) + '" onchange="closingsSetSummaryRange(this.value, document.getElementById(\'closingsSummaryTo\').value)" style="background:rgba(0,0,0,0.45);border:1px solid rgba(155,48,255,0.40);color:#fff;padding:4px 7px;border-radius:5px;font-size:11.5px;">';
        html += '<label style="color:#aaa;font-size:10.5px;">Hasta</label>';
        html += '<input type="date" id="closingsSummaryTo" value="' + escapeHtml(range.to) + '" onchange="closingsSetSummaryRange(document.getElementById(\'closingsSummaryFrom\').value, this.value)" style="background:rgba(0,0,0,0.45);border:1px solid rgba(155,48,255,0.40);color:#fff;padding:4px 7px;border-radius:5px;font-size:11.5px;">';
        html += '<button type="button" onclick="closingsSetSummaryRange(\'' + _closingsTodayART() + '\',\'' + _closingsTodayART() + '\')" style="background:rgba(0,212,255,0.10);border:1px solid rgba(0,212,255,0.45);color:#00d4ff;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:700;cursor:pointer;">Hoy</button>';
        const lastWeek = new Date(); lastWeek.setDate(lastWeek.getDate() - 6);
        const last7 = lastWeek.toISOString().slice(0, 10);
        html += '<button type="button" onclick="closingsSetSummaryRange(\'' + last7 + '\',\'' + _closingsTodayART() + '\')" style="background:rgba(0,212,255,0.10);border:1px solid rgba(0,212,255,0.45);color:#00d4ff;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:700;cursor:pointer;">7 días</button>';
        const lastMonth = new Date(); lastMonth.setDate(lastMonth.getDate() - 29);
        const last30 = lastMonth.toISOString().slice(0, 10);
        html += '<button type="button" onclick="closingsSetSummaryRange(\'' + last30 + '\',\'' + _closingsTodayART() + '\')" style="background:rgba(0,212,255,0.10);border:1px solid rgba(0,212,255,0.45);color:#00d4ff;padding:4px 10px;border-radius:5px;font-size:11px;font-weight:700;cursor:pointer;">30 días</button>';
        html += '<span style="color:#888;font-size:10.5px;margin-left:auto;">' + (d.bySector[0]?.entries || 0) + ' cierre(s) · ' + rangeLabel + '</span>';
        html += '</div>';

        // ===== Cards =====
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px;margin-bottom:10px;">';

        // ENTRÓ — total depósitos bruto + comisión perdida + promedio %
        html += '<div style="background:rgba(102,255,102,0.10);border:1.5px solid #66ff66;border-radius:9px;padding:9px;text-align:center;">';
        html += '<div style="color:#aaffaa;font-size:10.5px;font-weight:800;letter-spacing:0.4px;">💰 ENTRÓ</div>';
        html += '<div style="color:#fff;font-size:17px;font-weight:900;">' + _closingFmt(t.depositsARS) + '</div>';
        html += '<div style="color:#888;font-size:9.5px;">todos los depósitos</div>';
        html += '<div style="margin-top:5px;padding-top:5px;border-top:1px dashed rgba(255,255,255,0.10);">';
        html += '<div style="color:#ff8080;font-size:10.5px;font-weight:700;">-' + _closingFmt(t.commission) + ' comisión</div>';
        html += '<div style="color:#888;font-size:9.5px;">prom. ' + avgCommissionPct.toFixed(2) + '%</div>';
        html += '</div>';
        html += '</div>';

        // VENTA — venta del día + pendiente del día anterior (lo que TIENE que bajarse en total)
        const pendAntTotal = Number(t.pendienteAnteriorARS || 0);
        const ventaConPend = Number(t.ventasARS || 0) + pendAntTotal;
        html += '<div style="background:rgba(255,208,160,0.10);border:1.5px solid #ffd0a0;border-radius:9px;padding:9px;text-align:center;">';
        html += '<div style="color:#ffd0a0;font-size:10.5px;font-weight:800;letter-spacing:0.4px;">🛒 VENTA + PEND. ANT.</div>';
        html += '<div style="color:#fff;font-size:17px;font-weight:900;">' + _closingFmt(ventaConPend) + '</div>';
        html += '<div style="color:#888;font-size:9.5px;">' + _closingFmt(t.ventasARS) + ' venta + ' + _closingFmt(pendAntTotal) + ' pend.ant</div>';
        html += '</div>';

        // BAJÓ
        html += '<div style="background:rgba(0,212,255,0.10);border:1.5px solid #00d4ff;border-radius:9px;padding:9px;text-align:center;">';
        html += '<div style="color:#aaffff;font-size:10.5px;font-weight:800;letter-spacing:0.4px;">🏃 BAJÓ</div>';
        html += '<div style="color:#fff;font-size:17px;font-weight:900;">' + _closingFmt(t.bajadaARS) + '</div>';
        html += '<div style="color:#888;font-size:9.5px;">de ' + _closingFmt(t.ventasARS) + ' a bajar</div>';
        html += '</div>';

        // PENDIENTE — lo que falta bajar (queda en CVU)
        const pendColor = t.pendienteHoy > 0 ? '#ff8080' : '#aaffaa';
        const pendBg = t.pendienteHoy > 0 ? 'rgba(255,128,128,0.10)' : 'rgba(102,255,102,0.06)';
        html += '<div style="background:' + pendBg + ';border:1.5px solid ' + pendColor + ';border-radius:9px;padding:9px;text-align:center;">';
        html += '<div style="color:' + pendColor + ';font-size:10.5px;font-weight:800;letter-spacing:0.4px;">⏳ PENDIENTE</div>';
        html += '<div style="color:#fff;font-size:17px;font-weight:900;">' + _closingFmt(t.pendienteHoy) + '</div>';
        html += '<div style="color:#888;font-size:9.5px;">' + (t.pendienteHoy > 0 ? 'falta bajar · queda en CVU' : 'todo bajado') + '</div>';
        html += '</div>';

        // BONOS REGALADOS — total + cantidad
        const bonusCount = Number(t.bonusCount || 0);
        const bonusAvg = bonusCount > 0 ? (t.bonusARS / bonusCount) : 0;
        html += '<div style="background:rgba(255,215,0,0.10);border:1.5px solid #ffd700;border-radius:9px;padding:9px;text-align:center;">';
        html += '<div style="color:#ffd700;font-size:10.5px;font-weight:800;letter-spacing:0.4px;">🎁 BONOS REGALADOS</div>';
        html += '<div style="color:#fff;font-size:17px;font-weight:900;">' + _closingFmt(t.bonusARS) + '</div>';
        html += '<div style="color:#888;font-size:9.5px;">' + bonusCount + ' bono(s) · prom ' + _closingFmt(bonusAvg) + '</div>';
        html += '</div>';

        html += '</div>';

        // Breakdown por sector: sólo mostrar si NO estamos filtrando ya por
        // un sector (en ese caso es redundante).
        if (!_closingsView.sector && d.bySector.length > 0) {
            html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:6px;">';
            for (const s of d.bySector) {
                html += '<div style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);border-radius:7px;padding:7px 9px;font-size:11px;">';
                html += '<div style="color:#fff;font-weight:800;margin-bottom:3px;">' + (sectorEmoji[s.sector] || '·') + ' ' + escapeHtml(s.sector.toUpperCase()) + ' <span style="color:#888;font-weight:600;">(' + s.entries + ')</span></div>';
                html += '<div style="color:#aaffaa;">Neto: <strong>' + _closingFmt(s.netoSector) + '</strong></div>';
                if (s.pendienteHoy > 0) {
                    html += '<div style="color:#ff8080;">⏳ Pend: ' + _closingFmt(s.pendienteHoy) + '</div>';
                }
                if (s.bonusARS > 0) {
                    html += '<div style="color:#ffd700;">🎁 Bonos: ' + _closingFmt(s.bonusARS) + '</div>';
                }
                html += '</div>';
            }
            html += '</div>';
        }
        box.innerHTML = html;
    } catch (_) {}
}

// Wire up live recompute: cualquier input dentro de [data-cls-id] dispara
// closingsRecompute() para refrescar el preview en vivo.
function _wireClosingsLiveRecompute() {
    document.querySelectorAll('[data-cls-id]').forEach(card => {
        const rid = card.getAttribute('data-cls-id');
        if (!rid || card.dataset.wiredRecompute === '1') return;
        card.dataset.wiredRecompute = '1';
        card.addEventListener('input', () => closingsRecompute(rid));
        // Recompute inicial
        closingsRecompute(rid);
    });
    _wireClosingsDragDrop();
}

// Drag & drop de fotos en CUALQUIER zona [data-cls-drop]. El usuario
// arrastra una imagen sobre el botón "📷 Foto..." y la suelta, sin
// necesidad de abrir el file picker. Si suelta varias, sube todas
// (respeta el cap de COMP_MAX_PER_KIND).
function _wireClosingsDragDrop() {
    // Listener delegado en el body — se setea UNA sola vez.
    if (document.body.dataset.clsDragWired === '1') return;
    document.body.dataset.clsDragWired = '1';

    const findDropTarget = (el) => {
        while (el && el.dataset) {
            if (el.dataset.clsDrop === '1') return el;
            el = el.parentElement;
        }
        return null;
    };

    document.body.addEventListener('dragover', (e) => {
        const t = findDropTarget(e.target);
        if (!t) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'copy';
        t.style.background = 'rgba(0,212,255,0.18)';
        t.style.boxShadow = '0 0 0 2px rgba(0,212,255,0.45)';
    });
    document.body.addEventListener('dragleave', (e) => {
        const t = findDropTarget(e.target);
        if (!t) return;
        t.style.background = '';
        t.style.boxShadow = '';
    });
    document.body.addEventListener('drop', async (e) => {
        const t = findDropTarget(e.target);
        if (!t) return;
        e.preventDefault();
        t.style.background = '';
        t.style.boxShadow = '';
        const rid = t.dataset.clsRid;
        const kind = t.dataset.clsKind;
        const teamSlotRaw = t.dataset.clsTeamslot;
        const teamSlot = teamSlotRaw === '' || teamSlotRaw == null ? null : Number(teamSlotRaw);
        if (!rid || !kind) return;
        if (String(rid).startsWith('new_')) {
            showToast('Guardá el cierre primero — después podés arrastrar fotos.', 'info');
            return;
        }
        const dt = e.dataTransfer;
        if (!dt || !dt.files || dt.files.length === 0) return;
        const imgs = Array.from(dt.files).filter(f => f.type && f.type.startsWith('image/'));
        if (imgs.length === 0) {
            showToast('Soltá una imagen (no es un archivo de imagen)', 'error');
            return;
        }
        // Reutilizar el flujo de uploads: setear state y simular onClosingFilePicked
        await _uploadClosingFiles(rid, kind, teamSlot, imgs);
    });
}

// Achica una imagen al máximo (maxW x maxH px) preservando proporción y
// la devuelve como data URL (image/jpeg, calidad 0.82). Reduce el peso
// de un screenshot típico de ~1MB a ~80-150KB.
async function _compressImageToDataUrl(file, maxW = 1400, maxH = 1400) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => {
            const img = new Image();
            img.onload = () => {
                let w = img.width, h = img.height;
                if (w > maxW || h > maxH) {
                    const r = Math.min(maxW / w, maxH / h);
                    w = Math.round(w * r); h = Math.round(h * r);
                }
                const canvas = document.createElement('canvas');
                canvas.width = w; canvas.height = h;
                const ctx = canvas.getContext('2d');
                ctx.drawImage(img, 0, 0, w, h);
                resolve(canvas.toDataURL('image/jpeg', 0.82));
            };
            img.onerror = () => reject(new Error('img load failed'));
            img.src = e.target.result;
        };
        reader.onerror = () => reject(new Error('file read failed'));
        reader.readAsDataURL(file);
    });
}

// Sube una lista de Files al cierre rid con (kind, teamSlot) — extraído
// de onClosingFilePicked para que el drag&drop / pegar lo reusen.
// La imagen se comprime y se guarda como data URI directo en la DB.
// Este proyecto no usa S3, así que no hay paso de presigned-url.
async function _uploadClosingFiles(rid, kind, teamSlot, files) {
    if (!files || files.length === 0) return;
    const row = (_closingsRowsCache || []).find(x => x.id === rid);
    const existingCount = row && Array.isArray(row.comprobantes) ? row.comprobantes.filter(c => c.kind === kind).length : 0;
    const remaining = Math.max(0, COMP_MAX_PER_KIND - existingCount);
    if (remaining === 0) {
        showToast('Ya hay ' + COMP_MAX_PER_KIND + ' fotos de este tipo (máximo).', 'error');
        return;
    }
    const toUpload = files.slice(0, remaining);
    if (files.length > remaining) {
        showToast('Sólo se suben ' + remaining + ' (cap de ' + COMP_MAX_PER_KIND + ' por tipo)', 'info');
    }
    let okCount = 0, failCount = 0, lastErr = '';
    for (const file of toUpload) {
        try {
            const dataUrl = await _compressImageToDataUrl(file);
            const payload = { url: dataUrl, kind };
            if (teamSlot != null && !isNaN(teamSlot)) payload.teamSlot = teamSlot;
            const r = await authFetch('/api/admin/closings/' + encodeURIComponent(rid) + '/comprobante', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const d = await r.json().catch(() => ({}));
            if (!r.ok || !d.success) { failCount++; lastErr = d.error || ('HTTP ' + r.status); continue; }
            okCount++;
        } catch (e) { failCount++; lastErr = (e && e.message) || 'error'; }
    }
    if (okCount > 0) {
        showToast('✅ ' + okCount + ' foto(s) subida(s)' + (failCount > 0 ? ' · ' + failCount + ' falló' : ''), 'success');
        loadClosings();
    } else {
        showToast('❌ No se pudo subir la foto' + (lastErr ? ' — ' + lastErr : ''), 'error');
    }
}

// Gráfico SVG simple del cuadre histórico:
//   - eje X: días (cronológico, izquierda → derecha = pasado → presente)
//   - eje Y: diff (0 = línea media)
//   - barras rojas: falta plata (diff > 0)
//   - barras verdes: sobra (diff < 0)
//   - barras grises: cerró en 0
//   - barra punteada: borrador (no confirmado)
function _renderClosingsChart(rows, sec) {
    if (!rows || rows.length === 0) return '';
    // Orden cronológico
    const data = [...rows].sort((a, b) => a.dateKey.localeCompare(b.dateKey));
    const W = 760, H = 180, padL = 50, padR = 12, padT = 14, padB = 28;
    const innerW = W - padL - padR;
    const innerH = H - padT - padB;

    // Escala Y: max abs(diff)
    let maxAbs = 1;
    data.forEach(r => {
        const v = Math.abs(Number((r.computed || {}).diff) || 0);
        if (v > maxAbs) maxAbs = v;
    });
    // Redondear maxAbs a un múltiplo "lindo"
    const niceMax = (function(n) {
        const exp = Math.floor(Math.log10(n));
        const base = Math.pow(10, exp);
        const m = n / base;
        if (m <= 1) return base;
        if (m <= 2) return 2 * base;
        if (m <= 5) return 5 * base;
        return 10 * base;
    })(maxAbs);

    const midY = padT + innerH / 2;
    const barW = Math.max(2, Math.min(20, (innerW - 4) / data.length - 2));
    const step = (innerW - 4) / data.length;
    const yFromDiff = (d) => {
        const ratio = d / niceMax; // -1..1
        return midY - ratio * (innerH / 2);
    };

    const fmtShort = (n) => {
        const a = Math.abs(n);
        if (a >= 1e6) return (n / 1e6).toFixed(1).replace(/\.0$/, '') + 'M';
        if (a >= 1e3) return (n / 1e3).toFixed(0) + 'k';
        return String(Math.round(n));
    };

    let svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" xmlns="http://www.w3.org/2000/svg" preserveAspectRatio="xMidYMid meet" style="width:100%;height:auto;display:block;">';
    // Background
    svg += '<rect width="' + W + '" height="' + H + '" fill="rgba(0,0,0,0.30)" rx="8"/>';
    // Eje 0 (línea media)
    svg += '<line x1="' + padL + '" y1="' + midY + '" x2="' + (W - padR) + '" y2="' + midY + '" stroke="rgba(255,255,255,0.30)" stroke-width="1.5"/>';
    // Labels Y
    svg += '<text x="' + (padL - 6) + '" y="' + (midY + 4) + '" text-anchor="end" fill="#888" font-size="10" font-family="monospace">0</text>';
    svg += '<text x="' + (padL - 6) + '" y="' + (padT + 12) + '" text-anchor="end" fill="#ff8080" font-size="10" font-family="monospace">+' + fmtShort(niceMax) + '</text>';
    svg += '<text x="' + (padL - 6) + '" y="' + (H - padB + 2) + '" text-anchor="end" fill="#66ff66" font-size="10" font-family="monospace">-' + fmtShort(niceMax) + '</text>';
    // Labels semantica
    svg += '<text x="' + (padL + 2) + '" y="' + (padT + 11) + '" fill="#ff8080" font-size="9.5" font-family="monospace" font-weight="700">FALTA $</text>';
    svg += '<text x="' + (padL + 2) + '" y="' + (H - padB - 3) + '" fill="#66ff66" font-size="9.5" font-family="monospace" font-weight="700">SOBRA $</text>';

    // Barras
    data.forEach((r, i) => {
        const c = r.computed || {};
        const diff = Number(c.diff) || 0;
        const x = padL + 2 + i * step + (step - barW) / 2;
        const yTop = Math.min(midY, yFromDiff(diff));
        const yBottom = Math.max(midY, yFromDiff(diff));
        const h = Math.max(2, yBottom - yTop);
        const isConfirmed = r.status === 'confirmed';
        const hasBankProof = (r.comprobantes || []).some(p => p.kind === 'pendiente_bank');
        let color;
        if (Math.abs(diff) < 1) {
            color = isConfirmed ? '#88cc88' : '#666';
        } else if (diff > 0) {
            color = isConfirmed ? (hasBankProof ? '#ffaa66' : '#ff5050') : 'rgba(255,80,80,0.45)';
        } else {
            color = isConfirmed ? '#66ff66' : 'rgba(102,255,102,0.45)';
        }
        const op = isConfirmed ? 1 : 0.65;
        const dashAttr = isConfirmed ? '' : ' stroke="' + color + '" stroke-width="1" stroke-dasharray="2 1.5"';
        svg += '<rect x="' + x.toFixed(1) + '" y="' + yTop.toFixed(1) + '" width="' + barW.toFixed(1) + '" height="' + h.toFixed(1) + '" fill="' + color + '" opacity="' + op + '"' + dashAttr + '><title>' + r.dateKey + ' · ' + (diff >= 0 ? '+' : '') + Math.round(diff).toLocaleString('es-AR') + (isConfirmed ? ' · confirmado' : ' · borrador') + '</title></rect>';
        // Label de fecha cada N barras
        const showLabel = (data.length <= 12) || (i === 0) || (i === data.length - 1) || (i % Math.ceil(data.length / 10) === 0);
        if (showLabel) {
            const dd = r.dateKey.slice(8, 10);
            const mm = r.dateKey.slice(5, 7);
            svg += '<text x="' + (x + barW / 2).toFixed(1) + '" y="' + (H - padB + 13) + '" text-anchor="middle" fill="#888" font-size="9" font-family="monospace">' + dd + '/' + mm + '</text>';
        }
    });

    svg += '</svg>';

    let html = '<div style="background:rgba(0,0,0,0.18);padding:11px 12px;border-bottom:1px solid rgba(255,255,255,0.06);">';
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;flex-wrap:wrap;gap:6px;">';
    html += '<div style="color:' + sec.color + ';font-size:11px;font-weight:900;letter-spacing:1px;">📈 GRÁFICO DE CUADRE — ' + data.length + ' día(s)</div>';
    html += '<div style="color:#888;font-size:10.5px;">Rojo = faltó bajar · Verde = sobró · Punteado = borrador</div>';
    html += '</div>';
    html += svg;
    html += '</div>';
    return html;
}

// Cerrar sesión desde el panel /cierresgeneral. Limpia el token, los
// cookies admin (vía endpoint), y redirige al login branded.
async function closingsLogout() {
    if (!confirm('¿Cerrar sesión?')) return;
    try {
        // Best-effort: pedir al server que limpie las cookies admin.
        await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
    } catch (_) {}
    try {
        localStorage.removeItem('closingsToken');
        localStorage.removeItem('closingsUser');
        // Por si quedó un viejo token bajo adminToken/adminUser:
        // sólo se borran si pertenecen a un closings_viewer
        try {
            const u = JSON.parse(localStorage.getItem('adminUser') || '{}');
            if (u && u.role === 'closings_viewer') {
                localStorage.removeItem('adminToken');
                localStorage.removeItem('adminUser');
            }
        } catch (_) {}
        sessionStorage.clear();
    } catch (_) {}
    location.href = '/cierresgeneral';
}

function _renderClosings() {
    const body = document.getElementById('closingsBody');
    if (!body) return;

    const sec = CLOSING_SECTORS_UI.find(s => s.key === _closingsView.sector) || CLOSING_SECTORS_UI[0];
    const date = _closingsView.date || _closingsTodayART();
    const today = _closingsTodayART();
    // En modo "only=closings" (entrada vía /cierresgeneral) mostramos un
    // botón de "Cerrar sesión" arriba ya que el sidebar/logout normal no
    // está visible.
    const onlyMode = (function() {
        try {
            return new URLSearchParams(location.search).get('only') === 'closings';
        } catch { return false; }
    })();

    let html = '';

    if (onlyMode) {
        html += '<div style="display:flex;justify-content:flex-end;margin-bottom:8px;">';
        html += '<button type="button" onclick="closingsLogout()" style="background:rgba(255,80,80,0.10);border:1px solid rgba(255,80,80,0.45);color:#ff8080;padding:6px 13px;border-radius:7px;font-weight:800;font-size:11.5px;cursor:pointer;display:inline-flex;align-items:center;gap:5px;">🚪 Cerrar sesión</button>';
        html += '</div>';
    }

    // ===== Selector de sector =====
    html += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px;align-items:center;">';
    for (const s of CLOSING_SECTORS_UI) {
        const active = s.key === _closingsView.sector;
        const bg = active ? s.color : 'rgba(255,255,255,0.04)';
        const color = active ? '#000' : s.color;
        const border = active ? s.color : (s.color + '55');
        html += '<button type="button" onclick="closingsSelectSector(\'' + s.key + '\')" style="flex:1;min-width:130px;background:' + bg + ';color:' + color + ';border:1.5px solid ' + border + ';padding:9px 12px;border-radius:9px;font-weight:900;font-size:12.5px;letter-spacing:0.4px;cursor:pointer;">' + s.label + '</button>';
    }
    // Botón para renombrar los 3 sectores (abre modal).
    html += '<button type="button" onclick="_openSectorRenameModal()" title="Renombrar los sectores" style="background:rgba(255,255,255,0.04);color:#d4af37;border:1.5px solid rgba(212,175,55,0.45);padding:9px 12px;border-radius:9px;font-weight:900;font-size:12.5px;cursor:pointer;">✏️ Nombres</button>';
    html += '</div>';

    // ===== Selector de día (visible solo para el editor) =====
    html += '<div style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);border-radius:9px;padding:9px 11px;margin-bottom:12px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;">';
    html += '<label style="color:#aaa;font-size:11px;font-weight:700;letter-spacing:0.5px;">📅 Día activo:</label>';
    html += '<input type="date" id="closingsActiveDate" value="' + escapeHtml(date) + '" max="' + escapeHtml(today) + '" onchange="closingsSelectDate(this.value)" style="background:rgba(0,0,0,0.45);border:1px solid rgba(255,215,0,0.40);color:#fff;padding:5px 9px;border-radius:6px;font-weight:700;font-size:12.5px;">';
    if (date !== today) {
        html += '<button type="button" onclick="closingsSelectDate(\'' + today + '\')" style="background:rgba(0,212,255,0.15);border:1px solid rgba(0,212,255,0.45);color:#00d4ff;padding:5px 10px;border-radius:6px;font-weight:700;font-size:11px;cursor:pointer;">↩ Volver a hoy</button>';
    }
    html += '</div>';

    // ===== Summary del día activo =====
    html += '<div id="closingsSummaryBox" style="margin-bottom:14px;"></div>';

    // ===== Panel de Análisis Comparativo =====
    html += '<div id="closingsAnalysisBox" style="margin-bottom:16px;"></div>';

    // ===== Editor del día activo =====
    const activeRow = _closingsRowsCache.find(r => r.dateKey === date);
    html += '<div style="background:rgba(0,0,0,0.30);border:1.5px solid ' + sec.color + '55;border-radius:11px;padding:14px;margin-bottom:18px;">';
    html += '<div style="color:' + sec.color + ';font-weight:900;font-size:13px;letter-spacing:0.6px;margin-bottom:8px;">' + sec.label + ' · ' + date + '</div>';
    if (sec.individual) {
        html += _renderTeamSectorEntry(sec, date, activeRow);
    } else {
        html += _renderClosingEntry(sec, date, null, activeRow);
    }
    html += '</div>';

    // ===== Tabla histórica (últimos N días para la selección) =====
    const filter = _closingsView.filter || 'all';
    const counts = {
        all: _closingsRowsCache.length,
        draft: _closingsRowsCache.filter(x => x.status !== 'confirmed').length,
        confirmed: _closingsRowsCache.filter(x => x.status === 'confirmed').length
    };
    const filteredRows = _closingsRowsCache.filter(r => {
        if (filter === 'draft')     return r.status !== 'confirmed';
        if (filter === 'confirmed') return r.status === 'confirmed';
        return true;
    });

    html += '<div style="background:rgba(0,0,0,0.25);border:1px solid rgba(255,255,255,0.08);border-radius:11px;overflow:hidden;">';
    html += '<div style="background:rgba(255,255,255,0.04);padding:9px 12px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;">';
    html += '<div style="color:#fff;font-weight:900;font-size:13px;letter-spacing:0.4px;">📜 HISTORIAL (últimos ' + CLOSINGS_HISTORY_DAYS + ' días)</div>';
    html += '<div style="color:#888;font-size:11px;">' + filteredRows.length + ' de ' + _closingsRowsCache.length + ' cierres</div>';
    html += '</div>';

    // Filtros: Todos · Borradores · Cerrados
    html += '<div style="background:rgba(0,0,0,0.18);padding:8px 12px;display:flex;gap:6px;flex-wrap:wrap;border-bottom:1px solid rgba(255,255,255,0.06);">';
    const filterDefs = [
        { key: 'all',       label: '📜 Todos',      activeColor: '#fff',    activeBg: 'rgba(255,255,255,0.15)' },
        { key: 'draft',     label: '📝 Borradores', activeColor: '#ffd700', activeBg: 'rgba(255,215,0,0.18)' },
        { key: 'confirmed', label: '✅ Cerrados',   activeColor: '#aaffaa', activeBg: 'rgba(102,255,102,0.18)' }
    ];
    for (const f of filterDefs) {
        const active = filter === f.key;
        const bg = active ? f.activeBg : 'rgba(0,0,0,0.30)';
        const color = active ? f.activeColor : '#aaa';
        const border = active ? f.activeColor : 'rgba(255,255,255,0.12)';
        html += '<button type="button" onclick="closingsSetFilter(\'' + f.key + '\')" style="background:' + bg + ';color:' + color + ';border:1px solid ' + border + ';padding:5px 11px;border-radius:6px;font-weight:800;font-size:11px;cursor:pointer;">' + f.label + ' (' + counts[f.key] + ')</button>';
    }
    html += '</div>';

    // Gráfico de cuadre histórico (solo si hay datos)
    if (_closingsRowsCache.length > 0) {
        html += _renderClosingsChart(filteredRows, sec);
    }

    if (filteredRows.length === 0) {
        html += '<div style="color:#888;text-align:center;padding:22px;font-size:12.5px;">' + (filter === 'all' ? 'Sin cierres en el rango. Cargá el primero arriba.' : 'Sin cierres con este filtro.') + '</div>';
    } else {
        html += '<div style="overflow-x:auto;">';
        html += '<table style="width:100%;border-collapse:collapse;font-size:11.5px;min-width:1480px;">';
        html += '<thead><tr style="background:rgba(255,255,255,0.04);color:' + sec.color + ';text-align:left;">';
        html += '<th style="padding:7px 10px;font-weight:800;">Fecha</th>';
        html += '<th style="padding:7px 10px;font-weight:800;text-align:right;">🔢 Tx</th>';
        // Estilos: venta y neto se agrandan ~10% más que el resto.
        const thStd  = 'padding:7px 10px;font-weight:800;text-align:right;font-size:11.5px;';
        const thBig  = 'padding:9px 14px;font-weight:900;text-align:right;font-size:13px;';
        html += '<th style="padding:7px 10px;font-weight:800;text-align:right;">💰 Depósitos</th>';
        html += '<th style="' + thStd + '">🏦 Comisión</th>';
        html += '<th style="' + thBig + 'color:#ffd0a0;" title="VENTA = total de descargas (cash-outs a clientes)">🛒 VENTA</th>';
        html += '<th style="' + thStd + '" title="Gastos del día (resta del neto)">🧾 Gastos</th>';
        html += '<th style="' + thStd + '" title="Egresos del día (préstamos hechos)">📤 Egresos</th>';
        html += '<th style="' + thStd + '" title="Ingresos del día (préstamos recibidos)">📥 Ingresos</th>';
        html += '<th style="' + thStd + '">🎁 Bonos</th>';
        html += '<th style="' + thStd + '" title="Pendiente que venía arrastrado del día anterior">↩️ Pend. día anterior</th>';
        html += '<th style="' + thStd + '" title="Pendiente calculado del día = lo que falta bajar">⏳ Pend. a bajar</th>';
        html += '<th style="' + thStd + '">🏃 Bajó</th>';
        html += '<th style="' + thStd + '" title="Saldo real del CVU/banco a las 00 hs">🏦 CVU 00h</th>';
        html += '<th style="' + thBig + 'color:#c89bff;" title="Neto del día = venta − comisión − gastos − egresos + ingresos">📐 NETO</th>';
        html += '<th style="' + thStd + '" title="Δ = Pendiente a bajar − CVU 00h. Positivo = falta · Negativo = sobra">Δ falta/sobra</th>';
        html += '<th style="' + thStd.replace('text-align:right', 'text-align:center') + '">Estado</th>';
        html += '<th style="' + thStd.replace('text-align:right', 'text-align:center') + '">Acción</th>';
        html += '</tr></thead><tbody>';
        const sorted = [...filteredRows].sort((a, b) => b.dateKey.localeCompare(a.dateKey));
        for (const r of sorted) {
            const c = r.computed || {};
            const isActive = r.dateKey === date;

            // Análisis del cierre basado en el cuadre (diff):
            //  diff == 0 → cerró exacto
            //  diff > 0  → falta bajar (pendiente; rojo si no hay foto banco)
            //  diff < 0  → bajaste de más (sobra plata, verde a favor)
            const hasBankProof = (r.comprobantes || []).some(p => p.kind === 'pendiente_bank');
            const isConfirmed = r.status === 'confirmed';
            const isDraft = r.status === 'draft';
            const dval = c.diff || 0;
            let stateBadge;
            if (dval === 0) {
                stateBadge = isConfirmed
                    ? '<span style="color:#aaffaa;font-weight:900;font-size:10px;">✅ CERRÓ BIEN</span>'
                    : '<span style="color:#888;font-size:10px;">📝 BORRADOR · en 0</span>';
            } else if (dval > 0) {
                if (isConfirmed && hasBankProof) {
                    stateBadge = '<span style="color:#ffaa66;font-weight:800;font-size:10px;" title="Falta bajar — respaldado con foto banco">⏳ PEND. RESPALDADO</span>';
                } else if (isConfirmed) {
                    stateBadge = '<span style="color:#ff5050;font-weight:900;font-size:10px;" title="Falta bajar SIN respaldo banco">🚨 PLATA FALTANTE</span>';
                } else {
                    stateBadge = '<span style="color:#888;font-size:10px;">📝 BORRADOR · falta bajar</span>';
                }
            } else {
                stateBadge = isConfirmed
                    ? '<span style="color:#66ff66;font-weight:900;font-size:10px;" title="Bajaste de más — sobra plata a favor">💚 SOBREPAGO (a favor)</span>'
                    : '<span style="color:#888;font-size:10px;">📝 BORRADOR · sobrepago</span>';
            }
            if (r.locked) {
                stateBadge += ' <span style="color:#ff8080;font-size:9.5px;">🔒</span>';
            }
            if (r.verifiedAt) {
                stateBadge += ' <span style="color:#66ff66;font-size:11px;font-weight:900;" title="Verificado por ' + escapeHtml(r.verifiedBy || '?') + '">✓</span>';
            }

            const pendColor = c.pendienteHoy > 0 ? '#ff8080' : '#888';
            const cvuMid = Number(r.cvuMidnightARS || 0);
            const gastosVal = Number(r.gastosARS || 0);
            const ingresosVal = Number(c.ingresos || 0);
            const egresosVal = Number(c.egresos || 0);
            const gastosColor = gastosVal > 0 ? '#ffaa66' : '#888';
            const ingresosColor = ingresosVal > 0 ? '#aaffaa' : '#888';
            const egresosColor = egresosVal > 0 ? '#ff8080' : '#888';
            // VENTA = total de descargas (cash-outs). Es lo que cargás en
            // el formulario como "ventasARS". Versión previa intentó
            // hacer dep−desc pero estaba mal — el dueño confirmó que
            // VENTA == ventasARS directo.
            const ventaNeta = Number(r.ventasARS || 0);
            const netoFinal = (c.neto != null)
                ? Number(c.neto)
                : (ventaNeta - Number(c.commission || 0) - gastosVal - egresosVal + ingresosVal);
            const netoFinalColor = netoFinal > 0 ? '#66ff66' : (netoFinal < 0 ? '#ff5050' : '#aaffaa');
            // Δ falta/sobra = pendiente CALCULADO − CVU 00h real
            // Compara lo que la fórmula dice que tendría que haber (calc)
            // contra lo que el banco realmente muestra (CVU). Antes usaba
            // pendienteHoy pero ahora pendienteHoy === CVU real → siempre 0.
            // El interesante es la divergencia entre cálculo y realidad.
            const pendCalcVal = Number(
                c.pendienteCalculado != null
                    ? c.pendienteCalculado
                    : Math.max(0, Number(c.totalABajar || 0) - Number(r.bajadaARS || 0))
            );
            const faltaSobra = pendCalcVal - cvuMid;
            let dcolor, dtext;
            if (cvuMid === 0 && pendCalcVal === 0) {
                dcolor = '#666'; dtext = '—';
            } else if (Math.abs(faltaSobra) < 1) {
                dcolor = '#aaffaa'; dtext = '✅ OK';
            } else if (faltaSobra > 0) {
                dcolor = '#ff5050'; dtext = '🚨 FALTAN ' + _closingFmt(faltaSobra);
            } else {
                dcolor = '#66ff66'; dtext = '💚 SOBRAN ' + _closingFmt(-faltaSobra);
            }
            // Estilos: venta y neto se renderizan más grandes que el resto.
            const tdStd = 'padding:6px 10px;text-align:right;';
            const tdBig = 'padding:8px 14px;text-align:right;font-size:13px;';
            html += '<tr style="border-top:1px solid rgba(255,255,255,0.05);' + (isActive ? 'background:rgba(255,215,0,0.06);' : '') + '">';
            html += '<td style="padding:6px 10px;color:#fff;font-weight:700;font-family:monospace;">' + escapeHtml(r.dateKey) + (isActive ? ' <span style="color:#ffd700;">←</span>' : '') + '</td>';
            html += '<td style="' + tdStd + 'color:#c89bff;font-weight:700;">' + Number(r.transactionsCount || 0).toLocaleString('es-AR') + '</td>';
            html += '<td style="' + tdStd + 'color:#aaffaa;">' + _closingFmt(r.depositsARS) + '</td>';
            html += '<td style="' + tdStd + 'color:#ff8080;">-' + _closingFmt(c.commission) + '</td>';
            // VENTA = total descargas (cash-outs a clientes)
            html += '<td style="' + tdBig + 'color:#ffd0a0;font-weight:900;">' + _closingFmt(ventaNeta) + '</td>';
            html += '<td style="' + tdStd + 'color:' + gastosColor + ';" title="Resta del neto">' + _closingFmt(gastosVal) + '</td>';
            html += '<td style="' + tdStd + 'color:' + egresosColor + ';" title="Préstamos hechos · resta del neto">' + _closingFmt(egresosVal) + '</td>';
            html += '<td style="' + tdStd + 'color:' + ingresosColor + ';" title="Préstamos recibidos · suma al neto">' + _closingFmt(ingresosVal) + '</td>';
            html += '<td style="' + tdStd + 'color:#ffd700;">' + _closingFmt(r.bonusARS) + '</td>';
            html += '<td style="' + tdStd + 'color:#ffaa66;" title="Arrastre del día anterior">' + _closingFmt(r.pendienteAnteriorARS) + '</td>';
            html += '<td style="' + tdStd + 'color:' + pendColor + ';font-weight:700;" title="Lo que falta bajar">' + _closingFmt(c.pendienteHoy) + '</td>';
            html += '<td style="' + tdStd + 'color:#aaffff;">' + _closingFmt(r.bajadaARS) + '</td>';
            html += '<td style="' + tdStd + 'color:#00d4ff;font-weight:700;" title="Saldo real CVU a las 00 hs">' + _closingFmt(cvuMid) + '</td>';
            // NETO — agrandado
            html += '<td style="' + tdBig + 'color:' + netoFinalColor + ';font-weight:900;" title="Neto del día = venta − comisión − gastos − egresos + ingresos">' + _closingFmt(netoFinal) + '</td>';
            html += '<td style="' + tdStd + 'color:' + dcolor + ';font-weight:800;" title="Δ = Pendiente a bajar − CVU 00h">' + dtext + '</td>';
            html += '<td style="padding:6px 10px;text-align:center;">' + stateBadge + '</td>';
            html += '<td style="padding:6px 10px;text-align:center;white-space:nowrap;">';
            html += '<button type="button" onclick="closingsSelectDate(\'' + r.dateKey + '\')" style="background:rgba(0,212,255,0.10);color:#00d4ff;border:1px solid rgba(0,212,255,0.40);padding:3px 8px;border-radius:5px;font-size:10.5px;font-weight:700;cursor:pointer;margin-right:3px;">Abrir</button>';
            html += '<button type="button" onclick="analyzeClosing(\'' + r.id + '\')" style="background:rgba(155,48,255,0.12);color:#c89bff;border:1px solid rgba(155,48,255,0.45);padding:3px 8px;border-radius:5px;font-size:10.5px;font-weight:700;cursor:pointer;margin-right:3px;">🔍 Analizar</button>';
            html += '<button type="button" onclick="deleteClosing(\'' + r.id + '\')" title="Borrar cierre (PIN)" style="background:rgba(255,80,80,0.12);color:#ff8080;border:1px solid rgba(255,80,80,0.45);padding:3px 7px;border-radius:5px;font-size:10.5px;font-weight:700;cursor:pointer;">🗑️</button>';
            html += '</td>';
            html += '</tr>';
        }
        html += '</tbody></table></div>';
    }
    html += '</div>';

    body.innerHTML = html;
    // Wire up live recompute on inputs y disparar primer cálculo
    setTimeout(_wireClosingsLiveRecompute, 10);
}

// Panel de comprobantes (fotos). Categorías:
//   📥 Depósitos · 🛒 Venta · 🎁 Bonificación · 🏃 Bajada · 🏦 Banco-Pendiente
// El owner puede adjuntar fotos por categoría para respaldar cada
// monto. Sin foto de "banco-pendiente" no se puede confirmar si hay
// pendiente > 0.
const COMP_KINDS = [
    { key: 'deposito',       label: '📥 Depósito',      color: '#aaffaa' },
    { key: 'venta',          label: '🛒 Venta',         color: '#ffd0a0' },
    { key: 'bonificacion',   label: '🎁 Bonificación',  color: '#ffd700' },
    { key: 'bajada',         label: '🏃 Bajada',        color: '#aaffff' },
    { key: 'pendiente_bank', label: '🏦 Banco-Pend.',   color: '#ffaa66' }
];

// Panel compacto: una sola línea con conteo de fotos por categoría,
// + alerta si falta foto banco-pendiente, + input file oculto necesario
// para el upload. Los botones para SUBIR están inline al lado de cada
// campo (no más sección grande abajo).
function _renderComprobantesPanel(row, rid, locked, computed) {
    const comps = (row && row.comprobantes) || [];
    const hasPendBank = comps.some(p => p.kind === 'pendiente_bank');
    const needsPendBank = (computed && computed.pendienteHoy > 0) && !hasPendBank;

    let html = '';

    // Resumen línea con conteos por categoría (todo en una sola fila)
    if (comps.length > 0) {
        const summary = [
            { k: 'deposito',       label: '📥 Depósitos',  color: '#aaffaa' },
            { k: 'bajada',         label: '🏃 Bajadas',    color: '#aaffff' },
            { k: 'pendiente_bank', label: '🏦 Banco-Pend.', color: '#ffaa66' },
            { k: 'ingreso',        label: '📥 Ingresos',   color: '#aaffaa' },
            { k: 'egreso',         label: '📤 Egresos',    color: '#ff8080' },
            { k: 'gasto',          label: '🧾 Gastos',     color: '#ffaa66' },
            { k: 'bonificacion',   label: '🎁 Bonif.',     color: '#ffd700' }
        ];
        html += '<div style="background:rgba(0,0,0,0.18);border:1px solid rgba(255,255,255,0.06);border-radius:7px;padding:7px 10px;margin-bottom:8px;display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:10.5px;">';
        html += '<div style="color:#888;font-weight:700;">📎 Fotos:</div>';
        for (const s of summary) {
            const n = comps.filter(c => c.kind === s.k).length;
            if (n === 0) continue;
            html += '<span style="color:' + s.color + ';font-weight:700;">' + s.label + ' <strong>' + n + '</strong></span>';
        }
        html += '<span style="color:#888;margin-left:auto;">total ' + comps.length + '</span>';
        html += '</div>';
    }

    // Alerta: pendiente sin foto banco
    if (needsPendBank) {
        html += '<div style="color:#ff8080;font-size:10.5px;margin-bottom:8px;background:rgba(255,80,80,0.08);border-left:3px solid #ff5050;padding:6px 9px;border-radius:0 6px 6px 0;">⚠️ Quedó pendiente — adjuntá la foto <strong>🏦 Banco</strong> arriba (al lado de "Pend. anterior") antes de confirmar.</div>';
    }

    // Input file oculto: necesario para que openClosingUpload pueda funcionar.
    if (!locked) {
        html += '<input type="file" accept="image/*" multiple id="cls_' + rid + '_file" style="display:none;" onchange="onClosingFilePicked(\'' + rid + '\')">';
    }
    return html;
}

// State: qué categoría se está subiendo + opcional teamSlot.
// Set por openClosingUpload(rid, kind, teamSlot).
const _closingUploadState = {};

// Cap por tipo de comprobante para evitar spam (10 fotos por kind)
const COMP_MAX_PER_KIND = 50;

function openClosingUpload(rid, kind, teamSlot) {
    // No se puede subir foto a un cierre que todavía no existe.
    if (String(rid).startsWith('new_')) {
        showToast('💾 Guardá el cierre primero — después podés adjuntar fotos.', 'info');
        return;
    }
    _closingUploadState[rid] = { kind, teamSlot: (teamSlot != null ? Number(teamSlot) : null) };
    _openClosingUploadModal(rid, kind, (teamSlot != null ? Number(teamSlot) : null));
}

// Modal de adjuntar foto: ofrece pegar (Ctrl+V), arrastrar o elegir
// archivo. Al estar abierto captura el paste de toda la página, así el
// usuario hace el recorte y aprieta Ctrl+V sin tener que apuntar nada.
function _openClosingUploadModal(rid, kind, teamSlot) {
    document.getElementById('clsUploadModal')?.remove();
    const overlay = document.createElement('div');
    overlay.id = 'clsUploadModal';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;padding:20px;';
    overlay.innerHTML =
        '<div style="background:#10131a;border:1.5px solid rgba(0,212,255,0.45);border-radius:14px;padding:22px;max-width:420px;width:100%;color:#fff;box-shadow:0 0 40px rgba(0,212,255,0.20);">' +
        '<div style="text-align:center;margin-bottom:14px;"><div style="font-size:30px;">📷</div>' +
        '<h3 style="margin:4px 0 2px;color:#00d4ff;font-size:16px;">Adjuntar foto</h3></div>' +
        '<div id="clsPasteZone" tabindex="0" style="border:2px dashed rgba(0,212,255,0.55);border-radius:12px;padding:24px 14px;text-align:center;cursor:pointer;outline:none;background:rgba(0,212,255,0.06);">' +
        '<div style="font-size:26px;margin-bottom:6px;">📋</div>' +
        '<div style="color:#00d4ff;font-weight:900;font-size:14px;">Pegá la captura acá</div>' +
        '<div style="color:#999;font-size:11.5px;margin-top:5px;line-height:1.5;">Hacé el recorte y apretá <strong>Ctrl+V</strong>.<br>También podés arrastrar la imagen o tocar para elegir un archivo.</div>' +
        '</div>' +
        '<div id="clsUploadMsg" style="min-height:15px;font-size:12px;text-align:center;margin:8px 0;"></div>' +
        '<div style="display:flex;gap:8px;">' +
        '<button type="button" id="clsUploadCancel" style="flex:1;background:rgba(255,255,255,0.08);border:1px solid rgba(255,255,255,0.20);color:#fff;padding:9px;border-radius:8px;font-weight:700;cursor:pointer;">Cerrar</button>' +
        '<button type="button" id="clsUploadPick" style="flex:2;background:rgba(0,212,255,0.15);border:1px solid rgba(0,212,255,0.5);color:#00d4ff;padding:9px;border-radius:8px;font-weight:900;cursor:pointer;">📁 Elegir archivo</button>' +
        '</div></div>';
    document.body.appendChild(overlay);
    const zone = document.getElementById('clsPasteZone');
    const msg = document.getElementById('clsUploadMsg');
    setTimeout(() => zone && zone.focus(), 30);

    const extractImgs = (src) => {
        const out = [];
        for (const it of Array.from((src && src.items) || [])) {
            if (it.kind === 'file' && it.type && it.type.startsWith('image/')) {
                const f = it.getAsFile(); if (f) out.push(f);
            }
        }
        if (out.length === 0) {
            for (const f of Array.from((src && src.files) || [])) {
                if (f.type && f.type.startsWith('image/')) out.push(f);
            }
        }
        return out;
    };
    const close = () => { document.removeEventListener('paste', onPaste); overlay.remove(); };
    const doUpload = async (imgs) => {
        close();
        await _uploadClosingFiles(rid, kind, teamSlot, imgs);
    };
    const onPaste = (e) => {
        const imgs = extractImgs(e.clipboardData);
        if (imgs.length === 0) { msg.style.color = '#ff8080'; msg.textContent = 'No hay una imagen en el portapapeles'; return; }
        e.preventDefault();
        doUpload(imgs);
    };
    document.addEventListener('paste', onPaste);
    zone.addEventListener('dragover', (e) => { e.preventDefault(); zone.style.background = 'rgba(0,212,255,0.20)'; });
    zone.addEventListener('dragleave', () => { zone.style.background = 'rgba(0,212,255,0.06)'; });
    zone.addEventListener('drop', (e) => {
        e.preventDefault();
        const imgs = extractImgs(e.dataTransfer);
        if (imgs.length === 0) { msg.style.color = '#ff8080'; msg.textContent = 'Eso no es una imagen'; return; }
        doUpload(imgs);
    });
    document.getElementById('clsUploadCancel').onclick = close;
    document.getElementById('clsUploadPick').onclick = () => {
        const fileEl = document.getElementById('cls_' + rid + '_file');
        close();
        if (fileEl) fileEl.click();
    };
    overlay.addEventListener('click', (e) => { if (e.target === overlay) close(); });
}

async function onClosingFilePicked(rid) {
    const fileEl = document.getElementById('cls_' + rid + '_file');
    if (!fileEl || !fileEl.files || fileEl.files.length === 0) return;
    const files = Array.from(fileEl.files);
    const state = _closingUploadState[rid] || { kind: 'deposito', teamSlot: null };
    await _uploadClosingFiles(rid, state.kind, state.teamSlot, files);
    if (fileEl) fileEl.value = '';
}

// Live preview: lee inputs del editor y muestra el cuadre del cierre
// en tiempo real (sin necesidad de guardar). Se vuelve a llamar en
// cada `oninput` de los campos que afectan el cálculo.
function closingsRecompute(rid) {
    const box = document.getElementById('cls_' + rid + '_preview');
    if (!box) return;
    const getV = (suffix) => {
        const el = document.getElementById('cls_' + rid + '_' + suffix);
        return el ? parseFloat(el.value) || 0 : 0;
    };
    // Datos del bloque general
    const bankPct = getV('bankMarginPercent');
    const bajada = getV('bajadaARS');
    const pendAnt = getV('pendienteAnteriorARS'); // CVU 00 hs día anterior
    // saldoInicial: removido del modelo. Se deja en 0 — la cifra real del
    // banco al cierre del día anterior ya viene reflejada en pendAnt (CVU 00 hs).
    const saldoInicial = 0;
    // Movimientos extra
    const ingresos = getV('ingresosARS');
    const egresos = getV('egresosARS');
    const gastos = getV('gastosARS');
    const cvuActual = getV('cvuMidnightARS');

    // Datos por equipo (si los hay).
    // `sumVentas` = Σ cash-outs a clientes (lo que pagamos a ganadores)
    // — guardado en el field `ventasARS` por team. El dueño llama a esto
    // VENTA directo (sin restar a los depósitos).
    let sumDeposits = 0, sumVentas = 0, sumBonus = 0;
    let sumCargasN = 0, sumDescN = 0, sumBonosN = 0;
    const teamInputs = document.querySelectorAll('[data-cls-id="' + rid + '"] [data-buffalo-team]');
    if (teamInputs.length > 0) {
        const teams = {};
        teamInputs.forEach(el => {
            const slot = el.getAttribute('data-buffalo-team');
            const field = el.getAttribute('data-field');
            if (!teams[slot]) teams[slot] = {};
            teams[slot][field] = parseFloat(el.value) || 0;
        });
        Object.values(teams).forEach(t => {
            sumDeposits += t.depositsARS || 0;
            sumVentas += t.ventasARS || 0;
            sumBonus += t.bonusARS || 0;
            sumCargasN += t.depositsCount || 0;
            sumDescN += t.withdrawalsCount || 0;
            sumBonosN += t.bonusCount || 0;
        });
    } else {
        // Sector simple (publicidad): inputs directos
        sumDeposits = getV('depositsARS');
        sumVentas = getV('ventasARS');
        sumBonus = getV('bonusARS');
        sumCargasN = getV('depositsCount');
        sumDescN = getV('withdrawalsCount');
        sumBonosN = getV('bonusCount');
    }

    // Mismo cálculo del backend (_closingComputeTotals)
    const commission = sumDeposits * (bankPct / 100);
    // Neto = venta neta − comisión − gastos − egresos + ingresos
    const neto = sumVentas - commission - gastos - egresos + ingresos;
    // Total a bajar = Neto + pendiente anterior (=CVU del día anterior)
    const totalABajar = neto + pendAnt;
    // Diferencia según la fórmula: total a bajar − bajada
    const diff = totalABajar - bajada;
    const pendienteCalculado = Math.max(0, diff);
    // Pendiente a bajar OFICIAL = CVU 00 hs real (si está cargado).
    // Si todavía no se cargó, cae al cálculo.
    const pendienteHoyLive = cvuActual > 0 ? cvuActual : pendienteCalculado;
    const totalTx = sumCargasN + sumDescN + sumBonosN;

    // CVU esperado SEGÚN cálculo = lo que la fórmula dice que debería quedar.
    const cvuExpected = pendienteCalculado + saldoInicial;
    // Δ falta/sobra = CVU real cargado − esperado (negativo = falta).
    const cvuDiscrepancy = cvuActual - cvuExpected;

    // Pintar preview
    const cuadreColor = diff === 0 ? '#aaffaa' : (diff > 0 ? '#ff8080' : '#66ff66');
    const cuadreLabel = diff === 0
        ? '✅ CUADRE EN 0 (cerró bien)'
        : (diff > 0 ? '⏳ FALTAN ' + _closingFmt(diff) + ' por bajar' : '💚 SOBRA ' + _closingFmt(-diff) + ' (a favor)');

    let html = '<div style="background:rgba(0,0,0,0.40);border:1.5px solid ' + cuadreColor + '55;border-radius:9px;padding:10px;font-size:11.5px;">';
    html += '<div style="color:#c89bff;font-size:10px;font-weight:900;letter-spacing:1px;margin-bottom:6px;">🧮 CÁLCULO EN VIVO (se actualiza al tipear)</div>';
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:5px;margin-bottom:6px;">';
    html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">Σ DEPÓSITOS</div><div style="color:#aaffaa;font-weight:800;">' + _closingFmt(sumDeposits) + '</div></div>';
    html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">VENTA (cash-out)</div><div style="color:#ffd0a0;font-weight:800;">' + _closingFmt(sumVentas) + '</div></div>';
    html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">COMISIÓN (' + bankPct + '% × depósitos)</div><div style="color:#ff8080;font-weight:800;">-' + _closingFmt(commission) + '</div></div>';
    html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">NETO (venta − com − gas − eg + ing)</div><div style="color:#c89bff;font-weight:800;">' + _closingFmt(neto) + '</div></div>';
    html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">TOTAL A BAJAR</div><div style="color:#fff;font-weight:800;">' + _closingFmt(totalABajar) + '</div><div style="color:#666;font-size:9px;">neto + pend ant</div></div>';
    html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">BAJADA REAL</div><div style="color:#aaffff;font-weight:800;">' + _closingFmt(bajada) + '</div></div>';
    html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">Σ BONIFICACIONES (dato)</div><div style="color:#ffd700;font-weight:800;">' + _closingFmt(sumBonus) + '</div><div style="color:#666;font-size:9px;">no afecta cuadre</div></div>';
    html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">Σ TRANSACCIONES</div><div style="color:#c89bff;font-weight:800;">' + totalTx.toLocaleString('es-AR') + '</div><div style="color:#666;font-size:9px;">' + sumCargasN + '+' + sumDescN + '+' + sumBonosN + '</div></div>';
    html += '</div>';
    html += '<div style="background:' + cuadreColor + '22;border:2px solid ' + cuadreColor + ';border-radius:8px;padding:9px;text-align:center;color:' + cuadreColor + ';font-weight:900;font-size:14px;letter-spacing:0.5px;margin-bottom:7px;">' + cuadreLabel + '</div>';

    // === CONTROL CVU 00 HS ===
    if (ingresos || egresos || gastos || cvuActual) {
        const cvuColor = Math.abs(cvuDiscrepancy) < 1 ? '#aaffaa' : (cvuDiscrepancy < 0 ? '#ff5050' : '#ffaa66');
        let cvuLabel;
        if (Math.abs(cvuDiscrepancy) < 1) {
            cvuLabel = '✅ CVU CUADRA — el saldo real coincide con el esperado';
        } else if (cvuDiscrepancy < 0) {
            cvuLabel = '🚨 FALTAN ' + _closingFmt(-cvuDiscrepancy) + ' EN EL CVU — saldo real es MENOR al esperado';
        } else {
            cvuLabel = '⚠️ SOBRAN ' + _closingFmt(cvuDiscrepancy) + ' EN EL CVU — entró plata sin registrar';
        }
        html += '<div style="background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.30);border-radius:8px;padding:8px;">';
        html += '<div style="color:#00d4ff;font-size:10px;font-weight:900;letter-spacing:1px;margin-bottom:6px;">🏦 CONTROL CVU 00 HS</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:5px;margin-bottom:6px;">';
        html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">📥 INGRESOS</div><div style="color:#aaffaa;font-weight:800;">' + _closingFmt(ingresos) + '</div></div>';
        html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">📤 EGRESOS</div><div style="color:#ff8080;font-weight:800;">-' + _closingFmt(egresos) + '</div></div>';
        html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">🧾 GASTOS</div><div style="color:#ffaa66;font-weight:800;">-' + _closingFmt(gastos) + '</div></div>';
        html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">CVU ESPERADO</div><div style="color:#fff;font-weight:800;">' + _closingFmt(cvuExpected) + '</div><div style="color:#666;font-size:9px;">= pendiente + saldo inicial</div></div>';
        html += '<div style="background:rgba(0,0,0,0.30);padding:5px 8px;border-radius:5px;"><div style="color:#888;font-size:9.5px;">CVU REAL (00 hs)</div><div style="color:#00d4ff;font-weight:800;">' + _closingFmt(cvuActual) + '</div></div>';
        html += '</div>';
        html += '<div style="background:' + cvuColor + '22;border:2px solid ' + cvuColor + ';border-radius:7px;padding:7px;text-align:center;color:' + cvuColor + ';font-weight:900;font-size:12.5px;">' + cvuLabel + '</div>';
        html += '</div>';
    }

    html += '</div>';
    box.innerHTML = html;
}

// Thumbnail clicable de una foto del cierre. Al clickear abre el
// lightbox a pantalla completa (con navegación entre fotos del cierre).
function _photoThumb(url, caption, borderColor) {
    if (!url) return '';
    const safe = escapeHtml(url);
    const cap = escapeHtml(caption || '');
    const col = borderColor || '#00d4ff';
    return '<div onclick="_openClsLightbox(\'' + safe.replace(/'/g, '\\\'') + '\', \'' + cap.replace(/'/g, '\\\'') + '\')" title="Clic para maximizar" style="position:relative;width:88px;height:88px;background:rgba(0,0,0,0.40);border:1.5px solid ' + col + '88;border-radius:7px;overflow:hidden;cursor:zoom-in;flex-shrink:0;">'
        + '<img src="' + safe + '" alt="' + cap + '" style="width:100%;height:100%;object-fit:cover;display:block;" loading="lazy">'
        + '<div style="position:absolute;inset:auto 0 0 0;background:linear-gradient(180deg,transparent,rgba(0,0,0,0.80));color:#fff;font-size:9px;font-weight:700;padding:3px 4px;line-height:1.15;">' + cap + '</div>'
        + '</div>';
}

// Lightbox global: imagen a pantalla completa, click fuera cierra,
// flechas ← → navegan entre las fotos del cierre activo (cache en
// window._clsAnalyzePhotos que setea analyzeClosing).
function _openClsLightbox(url, caption) {
    const prev = document.getElementById('clsLightbox');
    if (prev) prev.remove();
    const photos = (window._clsAnalyzePhotos || []).slice();
    let idx = Math.max(0, photos.indexOf(url));
    const show = (newIdx) => {
        if (newIdx < 0 || newIdx >= photos.length) return;
        idx = newIdx;
        const imgEl = document.getElementById('clsLightboxImg');
        if (imgEl) imgEl.src = photos[idx];
        const caps = document.getElementById('clsLightboxCap');
        if (caps) caps.textContent = (photos.length > 1 ? (idx + 1) + ' / ' + photos.length + ' · ' : '') + (caption || '');
    };
    const lb = document.createElement('div');
    lb.id = 'clsLightbox';
    lb.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.94);z-index:100000;display:flex;align-items:center;justify-content:center;padding:18px;cursor:zoom-out;';
    lb.onclick = (e) => { if (e.target === lb || e.target.id === 'clsLightboxClose') lb.remove(); };
    let h = '<div style="position:relative;max-width:96vw;max-height:92vh;display:flex;flex-direction:column;align-items:center;gap:10px;" onclick="event.stopPropagation()">';
    h += '<img id="clsLightboxImg" src="' + escapeHtml(url) + '" style="max-width:96vw;max-height:80vh;object-fit:contain;border-radius:6px;box-shadow:0 12px 40px rgba(0,0,0,0.60);">';
    h += '<div id="clsLightboxCap" style="color:#ddd;font-size:13px;font-weight:700;text-align:center;background:rgba(0,0,0,0.55);padding:6px 14px;border-radius:7px;">' + escapeHtml(caption || '') + '</div>';
    if (photos.length > 1) {
        h += '<div style="display:flex;gap:14px;">';
        h += '<button onclick="_clsLightboxNav(-1)" style="background:rgba(255,255,255,0.10);color:#fff;border:1px solid rgba(255,255,255,0.20);padding:8px 18px;border-radius:8px;font-weight:800;cursor:pointer;">← Anterior</button>';
        h += '<button onclick="_clsLightboxNav(1)" style="background:rgba(255,255,255,0.10);color:#fff;border:1px solid rgba(255,255,255,0.20);padding:8px 18px;border-radius:8px;font-weight:800;cursor:pointer;">Siguiente →</button>';
        h += '</div>';
    }
    h += '<button id="clsLightboxClose" onclick="document.getElementById(\'clsLightbox\').remove()" style="position:absolute;top:-10px;right:-10px;background:rgba(255,80,80,0.30);border:1px solid rgba(255,80,80,0.55);color:#fff;width:38px;height:38px;border-radius:50%;font-size:20px;font-weight:900;cursor:pointer;">✕</button>';
    h += '</div>';
    lb.innerHTML = h;
    // Navigation handlers a window
    window._clsLightboxNav = (dir) => show(idx + dir);
    document.body.appendChild(lb);
    // Esc cierra, flechas navegan
    const onKey = (e) => {
        if (e.key === 'Escape') { lb.remove(); document.removeEventListener('keydown', onKey); }
        else if (e.key === 'ArrowLeft') show(idx - 1);
        else if (e.key === 'ArrowRight') show(idx + 1);
    };
    document.addEventListener('keydown', onKey);
}

// Modal de análisis profundo de un cierre puntual.
// Muestra cálculo paso a paso, contribución por equipo (Buffalo/Ganamos),
// chequeo CVU, comprobantes adjuntos y diagnóstico de qué falta.
async function analyzeClosing(id) {
    const rLite = (_closingsRowsCache || []).find(x => x.id === id);
    if (!rLite) {
        showToast('Cierre no encontrado', 'error');
        return;
    }
    // El listado viene en modo lite (sin urls de fotos). Si todavía no
    // pedimos el row completo con fotos, lo buscamos ahora on-demand.
    let r = rLite;
    const hasUrls = Array.isArray(r.comprobantes) && r.comprobantes.some(c => c && c.url);
    const hasComps = Array.isArray(r.comprobantes) && r.comprobantes.length > 0;
    if (hasComps && !hasUrls) {
        try {
            const resp = await authFetch('/api/admin/closings/' + encodeURIComponent(id));
            const d = await resp.json();
            if (resp.ok && d.success && d.row) {
                r = d.row;
                // Actualizamos el cache para que el lightbox no re-fetchee.
                const idx = (_closingsRowsCache || []).findIndex(x => x.id === id);
                if (idx >= 0) _closingsRowsCache[idx] = r;
            }
        } catch (e) {
            console.warn('analyzeClosing fetch full failed:', e);
        }
    }
    const c = r.computed || {};
    const fmt = _closingFmt;
    const escH = (typeof escapeHtml === 'function') ? escapeHtml : (s => String(s || ''));

    // Diagnóstico de cuadre (lo que falta bajar)
    const diff = Number(c.diff || 0);
    const cuadreColor = Math.abs(diff) < 1 ? '#aaffaa' : (diff > 0 ? '#ff5050' : '#66ff66');
    const cuadreText = Math.abs(diff) < 1
        ? '✅ EL CIERRE CUADRA EN 0 — todo lo que había que bajar se bajó.'
        : (diff > 0
            ? '⏳ FALTAN $' + fmt(diff).replace('$', '') + ' por bajar — quedaron como pendiente.'
            : '💚 SOBRA $' + fmt(-diff).replace('$', '') + ' — bajaste más de lo necesario (a favor).');

    // Diagnóstico CVU
    const cvuDiscrepancy = Number(c.cvuDiscrepancy || 0);
    const cvuActual = Number(c.cvuActual || 0);
    const cvuExpected = Number(c.cvuExpected || 0);
    const hasCvuData = cvuActual > 0 || Number(c.ingresos || 0) > 0 || Number(c.egresos || 0) > 0 || Number(c.gastos || 0) > 0;
    let cvuColor = '#aaffaa', cvuText = '';
    if (hasCvuData) {
        if (Math.abs(cvuDiscrepancy) < 1) {
            cvuText = '✅ EL SALDO CVU COINCIDE — la plata está donde tiene que estar.';
        } else if (cvuDiscrepancy < 0) {
            cvuColor = '#ff5050';
            cvuText = '🚨 FALTAN $' + fmt(-cvuDiscrepancy).replace('$', '') + ' EN EL CVU — saldo real es MENOR al esperado. Posible plata salida sin registrar.';
        } else {
            cvuColor = '#ffaa66';
            cvuText = '⚠️ SOBRAN $' + fmt(cvuDiscrepancy).replace('$', '') + ' EN EL CVU — entró plata sin registrar. Revisar movimientos.';
        }
    }

    // Comprobantes por categoría
    const comps = r.comprobantes || [];
    const compsByKind = {};
    for (const k of ['deposito','venta','bonificacion','bajada','pendiente_bank']) {
        compsByKind[k] = comps.filter(p => p.kind === k);
    }
    const hasBankProof = compsByKind.pendiente_bank.length > 0;

    // Faltantes detectados
    const faltantes = [];
    if (c.pendienteHoy > 0 && !hasBankProof) {
        faltantes.push('🏦 Falta foto del BANCO mostrando los $' + fmt(c.pendienteHoy).replace('$', '') + ' pendientes — sin esto, no se puede confirmar.');
    }
    if (c.diff > 0 && r.status === 'confirmed' && !hasBankProof) {
        faltantes.push('🚨 Confirmado con pendiente y sin respaldo bancario — plata faltante.');
    }
    if (compsByKind.bajada.length === 0 && Number(r.bajadaARS) > 0) {
        faltantes.push('🏃 Bajaste $' + fmt(r.bajadaARS).replace('$', '') + ' pero no adjuntaste comprobante de bajada (transferencia).');
    }
    if (compsByKind.deposito.length === 0 && Number(r.depositsARS) > 0) {
        faltantes.push('📥 Hay depósitos por $' + fmt(r.depositsARS).replace('$', '') + ' sin foto adjunta.');
    }
    if (hasCvuData && cvuDiscrepancy < -1) {
        faltantes.push('💸 La cuenta tiene MENOS plata que la calculada — revisar todos los movimientos del día.');
    }
    if (Number(r.bajadaARS) > Number(c.totalABajar)) {
        faltantes.push('⚠️ Bajaste $' + fmt(r.bajadaARS - c.totalABajar).replace('$', '') + ' DE MÁS que el total a bajar — revisar el dato.');
    }

    // Sector label
    const secLabel = _sectorLabel(r.sector);

    // Modal
    let m = document.getElementById('clsAnalyzeModal');
    if (m) m.remove();
    m = document.createElement('div');
    m.id = 'clsAnalyzeModal';
    m.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:99999;display:flex;align-items:center;justify-content:center;padding:18px;overflow-y:auto;';
    m.onclick = (e) => { if (e.target === m) m.remove(); };

    let html = '<div style="background:linear-gradient(180deg,#16162a,#0c0c1a);border:1.5px solid rgba(155,48,255,0.45);border-radius:14px;max-width:920px;width:100%;max-height:90vh;overflow-y:auto;padding:18px;color:#fff;">';

    // Header
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid rgba(255,255,255,0.10);">';
    html += '<div>';
    html += '<div style="color:#c89bff;font-size:11px;font-weight:900;letter-spacing:1.5px;">🔍 ANÁLISIS DE CIERRE</div>';
    html += '<div style="color:#fff;font-size:17px;font-weight:900;margin-top:3px;">' + secLabel + ' · ' + escH(r.dateKey) + '</div>';
    html += '<div style="color:#888;font-size:11px;margin-top:2px;">';
    html += (r.status === 'confirmed' ? '✅ Confirmado' : '📝 Borrador');
    if (r.locked) html += ' · 🔒 Bloqueado';
    if (r.verifiedAt) html += ' · ✓ Verificado por ' + escH(r.verifiedBy || '?');
    html += '</div>';
    html += '</div>';
    html += '<button onclick="document.getElementById(\'clsAnalyzeModal\').remove()" style="background:rgba(255,80,80,0.18);border:1px solid rgba(255,80,80,0.50);color:#ff8080;width:34px;height:34px;border-radius:50%;font-size:18px;font-weight:900;cursor:pointer;">✕</button>';
    html += '</div>';

    // === 1. CÁLCULO PASO A PASO ===
    html += '<div style="background:rgba(0,0,0,0.30);border-radius:10px;padding:13px;margin-bottom:12px;">';
    html += '<div style="color:#c89bff;font-size:11px;font-weight:900;letter-spacing:1px;margin-bottom:9px;">🧮 CÁLCULO PASO A PASO</div>';
    html += '<div style="font-family:monospace;font-size:12.5px;line-height:1.8;color:#ddd;">';
    // VENTA = lo que está en el campo ventasARS (cash-out, alias venta).
    // El dueño definió que esta columna se llama VENTA y no se resta a
    // los depósitos.
    const ventaCalc = Number(r.ventasARS || 0);
    html += '<div>1. Σ Depósitos del día: <strong style="color:#aaffaa;">' + fmt(r.depositsARS) + '</strong> · base de la comisión</div>';
    html += '<div style="border-top:1px dashed rgba(255,255,255,0.15);padding-top:5px;margin-top:5px;">2. <strong>VENTA</strong> (cash-out a clientes): <strong style="color:#ffd0a0;font-size:13.5px;">' + fmt(ventaCalc) + '</strong></div>';
    html += '<div>3. Comisión banco (depósitos × ' + Number(r.bankMarginPercent || 0) + '%): <strong style="color:#ff8080;">-' + fmt(c.commission) + '</strong></div>';
    html += '<div>4. Gastos del día: <strong style="color:#ffaa66;">-' + fmt(c.gastos || 0) + '</strong></div>';
    html += '<div>5. Egresos (préstamos hechos): <strong style="color:#ff8080;">-' + fmt(c.egresos || 0) + '</strong></div>';
    html += '<div>6. Ingresos (préstamos recibidos): <strong style="color:#aaffaa;">+' + fmt(c.ingresos || 0) + '</strong></div>';
    const netoCalc = Number(c.neto != null ? c.neto : (ventaCalc - Number(c.commission||0) - Number(c.gastos||0) - Number(c.egresos||0) + Number(c.ingresos||0)));
    html += '<div style="border-top:1px dashed rgba(255,255,255,0.15);padding-top:5px;margin-top:5px;">7. <strong>NETO del día</strong> = venta − comisión − gastos − egresos + ingresos = <strong style="color:#c89bff;font-size:14px;">' + fmt(netoCalc) + '</strong></div>';
    html += '<div>8. Pendiente del día anterior (CVU 00 hs): <strong style="color:#ffaa66;">+' + fmt(r.pendienteAnteriorARS) + '</strong></div>';
    html += '<div style="border-top:1px dashed rgba(255,255,255,0.15);padding-top:5px;margin-top:5px;">9. <strong>TOTAL A BAJAR</strong> = neto + pend ant = <strong style="color:#fff;font-size:14px;">' + fmt(c.totalABajar) + '</strong></div>';
    html += '<div>10. Bajada REAL del día: <strong style="color:#aaffff;">-' + fmt(r.bajadaARS) + '</strong></div>';
    const pendCalc = Number(c.pendienteCalculado != null ? c.pendienteCalculado : Math.max(0, diff));
    const pendReal = Number(c.pendienteHoy || 0);
    const usingCvu = Number(c.cvuActual || 0) > 0;
    html += '<div style="border-top:1px dashed rgba(255,255,255,0.15);padding-top:5px;margin-top:5px;">11a. <strong>según cálculo</strong> (total a bajar − bajada) = <strong style="color:#aaa;font-size:13px;">' + fmt(pendCalc) + '</strong></div>';
    html += '<div>11b. <strong>CVU 00 hs real</strong> (lo que muestra el banco) = <strong style="color:#00d4ff;font-size:13px;">' + fmt(Number(c.cvuActual || 0)) + '</strong></div>';
    html += '<div style="border-top:1px dashed rgba(255,255,255,0.15);padding-top:5px;margin-top:5px;">12. <strong>PENDIENTE A BAJAR</strong> = <strong style="color:' + cuadreColor + ';font-size:14px;">' + fmt(pendReal) + '</strong> <span style="color:#888;font-size:10.5px;">' + (usingCvu ? '(tomado del CVU real)' : '(no se cargó CVU — se usa el calculado)') + '</span></div>';
    html += '<div style="color:#888;font-size:10.5px;margin-top:3px;">↪ Este monto arrastra al "CVU 00 hs día anterior" del próximo cierre.</div>';
    html += '</div>';
    html += '<div style="background:' + cuadreColor + '22;border:2px solid ' + cuadreColor + ';border-radius:8px;padding:10px;margin-top:10px;text-align:center;color:' + cuadreColor + ';font-weight:900;font-size:14px;">' + cuadreText + '</div>';

    // Fotos relacionadas con el cuadre: bajada (transferencias) + banco-pendiente.
    // Permite ver el respaldo directamente desde el alert sin scrollear.
    const bajadaPhotos = (r.comprobantes || []).filter(c => c.kind === 'bajada');
    const bankPhotos = (r.comprobantes || []).filter(c => c.kind === 'pendiente_bank');
    if (bajadaPhotos.length || bankPhotos.length) {
        html += '<div style="margin-top:10px;padding-top:10px;border-top:1px dashed rgba(255,255,255,0.10);">';
        html += '<div style="color:#aaa;font-size:10.5px;font-weight:700;margin-bottom:6px;">📎 Comprobantes del cuadre:</div>';
        if (bajadaPhotos.length) {
            html += '<div style="margin-bottom:7px;"><div style="color:#aaffff;font-size:10px;font-weight:700;margin-bottom:4px;">🏃 Bajada (transferencias) — ' + bajadaPhotos.length + ' foto(s)</div>';
            html += '<div style="display:flex;flex-wrap:wrap;gap:5px;">';
            bajadaPhotos.forEach((cp, i) => { html += _photoThumb(cp.url, '🏃 Bajada #' + (i + 1), '#aaffff'); });
            html += '</div></div>';
        }
        if (bankPhotos.length) {
            html += '<div><div style="color:#ffaa66;font-size:10px;font-weight:700;margin-bottom:4px;">🏦 Banco-pendiente — ' + bankPhotos.length + ' foto(s)</div>';
            html += '<div style="display:flex;flex-wrap:wrap;gap:5px;">';
            bankPhotos.forEach((cp, i) => { html += _photoThumb(cp.url, '🏦 Banco-Pend #' + (i + 1), '#ffaa66'); });
            html += '</div></div>';
        }
        html += '</div>';
    }
    html += '</div>';

    // === 2. CONTROL CVU + MOVIMIENTOS EXTRA ===
    if (hasCvuData) {
        html += '<div style="background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.25);border-radius:10px;padding:13px;margin-bottom:12px;">';
        html += '<div style="color:#00d4ff;font-size:11px;font-weight:900;letter-spacing:1px;margin-bottom:9px;">🏦 CONTROL CVU + MOVIMIENTOS EXTRA</div>';
        html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:7px;margin-bottom:10px;">';
        const ingPhotos = (r.comprobantes || []).filter(c2 => c2.kind === 'ingreso');
        const egrPhotos = (r.comprobantes || []).filter(c2 => c2.kind === 'egreso');
        const gasPhotos = (r.comprobantes || []).filter(c2 => c2.kind === 'gasto');
        html += '<div style="background:rgba(0,0,0,0.30);padding:7px 9px;border-radius:6px;"><div style="color:#888;font-size:10px;">📥 Ingresos (préstamos recibidos)</div><div style="color:#aaffaa;font-weight:800;">+' + fmt(c.ingresos || 0) + '</div>';
        if (r.ingresosNote) html += '<div style="color:#aaa;font-size:10px;margin-top:3px;font-style:italic;">"' + escH(r.ingresosNote) + '"</div>';
        if (ingPhotos.length) { html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:5px;">'; ingPhotos.forEach((cp, i) => { html += _photoThumb(cp.url, '📥 Ingreso #' + (i + 1), '#aaffaa'); }); html += '</div>'; }
        html += '</div>';
        html += '<div style="background:rgba(0,0,0,0.30);padding:7px 9px;border-radius:6px;"><div style="color:#888;font-size:10px;">📤 Egresos (préstamos hechos)</div><div style="color:#ff8080;font-weight:800;">-' + fmt(c.egresos || 0) + '</div>';
        if (r.egresosNote) html += '<div style="color:#aaa;font-size:10px;margin-top:3px;font-style:italic;">"' + escH(r.egresosNote) + '"</div>';
        if (egrPhotos.length) { html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:5px;">'; egrPhotos.forEach((cp, i) => { html += _photoThumb(cp.url, '📤 Egreso #' + (i + 1), '#ff8080'); }); html += '</div>'; }
        html += '</div>';
        html += '<div style="background:rgba(0,0,0,0.30);padding:7px 9px;border-radius:6px;"><div style="color:#888;font-size:10px;">🧾 Gastos del día</div><div style="color:#ffaa66;font-weight:800;">-' + fmt(c.gastos || 0) + '</div>';
        if (r.gastosNote) html += '<div style="color:#aaa;font-size:10px;margin-top:3px;font-style:italic;">"' + escH(r.gastosNote) + '"</div>';
        if (gasPhotos.length) { html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-top:5px;">'; gasPhotos.forEach((cp, i) => { html += _photoThumb(cp.url, '🧾 Gasto #' + (i + 1), '#ffaa66'); }); html += '</div>'; }
        html += '</div>';
        html += '</div>';
        html += '<div style="font-family:monospace;font-size:12px;line-height:1.7;color:#ddd;background:rgba(0,0,0,0.25);padding:9px;border-radius:7px;margin-bottom:8px;">';
        const saldoIni = Number(r.saldoInicialARS || 0);
        html += '<div>CVU esperado = Pendiente a bajar + Saldo inicial</div>';
        html += '<div style="margin-top:4px;">             = ' + fmt(c.pendienteHoy || 0) + ' + ' + fmt(saldoIni) + '</div>';
        html += '<div style="margin-top:4px;">             = <strong style="color:#fff;font-size:13px;">' + fmt(cvuExpected) + '</strong></div>';
        html += '<div style="color:#888;font-size:10.5px;">(Gastos, egresos e ingresos ya están descontados dentro del pendiente vía Neto)</div>';
        html += '<div style="margin-top:5px;border-top:1px dashed rgba(255,255,255,0.10);padding-top:5px;">CVU real cargado: <strong style="color:#00d4ff;">' + fmt(cvuActual) + '</strong></div>';
        html += '<div>Diferencia (CVU real − esperado): <strong style="color:' + cvuColor + ';">' + (cvuDiscrepancy >= 0 ? '+' : '') + fmt(cvuDiscrepancy) + '</strong></div>';
        html += '</div>';
        html += '<div style="background:' + cvuColor + '22;border:2px solid ' + cvuColor + ';border-radius:7px;padding:9px;text-align:center;color:' + cvuColor + ';font-weight:900;font-size:13px;">' + cvuText + '</div>';
        html += '</div>';
    }

    // === 3. CONTRIBUCIÓN POR EQUIPO (los 3 sectores con teams) ===
    if (Array.isArray(r.teams) && r.teams.length > 0) {
        html += '<div style="background:rgba(255,215,0,0.04);border:1px solid rgba(255,215,0,0.25);border-radius:10px;padding:13px;margin-bottom:12px;">';
        html += '<div style="color:#ffd700;font-size:11px;font-weight:900;letter-spacing:1px;margin-bottom:9px;">🎯 CONTRIBUCIÓN POR EQUIPO</div>';
        html += '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:11.5px;">';
        html += '<thead><tr style="color:#888;text-align:left;border-bottom:1px solid rgba(255,255,255,0.15);">';
        html += '<th style="padding:5px 8px;">#</th><th style="padding:5px 8px;">Equipo</th>';
        html += '<th style="padding:5px 8px;text-align:right;">Depósito $</th><th style="padding:5px 8px;text-align:right;">Depós #</th>';
        html += '<th style="padding:5px 8px;text-align:right;" title="Venta $ del equipo (cash-out a clientes)">Venta $</th>';
        html += '<th style="padding:5px 8px;text-align:right;">Bon $</th><th style="padding:5px 8px;text-align:right;">Bon #</th>';
        html += '<th style="padding:5px 8px;text-align:right;">Desc #</th>';
        html += '</tr></thead><tbody>';
        const teamsSorted = [...r.teams].sort((a, b) => (a.slot || 0) - (b.slot || 0));
        for (const t of teamsSorted) {
            html += '<tr style="border-bottom:1px solid rgba(255,255,255,0.05);">';
            html += '<td style="padding:5px 8px;color:#ffd700;font-weight:900;">' + ((t.slot || 0) + 1) + '</td>';
            html += '<td style="padding:5px 8px;color:#fff;">' + escH(t.name || '(sin nombre)') + '</td>';
            html += '<td style="padding:5px 8px;text-align:right;color:#aaffaa;">' + fmt(t.depositsARS) + '</td>';
            html += '<td style="padding:5px 8px;text-align:right;color:#c89bff;">' + Number(t.depositsCount || 0) + '</td>';
            html += '<td style="padding:5px 8px;text-align:right;color:#ffd0a0;">' + fmt(t.ventasARS) + '</td>';
            html += '<td style="padding:5px 8px;text-align:right;color:#ffd700;">' + fmt(t.bonusARS) + '</td>';
            html += '<td style="padding:5px 8px;text-align:right;color:#c89bff;">' + Number(t.bonusCount || 0) + '</td>';
            html += '<td style="padding:5px 8px;text-align:right;color:#c89bff;">' + Number(t.withdrawalsCount || 0) + '</td>';
            html += '</tr>';
        }
        // Totales
        const ttDep = teamsSorted.reduce((a, t) => a + Number(t.depositsARS || 0), 0);
        const ttCarg = teamsSorted.reduce((a, t) => a + Number(t.depositsCount || 0), 0);
        const ttVen = teamsSorted.reduce((a, t) => a + Number(t.ventasARS || 0), 0);
        const ttBon = teamsSorted.reduce((a, t) => a + Number(t.bonusARS || 0), 0);
        const ttBonN = teamsSorted.reduce((a, t) => a + Number(t.bonusCount || 0), 0);
        const ttDesc = teamsSorted.reduce((a, t) => a + Number(t.withdrawalsCount || 0), 0);
        html += '<tr style="border-top:2px solid rgba(255,255,255,0.20);font-weight:900;">';
        html += '<td colspan="2" style="padding:6px 8px;color:#fff;">TOTAL</td>';
        html += '<td style="padding:6px 8px;text-align:right;color:#aaffaa;">' + fmt(ttDep) + '</td>';
        html += '<td style="padding:6px 8px;text-align:right;color:#c89bff;">' + ttCarg + '</td>';
        html += '<td style="padding:6px 8px;text-align:right;color:#ffd0a0;">' + fmt(ttVen) + '</td>';
        html += '<td style="padding:6px 8px;text-align:right;color:#ffd700;">' + fmt(ttBon) + '</td>';
        html += '<td style="padding:6px 8px;text-align:right;color:#c89bff;">' + ttBonN + '</td>';
        html += '<td style="padding:6px 8px;text-align:right;color:#c89bff;">' + ttDesc + '</td>';
        html += '</tr>';
        html += '</tbody></table></div>';
        html += '</div>';
    }

    // === 4. COMPROBANTES con thumbnails clicables (lightbox) ===
    // Cache global con todas las URLs del cierre para que el lightbox pueda
    // navegar entre fotos del mismo cierre.
    window._clsAnalyzePhotos = comps.filter(c => c && c.url).map(c => c.url);

    // Recolectar TODOS los kinds — incluye los nuevos (ingreso/egreso/gasto).
    const allKinds = ['deposito','bajada','pendiente_bank','ingreso','egreso','gasto','bonificacion','venta'];
    const kindLabels = {
        deposito: '📥 Depósito (cargas+venta+tx)',
        venta: '🛒 Venta',
        bonificacion: '🎁 Bonificación',
        bajada: '🏃 Bajada (transferencias)',
        pendiente_bank: '🏦 Banco — pendiente',
        ingreso: '📥 Ingreso (préstamo recibido)',
        egreso: '📤 Egreso (préstamo hecho)',
        gasto: '🧾 Gasto'
    };
    const kindColors = {
        deposito: '#aaffaa', venta: '#ffd0a0', bonificacion: '#ffd700',
        bajada: '#aaffff', pendiente_bank: '#ffaa66',
        ingreso: '#aaffaa', egreso: '#ff8080', gasto: '#ffaa66'
    };

    html += '<div style="background:rgba(0,0,0,0.30);border-radius:10px;padding:13px;margin-bottom:12px;">';
    html += '<div style="color:#aaffff;font-size:11px;font-weight:900;letter-spacing:1px;margin-bottom:9px;">📎 COMPROBANTES ADJUNTOS (' + comps.length + ')</div>';

    // Re-agregar kinds nuevos al filtro
    for (const k of allKinds) {
        compsByKind[k] = comps.filter(p => p.kind === k);
    }
    for (const k of allKinds) {
        const list = compsByKind[k] || [];
        const color = kindColors[k];
        html += '<div style="padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.05);">';
        html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:' + (list.length > 0 ? '6px' : '0') + ';">';
        html += '<span style="color:' + color + ';font-weight:800;font-size:11px;min-width:200px;">' + kindLabels[k] + '</span>';
        html += '<span style="color:#fff;font-weight:700;font-size:11px;">' + list.length + (list.length === 0 ? ' ❌' : ' ✓') + '</span>';
        html += '</div>';
        if (list.length > 0) {
            html += '<div style="display:flex;flex-wrap:wrap;gap:6px;">';
            list.forEach((cp, i) => {
                html += _photoThumb(cp.url, kindLabels[k] + ' · #' + (i + 1), color);
            });
            html += '</div>';
        }
        html += '</div>';
    }
    html += '</div>';

    // === 5. DIAGNÓSTICO FINAL ===
    html += '<div style="background:' + (faltantes.length > 0 ? 'rgba(255,80,80,0.07)' : 'rgba(102,255,102,0.07)') + ';border:1.5px solid ' + (faltantes.length > 0 ? '#ff5050' : '#66ff66') + ';border-radius:10px;padding:13px;">';
    html += '<div style="color:' + (faltantes.length > 0 ? '#ff8080' : '#aaffaa') + ';font-size:12px;font-weight:900;letter-spacing:1px;margin-bottom:9px;">';
    html += faltantes.length > 0 ? '⚠️ DIAGNÓSTICO — ' + faltantes.length + ' COSA(S) PARA REVISAR' : '✅ DIAGNÓSTICO — TODO OK';
    html += '</div>';
    if (faltantes.length > 0) {
        html += '<ul style="margin:0;padding-left:18px;color:#ddd;font-size:11.5px;line-height:1.7;">';
        for (const f of faltantes) html += '<li style="margin-bottom:4px;">' + f + '</li>';
        html += '</ul>';
    } else {
        html += '<div style="color:#aaffaa;font-size:11.5px;">El cierre está completo y todos los datos cuadran. Listo para confirmar (si aún no lo está).</div>';
    }
    html += '</div>';

    html += '</div>'; // /modal content
    m.innerHTML = html;
    document.body.appendChild(m);
}

// Sección "Movimientos extra del día": préstamos (ingresos/egresos),
// gastos, y CVU control a las 00 hs. Cada uno con detalle (note).
// Aparece en TODOS los sectores (Buffalo/Ganamos/Publicidad).
function _renderClosingExtras(rid, row, locked) {
    const disabledAttr = locked ? 'disabled' : '';
    const inputStyle = 'background:rgba(0,0,0,0.50);border:1px solid rgba(255,255,255,0.12);color:#fff;padding:6px 9px;border-radius:6px;font-size:12.5px;font-weight:700;width:100%;box-sizing:border-box;';
    const noteStyle = 'background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#ddd;padding:5px 8px;border-radius:5px;font-size:11px;width:100%;box-sizing:border-box;margin-top:4px;';
    const r = row || {};
    let html = '<div style="background:rgba(255,170,102,0.05);border:1.5px solid rgba(255,170,102,0.35);border-radius:9px;padding:11px;margin-bottom:11px;">';
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">';
    html += '<div style="color:#ffaa66;font-weight:900;font-size:11px;letter-spacing:1px;">💸 MOVIMIENTOS EXTRA DEL DÍA</div>';
    html += '<div style="color:#888;font-size:10px;">préstamos · gastos · saldo CVU</div>';
    html += '</div>';

    // 3 columnas: INGRESOS · EGRESOS · GASTOS (con detalle abajo c/u)
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:8px;margin-bottom:9px;">';

    // INGRESOS = préstamos que NOS HICIERON (entró plata extra)
    html += '<div style="background:rgba(102,255,102,0.06);border:1px solid rgba(102,255,102,0.25);border-radius:7px;padding:8px;">';
    html += '<label style="color:#aaffaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;font-weight:800;">📥 Ingresos / préstamos recibidos $</label>';
    html += '<input type="number" id="cls_' + rid + '_ingresosARS" value="' + (Number(r.ingresosARS) || 0) + '" min="0" step="1000" style="' + inputStyle + 'border-color:rgba(102,255,102,0.35);" ' + disabledAttr + '>';
    html += '<input type="text" id="cls_' + rid + '_ingresosNote" value="' + escapeHtml(r.ingresosNote || '') + '" placeholder="Detalle (de quién, motivo…)" maxlength="300" style="' + noteStyle + '" ' + disabledAttr + '>';
    html += '<div style="margin-top:5px;display:flex;gap:4px;flex-wrap:wrap;align-items:center;">' + _inlineUploadBtn(rid, row, 'ingreso', null, '📷 Foto ingreso', locked) + _inlineUploadList(rid, row, 'ingreso', null, locked) + '</div>';
    html += '</div>';

    // EGRESOS = préstamos que NOSOTROS HICIMOS (sale plata, vuelve después)
    html += '<div style="background:rgba(255,128,128,0.06);border:1px solid rgba(255,128,128,0.25);border-radius:7px;padding:8px;">';
    html += '<label style="color:#ff8080;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;font-weight:800;">📤 Egresos / préstamos hechos $</label>';
    html += '<input type="number" id="cls_' + rid + '_egresosARS" value="' + (Number(r.egresosARS) || 0) + '" min="0" step="1000" style="' + inputStyle + 'border-color:rgba(255,128,128,0.35);" ' + disabledAttr + '>';
    html += '<input type="text" id="cls_' + rid + '_egresosNote" value="' + escapeHtml(r.egresosNote || '') + '" placeholder="Detalle (a quién, motivo…)" maxlength="300" style="' + noteStyle + '" ' + disabledAttr + '>';
    html += '<div style="margin-top:5px;display:flex;gap:4px;flex-wrap:wrap;align-items:center;">' + _inlineUploadBtn(rid, row, 'egreso', null, '📷 Foto egreso', locked) + _inlineUploadList(rid, row, 'egreso', null, locked) + '</div>';
    html += '</div>';

    // GASTOS = gastos consumidos del día (no vuelven: insumos, sueldos, etc.)
    html += '<div style="background:rgba(255,170,102,0.06);border:1px solid rgba(255,170,102,0.25);border-radius:7px;padding:8px;">';
    html += '<label style="color:#ffaa66;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;font-weight:800;">🧾 Gastos del día $</label>';
    html += '<input type="number" id="cls_' + rid + '_gastosARS" value="' + (Number(r.gastosARS) || 0) + '" min="0" step="100" style="' + inputStyle + 'border-color:rgba(255,170,102,0.35);" ' + disabledAttr + '>';
    html += '<input type="text" id="cls_' + rid + '_gastosNote" value="' + escapeHtml(r.gastosNote || '') + '" placeholder="Detalle (en qué se gastó…)" maxlength="300" style="' + noteStyle + '" ' + disabledAttr + '>';
    html += '<div style="margin-top:5px;display:flex;gap:4px;flex-wrap:wrap;align-items:center;">' + _inlineUploadBtn(rid, row, 'gasto', null, '📷 Foto gasto', locked) + _inlineUploadList(rid, row, 'gasto', null, locked) + '</div>';
    html += '</div>';

    html += '</div>';

    // CVU a las 00 hs (control)
    html += '<div style="background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.30);border-radius:7px;padding:8px;display:grid;grid-template-columns:1fr 2fr;gap:8px;align-items:start;">';
    html += '<div>';
    html += '<label style="color:#00d4ff;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;font-weight:800;">🏦 Saldo CVU a las 00 hs $</label>';
    html += '<input type="number" id="cls_' + rid + '_cvuMidnightARS" value="' + (Number(r.cvuMidnightARS) || 0) + '" min="0" step="1000" style="' + inputStyle + 'border-color:rgba(0,212,255,0.40);" ' + disabledAttr + '>';
    html += '</div>';
    html += '<div style="background:rgba(0,0,0,0.30);border-radius:6px;padding:7px 9px;font-size:10.5px;color:#aaa;">';
    html += '<strong style="color:#00d4ff;">¿Para qué?</strong> Anotá la plata REAL que hay en el CVU/banco al cerrar el día. ';
    html += 'El sistema compara con el saldo esperado (depósitos + ingresos − comisión − bajada − bonus − egresos − gastos). ';
    html += 'Si <strong style="color:#ff8080;">hay menos</strong> = problema, falta plata. Si hay más = revisar movimientos sin registrar.';
    html += '</div>';
    html += '</div>';

    html += '</div>';
    return html;
}

// Sector con hasta 10 equipos (Buffalo o Ganamos). Una entry por día.
// Generales arriba (% banco + pendiente a completar + depósitos totales
// y transacciones totales COMPUTADOS de los equipos). Abajo los equipos
// con sus campos individuales.
// Neto = Σ(ventas) − Σ(cargas × banco%). Bonificaciones no afectan neto.
function _renderTeamSectorEntry(sec, date, row) {
    const exists = !!row;
    const locked = row && row.locked;
    const confirmed = row && row.status === 'confirmed';
    const c = (row && row.computed) || {};
    const rid = row ? row.id : ('new_' + sec.key + '_main');
    // Para cierres NUEVOS: buscamos el cierre más reciente del MISMO sector
    // que tenga nombres de equipo y los usamos como default. Editable después.
    const recentNames = _latestTeamNames(sec.key, row ? row.id : null);
    let teams;
    if (row && Array.isArray(row.teams) && row.teams.length > 0) {
        // Usar los equipos cargados y completar hasta BUFFALO_TEAM_SLOTS
        // (cubre cierres viejos que se guardaron con menos equipos).
        teams = row.teams.slice();
        for (let i = teams.length; i < BUFFALO_TEAM_SLOTS; i++) {
            teams.push({ slot: i, name: recentNames[i] || '', depositsARS: 0, depositsCount: 0, ventasARS: 0, bonusARS: 0, bonusCount: 0, withdrawalsCount: 0 });
        }
    } else {
        teams = Array.from({ length: BUFFALO_TEAM_SLOTS }, (_, i) => ({ slot: i, name: recentNames[i] || '', depositsARS: 0, depositsCount: 0, ventasARS: 0, bonusARS: 0, bonusCount: 0, withdrawalsCount: 0 }));
        // Migración legacy: cierres viejos de publicidad/ganamos sin teams[]
        // tenían los totales guardados en el row top-level. Los cargamos en
        // el slot 1 para no perder data si el dueño abre y guarda sin tocar.
        if (row && (Number(row.depositsARS) > 0 || Number(row.ventasARS) > 0 || Number(row.bonusARS) > 0)) {
            teams[0] = {
                slot: 0,
                name: row.teamName || teams[0].name || '(legacy)',
                depositsARS: Number(row.depositsARS || 0),
                depositsCount: 0,
                ventasARS: Number(row.ventasARS || 0),
                bonusARS: Number(row.bonusARS || 0),
                bonusCount: Number(row.bonusCount || 0),
                withdrawalsCount: Number(row.withdrawalsCount || 0)
            };
        }
    }

    const inputStyle = 'background:rgba(0,0,0,0.50);border:1px solid rgba(255,255,255,0.12);color:#fff;padding:6px 9px;border-radius:6px;font-size:12.5px;font-weight:700;width:100%;box-sizing:border-box;';
    const disabledAttr = locked ? 'disabled' : '';

    let html = '<div data-cls-id="' + rid + '">';

    // Status badge
    html += '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">';
    html += '<div style="color:#aaa;font-size:11px;letter-spacing:0.5px;">Cierre del ' + escapeHtml(date) + '</div>';
    html += (locked ? '<span style="color:#ff8080;font-size:10px;font-weight:800;">🔒 BLOQUEADO 24h</span>' : (confirmed ? '<span style="color:#aaffaa;font-size:10px;font-weight:800;">✅ CONFIRMADO</span>' : '<span style="color:#888;font-size:10px;">📝 BORRADOR</span>'));
    html += '</div>';

    // === Preview en vivo (se rellena por closingsRecompute) ===
    html += '<div id="cls_' + rid + '_preview" style="margin-bottom:11px;"></div>';

    // Computed (suma de los equipos).
    // `sumVentas` = total cash-outs (lo que pagamos a los ganadores) —
    //               guardado en el field ventasARS. El dueño llama a esto
    //               VENTA en la UI.
    const sumDeposits = teams.reduce((a, t) => a + Number(t.depositsARS || 0), 0);
    const sumVentas = teams.reduce((a, t) => a + Number(t.ventasARS || 0), 0);
    const sumTransactions = teams.reduce((a, t) => a + Number(t.depositsCount || 0) + Number(t.withdrawalsCount || 0) + Number(t.bonusCount || 0), 0);

    // === GENERALES ===
    html += '<div style="background:rgba(0,212,255,0.06);border:1.5px solid rgba(0,212,255,0.35);border-radius:9px;padding:11px;margin-bottom:11px;">';
    html += '<div style="color:#00d4ff;font-weight:900;font-size:11px;letter-spacing:1px;margin-bottom:8px;">🤝 GENERAL (uno para los 7 equipos)</div>';
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:7px;">';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🏦 % Banco (sobre depósitos)</label><input type="number" id="cls_' + rid + '_bankMarginPercent" value="' + (row ? row.bankMarginPercent : 0) + '" min="0" max="100" step="0.1" style="' + inputStyle + '" ' + disabledAttr + '></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">💰 Depósitos totales</label><div style="' + inputStyle + 'background:rgba(0,0,0,0.30);color:#aaffaa;cursor:not-allowed;">' + _closingFmt(sumDeposits) + '</div><div style="color:#666;font-size:9.5px;margin-top:2px;">∑ depósito$ de los 7 · base de la comisión</div></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🛒 VENTA (cash-out)</label><div style="' + inputStyle + 'background:rgba(0,0,0,0.30);color:#ffd0a0;cursor:not-allowed;" title="Σ Ventas (descargas) de los 7 equipos — auto desde los inputs por equipo">' + _closingFmt(sumVentas) + '</div><div style="color:#666;font-size:9.5px;margin-top:2px;">∑ venta$ de los 7 — lo pagado a clientes</div></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🏃 Bajada real $</label><input type="number" id="cls_' + rid + '_bajadaARS" value="' + (row ? row.bajadaARS : 0) + '" min="0" step="1000" style="' + inputStyle + '" ' + disabledAttr + '>';
    html += '<div style="margin-top:4px;display:flex;gap:4px;flex-wrap:wrap;align-items:center;">' + _inlineUploadBtn(rid, row, 'bajada', null, '📷 Foto bajada', locked) + _inlineUploadList(rid, row, 'bajada', null, locked) + '</div>';
    html += '<div style="color:#666;font-size:9px;margin-top:2px;">hasta 10 fotos (varias transferencias)</div></div>';
    // CVU 00 hs del día anterior — comportamiento:
    //   - Si el cierre YA existe → usar el valor guardado, READ-ONLY.
    //   - Si es NUEVO y hay cierre del día anterior → autocompletar con su
    //     cvuMidnightARS y READ-ONLY (arrastre del CVU REAL del banco).
    //   - Si es NUEVO y NO hay día anterior (primer cierre del sector) →
    //     editable para que el owner cargue manualmente.
    // Antes se usaba el "pendienteHoy" calculado pero eso siempre arrastraba
    // diferencias contra la realidad bancaria. Ahora arrastra el CVU 00 hs
    // del día previo — la cifra REAL que muestra el banco al cierre del día.
    const prevExists = !!(_closingsRowsCache || []).find(rr => rr.dateKey === _prevDateKey(date) && rr.sector === sec.key);
    const pendAntAuto = row
        ? Number(row.pendienteAnteriorARS || 0)
        : _autoPendienteAnterior(date, sec.key);
    // El dueño pidió que se pueda editar SIEMPRE (antes era readonly
    // cuando había arrastre del día anterior). Si lo dejan como vino del
    // auto, listo; si lo quieren pisar, también.
    const pendAntStyle = inputStyle + 'border-color:rgba(0,212,255,0.40);';
    const pendAntHint = (!row && !prevExists)
        ? 'PRIMER CIERRE · cargá manual el CVU al arrancar'
        : 'arrastre auto del día anterior · editable si querés corregir';
    const pendAntLabel = '🏦 CVU 00 hs día anterior';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">' + pendAntLabel + '</label><input type="number" id="cls_' + rid + '_pendienteAnteriorARS" value="' + pendAntAuto + '" step="1000" style="' + pendAntStyle + '" ' + (locked ? 'disabled' : '') + '>';
    html += '<div style="margin-top:4px;display:flex;gap:4px;flex-wrap:wrap;align-items:center;">' + _inlineUploadBtn(rid, row, 'pendiente_bank', null, '🏦 Foto banco', locked) + _inlineUploadList(rid, row, 'pendiente_bank', null, locked) + '</div>';
    html += '<div style="color:#666;font-size:9px;margin-top:2px;">' + pendAntHint + '</div></div>';
    // Saldo inicial — REMOVIDO del flujo. Se mantienen los campos en el
    // payload por backwards-compat (cierres viejos), pero ya no se muestran.
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🔢 Transacc. totales</label><div style="' + inputStyle + 'background:rgba(0,0,0,0.30);color:#c89bff;cursor:not-allowed;">' + sumTransactions.toLocaleString('es-AR') + '</div><div style="color:#666;font-size:9.5px;margin-top:2px;">∑ depósito# + descargas# + bonos#</div></div>';
    html += '</div>';
    html += '</div>';

    // === MOVIMIENTOS EXTRA (préstamos + gastos + CVU control) ===
    html += _renderClosingExtras(rid, row, locked);

    // === EQUIPOS (individual) ===
    html += '<div style="background:rgba(255,215,0,0.04);border:1.5px solid rgba(255,215,0,0.35);border-radius:9px;padding:11px;margin-bottom:11px;">';
    html += '<div style="color:#ffd700;font-weight:900;font-size:11px;letter-spacing:1px;margin-bottom:8px;">🎯 POR EQUIPO (individual cada uno)</div>';
    for (let i = 0; i < BUFFALO_TEAM_SLOTS; i++) {
        const t = teams[i] || { slot: i, name: '', depositsARS: 0, depositsCount: 0, ventasARS: 0, bonusARS: 0, bonusCount: 0, withdrawalsCount: 0 };
        html += '<div style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.06);border-radius:8px;padding:8px;margin-bottom:6px;">';
        // Header: número + nombre del equipo + botón de foto
        html += '<div style="display:flex;align-items:center;gap:7px;margin-bottom:7px;flex-wrap:wrap;">';
        html += '<div style="background:#ffd700;color:#000;font-weight:900;font-size:11px;width:22px;height:22px;border-radius:50%;display:flex;align-items:center;justify-content:center;">' + (i + 1) + '</div>';
        html += '<input type="text" data-buffalo-team="' + i + '" data-field="name" value="' + escapeHtml(t.name) + '" placeholder="Nombre equipo ' + (i + 1) + '" style="flex:1;min-width:120px;background:rgba(0,0,0,0.45);border:1px solid rgba(255,255,255,0.15);color:#fff;padding:4px 8px;border-radius:5px;font-size:12px;font-weight:700;" ' + disabledAttr + '>';
        // Botón foto + lista de adjuntas para ESTE equipo (kind='deposito')
        html += _inlineUploadBtn(rid, row, 'deposito', i, '📷 Foto (depósito+venta+tx)', locked);
        html += _inlineUploadList(rid, row, 'deposito', i, locked);
        html += '</div>';

        // UNA SOLA FILA: 3 montos ($) + 3 contadores (#) — counts compactos.
        // Desktop: una línea horizontal. Mobile: wrap.
        const countInputStyle = inputStyle + 'font-size:11.5px;padding:4px 6px;text-align:center;';
        const moneyInputStyle = inputStyle + 'font-size:11.5px;padding:4px 8px;';
        html += '<div style="display:grid;grid-template-columns:1.6fr 1.6fr 1.6fr 1fr 1fr 1fr;gap:5px;align-items:end;">';
        html += '<div><label style="color:#aaffaa;font-size:9.5px;text-transform:uppercase;font-weight:700;">💰 Depósito $</label><input type="number" data-buffalo-team="' + i + '" data-field="depositsARS" value="' + (t.depositsARS || 0) + '" min="0" step="1000" style="' + moneyInputStyle + 'border-color:rgba(102,255,102,0.30);" ' + disabledAttr + '></div>';
        html += '<div><label style="color:#ffd0a0;font-size:9.5px;text-transform:uppercase;font-weight:700;" title="VENTA del equipo (cash-out a clientes). Puede ser NEGATIVA si la operatoria del día cerró perdiendo.">🛒 Venta $</label><input type="number" data-buffalo-team="' + i + '" data-field="ventasARS" value="' + (t.ventasARS || 0) + '" step="1000" style="' + moneyInputStyle + 'border-color:rgba(255,208,160,0.30);" ' + disabledAttr + '></div>';
        html += '<div><label style="color:#ffd700;font-size:9.5px;text-transform:uppercase;font-weight:700;">🎁 Bonif. $</label><input type="number" data-buffalo-team="' + i + '" data-field="bonusARS" value="' + (t.bonusARS || 0) + '" min="0" step="100" style="' + moneyInputStyle + 'border-color:rgba(255,215,0,0.30);" ' + disabledAttr + '></div>';
        html += '<div><label style="color:#c89bff;font-size:9.5px;text-transform:uppercase;font-weight:700;" title="Cantidad de depósitos (operaciones de carga)">📥 Depós#</label><input type="number" data-buffalo-team="' + i + '" data-field="depositsCount" value="' + (t.depositsCount || 0) + '" min="0" max="9999" step="1" maxlength="4" style="' + countInputStyle + 'border-color:rgba(155,48,255,0.30);" ' + disabledAttr + '></div>';
        html += '<div><label style="color:#c89bff;font-size:9.5px;text-transform:uppercase;font-weight:700;" title="Cantidad de descargas (operaciones de retiro)">📤 Desc#</label><input type="number" data-buffalo-team="' + i + '" data-field="withdrawalsCount" value="' + (t.withdrawalsCount || 0) + '" min="0" max="9999" step="1" maxlength="4" style="' + countInputStyle + 'border-color:rgba(155,48,255,0.30);" ' + disabledAttr + '></div>';
        html += '<div><label style="color:#c89bff;font-size:9.5px;text-transform:uppercase;font-weight:700;" title="Cantidad de bonificaciones entregadas">🎁 Bon#</label><input type="number" data-buffalo-team="' + i + '" data-field="bonusCount" value="' + (t.bonusCount || 0) + '" min="0" max="9999" step="1" maxlength="4" style="' + countInputStyle + 'border-color:rgba(155,48,255,0.30);" ' + disabledAttr + '></div>';
        html += '</div>';
        html += '</div>';
    }
    html += '</div>';

    // Computed inline + análisis
    if (exists) {
        const diff = c.diff || 0;
        const netoColor = diff === 0 ? '#aaffaa' : (diff > 0 ? '#ff8080' : '#66ff66');
        const netoLabel = diff === 0 ? '✅ CIERRE EN 0' : (diff > 0 ? '⏳ FALTAN ' + _closingFmt(diff) : '💚 SOBRA ' + _closingFmt(-diff));
        html += '<div style="background:rgba(0,0,0,0.30);border-radius:6px;padding:9px 11px;margin-bottom:8px;font-size:11.5px;">';
        html += '<div style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:5px;">';
        html += '<span style="color:#aaa;">Σ Depósito: <strong style="color:#aaffaa;">' + _closingFmt(row.depositsARS) + '</strong></span>';
        html += '<span style="color:#aaa;">Σ Venta: <strong style="color:#ffd0a0;">' + _closingFmt(row.ventasARS) + '</strong></span>';
        html += '<span style="color:#aaa;">Comisión banco (sobre depósitos): <strong style="color:#ff8080;">-' + _closingFmt(c.commission) + '</strong></span>';
        html += '<span style="color:#aaa;">A bajar total: <strong>' + _closingFmt(c.totalABajar) + '</strong></span>';
        html += '<span style="color:#aaa;">Bajada real: <strong style="color:#aaffff;">' + _closingFmt(row.bajadaARS) + '</strong></span>';
        html += '<span style="color:#aaa;">Σ Bonificaciones (dato): <strong style="color:#ffd700;">' + _closingFmt(row.bonusARS) + '</strong></span>';
        html += '</div>';
        html += '<div style="font-size:14px;font-weight:900;color:' + netoColor + ';text-align:center;padding:6px;border-top:1px dashed rgba(255,255,255,0.10);margin-top:4px;">' + netoLabel + '</div>';
        html += '</div>';

        html += _renderComprobantesPanel(row, rid, locked, c);
        if (row.editHistory && row.editHistory.length > 0) {
            html += '<div style="font-size:10.5px;color:#888;margin-bottom:6px;">📝 Editado ' + row.editHistory.length + ' veces · último por <strong>' + escapeHtml(row.editHistory[row.editHistory.length - 1].editedBy || '?') + '</strong></div>';
        }
    }

    // Action buttons
    html += '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">';
    if (!locked) {
        html += '<button type="button" onclick="saveTeamSectorClosing(\'' + rid + '\', \'' + date + '\', \'' + sec.key + '\')" style="background:rgba(102,255,102,0.15);border:1px solid rgba(102,255,102,0.45);color:#aaffaa;padding:6px 12px;border-radius:6px;font-weight:800;font-size:11.5px;cursor:pointer;">' + (exists ? '💾 GUARDAR CAMBIOS' : '💾 CREAR CIERRE') + '</button>';
        if (exists && !confirmed) {
            html += '<button type="button" onclick="confirmClosing(\'' + rid + '\')" style="background:linear-gradient(135deg,#ffd700,#ff8800);color:#000;border:none;padding:6px 14px;border-radius:6px;font-weight:900;font-size:11.5px;cursor:pointer;">✅ CONFIRMAR (lock 24h)</button>';
        }
    } else {
        html += '<span style="color:#888;font-size:11px;">Bloqueado · solo lectura</span>';
    }
    if (exists && confirmed) {
        const isVerified = !!row.verifiedAt;
        const vBg = isVerified ? 'linear-gradient(135deg,#66ff66,#25d366)' : 'rgba(102,255,102,0.08)';
        const vColor = isVerified ? '#000' : '#aaffaa';
        const vBorder = isVerified ? '#66ff66' : 'rgba(102,255,102,0.40)';
        const vText = isVerified ? '✓ VERIFICADO · destildear' : '☐ Marcar como verificado';
        html += '<button type="button" onclick="verifyClosing(\'' + rid + '\')" style="background:' + vBg + ';border:1px solid ' + vBorder + ';color:' + vColor + ';padding:6px 12px;border-radius:6px;font-weight:800;font-size:11.5px;cursor:pointer;margin-left:auto;">' + vText + '</button>';
        if (isVerified) {
            html += '<span style="color:#aaffaa;font-size:10.5px;">por <strong>' + escapeHtml(row.verifiedBy || '?') + '</strong></span>';
        }
    }
    html += '</div>';
    html += '</div>';
    return html;
}

// Borrar cierre con PIN (1818). El owner usa esta opción para empezar
// de cero un día puntual — funciona incluso si el cierre está confirmado.
async function deleteClosing(rid) {
    const pin = prompt('🗑️ Borrar cierre — ingresá el PIN:');
    if (!pin) return;
    if (!confirm('¿Confirmás que querés BORRAR este cierre?\n\nLa entrada se elimina por completo (no se puede deshacer).')) return;
    try {
        const r = await authFetch('/api/admin/closings/' + encodeURIComponent(rid) + '?pin=' + encodeURIComponent(pin), {
            method: 'DELETE'
        });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error al borrar', 'error');
            return;
        }
        showToast('🗑️ Cierre borrado', 'success');
        loadClosings();
    } catch (e) {
        showToast('Error al borrar', 'error');
    }
}

async function verifyClosing(rid) {
    try {
        const r = await authFetch('/api/admin/closings/' + encodeURIComponent(rid) + '/verify', { method: 'POST' });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error', 'error');
            return;
        }
        showToast(d.verified ? '✓ Verificado' : 'Tilde sacado', 'success');
        loadClosings();
    } catch (e) {
        showToast('Error', 'error');
    }
}

// Save para sectores con teams[] (Buffalo y Ganamos). Arma el array
// teams[] desde los inputs + envía generales.
async function saveTeamSectorClosing(rid, date, sector) {
    const get = (suffix) => {
        const el = document.getElementById('cls_' + rid + '_' + suffix);
        return el ? el.value : '';
    };
    const teams = [];
    for (let i = 0; i < BUFFALO_TEAM_SLOTS; i++) {
        const find = (field) => {
            const sel = '[data-cls-id="' + rid + '"] [data-buffalo-team="' + i + '"][data-field="' + field + '"]';
            const el = document.querySelector(sel);
            return el ? el.value : '';
        };
        teams.push({
            slot: i,
            name: (find('name') || '').trim(),
            depositsARS: parseFloat(find('depositsARS')) || 0,
            depositsCount: parseInt(find('depositsCount'), 10) || 0,
            ventasARS: parseFloat(find('ventasARS')) || 0,
            bonusARS: parseFloat(find('bonusARS')) || 0,
            bonusCount: parseInt(find('bonusCount'), 10) || 0,
            withdrawalsCount: parseInt(find('withdrawalsCount'), 10) || 0
        });
    }
    const payload = {
        sector,
        dateKey: date,
        bankMarginPercent: parseFloat(get('bankMarginPercent')) || 0,
        bajadaARS: parseFloat(get('bajadaARS')) || 0,
        pendienteAnteriorARS: parseFloat(get('pendienteAnteriorARS')) || 0,
        saldoInicialARS: 0,
        saldoInicialNote: '',
        ingresosARS: parseFloat(get('ingresosARS')) || 0,
        ingresosNote: get('ingresosNote') || '',
        egresosARS: parseFloat(get('egresosARS')) || 0,
        egresosNote: get('egresosNote') || '',
        gastosARS: parseFloat(get('gastosARS')) || 0,
        gastosNote: get('gastosNote') || '',
        cvuMidnightARS: parseFloat(get('cvuMidnightARS')) || 0,
        teams
    };

    const isNew = rid.startsWith('new_');
    try {
        const r = isNew
            ? await authFetch('/api/admin/closings', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
            : await authFetch('/api/admin/closings/' + encodeURIComponent(rid), { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error al guardar', 'error');
            return;
        }
        showToast('✅ ' + sector.toUpperCase() + ' guardado', 'success');
        loadClosings();
    } catch (e) {
        showToast('Error al guardar', 'error');
    }
}

function _renderClosingEntry(sec, date, teamSlot, row) {
    const exists = !!row;
    const locked = row && row.locked;
    const confirmed = row && row.status === 'confirmed';
    const c = row && row.computed || {};
    const rid = row ? row.id : ('new_' + sec.key + '_' + (teamSlot == null ? 'main' : teamSlot));

    let header = '';
    if (sec.individual) {
        const tname = (row && row.teamName) || '';
        header = '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">' +
            '<div style="background:' + sec.color + ';color:#000;font-weight:900;font-size:11px;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;">' + (teamSlot + 1) + '</div>' +
            '<input type="text" id="cls_' + rid + '_teamName" value="' + escapeHtml(tname) + '" placeholder="Nombre del equipo (ej: ROYAL, TIGER)" style="flex:1;background:rgba(0,0,0,0.45);border:1px solid rgba(255,255,255,0.15);color:#fff;padding:5px 9px;border-radius:6px;font-size:12.5px;font-weight:700;" ' + (locked ? 'disabled' : '') + '>' +
            (locked ? '<span style="color:#ff8080;font-size:10px;font-weight:800;">🔒 BLOQUEADO 24h</span>' : (confirmed ? '<span style="color:#aaffaa;font-size:10px;font-weight:800;">✅ CONFIRMADO</span>' : '<span style="color:#888;font-size:10px;">📝 BORRADOR</span>')) +
            '</div>';
    } else {
        header = '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">' +
            '<div style="color:#aaa;font-size:11px;letter-spacing:0.5px;">Cierre del ' + escapeHtml(date) + '</div>' +
            (locked ? '<span style="color:#ff8080;font-size:10px;font-weight:800;">🔒 BLOQUEADO 24h</span>' : (confirmed ? '<span style="color:#aaffaa;font-size:10px;font-weight:800;">✅ CONFIRMADO</span>' : '<span style="color:#888;font-size:10px;">📝 BORRADOR</span>')) +
            '</div>';
    }

    const inputStyle = 'background:rgba(0,0,0,0.50);border:1px solid rgba(255,255,255,0.12);color:#fff;padding:6px 9px;border-radius:6px;font-size:12.5px;font-weight:700;width:100%;box-sizing:border-box;';
    const disabledAttr = locked ? 'disabled' : '';

    let html = '<div style="background:rgba(0,0,0,0.22);border:1px solid rgba(255,255,255,0.08);border-radius:9px;padding:11px;margin-bottom:9px;" data-cls-id="' + rid + '">';
    html += header;
    html += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:7px;margin-bottom:8px;">';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">💰 Depósitos</label><input type="number" id="cls_' + rid + '_depositsARS" value="' + (row ? row.depositsARS : 0) + '" min="0" step="100" style="' + inputStyle + '" ' + disabledAttr + '></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🏦 % Banco</label><input type="number" id="cls_' + rid + '_bankMarginPercent" value="' + (row ? row.bankMarginPercent : 0) + '" min="0" max="100" step="0.1" style="' + inputStyle + '" ' + disabledAttr + '></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;" title="VENTA = lo que se pagó a clientes (cash-out). Puede ser NEGATIVA.">🛒 Venta $</label><input type="number" id="cls_' + rid + '_ventasARS" value="' + (row ? row.ventasARS : 0) + '" step="100" style="' + inputStyle + 'border-color:rgba(255,208,160,0.30);" ' + disabledAttr + '><div style="color:#666;font-size:9.5px;margin-top:2px;">cash-out (acepta negativos si cerró mal)</div></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🏃 Bajada real</label><input type="number" id="cls_' + rid + '_bajadaARS" value="' + (row ? row.bajadaARS : 0) + '" min="0" step="100" style="' + inputStyle + '" ' + disabledAttr + '></div>';
    (function() {
        const pAuto = row ? Number(row.pendienteAnteriorARS || 0) : _autoPendienteAnterior(date, sec.key);
        // Siempre editable — el dueño puede corregirlo si la auto-fill es mala.
        const pStyle = inputStyle + 'border-color:rgba(0,212,255,0.40);';
        html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🏦 CVU 00 hs anterior</label><input type="number" id="cls_' + rid + '_pendienteAnteriorARS" value="' + pAuto + '" step="100" style="' + pStyle + '" ' + (locked ? 'disabled' : '') + '></div>';
    })();
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🎁 Bonos ($)</label><input type="number" id="cls_' + rid + '_bonusARS" value="' + (row ? row.bonusARS : 0) + '" min="0" step="100" style="' + inputStyle + '" ' + disabledAttr + '></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🔢 Transacc. totales</label><input type="number" id="cls_' + rid + '_transactionsCount" value="' + (row ? (row.transactionsCount || 0) : 0) + '" min="0" step="1" style="' + inputStyle + '" ' + disabledAttr + '></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">📤 Descargas (cant.)</label><input type="number" id="cls_' + rid + '_withdrawalsCount" value="' + (row ? (row.withdrawalsCount || 0) : 0) + '" min="0" step="1" style="' + inputStyle + '" ' + disabledAttr + '></div>';
    html += '<div><label style="color:#aaa;font-size:10px;text-transform:uppercase;letter-spacing:0.5px;">🎁 Bonificaciones (cant.)</label><input type="number" id="cls_' + rid + '_bonusCount" value="' + (row ? (row.bonusCount || 0) : 0) + '" min="0" step="1" style="' + inputStyle + '" ' + disabledAttr + '></div>';
    html += '</div>';

    // === MOVIMIENTOS EXTRA (préstamos + gastos + CVU control) ===
    html += _renderClosingExtras(rid, row, locked);

    if (exists) {
        const pendColor = c.pendienteHoy > 0 ? '#ff8080' : '#aaffaa';
        const netColor = c.netoSector < 0 ? '#ff8080' : '#ffd700';
        html += '<div style="background:rgba(0,0,0,0.30);border-radius:6px;padding:7px 9px;margin-bottom:8px;display:flex;flex-wrap:wrap;gap:10px;font-size:11px;">';
        html += '<span style="color:#aaa;">Comisión: <strong style="color:#ff8080;">-' + _closingFmt(c.commission) + '</strong></span>';
        html += '<span style="color:#aaa;">Neto entró: <strong style="color:#aaffaa;">' + _closingFmt(c.depositsNet) + '</strong></span>';
        html += '<span style="color:#aaa;">A bajar total: <strong>' + _closingFmt(c.totalABajar) + '</strong></span>';
        html += '<span style="color:#aaa;">Pendiente hoy: <strong style="color:' + pendColor + ';">' + _closingFmt(c.pendienteHoy) + '</strong></span>';
        html += '<span style="color:#aaa;">Cash en banco: <strong style="color:#aaffff;" title="depositsNet − bajada — lo que tiene que haber sobrante en la cuenta">' + _closingFmt(c.cashEnBanco) + '</strong></span>';
        html += '<span style="color:#aaa;">Neto sector: <strong style="color:' + netColor + ';">' + _closingFmt(c.netoSector) + '</strong></span>';
        html += '</div>';

        // Análisis del cierre (visible apenas se carga la entrada)
        const hasBankProof = (row.comprobantes || []).some(p => p.kind === 'pendiente_bank');
        const overpaid = row.bajadaARS > c.totalABajar;
        let analysisText = '', analysisBg = '', analysisColor = '';
        if (overpaid) {
            analysisText = '⚠️ Bajaste $' + Math.round(row.bajadaARS - c.totalABajar).toLocaleString('es-AR') + ' MÁS de lo que había que bajar. Revisá el dato.';
            analysisBg = 'rgba(255,170,102,0.10)'; analysisColor = '#ffaa66';
        } else if (c.pendienteHoy > 0) {
            if (row.status === 'confirmed' && hasBankProof) {
                analysisText = '⏳ Pendiente $' + Math.round(c.pendienteHoy).toLocaleString('es-AR') + ' arrastra al día siguiente. Con respaldo bancario — la plata sigue en cuenta.';
                analysisBg = 'rgba(255,170,102,0.08)'; analysisColor = '#ffaa66';
            } else if (row.status === 'confirmed') {
                analysisText = '🚨 PLATA FALTANTE $' + Math.round(c.pendienteHoy).toLocaleString('es-AR') + ' — confirmado sin foto del banco que muestre la plata.';
                analysisBg = 'rgba(255,80,80,0.12)'; analysisColor = '#ff5050';
            } else {
                analysisText = '📝 Borrador — pendiente $' + Math.round(c.pendienteHoy).toLocaleString('es-AR') + '. Adjuntá foto banco antes de confirmar.';
                analysisBg = 'rgba(255,170,102,0.06)'; analysisColor = '#ffaa66';
            }
        } else {
            if (row.status === 'confirmed') {
                if (c.netoSector < 0) {
                    analysisText = '📉 CERRÓ EN ROJO — el sector perdió $' + Math.round(Math.abs(c.netoSector)).toLocaleString('es-AR') + ' este día (ventas + bonos superaron depósitos netos).';
                    analysisBg = 'rgba(255,128,128,0.10)'; analysisColor = '#ff8080';
                } else {
                    analysisText = '✅ CERRÓ BIEN — todo bajado, neto del sector $' + Math.round(c.netoSector).toLocaleString('es-AR') + '.';
                    analysisBg = 'rgba(102,255,102,0.10)'; analysisColor = '#aaffaa';
                }
            } else {
                analysisText = '📝 Borrador — sin pendientes. Listo para confirmar.';
                analysisBg = 'rgba(0,212,255,0.08)'; analysisColor = '#aaffff';
            }
        }
        html += '<div style="background:' + analysisBg + ';border-left:3px solid ' + analysisColor + ';border-radius:0 6px 6px 0;padding:7px 10px;margin-bottom:8px;color:' + analysisColor + ';font-size:11.5px;font-weight:700;">' + analysisText + '</div>';
        html += _renderComprobantesPanel(row, rid, locked, c);
        if (row.editHistory && row.editHistory.length > 0) {
            html += '<div style="font-size:10.5px;color:#888;margin-bottom:6px;">📝 Editado ' + row.editHistory.length + ' veces · último por <strong>' + escapeHtml(row.editHistory[row.editHistory.length - 1].editedBy || '?') + '</strong></div>';
        }
    }

    // Action buttons
    html += '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;">';
    if (!locked) {
        html += '<button type="button" onclick="saveClosing(\'' + rid + '\', \'' + sec.key + '\', ' + (teamSlot == null ? 'null' : teamSlot) + ', \'' + date + '\')" style="background:rgba(102,255,102,0.15);border:1px solid rgba(102,255,102,0.45);color:#aaffaa;padding:6px 12px;border-radius:6px;font-weight:800;font-size:11.5px;cursor:pointer;">' + (exists ? '💾 GUARDAR CAMBIOS' : '💾 CREAR CIERRE') + '</button>';
        if (exists && !confirmed) {
            html += '<button type="button" onclick="confirmClosing(\'' + rid + '\')" style="background:linear-gradient(135deg,#ffd700,#ff8800);color:#000;border:none;padding:6px 14px;border-radius:6px;font-weight:900;font-size:11.5px;cursor:pointer;">✅ CONFIRMAR (lock 24h)</button>';
        }
    } else {
        html += '<span style="color:#888;font-size:11px;">Bloqueado · solo lectura</span>';
    }
    if (exists && confirmed) {
        const isVerified = !!row.verifiedAt;
        const vBg = isVerified ? 'linear-gradient(135deg,#66ff66,#25d366)' : 'rgba(102,255,102,0.08)';
        const vColor = isVerified ? '#000' : '#aaffaa';
        const vBorder = isVerified ? '#66ff66' : 'rgba(102,255,102,0.40)';
        const vText = isVerified ? '✓ VERIFICADO · destildear' : '☐ Marcar como verificado';
        html += '<button type="button" onclick="verifyClosing(\'' + rid + '\')" style="background:' + vBg + ';border:1px solid ' + vBorder + ';color:' + vColor + ';padding:6px 12px;border-radius:6px;font-weight:800;font-size:11.5px;cursor:pointer;margin-left:auto;">' + vText + '</button>';
        if (isVerified) {
            html += '<span style="color:#aaffaa;font-size:10.5px;">por <strong>' + escapeHtml(row.verifiedBy || '?') + '</strong></span>';
        }
    }
    html += '</div>';
    html += '</div>';
    return html;
}

async function saveClosing(rid, sector, teamSlot, date) {
    const get = (suffix) => {
        const el = document.getElementById('cls_' + rid + '_' + suffix);
        return el ? el.value : '';
    };
    const payload = {
        sector,
        dateKey: date,
        depositsARS: parseFloat(get('depositsARS')) || 0,
        bankMarginPercent: parseFloat(get('bankMarginPercent')) || 0,
        ventasARS: parseFloat(get('ventasARS')) || 0,
        bajadaARS: parseFloat(get('bajadaARS')) || 0,
        pendienteAnteriorARS: parseFloat(get('pendienteAnteriorARS')) || 0,
        bonusARS: parseFloat(get('bonusARS')) || 0,
        transactionsCount: parseInt(get('transactionsCount'), 10) || 0,
        withdrawalsCount: parseInt(get('withdrawalsCount'), 10) || 0,
        bonusCount: parseInt(get('bonusCount'), 10) || 0,
        saldoInicialARS: 0,
        saldoInicialNote: '',
        ingresosARS: parseFloat(get('ingresosARS')) || 0,
        ingresosNote: get('ingresosNote') || '',
        egresosARS: parseFloat(get('egresosARS')) || 0,
        egresosNote: get('egresosNote') || '',
        gastosARS: parseFloat(get('gastosARS')) || 0,
        gastosNote: get('gastosNote') || '',
        cvuMidnightARS: parseFloat(get('cvuMidnightARS')) || 0
    };
    if (sector === 'buffalo') {
        payload.teamSlot = teamSlot;
        payload.teamName = get('teamName') || '';
    }

    const isNew = rid.startsWith('new_');
    try {
        let r, d;
        if (isNew) {
            r = await authFetch('/api/admin/closings', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        } else {
            r = await authFetch('/api/admin/closings/' + encodeURIComponent(rid), {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
        }
        d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error al guardar', 'error');
            return;
        }
        showToast('✅ Guardado', 'success');
        loadClosings();
    } catch (e) {
        showToast('Error al guardar', 'error');
    }
}

async function confirmClosing(rid) {
    if (!confirm('¿Confirmar este cierre? Después de 24hs queda bloqueado y no se va a poder editar.')) return;
    try {
        const r = await authFetch('/api/admin/closings/' + encodeURIComponent(rid) + '/confirm', { method: 'POST' });
        const d = await r.json();
        if (!r.ok || !d.success) {
            if (d.missingBankProof) {
                alert('⚠️ ' + d.error + '\n\nAdjuntá la foto del banco (tipo "Banco-pendiente") y volvé a confirmar.');
            } else {
                showToast(d.error || 'Error', 'error');
            }
            return;
        }
        showToast('✅ Cierre confirmado', 'success');
        loadClosings();
    } catch (e) {
        showToast('Error al confirmar', 'error');
    }
}

async function removeClosingComprobante(rid, idx) {
    if (!confirm('¿Sacar este comprobante?')) return;
    try {
        const r = await authFetch('/api/admin/closings/' + encodeURIComponent(rid) + '/comprobante/' + idx, { method: 'DELETE' });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error', 'error');
            return;
        }
        loadClosings();
    } catch (e) {
        showToast('Error', 'error');
    }
}

// ============================================================
// COTIZACIONES SEMANALES
// ============================================================
// Sección financiera dedicada: cada lunes (o la fecha que el owner
// elija) se cierra una cotización por equipo (hasta 10). Sumás el
// total $ acumulado del equipo, completás el valor del USDT del día,
// y el precio a cotizar sale solo: total / usdt_rate. El owner marca
// con ✓ (cotizado) o ✗ (sin cotizar).

let _cotizacionesCache = [];
let _cotizacionesExternoCache = [];

// Scope helpers: el módulo de cotizaciones soporta dos backends paralelos
// (interna = /api/admin/cotizaciones, externa = /api/admin/cotizaciones-externo).
// Cada uno tiene su propio cache, sección y URL base.
function _cotApiBase(scope) {
    return scope === 'externa' ? '/api/admin/cotizaciones-externo' : '/api/admin/cotizaciones';
}
function _cotCache(scope) {
    return scope === 'externa' ? _cotizacionesExternoCache : _cotizacionesCache;
}
function _cotBodyId(scope) {
    return scope === 'externa' ? 'cotizacionesExternoBody' : 'cotizacionesBody';
}
function _cotCardIdPrefix(scope) {
    return scope === 'externa' ? 'cotEx_' : 'cot_';
}
// Scope activo de la última card que el usuario interactuó. Se setea en
// _renderCotizacionCard y lo usan las acciones (save/close/etc) para saber
// a qué backend pegarle. Cada función expuesta acepta un scope explícito
// pero los onclick generados usan este lookup vía data-cot-scope.
function _cotScopeOfId(id) {
    if ((_cotizacionesExternoCache || []).find(x => x.id === id)) return 'externa';
    return 'interna';
}

// Devuelve el lunes de la semana actual (o el de hoy si es lunes), en
// formato YYYY-MM-DD hora Argentina. Útil como default del date picker.
function _cotMondayOfThisWeek() {
    const tz = 'America/Argentina/Buenos_Aires';
    const now = new Date();
    // Obtener "hoy en ART"
    const fmt = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit', weekday: 'short' });
    const parts = fmt.formatToParts(now);
    const get = (t) => (parts.find(p => p.type === t) || {}).value;
    const y = Number(get('year')), m = Number(get('month')), d = Number(get('day'));
    const wd = String(get('weekday') || '').toLowerCase(); // mon,tue,...
    const dowMap = { sun: 0, mon: 1, tue: 2, wed: 3, thu: 4, fri: 5, sat: 6 };
    const dow = dowMap[wd] != null ? dowMap[wd] : 1;
    const delta = (dow === 0) ? -6 : (1 - dow); // lunes = delta 0; martes = -1, ...
    const base = new Date(Date.UTC(y, m - 1, d));
    base.setUTCDate(base.getUTCDate() + delta);
    return base.toISOString().slice(0, 10);
}

async function loadCotizaciones(scope) {
    scope = scope || 'interna';
    const body = document.getElementById(_cotBodyId(scope));
    if (!body) return;
    body.innerHTML = '<div style="color:#aaa;text-align:center;padding:24px;">⏳ Cargando…</div>';
    let r, d;
    try {
        r = await authFetch(_cotApiBase(scope));
        d = await r.json();
    } catch (e) {
        // Fallo en el fetch o el parse JSON. Loggeamos el error real para
        // que sea visible en DevTools cuando algo realmente revienta de red.
        console.error('[cotizaciones] fetch/parse fail:', e);
        body.innerHTML = '<div style="color:#f55;text-align:center;padding:24px;">Error de conexión: ' + escapeHtml(e.message || String(e)) + '</div>';
        return;
    }
    if (!r.ok || !d.success) {
        body.innerHTML = '<div style="color:#f55;text-align:center;padding:24px;">Error: ' + escapeHtml(d.error || ('HTTP ' + r.status)) + '</div>';
        return;
    }
    if (scope === 'externa') _cotizacionesExternoCache = d.items || [];
    else _cotizacionesCache = d.items || [];
    // Render aislado del fetch: si el render tira, ya tenemos la data en
    // cache pero mostramos el error específico (no decimos "Error de
    // conexión" cuando el problema es un bug del render).
    try {
        _renderCotizaciones(scope);
    } catch (renderErr) {
        console.error('[cotizaciones] render fail:', renderErr);
        body.innerHTML = '<div style="color:#f55;text-align:center;padding:24px;">Bug del render: ' + escapeHtml(renderErr.message || String(renderErr)) + '<br><small style="color:#888;">Abrí la consola (F12) para ver el stack completo.</small></div>';
    }
}

// Wrapper para el sidebar "Cotizaciones Externo" — mismo flujo apuntando
// a /api/admin/cotizaciones-externo (collection separada en Mongo).
async function loadCotizacionesExterno() {
    return loadCotizaciones('externa');
}

function _renderCotizaciones(scope) {
    scope = scope || 'interna';
    const body = document.getElementById(_cotBodyId(scope));
    if (!body) return;
    const items = _cotCache(scope) || [];
    const defaultDate = _cotMondayOfThisWeek();
    const titlePrefix = scope === 'externa' ? '🌐 ' : '';
    const createFn = scope === 'externa' ? 'createCotizacionExterno()' : 'createCotizacion()';
    const newDateInputId = scope === 'externa' ? 'newCotExDate' : 'newCotDate';

    let h = '';

    // === Crear nueva cotización ===
    h += '<div style="background:rgba(0,200,150,0.06);border:1px solid rgba(0,200,150,0.30);border-radius:10px;padding:14px;margin-bottom:18px;">';
    h += '<div style="color:#00c896;font-weight:800;font-size:13px;margin-bottom:10px;">➕ ' + titlePrefix + 'Nueva cotización</div>';
    h += '<div style="display:flex;gap:10px;align-items:end;flex-wrap:wrap;">';
    h += '<div>';
    h += '<label style="color:#aaa;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px;">Fecha</label>';
    h += '<input type="date" id="' + newDateInputId + '" value="' + escapeHtml(defaultDate) + '" style="background:rgba(0,0,0,0.40);border:1px solid rgba(255,255,255,0.14);color:#fff;padding:8px 10px;border-radius:7px;font-size:13px;font-weight:600;">';
    h += '</div>';
    h += '<button onclick="' + createFn + '" style="background:linear-gradient(135deg,#00c896 0%,#008f6c 100%);color:#000;border:none;padding:9px 18px;border-radius:8px;font-weight:900;font-size:12.5px;cursor:pointer;letter-spacing:0.5px;">CREAR CIERRE</button>';
    h += '<span style="color:#888;font-size:11px;">Default = lunes de esta semana. Podés elegir cualquier fecha.</span>';
    h += '</div>';
    h += '</div>';

    if (items.length === 0) {
        h += '<div style="background:rgba(255,255,255,0.03);border:1px dashed rgba(255,255,255,0.15);border-radius:10px;padding:30px;text-align:center;color:#888;font-size:13px;">Todavía no hay cotizaciones cargadas. Creá la primera arriba ⬆️</div>';
        body.innerHTML = h;
        return;
    }

    // === Header del historial + filtros + total cotizado general ===
    const closedN = items.filter(x => x.status === 'closed').length;
    const draftN = items.length - closedN;
    const allCotizadasN = items.filter(x => x.allCotizadas || x.cotizado).length;
    const sumCotizadoARS = items.reduce((a, x) => a + Number(x.totalCotizadoNetARS || 0), 0);
    const sumCotizadoUSDT = items.reduce((a, x) => a + Number(x.totalCotizadoUSDT || 0), 0);
    const sumPendienteARS = items.reduce((a, x) => a + Number(x.totalPendienteNetARS || 0), 0);

    h += '<div style="background:rgba(255,255,255,0.04);border-radius:8px;padding:12px 14px;margin-bottom:14px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:10px;">';
    h += '<div style="color:#fff;font-weight:900;font-size:13px;letter-spacing:0.5px;">📋 HISTORIAL DE COTIZACIONES</div>';
    h += '<div style="display:flex;gap:10px;font-size:11.5px;font-weight:700;flex-wrap:wrap;">';
    h += '<span style="color:#aaa;">Total: <strong style="color:#fff;">' + items.length + '</strong></span>';
    h += '<span style="color:#ffd700;">📝 Draft: <strong>' + draftN + '</strong></span>';
    h += '<span style="color:#00d4ff;">🔒 Cerradas: <strong>' + closedN + '</strong></span>';
    h += '<span style="color:#0f0;">✓ Todas cotizadas: <strong>' + allCotizadasN + '</strong></span>';
    h += '</div>';
    h += '</div>';

    // Banner total cotizado general (suma de TODOS los equipos cotizados en
    // TODOS los cierres del scope). Es la métrica clave para el dueño.
    // === Comisión acumulada ===
    // De cada cierre cotizado, ese %comisión × monto = lo que se queda la
    // casa. Lo queremos ver por SEMANA (la cotización es semanal) y total.
    // Iteramos los items, sumamos teams cotizados por semana ISO (lunes-domingo).
    function _isoWeekKey(d) {
        // Año-Semana ISO 8601 (lunes inicia semana). Devuelve "YYYY-W##".
        const date = new Date(d);
        date.setUTCHours(0, 0, 0, 0);
        // Jueves de esta semana ISO
        date.setUTCDate(date.getUTCDate() + 4 - (date.getUTCDay() || 7));
        const yearStart = new Date(Date.UTC(date.getUTCFullYear(), 0, 1));
        const weekNum = Math.ceil(((date - yearStart) / 86400000 + 1) / 7);
        return date.getUTCFullYear() + '-W' + String(weekNum).padStart(2, '0');
    }
    const _nowWeek = _isoWeekKey(new Date());
    let commWeekARS = 0, commWeekUSDT = 0;
    let commTotalARS = 0, commTotalUSDT = 0;
    for (const cot of items) {
        const rate = Number(cot.usdtRate || 0);
        const cotTeams = Array.isArray(cot.teams) ? cot.teams : [];
        for (const t of cotTeams) {
            if (!t.cotizado || !t.cotizedAt) continue;
            const commARS = Number(t.commissionARS || 0);
            const commUSDT = rate > 0 ? (commARS / rate) : 0;
            commTotalARS += commARS;
            commTotalUSDT += commUSDT;
            if (_isoWeekKey(t.cotizedAt) === _nowWeek) {
                commWeekARS += commARS;
                commWeekUSDT += commUSDT;
            }
        }
    }

    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-bottom:12px;">';
    h += '<div style="background:linear-gradient(135deg,rgba(0,255,102,0.10) 0%,rgba(0,200,150,0.06) 100%);border:1px solid rgba(0,255,102,0.30);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">💎 Total cotizado general</div>';
    h += '<div style="color:#0f0;font-weight:900;font-size:18px;margin-top:3px;">' + formatMoney(sumCotizadoARS) + '</div>';
    h += '<div style="color:#aaffaa;font-weight:800;font-size:12px;">' + sumCotizadoUSDT.toFixed(2) + ' USDT</div>';
    h += '</div>';
    h += '<div style="background:rgba(255,170,102,0.06);border:1px solid rgba(255,170,102,0.25);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">⏳ Pendiente de cotizar</div>';
    h += '<div style="color:#ffaa66;font-weight:900;font-size:18px;margin-top:3px;">' + formatMoney(sumPendienteARS) + '</div>';
    h += '</div>';
    // Comisión: dos cards — semana actual + total acumulado
    h += '<div style="background:linear-gradient(135deg,rgba(255,215,0,0.10) 0%,rgba(255,170,0,0.06) 100%);border:1px solid rgba(255,215,0,0.35);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">💰 Comisión semana actual</div>';
    h += '<div style="color:#ffd700;font-weight:900;font-size:17px;margin-top:3px;">' + formatMoney(Math.round(commWeekARS)) + '</div>';
    h += '<div style="color:#ffe88a;font-weight:800;font-size:12px;">' + commWeekUSDT.toFixed(2) + ' USDT</div>';
    h += '<div style="color:#888;font-size:9.5px;margin-top:2px;">semana ' + escapeHtml(_nowWeek) + '</div>';
    h += '</div>';
    h += '<div style="background:rgba(212,175,55,0.06);border:1px solid rgba(212,175,55,0.30);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">🏦 Comisión total acumulada</div>';
    h += '<div style="color:#d4af37;font-weight:900;font-size:17px;margin-top:3px;">' + formatMoney(Math.round(commTotalARS)) + '</div>';
    h += '<div style="color:#e8d180;font-weight:800;font-size:12px;">' + commTotalUSDT.toFixed(2) + ' USDT</div>';
    h += '</div>';
    h += '</div>';

    // === Historial de actividad: timeline de cotizaciones por equipo ===
    // Recolecta cada evento individual (equipo cotizado) ordenado por fecha.
    // Le da al dueño un log día por día de qué se fue cotizando.
    const events = [];
    for (const cot of items) {
        const cotTeams = Array.isArray(cot.teams) ? cot.teams : [];
        for (const t of cotTeams) {
            if (!t.cotizado || !t.cotizedAt) continue;
            events.push({
                cotId: cot.id,
                dateKey: cot.dateKey,
                slot: t.slot,
                name: t.name || ('Equipo ' + (Number(t.slot || 0) + 1)),
                netARS: Number(t.netARS || t.totalARS || 0),
                precioUSDT: Number(t.precioUSDT || 0),
                cotizedAt: t.cotizedAt,
                cotizedBy: t.cotizedBy || ''
            });
        }
    }
    events.sort((a, b) => new Date(b.cotizedAt) - new Date(a.cotizedAt));

    if (events.length > 0) {
        const histKey = scope === 'externa' ? '_cotExHistOpen' : '_cotHistOpen';
        const histOpen = (scope === 'externa') ? _cotExHistOpen : _cotHistOpen;
        h += '<div style="background:rgba(0,0,0,0.30);border:1px solid rgba(0,255,102,0.20);border-radius:8px;margin-bottom:12px;overflow:hidden;">';
        h += '<div onclick="toggleCotHistory(\'' + scope + '\')" style="cursor:pointer;padding:10px 14px;display:flex;justify-content:space-between;align-items:center;user-select:none;">';
        h += '<div style="color:#aaffaa;font-weight:900;font-size:12px;letter-spacing:0.5px;">📅 HISTORIAL DE COTIZACIONES (' + events.length + ' eventos) — día por día</div>';
        h += '<div style="color:#aaa;font-size:11px;">' + (histOpen ? '▲ ocultar' : '▼ ver') + '</div>';
        h += '</div>';
        if (histOpen) {
            // Agrupar por día de cotización (cuando se tildó, no la fecha del cierre).
            const byDay = {};
            for (const ev of events) {
                const day = new Date(ev.cotizedAt).toISOString().slice(0, 10);
                if (!byDay[day]) byDay[day] = [];
                byDay[day].push(ev);
            }
            const days = Object.keys(byDay).sort().reverse();
            h += '<div style="border-top:1px solid rgba(255,255,255,0.06);padding:8px 14px;max-height:340px;overflow-y:auto;">';
            for (const day of days) {
                const dayEvents = byDay[day];
                const dayTotal = dayEvents.reduce((a, e) => a + e.netARS, 0);
                const dayUSDT = dayEvents.reduce((a, e) => a + e.precioUSDT, 0);
                h += '<div style="margin-bottom:9px;padding-bottom:7px;border-bottom:1px dashed rgba(255,255,255,0.08);">';
                h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;">';
                h += '<strong style="color:#fff;font-size:12.5px;">📆 ' + escapeHtml(day) + '</strong>';
                h += '<span style="color:#aaffaa;font-weight:800;font-size:11.5px;">' + dayEvents.length + ' ' + (dayEvents.length === 1 ? 'equipo' : 'equipos') + ' · ' + formatMoney(dayTotal) + ' · ' + dayUSDT.toFixed(2) + ' USDT</span>';
                h += '</div>';
                for (const ev of dayEvents) {
                    h += '<div style="display:flex;justify-content:space-between;font-size:11.5px;padding:3px 6px;border-radius:4px;background:rgba(0,255,102,0.04);margin-bottom:3px;">';
                    h += '<span style="color:#ddd;"><strong style="color:#fff;">' + escapeHtml(ev.name) + '</strong> · cierre del ' + escapeHtml(ev.dateKey) + (ev.cotizedBy ? ' · por ' + escapeHtml(ev.cotizedBy) : '') + '</span>';
                    h += '<span style="color:#aaffaa;font-weight:700;">' + formatMoney(ev.netARS) + ' · ' + ev.precioUSDT.toFixed(2) + ' USDT</span>';
                    h += '</div>';
                }
                h += '</div>';
            }
            h += '</div>';
        }
        h += '</div>';
    }

    // Filtros: por estado + ir a una fecha específica
    h += '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;font-size:11.5px;">';
    h += '<span style="color:#888;">Filtrar:</span>';
    const filterBtn = (key, label, active) => {
        const css = active
            ? 'background:rgba(0,212,255,0.20);color:#00d4ff;border-color:rgba(0,212,255,0.50);'
            : 'background:rgba(255,255,255,0.04);color:#aaa;border-color:rgba(255,255,255,0.10);';
        return '<button onclick="setCotFilter(\'' + key + '\',\'' + scope + '\')" style="' + css + 'border:1px solid;padding:5px 11px;border-radius:6px;font-weight:800;font-size:11px;cursor:pointer;">' + label + '</button>';
    };
    const filterKey = scope === 'externa' ? '_cotExFilter' : '_cotFilter';
    const f = (scope === 'externa' ? _cotExFilter : _cotFilter) || 'all';
    h += filterBtn('all',          'Todos',         f === 'all');
    h += filterBtn('draft',        '📝 Draft',      f === 'draft');
    h += filterBtn('closed',       '🔒 Cerradas',   f === 'closed');
    h += filterBtn('cotizado',     '✓ Cotizadas',   f === 'cotizado');
    h += filterBtn('no_cotizado',  '✗ No cotizadas',f === 'no_cotizado');
    h += '<span style="color:#888;margin-left:10px;">Ir a fecha:</span>';
    const jumpId = scope === 'externa' ? 'cotExJumpDate' : 'cotJumpDate';
    h += '<input type="date" id="' + jumpId + '" onchange="jumpToCotDate(this.value,\'' + scope + '\')" style="background:rgba(0,0,0,0.40);border:1px solid rgba(255,255,255,0.14);color:#fff;padding:5px 9px;border-radius:6px;font-weight:700;font-size:11.5px;">';
    h += '</div>';
    h += '</div>';

    // Filtrado
    const filtered = items.filter(it => {
        if (f === 'draft') return it.status !== 'closed';
        if (f === 'closed') return it.status === 'closed';
        if (f === 'cotizado') return !!it.cotizado;
        if (f === 'no_cotizado') return !it.cotizado;
        return true;
    });

    if (filtered.length === 0) {
        h += '<div style="background:rgba(255,255,255,0.03);border:1px dashed rgba(255,255,255,0.15);border-radius:10px;padding:20px;text-align:center;color:#888;font-size:12.5px;">Ninguna cotización coincide con el filtro.</div>';
    } else {
        for (const it of filtered) {
            h += _renderCotizacionCard(it, scope);
        }
    }

    body.innerHTML = h;
}

let _cotFilter = 'all';
let _cotExFilter = 'all';
// Toggle del historial detallado de cotizaciones (por scope).
let _cotHistOpen = false;
let _cotExHistOpen = false;
function toggleCotHistory(scope) {
    scope = scope || 'interna';
    if (scope === 'externa') _cotExHistOpen = !_cotExHistOpen;
    else _cotHistOpen = !_cotHistOpen;
    _renderCotizaciones(scope);
}
// Estado de expansión por id. _cotExpanded[id]:
//   undefined → usa el default (drafts y cerradas con pendientes: abiertas;
//               cerradas con todo cotizado: colapsadas).
//   true/false → override manual del dueño.
const _cotExpanded = {};
function toggleCotExpand(id, scope) {
    scope = scope || 'interna';
    // Si es undefined, asumimos el default actual y lo flipeamos.
    // Si es booleano, lo flipeamos.
    const cur = _cotExpanded[id];
    if (cur === undefined) {
        // Necesitamos saber el default actual de esa card. Como toggleCotExpand
        // siempre se llama desde un botón visible, asumimos que el dueño quiere
        // lo opuesto al estado actualmente renderizado — invertir el default.
        const item = (_cotCache(scope) || []).find(x => x.id === id);
        const defaultExpanded = item ? (item.status !== 'closed' || !item.allCotizadas) : true;
        _cotExpanded[id] = !defaultExpanded;
    } else {
        _cotExpanded[id] = !cur;
    }
    _renderCotizaciones(scope);
    // Scroll back to the card after re-render (DOM was rebuilt).
    setTimeout(() => {
        const el = document.getElementById(_cotCardIdPrefix(scope) + id);
        if (el) el.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 50);
}
function setCotFilter(key, scope) {
    scope = scope || 'interna';
    if (scope === 'externa') _cotExFilter = key;
    else _cotFilter = key;
    _renderCotizaciones(scope);
}

// Scroll a la tarjeta de la fecha elegida (si existe en el scope dado).
function jumpToCotDate(dateKey, scope) {
    scope = scope || 'interna';
    if (!dateKey) return;
    const found = (_cotCache(scope) || []).find(it => it.dateKey === dateKey);
    if (!found) {
        showToast('No hay cotización para esa fecha', 'info');
        return;
    }
    const el = document.getElementById(_cotCardIdPrefix(scope) + found.id);
    if (el) {
        el.scrollIntoView({ behavior: 'smooth', block: 'center' });
        el.style.outline = '2px solid #00d4ff';
        setTimeout(() => { el.style.outline = ''; }, 1800);
    }
}

function _renderCotizacionCard(it, scope) {
    scope = scope || 'interna';
    const idPfx = _cotCardIdPrefix(scope);
    const scopeArg = ',\'' + scope + '\'';
    const rate = Number(it.usdtRate || 0);
    const teams = Array.isArray(it.teams) ? it.teams : [];
    const allCotizadas = !!it.allCotizadas;
    const someCotizadas = (Number(it.teamsCotizadasN || 0) > 0);
    const isClosed = (it.status === 'closed');
    const ro = isClosed ? ' readonly tabindex="-1"' : '';
    const roCss = isClosed ? 'background:rgba(0,0,0,0.55);cursor:default;color:#bbb;' : '';

    // Reglas de expansión por default:
    //  - draft: siempre expandida (hay que editar).
    //  - cerrada con equipos pendientes: expandida por default así el dueño
    //    ve el botón ESTADO de cada equipo y puede tildar sin un click extra.
    //  - cerrada con TODO cotizado: colapsada por default (sólo resumen).
    // El estado manual (toggleCotExpand) overridea el default cuando existe.
    const defaultExpanded = !isClosed || !allCotizadas;
    const userOverride = _cotExpanded[it.id];
    const expanded = (userOverride === undefined) ? defaultExpanded : !!userOverride;
    const showBody = expanded;

    // Borde y color: el ESTADO de cierre define el marco.
    const frameBorder = isClosed ? 'rgba(0,212,255,0.45)' : 'rgba(255,255,255,0.10)';
    const frameBg = isClosed ? 'rgba(0,40,80,0.20)' : 'rgba(0,0,0,0.30)';
    const statusBadge = isClosed
        ? '<span style="background:rgba(0,212,255,0.12);color:#00d4ff;padding:5px 12px;border-radius:7px;font-weight:900;font-size:11px;letter-spacing:1px;border:1px solid rgba(0,212,255,0.40);">🔒 CERRADA</span>'
        : '<span style="background:rgba(255,215,0,0.10);color:#ffd700;padding:5px 12px;border-radius:7px;font-weight:900;font-size:11px;letter-spacing:1px;border:1px solid rgba(255,215,0,0.35);">📝 DRAFT</span>';
    let cotizadoBadge;
    if (allCotizadas) {
        cotizadoBadge = '<span style="background:rgba(0,255,0,0.10);color:#0f0;padding:5px 12px;border-radius:7px;font-weight:900;font-size:11px;letter-spacing:1px;border:1px solid rgba(0,255,0,0.40);">✓ TODAS COTIZADAS</span>';
    } else if (someCotizadas) {
        cotizadoBadge = '<span style="background:rgba(255,200,80,0.10);color:#ffc850;padding:5px 12px;border-radius:7px;font-weight:900;font-size:11px;letter-spacing:1px;border:1px solid rgba(255,200,80,0.35);">⏳ PARCIAL ' + (it.teamsCotizadasN || 0) + '/' + ((it.teamsCotizadasN || 0) + (it.teamsPendientesN || 0)) + '</span>';
    } else {
        cotizadoBadge = '<span style="background:rgba(255,80,80,0.10);color:#f55;padding:5px 12px;border-radius:7px;font-weight:900;font-size:11px;letter-spacing:1px;border:1px solid rgba(255,80,80,0.30);">✗ PENDIENTE</span>';
    }

    let h = '<div id="' + idPfx + escapeHtml(it.id) + '" data-cot-id="' + escapeHtml(it.id) + '" data-cot-scope="' + scope + '" style="background:' + frameBg + ';border:1px solid ' + frameBorder + ';border-radius:12px;padding:16px;margin-bottom:18px;">';

    // Header
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:12px;">';
    h += '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">';
    h += '<input type="date" data-cot-field="dateKey" value="' + escapeHtml(it.dateKey) + '" ' + ro + ' style="' + roCss + 'background:rgba(0,0,0,0.40);border:1px solid rgba(255,255,255,0.14);color:#fff;padding:7px 10px;border-radius:7px;font-size:13px;font-weight:700;">';
    h += statusBadge;
    h += cotizadoBadge;
    h += '</div>';
    h += '<div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">';
    if (!isClosed) {
        // === Modo DRAFT: editar, guardar plantilla y cerrar ===
        h += '<button onclick="saveCotizacion(' + escapeJsArg(it.id) + scopeArg + ')" style="background:rgba(0,212,255,0.18);color:#00d4ff;border:1px solid rgba(0,212,255,0.40);padding:7px 14px;border-radius:8px;font-weight:800;font-size:11.5px;cursor:pointer;letter-spacing:0.5px;">💾 GUARDAR</button>';
        h += '<button onclick="saveCotizacionDefaults(' + escapeJsArg(it.id) + scopeArg + ')" title="Guarda los nombres y % de comisión como plantilla. Los próximos cierres arrancan con esto pre-cargado." style="background:rgba(155,48,255,0.15);color:#c89bff;border:1px solid rgba(155,48,255,0.45);padding:7px 12px;border-radius:8px;font-weight:800;font-size:11.5px;cursor:pointer;letter-spacing:0.3px;">⭐ Guardar plantilla</button>';
        h += '<button onclick="closeCotizacion(' + escapeJsArg(it.id) + scopeArg + ')" style="background:linear-gradient(135deg,#00d4ff 0%,#0080ff 100%);color:#000;border:none;padding:7px 16px;border-radius:8px;font-weight:900;font-size:11.5px;cursor:pointer;letter-spacing:0.5px;">🔒 CERRAR COTIZACIÓN</button>';
    } else {
        // === Modo CERRADA ===
        // Botón "marcar TODOS de una". Tildea/destildea todos los equipos
        // con monto > 0 (el toggle entry-level del backend hace esto). El
        // tildeo por equipo se hace en la columna ESTADO de cada fila.
        if (allCotizadas) {
            h += '<button onclick="setCotizado(' + escapeJsArg(it.id) + ', false' + scopeArg + ')" style="background:rgba(255,80,80,0.15);color:#f55;border:1px solid rgba(255,80,80,0.40);padding:7px 14px;border-radius:8px;font-weight:800;font-size:11.5px;cursor:pointer;letter-spacing:0.5px;">✗ DESMARCAR TODOS</button>';
        } else {
            h += '<button onclick="setCotizado(' + escapeJsArg(it.id) + ', true' + scopeArg + ')" style="background:linear-gradient(135deg,#00ff66 0%,#00c896 100%);color:#000;border:none;padding:7px 16px;border-radius:8px;font-weight:900;font-size:11.5px;cursor:pointer;letter-spacing:0.5px;">✓ MARCAR TODOS COTIZADOS</button>';
        }
        h += '<button onclick="reopenCotizacion(' + escapeJsArg(it.id) + scopeArg + ')" style="background:rgba(255,170,102,0.12);color:#ffaa66;border:1px solid rgba(255,170,102,0.40);padding:7px 12px;border-radius:8px;font-weight:800;font-size:11.5px;cursor:pointer;" title="Volver a editar (descerrar)">🔓 REABRIR</button>';
    }
    h += '<button onclick="deleteCotizacion(' + escapeJsArg(it.id) + scopeArg + ')" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);padding:7px 12px;border-radius:8px;font-weight:800;font-size:11.5px;cursor:pointer;">🗑</button>';
    // Botón expandir/colapsar — sólo visible cuando está cerrada (drafts
    // ya están full editables, no tiene sentido colapsarlos).
    if (isClosed) {
        h += '<button onclick="toggleCotExpand(' + escapeJsArg(it.id) + scopeArg + ')" style="background:rgba(255,255,255,0.06);color:#aaa;border:1px solid rgba(255,255,255,0.15);padding:7px 12px;border-radius:8px;font-weight:800;font-size:11.5px;cursor:pointer;">' + (expanded ? '▲ Colapsar' : '▼ Expandir') + '</button>';
    }
    h += '</div>';
    h += '</div>';

    // === Resumen rápido SIEMPRE VISIBLE (incluso colapsada) ===
    // Muestra el total general / cotizado / pendiente del cierre, así el
    // dueño ve el estado de un vistazo sin tener que expander.
    const tCotizado = Number(it.totalCotizadoNetARS || 0);
    const tPendiente = Number(it.totalPendienteNetARS || 0);
    const tTotal = Number(it.totalNetARS || 0);
    const pct = tTotal > 0 ? Math.round((tCotizado / tTotal) * 100) : 0;
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:' + (showBody ? '12' : '0') + 'px;">';
    h += '<div style="background:rgba(255,255,255,0.04);border-radius:6px;padding:8px 12px;">';
    h += '<div style="color:#888;font-size:9.5px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;">Total cierre</div>';
    h += '<div style="color:#fff;font-weight:900;font-size:14px;">' + formatMoney(tTotal) + '</div>';
    h += '<div style="color:#aaa;font-size:11px;">' + (rate > 0 ? (tTotal / rate).toFixed(2) : '0') + ' USDT</div>';
    h += '</div>';
    h += '<div style="background:rgba(0,255,102,0.06);border:1px solid rgba(0,255,102,0.20);border-radius:6px;padding:8px 12px;">';
    h += '<div style="color:#aaffaa;font-size:9.5px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;">✓ Cotizado · ' + pct + '%</div>';
    h += '<div style="color:#0f0;font-weight:900;font-size:14px;">' + formatMoney(tCotizado) + '</div>';
    h += '<div style="color:#aaffaa;font-size:11px;">' + Number(it.totalCotizadoUSDT || 0).toFixed(2) + ' USDT</div>';
    h += '</div>';
    h += '<div style="background:rgba(255,170,102,0.05);border:1px solid rgba(255,170,102,0.20);border-radius:6px;padding:8px 12px;">';
    h += '<div style="color:#ffaa66;font-size:9.5px;font-weight:700;letter-spacing:0.6px;text-transform:uppercase;">⏳ Pendiente</div>';
    h += '<div style="color:#ffaa66;font-weight:900;font-size:14px;">' + formatMoney(tPendiente) + '</div>';
    h += '<div style="color:#ffcfa0;font-size:11px;">' + Number(it.totalPendienteUSDT || 0).toFixed(2) + ' USDT</div>';
    h += '</div>';
    h += '</div>';

    if (!showBody) {
        // Card colapsada — cerrar aquí.
        h += '</div>';
        return h;
    }

    // USDT rate
    h += '<div style="display:flex;gap:14px;align-items:end;flex-wrap:wrap;margin-bottom:12px;background:rgba(255,215,0,0.04);border:1px solid rgba(255,215,0,0.20);border-radius:8px;padding:10px 14px;">';
    h += '<div>';
    h += '<label style="color:#aaa;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:0.6px;display:block;margin-bottom:4px;">Valor USDT (ARS)</label>';
    h += '<input type="number" min="0" step="0.01" data-cot-field="usdtRate" value="' + (rate || '') + '" placeholder="ej: 1500" ' + ro + ' oninput="_cotRecompute(' + escapeJsArg(it.id) + scopeArg + ')" style="' + roCss + 'background:rgba(0,0,0,0.50);border:1px solid rgba(255,215,0,0.40);color:#ffd700;padding:9px 12px;border-radius:7px;font-size:14px;font-weight:800;width:140px;">';
    h += '</div>';
    h += '<div style="color:#888;font-size:11px;line-height:1.4;">';
    h += 'precio_equipo = <strong style="color:#fff;">total_ARS / valor_USDT</strong>';
    h += '</div>';
    h += '</div>';

    // Tabla de 10 equipos
    h += '<div style="overflow-x:auto;border:1px solid rgba(255,255,255,0.08);border-radius:8px;">';
    h += '<table style="width:100%;border-collapse:collapse;font-size:12.5px;min-width:820px;">';
    h += '<thead><tr style="background:rgba(255,255,255,0.04);">';
    h += '<th style="padding:8px;text-align:center;color:#aaa;font-size:10.5px;letter-spacing:0.5px;width:36px;">#</th>';
    h += '<th style="padding:8px;text-align:left;color:#aaa;font-size:10.5px;letter-spacing:0.5px;">EQUIPO</th>';
    h += '<th style="padding:8px;text-align:right;color:#aaa;font-size:10.5px;letter-spacing:0.5px;">TOTAL $ (ARS)</th>';
    h += '<th style="padding:8px;text-align:right;color:#aaa;font-size:10.5px;letter-spacing:0.5px;" title="% comisión que se descuenta del total antes de cotizar">% COM</th>';
    h += '<th style="padding:8px;text-align:right;color:#aaa;font-size:10.5px;letter-spacing:0.5px;" title="Total − comisión (lo que efectivamente se cotiza)">NETO $</th>';
    h += '<th style="padding:8px;text-align:right;color:#aaa;font-size:10.5px;letter-spacing:0.5px;">PRECIO (USDT)</th>';
    h += '<th style="padding:8px;text-align:center;color:#aaa;font-size:10.5px;letter-spacing:0.5px;" title="Tilde por equipo cuando ya se cotizó">ESTADO</th>';
    h += '</tr></thead><tbody>';

    let totalARS = 0;
    let totalCommARS = 0;
    let totalNetARS = 0;
    for (let i = 0; i < 10; i++) {
        const t = teams.find(x => Number(x.slot) === i) || { slot: i, name: '', totalARS: 0, commissionPercent: 0, cotizado: false };
        const totA = Number(t.totalARS || 0);
        const pct = Math.max(0, Math.min(100, Number(t.commissionPercent || 0)));
        const commARS = Math.round(totA * (pct / 100));
        const netA = Math.max(0, totA - commARS);
        const teamCotizado = !!t.cotizado;
        totalARS += totA;
        totalCommARS += commARS;
        totalNetARS += netA;
        const precioUSDT = rate > 0 ? (netA / rate) : 0;
        // Tinte verde sutil en filas cotizadas para ver de un vistazo.
        const rowBg = teamCotizado ? 'background:rgba(0,255,102,0.04);' : '';
        h += '<tr style="' + rowBg + 'border-top:1px solid rgba(255,255,255,0.05);">';
        h += '<td style="padding:7px;text-align:center;color:#888;font-weight:700;">' + (i + 1) + '</td>';
        h += '<td style="padding:7px;">';
        h += '<input type="text" data-cot-team-slot="' + i + '" data-cot-team-field="name" value="' + escapeHtml(t.name || '') + '" placeholder="Nombre equipo" maxlength="80" ' + ro + ' style="' + roCss + 'width:100%;background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#fff;padding:6px 10px;border-radius:6px;font-size:12.5px;font-weight:600;">';
        h += '</td>';
        h += '<td style="padding:7px;text-align:right;">';
        h += '<input type="number" min="0" step="1" data-cot-team-slot="' + i + '" data-cot-team-field="totalARS" value="' + (totA || '') + '" placeholder="0" ' + ro + ' oninput="_cotRecompute(' + escapeJsArg(it.id) + scopeArg + ')" style="' + roCss + 'width:120px;background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#fff;padding:6px 10px;border-radius:6px;font-size:12.5px;font-weight:700;text-align:right;">';
        h += '</td>';
        h += '<td style="padding:7px;text-align:right;">';
        h += '<input type="number" min="0" max="100" step="0.1" data-cot-team-slot="' + i + '" data-cot-team-field="commissionPercent" value="' + (pct || '') + '" placeholder="0" ' + ro + ' oninput="_cotRecompute(' + escapeJsArg(it.id) + scopeArg + ')" style="' + roCss + 'width:70px;background:rgba(0,0,0,0.30);border:1px solid rgba(255,170,102,0.30);color:#ffaa66;padding:6px 8px;border-radius:6px;font-size:12.5px;font-weight:700;text-align:right;" title="% comisión que se descuenta">';
        h += '</td>';
        h += '<td data-cot-net-slot="' + i + '" style="padding:7px;text-align:right;color:#fff;font-weight:700;font-size:12px;">' + (netA > 0 ? formatMoney(netA) : '—') + '</td>';
        h += '<td data-cot-precio-slot="' + i + '" style="padding:7px;text-align:right;color:#00c896;font-weight:800;font-size:13px;">' + (rate > 0 && netA > 0 ? precioUSDT.toFixed(2) + ' USDT' : '—') + '</td>';
        // Columna ESTADO — tilde por equipo. Solo se puede tildar cuando la
        // cotización está cerrada Y el equipo tiene monto (>0). En draft
        // mostramos un placeholder porque todavía está cargando data.
        h += '<td style="padding:7px;text-align:center;">';
        if (totA <= 0) {
            h += '<span style="color:#444;font-size:11px;">—</span>';
        } else if (!isClosed) {
            h += '<span style="color:#666;font-size:10px;font-style:italic;" title="Cerrá la cotización primero para poder tildar equipos">cerrá primero</span>';
        } else if (teamCotizado) {
            const tip = t.cotizedAt ? 'Cotizado el ' + formatDate(t.cotizedAt) + (t.cotizedBy ? ' por ' + t.cotizedBy : '') : 'Cotizado';
            h += '<button onclick="toggleTeamCotizado(' + escapeJsArg(it.id) + ',' + i + scopeArg + ')" title="' + escapeHtml(tip) + '" style="background:linear-gradient(135deg,#00ff66 0%,#00c896 100%);color:#000;border:none;padding:5px 10px;border-radius:6px;font-weight:900;font-size:11px;cursor:pointer;letter-spacing:0.3px;">✓ COTIZADO</button>';
        } else {
            h += '<button onclick="toggleTeamCotizado(' + escapeJsArg(it.id) + ',' + i + scopeArg + ')" title="Marcar este equipo como cotizado" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.40);padding:5px 10px;border-radius:6px;font-weight:800;font-size:11px;cursor:pointer;letter-spacing:0.3px;">✗ PENDIENTE</button>';
        }
        h += '</td>';
        h += '</tr>';
    }

    const totalUSDT = rate > 0 ? (totalNetARS / rate) : 0;
    h += '<tr style="border-top:2px solid rgba(0,200,150,0.30);background:rgba(0,200,150,0.06);">';
    h += '<td colspan="2" style="padding:9px;text-align:right;color:#00c896;font-weight:900;font-size:12px;letter-spacing:1px;">TOTAL</td>';
    h += '<td data-cot-total-ars style="padding:9px;text-align:right;color:#fff;font-weight:900;font-size:13px;">' + formatMoney(totalARS) + '</td>';
    h += '<td data-cot-total-comm style="padding:9px;text-align:right;color:#ffaa66;font-weight:900;font-size:12px;">−' + formatMoney(totalCommARS) + '</td>';
    h += '<td data-cot-total-net style="padding:9px;text-align:right;color:#fff;font-weight:900;font-size:13px;">' + formatMoney(totalNetARS) + '</td>';
    h += '<td data-cot-total-usdt style="padding:9px;text-align:right;color:#00c896;font-weight:900;font-size:13.5px;">' + (rate > 0 ? totalUSDT.toFixed(2) + ' USDT' : '—') + '</td>';
    h += '<td style="padding:9px;text-align:center;color:#aaa;font-weight:900;font-size:11px;">' + (it.teamsCotizadasN || 0) + ' / ' + ((it.teamsCotizadasN || 0) + (it.teamsPendientesN || 0)) + '</td>';
    h += '</tr>';

    h += '</tbody></table></div>';

    // Notas + meta
    h += '<div style="margin-top:10px;display:flex;gap:10px;flex-wrap:wrap;align-items:end;">';
    h += '<div style="flex:1;min-width:260px;">';
    h += '<label style="color:#aaa;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:0.5px;display:block;margin-bottom:4px;">Notas (opcional)</label>';
    h += '<input type="text" data-cot-field="notes" value="' + escapeHtml(it.notes || '') + '" maxlength="500" placeholder="Detalle, recordatorio…" style="width:100%;background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#fff;padding:7px 10px;border-radius:6px;font-size:12px;">';
    h += '</div>';
    h += '<div style="color:#666;font-size:10.5px;text-align:right;">';
    if (isClosed && it.closedAt) {
        h += '🔒 Cerrada: <strong style="color:#00d4ff;">' + escapeHtml(formatDate(it.closedAt)) + '</strong>';
        if (it.closedBy) h += ' por ' + escapeHtml(it.closedBy);
        h += '<br>';
    }
    if (it.cotizado && it.cotizedAt) {
        h += '✓ Cotizado: <strong style="color:#0f0;">' + escapeHtml(formatDate(it.cotizedAt)) + '</strong>';
        if (it.cotizedBy) h += ' por ' + escapeHtml(it.cotizedBy);
        h += '<br>';
    }
    if (it.createdBy) h += 'Creado por ' + escapeHtml(it.createdBy);
    h += '</div>';
    h += '</div>';

    h += '</div>';
    return h;
}

// Recalcula los precios en USDT, neto y totales cuando cambia el rate,
// un total $ o un % de comisión.
function _cotRecompute(id, scope) {
    scope = scope || 'interna';
    const card = document.getElementById(_cotCardIdPrefix(scope) + id);
    if (!card) return;
    const rateInput = card.querySelector('[data-cot-field="usdtRate"]');
    const rate = Number((rateInput && rateInput.value) || 0);
    let totalARS = 0;
    let totalCommARS = 0;
    let totalNetARS = 0;
    for (let i = 0; i < 10; i++) {
        const totInput = card.querySelector('[data-cot-team-slot="' + i + '"][data-cot-team-field="totalARS"]');
        const pctInput = card.querySelector('[data-cot-team-slot="' + i + '"][data-cot-team-field="commissionPercent"]');
        const totA = Number((totInput && totInput.value) || 0);
        const pct = Math.max(0, Math.min(100, Number((pctInput && pctInput.value) || 0)));
        const commARS = Math.round(totA * (pct / 100));
        const netA = Math.max(0, totA - commARS);
        totalARS += totA;
        totalCommARS += commARS;
        totalNetARS += netA;
        const netCell = card.querySelector('[data-cot-net-slot="' + i + '"]');
        if (netCell) netCell.textContent = netA > 0 ? formatMoney(netA) : '—';
        const precioCell = card.querySelector('[data-cot-precio-slot="' + i + '"]');
        if (precioCell) {
            precioCell.textContent = (rate > 0 && netA > 0) ? (netA / rate).toFixed(2) + ' USDT' : '—';
        }
    }
    const totA = card.querySelector('[data-cot-total-ars]');
    if (totA) totA.textContent = formatMoney(totalARS);
    const totC = card.querySelector('[data-cot-total-comm]');
    if (totC) totC.textContent = '−' + formatMoney(totalCommARS);
    const totN = card.querySelector('[data-cot-total-net]');
    if (totN) totN.textContent = formatMoney(totalNetARS);
    const totU = card.querySelector('[data-cot-total-usdt]');
    if (totU) totU.textContent = rate > 0 ? (totalNetARS / rate).toFixed(2) + ' USDT' : '—';
}

async function createCotizacion(scope) {
    scope = scope || 'interna';
    const inputId = scope === 'externa' ? 'newCotExDate' : 'newCotDate';
    const inp = document.getElementById(inputId);
    const dateKey = inp ? inp.value : '';
    if (!/^\d{4}-\d{2}-\d{2}$/.test(dateKey)) {
        showToast('Elegí una fecha válida', 'error');
        return;
    }
    try {
        const r = await authFetch(_cotApiBase(scope), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ dateKey })
        });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error al crear', 'error');
            return;
        }
        showToast('✅ Cotización creada', 'success');
        loadCotizaciones(scope);
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

async function createCotizacionExterno() { return createCotizacion('externa'); }

// Extrae el payload (dateKey, rate, notes, teams) desde el DOM de la tarjeta.
function _collectCotizacionPayload(id, scope) {
    scope = scope || 'interna';
    const card = document.getElementById(_cotCardIdPrefix(scope) + id);
    if (!card) return null;
    const dateKey = (card.querySelector('[data-cot-field="dateKey"]') || {}).value || '';
    const usdtRate = Number((card.querySelector('[data-cot-field="usdtRate"]') || {}).value || 0);
    const notes = (card.querySelector('[data-cot-field="notes"]') || {}).value || '';
    const teams = [];
    for (let i = 0; i < 10; i++) {
        const nameEl = card.querySelector('[data-cot-team-slot="' + i + '"][data-cot-team-field="name"]');
        const totEl  = card.querySelector('[data-cot-team-slot="' + i + '"][data-cot-team-field="totalARS"]');
        const pctEl  = card.querySelector('[data-cot-team-slot="' + i + '"][data-cot-team-field="commissionPercent"]');
        teams.push({
            slot: i,
            name: nameEl ? nameEl.value : '',
            totalARS: Number((totEl && totEl.value) || 0),
            commissionPercent: Number((pctEl && pctEl.value) || 0)
        });
    }
    return { dateKey, usdtRate, notes, teams };
}

// PUT sin reload — devuelve true/false.
async function _persistCotizacion(id, payload, scope) {
    scope = scope || 'interna';
    try {
        const r = await authFetch(_cotApiBase(scope) + '/' + encodeURIComponent(id), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error al guardar', 'error');
            return false;
        }
        return true;
    } catch (e) {
        showToast('Error de conexión', 'error');
        return false;
    }
}

async function saveCotizacion(id, scope) {
    scope = scope || 'interna';
    const payload = _collectCotizacionPayload(id, scope);
    if (!payload) return;
    const ok = await _persistCotizacion(id, payload, scope);
    if (ok) {
        showToast('💾 Guardado', 'success');
        loadCotizaciones(scope);
    }
}

// Guarda los nombres + % comisión de los equipos como PLANTILLA para los
// próximos cierres del mismo scope. Los montos NO se incluyen — siempre
// arrancan en 0 en cada cierre nuevo.
async function saveCotizacionDefaults(id, scope) {
    scope = scope || 'interna';
    const payload = _collectCotizacionPayload(id, scope);
    if (!payload) return;
    if (!confirm('¿Guardar los nombres y % de comisión actuales como plantilla?\n\nLos próximos cierres del scope ' + scope.toUpperCase() + ' van a arrancar con estos nombres y porcentajes pre-cargados.')) return;
    // Sólo mandamos name + commissionPercent (no montos).
    const teams = payload.teams.map(t => ({
        slot: t.slot,
        name: t.name || '',
        commissionPercent: Number(t.commissionPercent) || 0
    }));
    try {
        const r = await authFetch(_cotApiBase(scope) + '/defaults', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ teams })
        });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error al guardar plantilla', 'error');
            return;
        }
        showToast('⭐ Plantilla guardada · los próximos cierres arrancan con esto', 'success');
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

// Cierra la cotización: primero guarda lo que esté cargado (para no perder
// cambios pendientes), después llama al endpoint /close que lockea los
// datos (rate, equipos, fecha). El tag cotizado sigue editable después.
async function closeCotizacion(id, scope) {
    scope = scope || 'interna';
    if (!confirm('¿Cerrar esta cotización? Después no vas a poder editar equipos, USDT ni la fecha (sí podés cambiar el tag cotizado/no cotizado).\n\nSe puede reabrir con "🔓 REABRIR" si te equivocás.')) return;
    const payload = _collectCotizacionPayload(id, scope);
    if (!payload) return;
    const saved = await _persistCotizacion(id, payload, scope);
    if (!saved) return;
    try {
        const r = await authFetch(_cotApiBase(scope) + '/' + encodeURIComponent(id) + '/close', { method: 'POST' });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast('Guardado, pero error al cerrar: ' + (d.error || ''), 'error');
            loadCotizaciones(scope);
            return;
        }
        showToast('🔒 Cotización cerrada', 'success');
        loadCotizaciones(scope);
    } catch (e) {
        showToast('Guardado, pero falló el cierre', 'error');
        loadCotizaciones(scope);
    }
}

async function reopenCotizacion(id, scope) {
    scope = scope || 'interna';
    if (!confirm('¿Reabrir esta cotización para volver a editar?')) return;
    try {
        const r = await authFetch(_cotApiBase(scope) + '/' + encodeURIComponent(id) + '/reopen', { method: 'POST' });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error al reabrir', 'error');
            return;
        }
        showToast('🔓 Reabierta — ya podés editar', 'success');
        loadCotizaciones(scope);
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

// Tildea/destildea un equipo individual de una cotización cerrada.
// El server actualiza el flag de la entry si todos quedaron cotizados.
async function toggleTeamCotizado(id, slot, scope) {
    scope = scope || 'interna';
    try {
        const r = await authFetch(_cotApiBase(scope) + '/' + encodeURIComponent(id) + '/team/' + slot + '/toggle', { method: 'POST' });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error', 'error');
            return;
        }
        showToast(d.teamCotizado ? '✓ Equipo cotizado' : '✗ Equipo vuelto a pendiente', 'success');
        // Mantener expandida la card que recién modificó.
        _cotExpanded[id] = true;
        loadCotizaciones(scope);
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

// Setea el tag cotizado al valor que se pase (true o false). Sólo dispara
// si el valor actual difiere — idempotente desde el lado del cliente.
async function setCotizado(id, target, scope) {
    scope = scope || 'interna';
    const item = (_cotCache(scope) || []).find(x => x.id === id);
    if (!item) return;
    // En el modelo nuevo el flag "todas cotizadas" es derivado (allCotizadas).
    // Comparamos contra eso para no toggle-ar dos veces si el target ya está.
    const currentlyAll = !!(item.allCotizadas || item.cotizado);
    if (currentlyAll === !!target) {
        showToast('Ya estaba en ese estado', 'info');
        return;
    }
    try {
        const r = await authFetch(_cotApiBase(scope) + '/' + encodeURIComponent(id) + '/toggle', { method: 'POST' });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error', 'error');
            return;
        }
        showToast(d.cotizado ? '✓ Marcado como COTIZADO' : '✗ Marcado SIN COTIZAR', 'success');
        loadCotizaciones(scope);
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

async function deleteCotizacion(id, scope) {
    scope = scope || 'interna';
    const pin = prompt('PIN para borrar la cotización:');
    if (pin == null) return;
    if (!pin) { showToast('PIN requerido', 'error'); return; }
    try {
        const r = await authFetch(_cotApiBase(scope) + '/' + encodeURIComponent(id) + '?pin=' + encodeURIComponent(pin), { method: 'DELETE' });
        const d = await r.json();
        if (!r.ok || !d.success) {
            showToast(d.error || 'Error', 'error');
            return;
        }
        showToast('🗑 Eliminada', 'success');
        loadCotizaciones(scope);
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

// ============================================================
// CENTRAL DE HISTORIAL
// ============================================================
// Consolida cotizaciones INTERNAS + EXTERNAS en una sola vista.
// Cada cotización cerrada tiene equipos con tilde individual (cotizado).
// Aquí agrupamos los eventos por período (día/semana/mes) y mostramos:
//   - Resumen del período (cantidad de eventos, total $, total USDT, comisión)
//   - Detalle expandible: cada evento con equipo, scope, monto, USDT, quién
//
// Datos se cargan llamando las dos APIs de cotizaciones existentes y
// procesando todo client-side (los volúmenes son chicos, no hace falta
// endpoint dedicado).

// Una vista por scope. Soporta 'all' (central, junta los dos), 'interna' o
// 'externa'. Cada vista mantiene su propio período y expansión por id de
// período para que las tres se naveguen independientemente sin pisarse.
const _histViewState = {
    all:     { period: 'week', expanded: {} },
    interna: { period: 'week', expanded: {} },
    externa: { period: 'week', expanded: {} }
};
function _histBodyId(view) {
    if (view === 'interna') return 'historialBuffaloBody';
    if (view === 'externa') return 'historialCotizacionBody';
    return 'centralHistorialBody';
}
function setCentralPeriod(p, view) {
    view = view || 'all';
    if (!_histViewState[view]) return;
    _histViewState[view].period = p;
    _histViewState[view].expanded = {}; // reset al cambiar granularidad
    _renderHistorialView(view);
}
function toggleCentralPeriod(key, view) {
    view = view || 'all';
    if (!_histViewState[view]) return;
    _histViewState[view].expanded[key] = !_histViewState[view].expanded[key];
    _renderHistorialView(view);
}

let _centralData = null; // { internas, externas } cargados — compartido entre las 3 vistas

// Carga ambas listas y refresca la vista pedida (o todas si view='all'
// porque la central las necesita combinadas).
async function _loadHistorialData(view) {
    const body = document.getElementById(_histBodyId(view));
    if (!body) return;
    body.innerHTML = '<div style="color:#aaa;text-align:center;padding:24px;">⏳ Cargando…</div>';
    try {
        const [rInt, rExt] = await Promise.all([
            authFetch('/api/admin/cotizaciones'),
            authFetch('/api/admin/cotizaciones-externo')
        ]);
        const [dInt, dExt] = await Promise.all([rInt.json(), rExt.json()]);
        if (!rInt.ok || !dInt.success) throw new Error(dInt.error || 'No se pudieron cargar las internas');
        if (!rExt.ok || !dExt.success) throw new Error(dExt.error || 'No se pudieron cargar las externas');
        _centralData = {
            internas: dInt.items || [],
            externas: dExt.items || []
        };
        _renderHistorialView(view);
    } catch (e) {
        console.error('[historial:' + view + '] load fail:', e);
        body.innerHTML = '<div style="color:#f55;text-align:center;padding:24px;">Error: ' + escapeHtml(e.message || String(e)) + '</div>';
    }
}

async function loadCentralHistorial()    { return _loadHistorialData('all'); }
async function loadHistorialBuffalo()    { return _loadHistorialData('interna'); }
async function loadHistorialCotizacion() { return _loadHistorialData('externa'); }

// Aplana las cotizaciones a una lista de eventos (1 evento por equipo
// cotizado). `view` controla qué scopes incluir:
//   'all'     → internas + externas
//   'interna' → sólo internas
//   'externa' → sólo externas
function _centralBuildEvents(view) {
    if (!_centralData) return [];
    const out = [];
    const push = (cot, scopeKey) => {
        const rate = Number(cot.usdtRate || 0);
        const teams = Array.isArray(cot.teams) ? cot.teams : [];
        for (const t of teams) {
            if (!t.cotizado || !t.cotizedAt) continue;
            const commARS = Number(t.commissionARS || 0);
            out.push({
                scope: scopeKey,
                cotId: cot.id,
                cotDateKey: cot.dateKey,
                slot: t.slot,
                name: t.name || ('Equipo ' + (Number(t.slot || 0) + 1)),
                netARS: Number(t.netARS || 0),
                precioUSDT: Number(t.precioUSDT || 0),
                commissionARS: commARS,
                commissionUSDT: rate > 0 ? +(commARS / rate).toFixed(2) : 0,
                cotizedAt: t.cotizedAt,
                cotizedBy: t.cotizedBy || ''
            });
        }
    };
    if (view !== 'externa') {
        for (const c of (_centralData.internas || [])) push(c, 'interna');
    }
    if (view !== 'interna') {
        for (const c of (_centralData.externas || [])) push(c, 'externa');
    }
    out.sort((a, b) => new Date(b.cotizedAt) - new Date(a.cotizedAt));
    return out;
}

// Clave de período en formato canónico ordenable por string.
function _centralPeriodKey(date, period) {
    const d = new Date(date);
    const y = d.getUTCFullYear();
    const m = d.getUTCMonth() + 1;
    const day = d.getUTCDate();
    if (period === 'day') {
        return y + '-' + String(m).padStart(2, '0') + '-' + String(day).padStart(2, '0');
    }
    if (period === 'month') {
        return y + '-' + String(m).padStart(2, '0');
    }
    // ISO week (year + week#)
    const dt = new Date(Date.UTC(y, m - 1, day));
    dt.setUTCDate(dt.getUTCDate() + 4 - (dt.getUTCDay() || 7));
    const yearStart = new Date(Date.UTC(dt.getUTCFullYear(), 0, 1));
    const weekNum = Math.ceil(((dt - yearStart) / 86400000 + 1) / 7);
    return dt.getUTCFullYear() + '-W' + String(weekNum).padStart(2, '0');
}

function _centralPeriodLabel(key, period) {
    if (period === 'day') return '📆 ' + key;
    if (period === 'month') return '📅 ' + key;
    return '🗓️ Semana ' + key;
}

// Wrapper para la vista central (mantiene el nombre histórico).
function _renderCentralHistorial() { return _renderHistorialView('all'); }

function _renderHistorialView(view) {
    view = view || 'all';
    const state = _histViewState[view] || _histViewState.all;
    const body = document.getElementById(_histBodyId(view));
    if (!body) return;
    if (!_centralData) {
        body.innerHTML = '<div style="color:#aaa;text-align:center;padding:24px;">Cargá los datos primero.</div>';
        return;
    }
    const events = _centralBuildEvents(view);
    const period = state.period;

    // === Header: filtros de período + totales globales ===
    let h = '';
    h += '<div style="background:rgba(255,255,255,0.04);border-radius:8px;padding:12px 14px;margin-bottom:14px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;margin-bottom:10px;">';
    h += '<div style="color:#fff;font-weight:900;font-size:13px;letter-spacing:0.5px;">🗂️ AGRUPADO POR</div>';
    h += '<div style="display:flex;gap:6px;">';
    const tabBtn = (k, lbl) => {
        const active = (period === k);
        const css = active
            ? 'background:rgba(212,175,55,0.20);color:#d4af37;border-color:rgba(212,175,55,0.55);'
            : 'background:rgba(255,255,255,0.04);color:#aaa;border-color:rgba(255,255,255,0.10);';
        return '<button onclick="setCentralPeriod(\'' + k + '\',\'' + view + '\')" style="' + css + 'border:1px solid;padding:6px 14px;border-radius:7px;font-weight:800;font-size:11.5px;cursor:pointer;letter-spacing:0.4px;">' + lbl + '</button>';
    };
    h += tabBtn('day', '📆 Diario');
    h += tabBtn('week', '🗓️ Semanal');
    h += tabBtn('month', '📅 Mensual');
    h += '</div>';
    h += '</div>';
    h += '</div>';

    // Resumen global (todos los eventos juntos)
    const sumNet = events.reduce((a, e) => a + e.netARS, 0);
    const sumUSDT = events.reduce((a, e) => a + e.precioUSDT, 0);
    const sumComm = events.reduce((a, e) => a + e.commissionARS, 0);
    const sumCommUSDT = events.reduce((a, e) => a + e.commissionUSDT, 0);
    const internasN = events.filter(e => e.scope === 'interna').length;
    const externasN = events.filter(e => e.scope === 'externa').length;

    const eventsSubtitle = (view === 'all')
        ? (internasN + ' interna · ' + externasN + ' externa')
        : (view === 'interna' ? 'sólo Buffalo (interna)' : 'sólo Externo');
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin-bottom:14px;">';
    h += _centralStatCard('💎 Total cotizado', formatMoney(Math.round(sumNet)), sumUSDT.toFixed(2) + ' USDT', '#0f0', 'rgba(0,255,102,0.10)', 'rgba(0,255,102,0.30)');
    h += _centralStatCard('🏦 Comisión total', formatMoney(Math.round(sumComm)), sumCommUSDT.toFixed(2) + ' USDT', '#ffd700', 'rgba(255,215,0,0.10)', 'rgba(255,215,0,0.35)');
    h += _centralStatCard('📊 Eventos totales', String(events.length), eventsSubtitle, '#00d4ff', 'rgba(0,212,255,0.08)', 'rgba(0,212,255,0.30)');
    h += '</div>';

    if (events.length === 0) {
        h += '<div style="background:rgba(255,255,255,0.03);border:1px dashed rgba(255,255,255,0.15);border-radius:10px;padding:30px;text-align:center;color:#888;font-size:13px;">Todavía no hay eventos cotizados. Tildeá equipos en COTIZACIONES o COTIZACIONES EXTERNO para que aparezcan acá.</div>';
        body.innerHTML = h;
        return;
    }

    // === Agrupar por período ===
    const groups = {}; // key → { events: [], totals }
    for (const ev of events) {
        const k = _centralPeriodKey(ev.cotizedAt, period);
        if (!groups[k]) groups[k] = { key: k, events: [], net: 0, usdt: 0, comm: 0, commUSDT: 0, internas: 0, externas: 0 };
        const g = groups[k];
        g.events.push(ev);
        g.net += ev.netARS;
        g.usdt += ev.precioUSDT;
        g.comm += ev.commissionARS;
        g.commUSDT += ev.commissionUSDT;
        if (ev.scope === 'interna') g.internas += 1; else g.externas += 1;
    }
    const sortedKeys = Object.keys(groups).sort().reverse();

    h += '<div style="display:flex;flex-direction:column;gap:8px;">';
    for (const k of sortedKeys) {
        const g = groups[k];
        const isOpen = !!state.expanded[k];
        const accent = '#d4af37';
        h += '<div style="background:rgba(0,0,0,0.30);border:1px solid rgba(212,175,55,0.25);border-radius:10px;overflow:hidden;">';
        h += '<div onclick="toggleCentralPeriod(\'' + escapeHtml(k) + '\',\'' + view + '\')" style="cursor:pointer;padding:11px 14px;display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;user-select:none;background:' + (isOpen ? 'rgba(212,175,55,0.05)' : 'transparent') + ';">';
        h += '<div style="color:' + accent + ';font-size:12px;width:18px;text-align:center;">' + (isOpen ? '▼' : '▶') + '</div>';
        h += '<div>';
        h += '<div style="color:#fff;font-weight:900;font-size:13.5px;">' + _centralPeriodLabel(k, period) + '</div>';
        const breakdown = (view === 'all')
            ? (g.events.length + ' eventos · ' + g.internas + ' int · ' + g.externas + ' ext')
            : (g.events.length + ' eventos');
        h += '<div style="color:#aaa;font-size:11px;margin-top:2px;">' + breakdown + '</div>';
        h += '</div>';
        h += '<div style="text-align:right;">';
        h += '<div style="color:#aaffaa;font-weight:900;font-size:13.5px;">' + formatMoney(Math.round(g.net)) + '</div>';
        h += '<div style="color:#aaa;font-size:11px;">' + g.usdt.toFixed(2) + ' USDT · com: ' + formatMoney(Math.round(g.comm)) + '</div>';
        h += '</div>';
        h += '</div>';

        if (isOpen) {
            h += '<div style="border-top:1px solid rgba(255,255,255,0.06);padding:8px 14px;">';
            h += '<table style="width:100%;border-collapse:collapse;font-size:11.5px;">';
            h += '<thead><tr style="color:#888;border-bottom:1px solid rgba(255,255,255,0.08);">';
            h += '<th style="padding:6px;text-align:left;font-size:10px;letter-spacing:0.5px;">SCOPE</th>';
            h += '<th style="padding:6px;text-align:left;font-size:10px;letter-spacing:0.5px;">FECHA TILDE</th>';
            h += '<th style="padding:6px;text-align:left;font-size:10px;letter-spacing:0.5px;">EQUIPO</th>';
            h += '<th style="padding:6px;text-align:left;font-size:10px;letter-spacing:0.5px;">CIERRE</th>';
            h += '<th style="padding:6px;text-align:right;font-size:10px;letter-spacing:0.5px;">NETO $</th>';
            h += '<th style="padding:6px;text-align:right;font-size:10px;letter-spacing:0.5px;">USDT</th>';
            h += '<th style="padding:6px;text-align:right;font-size:10px;letter-spacing:0.5px;">COMISIÓN</th>';
            h += '<th style="padding:6px;text-align:left;font-size:10px;letter-spacing:0.5px;">POR</th>';
            h += '</tr></thead><tbody>';
            for (const ev of g.events) {
                const scopeBadge = ev.scope === 'externa'
                    ? '<span style="background:rgba(0,150,255,0.15);color:#0080ff;padding:2px 8px;border-radius:4px;font-weight:800;font-size:10px;">🌐 EXT</span>'
                    : '<span style="background:rgba(0,200,150,0.15);color:#00c896;padding:2px 8px;border-radius:4px;font-weight:800;font-size:10px;">💱 INT</span>';
                h += '<tr style="border-bottom:1px solid rgba(255,255,255,0.04);">';
                h += '<td style="padding:6px;">' + scopeBadge + '</td>';
                h += '<td style="padding:6px;color:#ddd;">' + escapeHtml(formatDate(ev.cotizedAt)) + '</td>';
                h += '<td style="padding:6px;color:#fff;font-weight:700;">' + escapeHtml(ev.name) + '</td>';
                h += '<td style="padding:6px;color:#aaa;">' + escapeHtml(ev.cotDateKey) + '</td>';
                h += '<td style="padding:6px;text-align:right;color:#fff;font-weight:700;">' + formatMoney(ev.netARS) + '</td>';
                h += '<td style="padding:6px;text-align:right;color:#aaffaa;font-weight:700;">' + ev.precioUSDT.toFixed(2) + '</td>';
                h += '<td style="padding:6px;text-align:right;color:#ffd700;font-weight:700;">' + formatMoney(ev.commissionARS) + '</td>';
                h += '<td style="padding:6px;color:#888;">' + escapeHtml(ev.cotizedBy || '—') + '</td>';
                h += '</tr>';
            }
            h += '</tbody></table>';
            h += '</div>';
        }
        h += '</div>';
    }
    h += '</div>';

    body.innerHTML = h;
}

function _centralStatCard(label, big, small, color, bg, border) {
    let h = '<div style="background:' + bg + ';border:1px solid ' + border + ';border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">' + label + '</div>';
    h += '<div style="color:' + color + ';font-weight:900;font-size:18px;margin-top:3px;">' + big + '</div>';
    h += '<div style="color:#bbb;font-weight:700;font-size:11.5px;">' + small + '</div>';
    h += '</div>';
    return h;
}

// ============================================================
// EMPLEADOS POR ESTRUCTURA
// ============================================================
// 3 sectores (ganamos, publicidad, buffalo) cada uno con puestos.
// Cada empleado tiene nombre, horario, sueldo y opcionalmente feriados
// con pago extra. Total mensual = sueldo + Σ feriados.
// Los puestos son strings libres — los defaults sugeridos se ofrecen al
// crear un nuevo grupo, pero el dueño puede crear cualquier puesto.

const EMP_SECTORS_UI = [
    { key: 'ganamos',    label: '💼 GANAMOS',    color: '#25d366' },
    { key: 'publicidad', label: '📢 PUBLICIDAD', color: '#00d4ff' },
    { key: 'buffalo',    label: '🐃 BUFFALO',    color: '#ffd700' }
];
const EMP_DEFAULT_ROLES = [
    { key: 'encargados',     label: 'Encargados' },
    { key: 'pagos',          label: 'Pagos' },
    { key: 'comunidad',      label: 'Comunidad' },
    { key: 'cargas',         label: 'Cargas' },
    { key: 'recontactacion', label: 'Recontactación' },
    { key: 'revision_chat',  label: 'Revisión de chat' }
];

let _empCache = [];
let _empSector = 'ganamos';
let _empSectorConfigs = {}; // { sector: { feriadosGenerales:[], usdRate } }
let _empClosingsCache = []; // historial de cierres

function _empRoleLabel(role) {
    const def = EMP_DEFAULT_ROLES.find(r => r.key === role);
    if (def) return def.label;
    // role libre — capitalizar y reemplazar _ por espacio
    return String(role || '').replace(/_/g, ' ').replace(/^\w/, c => c.toUpperCase());
}

const EMP_FRANCO_DAYS_UI = [
    { key: 'lunes',     short: 'Lun' },
    { key: 'martes',    short: 'Mar' },
    { key: 'miercoles', short: 'Mié' },
    { key: 'jueves',    short: 'Jue' },
    { key: 'viernes',   short: 'Vie' },
    { key: 'sabado',    short: 'Sáb' },
    { key: 'domingo',   short: 'Dom' }
];

// Cálculo local del pago — espeja _empCompute del server para que el
// resumen refleje al instante lo cargado antes de guardar.
function _empComputeLocal(e) {
    const sueldo = Number(e.sueldoARS || 0);
    const valorDia = sueldo / 30;
    const feriados = Array.isArray(e.feriados) ? e.feriados : [];
    const faltantes = Array.isArray(e.faltantes) ? e.faltantes : [];
    const descuentos = Array.isArray(e.descuentos) ? e.descuentos : [];
    const feriadosTotal = feriados.reduce((s, f) => {
        const a = Number(f.amountARS || 0);
        return s + (a > 0 ? a : valorDia);
    }, 0);
    // Feriados generales del sector que el empleado cobra (no excluidos).
    const excl = new Set(Array.isArray(e.feriadosGeneralesExcluidos) ? e.feriadosGeneralesExcluidos : []);
    const generales = ((_empSectorConfigs[e.sector] || {}).feriadosGenerales) || [];
    let feriadosGeneralesTotal = 0, feriadosGeneralesCount = 0;
    for (const g of generales) {
        if (excl.has(g.id)) continue;
        const a = Number(g.amountARS || 0);
        feriadosGeneralesTotal += (a > 0 ? a : valorDia);
        feriadosGeneralesCount++;
    }
    const faltantesTotal = faltantes.length * valorDia;
    const descuentosTotal = descuentos.reduce((s, d) => s + Number(d.amountARS || 0), 0);
    const ajustes = Array.isArray(e.ajustes) ? e.ajustes : [];
    const ajustesTotal = ajustes.reduce((s, a) => s + Number(a.amountARS || 0), 0);
    const comisionUSD = Number(e.comisionUSD != null ? e.comisionUSD : 2);
    const usdRate = Number(((_empSectorConfigs[e.sector] || {}).usdRate) || 0);
    const comisionARS = comisionUSD * usdRate;
    const totalMensual = sueldo + feriadosTotal + feriadosGeneralesTotal - faltantesTotal - descuentosTotal + ajustesTotal;
    return {
        sueldoARS: sueldo, valorDia,
        feriadosTotal, feriadosCount: feriados.length,
        feriadosGeneralesTotal, feriadosGeneralesCount,
        faltantesTotal, faltantesCount: faltantes.length,
        descuentosTotal, descuentosCount: descuentos.length,
        ajustesTotal, ajustesCount: ajustes.length,
        comisionUSD, comisionARS,
        totalMensual,
        costoTotal: totalMensual + comisionARS
    };
}

// Vuelca los inputs del DOM de un empleado al cache, para no perder
// ediciones sin guardar cuando se re-renderiza (al sumar/sacar items).
function _empSyncFromDom(id) {
    const emp = (_empCache || []).find(e => e.id === id);
    const payload = _collectEmpPayload(id);
    if (emp && payload) Object.assign(emp, payload);
    // También preservar lo cargado en la config del sector sin guardar.
    _empSyncSectorCfgFromDom();
    return emp;
}

function setEmpSector(s) {
    _empSector = s;
    _renderEmpleados();
}

async function loadEmpleados() {
    const body = document.getElementById('empleadosBody');
    if (!body) return;
    body.innerHTML = '<div style="color:#aaa;text-align:center;padding:24px;">⏳ Cargando…</div>';
    try {
        const [r, rc] = await Promise.all([
            authFetch('/api/admin/empleados'),
            authFetch('/api/admin/empleados/cierres')
        ]);
        const d = await r.json();
        if (!r.ok || !d.success) throw new Error(d.error || 'No se pudo cargar');
        _empCache = d.items || [];
        _empSectorConfigs = d.sectorConfigs || {};
        try {
            const dc = await rc.json();
            _empClosingsCache = (rc.ok && dc.success) ? (dc.items || []) : [];
        } catch (_) { _empClosingsCache = []; }
        _renderEmpleados();
    } catch (e) {
        console.error('[empleados] load fail:', e);
        body.innerHTML = '<div style="color:#f55;text-align:center;padding:24px;">Error: ' + escapeHtml(e.message || String(e)) + '</div>';
    }
}

// Cierra el período: congela una foto en el historial y deja la hoja limpia.
async function doEmpCierre() {
    const label = (document.getElementById('empCierreLabel') && document.getElementById('empCierreLabel').value || '').trim();
    if (!confirm('¿Cerrar el período' + (label ? ' "' + label + '"' : '') + '?\n\nSe guarda una foto en el historial con el total de cada empleado. Después la hoja queda limpia de feriados/faltas/descuentos — los empleados y sueldos se conservan.')) return;
    try {
        const r = await authFetch('/api/admin/empleados/cierre', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ periodLabel: label })
        });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'No se pudo cerrar', 'error'); return; }
        showToast('✅ Período cerrado — ' + (d.employeeCount || 0) + ' empleados', 'success');
        loadEmpleados();
    } catch (e) {
        showToast('Error al cerrar el período', 'error');
    }
}

async function toggleEmpClosingPaid(id, paid) {
    try {
        const r = await authFetch('/api/admin/empleados/cierres/' + encodeURIComponent(id) + '/paid', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ paid: !!paid })
        });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error', 'error'); return; }
        const c = (_empClosingsCache || []).find(x => x.id === id);
        if (c) { c.paid = !!paid; c.paidAt = d.paidAt; }
        _renderEmpleados();
    } catch (e) {
        showToast('Error al guardar', 'error');
    }
}

async function viewEmpClosing(id) {
    try {
        const r = await authFetch('/api/admin/empleados/cierres/' + encodeURIComponent(id));
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error', 'error'); return; }
        _showEmpClosingModal(d.closing);
    } catch (e) {
        showToast('Error al cargar el cierre', 'error');
    }
}

// Reabre un cierre: si se cerró con un error, vuelve los movimientos de
// ese período a la hoja viva y saca el cierre del historial.
async function reopenEmpClosing(id) {
    if (!confirm('¿Reabrir este cierre?\n\nLos feriados, faltas y descuentos de ese período vuelven a la hoja viva (pisan lo que tengas cargado ahora) y el cierre se saca del historial. Después corregís y volvés a cerrar.')) return;
    try {
        const r = await authFetch('/api/admin/empleados/cierres/' + encodeURIComponent(id) + '/reabrir', { method: 'POST' });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'No se pudo reabrir', 'error'); return; }
        showToast('↩ Cierre reabierto — ' + (d.restored || 0) + ' empleados restaurados', 'success');
        loadEmpleados();
    } catch (e) {
        showToast('Error al reabrir', 'error');
    }
}

function _showEmpClosingModal(c) {
    const old = document.getElementById('empClosingModal');
    if (old) old.remove();
    const fch = c.closedAt ? new Date(c.closedAt).toLocaleString('es-AR') : '';
    let rows = '';
    for (const e of (c.employees || [])) {
        const cp = e.computed || {};
        rows += '<tr style="border-top:1px solid rgba(255,255,255,0.07);">'
            + '<td style="padding:5px 7px;color:#aaa;">' + escapeHtml(e.sector || '') + '</td>'
            + '<td style="padding:5px 7px;color:#fff;">' + escapeHtml(e.name || '—') + '</td>'
            + '<td style="padding:5px 7px;color:#aaa;">' + escapeHtml(e.role || '') + '</td>'
            + '<td style="padding:5px 7px;text-align:right;color:#00d4ff;">' + formatMoney(Math.round(cp.sueldoARS || 0)) + '</td>'
            + '<td style="padding:5px 7px;text-align:right;color:#d4af37;font-weight:800;">' + formatMoney(Math.round(cp.totalMensual || 0)) + '</td>'
            + '</tr>';
    }
    const overlay = document.createElement('div');
    overlay.id = 'empClosingModal';
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,0.85);z-index:40000;display:flex;align-items:flex-start;justify-content:center;padding:18px;overflow-y:auto;';
    overlay.innerHTML =
        '<div style="background:#14141c;border:1.5px solid rgba(212,175,55,0.45);border-radius:14px;max-width:680px;width:100%;padding:18px;">'
        + '<div style="display:flex;justify-content:space-between;align-items:flex-start;gap:10px;margin-bottom:10px;">'
        + '<div><div style="color:#d4af37;font-weight:900;font-size:15px;">🔒 ' + escapeHtml(c.periodLabel || fch || 'Cierre') + (c.paid ? ' · ✅ PAGADO' : '') + '</div>'
        + '<div style="color:#888;font-size:11px;">Cerrado: ' + escapeHtml(fch) + ' · ' + (c.employeeCount || 0) + ' empleados</div></div>'
        + '<button onclick="document.getElementById(\'empClosingModal\').remove()" style="background:none;border:none;color:#999;font-size:22px;cursor:pointer;line-height:1;">×</button>'
        + '</div>'
        + '<div style="color:#fff;font-size:14px;font-weight:900;margin-bottom:8px;">Total del cierre: <span style="color:#d4af37;">' + formatMoney(Math.round(c.grandTotalARS || 0)) + '</span></div>'
        + '<div style="max-height:60vh;overflow-y:auto;"><table style="width:100%;border-collapse:collapse;font-size:11.5px;">'
        + '<tr style="color:#aaa;font-size:10px;text-transform:uppercase;"><th style="padding:5px 7px;text-align:left;">Sector</th><th style="padding:5px 7px;text-align:left;">Nombre</th><th style="padding:5px 7px;text-align:left;">Puesto</th><th style="padding:5px 7px;text-align:right;">Sueldo</th><th style="padding:5px 7px;text-align:right;">Total</th></tr>'
        + rows
        + '</table></div>'
        + '</div>';
    overlay.addEventListener('click', (ev) => { if (ev.target === overlay) overlay.remove(); });
    document.body.appendChild(overlay);
}

function _renderEmpleados() {
    const body = document.getElementById('empleadosBody');
    if (!body) return;
    const items = (_empCache || []).filter(e => e.sector === _empSector);

    let h = '';

    // === Selector de sector ===
    h += '<div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:14px;">';
    for (const s of EMP_SECTORS_UI) {
        const active = s.key === _empSector;
        const bg = active ? s.color : 'rgba(255,255,255,0.04)';
        const color = active ? '#000' : s.color;
        const border = active ? s.color : (s.color + '55');
        h += '<button onclick="setEmpSector(\'' + s.key + '\')" style="flex:1;min-width:140px;background:' + bg + ';color:' + color + ';border:1.5px solid ' + border + ';padding:10px 12px;border-radius:9px;font-weight:900;font-size:13px;letter-spacing:0.5px;cursor:pointer;">' + s.label + '</button>';
    }
    h += '</div>';

    // === Cierre de empleados (global — todos los sectores) ===
    const _clos = _empClosingsCache || [];
    h += '<div style="background:rgba(212,175,55,0.06);border:1.5px solid rgba(212,175,55,0.40);border-radius:11px;padding:13px 14px;margin-bottom:14px;">';
    h += '<div style="color:#d4af37;font-weight:900;font-size:12.5px;letter-spacing:0.5px;margin-bottom:4px;">🔒 CIERRE DE EMPLEADOS</div>';
    h += '<div style="color:#888;font-size:10.5px;margin-bottom:9px;line-height:1.5;">Cerrá el período (el 5 de cada mes o cuando quieras). Se guarda una foto en el historial con el total de cada empleado. Después la hoja arranca limpia: se conservan empleados y sueldos, se resetean feriados / faltas / descuentos.</div>';
    h += '<div style="display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin-bottom:10px;">';
    h += '<input id="empCierreLabel" type="text" maxlength="80" placeholder="Nombre del período (ej: Mayo 2026)" style="flex:1;min-width:180px;background:rgba(0,0,0,0.45);border:1px solid rgba(212,175,55,0.40);color:#fff;padding:8px 11px;border-radius:7px;font-size:13px;box-sizing:border-box;">';
    h += '<button onclick="doEmpCierre()" style="background:linear-gradient(135deg,#d4af37,#f7931e);color:#000;border:none;padding:9px 18px;border-radius:8px;font-weight:900;font-size:12.5px;cursor:pointer;letter-spacing:0.4px;">🔒 CERRAR PERÍODO</button>';
    h += '</div>';
    if (_clos.length === 0) {
        h += '<div style="color:#666;font-size:11px;font-style:italic;">Todavía no hay cierres.</div>';
    } else {
        h += '<div style="color:#aaa;font-size:10.5px;font-weight:800;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">📁 Historial de cierres (' + _clos.length + ')</div>';
        for (const c of _clos) {
            const fch = c.closedAt ? new Date(c.closedAt).toLocaleDateString('es-AR') : '';
            const lbl = c.periodLabel || fch || 'Cierre';
            h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;background:rgba(0,0,0,0.30);border:1px solid ' + (c.paid ? 'rgba(102,255,102,0.35)' : 'rgba(255,255,255,0.08)') + ';border-radius:8px;padding:8px 11px;margin-bottom:6px;">';
            h += '<div style="min-width:0;">';
            h += '<div style="color:#fff;font-weight:800;font-size:12.5px;">' + escapeHtml(lbl) + (c.paid ? ' <span style="color:#66ff66;font-size:10.5px;">✅ PAGADO</span>' : '') + '</div>';
            h += '<div style="color:#888;font-size:10.5px;">' + escapeHtml(fch) + ' · ' + (c.employeeCount || 0) + ' empleados · <strong style="color:#d4af37;">' + formatMoney(Math.round(c.grandTotalARS || 0)) + '</strong></div>';
            h += '</div>';
            h += '<div style="display:flex;gap:5px;flex-wrap:wrap;">';
            h += '<label style="display:flex;align-items:center;gap:4px;font-size:11px;color:#fff;cursor:pointer;background:rgba(255,255,255,0.04);padding:4px 9px;border-radius:6px;"><input type="checkbox" ' + (c.paid ? 'checked' : '') + ' onchange="toggleEmpClosingPaid(\'' + escapeHtml(c.id) + '\', this.checked)"> Pagado</label>';
            h += '<button onclick="viewEmpClosing(\'' + escapeHtml(c.id) + '\')" style="background:rgba(212,175,55,0.12);color:#d4af37;border:1px solid rgba(212,175,55,0.40);padding:4px 11px;border-radius:6px;font-weight:800;font-size:11px;cursor:pointer;">👁 Ver</button>';
            h += '<button onclick="reopenEmpClosing(\'' + escapeHtml(c.id) + '\')" style="background:rgba(0,212,255,0.12);color:#00d4ff;border:1px solid rgba(0,212,255,0.40);padding:4px 11px;border-radius:6px;font-weight:800;font-size:11px;cursor:pointer;">↩ Reabrir</button>';
            h += '</div>';
            h += '</div>';
        }
    }
    h += '</div>';

    // === Resumen de totales del sector ===
    const _cs = items.map(e => _empComputeLocal(e));
    const sectorTotal = _cs.reduce((a, c) => a + c.totalMensual, 0);
    const sectorSueldo = _cs.reduce((a, c) => a + c.sueldoARS, 0);
    const sectorFeriados = _cs.reduce((a, c) => a + c.feriadosTotal + (c.feriadosGeneralesTotal || 0), 0);
    const sectorFaltantes = _cs.reduce((a, c) => a + c.faltantesTotal, 0);
    const sectorDescuentos = _cs.reduce((a, c) => a + c.descuentosTotal, 0);
    const sectorActivos = items.filter(e => e.active !== false).length;

    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:8px;margin-bottom:14px;">';
    h += '<div style="background:rgba(155,48,255,0.10);border:1px solid rgba(155,48,255,0.35);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">💰 Total mensual</div>';
    h += '<div style="color:#c89bff;font-weight:900;font-size:18px;margin-top:3px;">' + formatMoney(Math.round(sectorTotal)) + '</div>';
    h += '<div style="color:#aaa;font-size:11px;">' + sectorActivos + ' empleados activos</div>';
    h += '</div>';
    h += '<div style="background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.25);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">💵 Sueldos base</div>';
    h += '<div style="color:#00d4ff;font-weight:900;font-size:17px;margin-top:3px;">' + formatMoney(Math.round(sectorSueldo)) + '</div>';
    h += '</div>';
    h += '<div style="background:rgba(255,170,102,0.06);border:1px solid rgba(255,170,102,0.25);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">🎉 Feriados</div>';
    h += '<div style="color:#ffaa66;font-weight:900;font-size:17px;margin-top:3px;">+' + formatMoney(Math.round(sectorFeriados)) + '</div>';
    h += '</div>';
    h += '<div style="background:rgba(255,80,80,0.06);border:1px solid rgba(255,80,80,0.25);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">🚫 Faltas</div>';
    h += '<div style="color:#f55;font-weight:900;font-size:17px;margin-top:3px;">-' + formatMoney(Math.round(sectorFaltantes)) + '</div>';
    h += '</div>';
    h += '<div style="background:rgba(255,80,80,0.06);border:1px solid rgba(255,80,80,0.25);border-radius:8px;padding:10px 14px;">';
    h += '<div style="color:#aaa;font-size:10px;font-weight:700;letter-spacing:0.8px;text-transform:uppercase;">➖ Descuentos</div>';
    h += '<div style="color:#f55;font-weight:900;font-size:17px;margin-top:3px;">-' + formatMoney(Math.round(sectorDescuentos)) + '</div>';
    h += '</div>';
    h += '</div>';

    // === Config del sector: feriados generales + valor USD ===
    const _cfg = _empSectorConfigs[_empSector] || { feriadosGenerales: [], usdRate: 0 };
    const _genFer = Array.isArray(_cfg.feriadosGenerales) ? _cfg.feriadosGenerales : [];
    const _usdRate = Number(_cfg.usdRate || 0);
    h += '<div style="background:rgba(255,170,102,0.05);border:1px solid rgba(255,170,102,0.30);border-radius:10px;padding:12px 14px;margin-bottom:14px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-bottom:6px;">';
    h += '<div style="color:#ffaa66;font-weight:900;font-size:12.5px;letter-spacing:0.4px;">🎌 FERIADOS GENERALES DEL SECTOR</div>';
    h += '<button onclick="addEmpGeneralFeriado()" style="background:rgba(255,170,102,0.14);color:#ffaa66;border:1px solid rgba(255,170,102,0.45);padding:5px 11px;border-radius:6px;font-weight:800;font-size:11px;cursor:pointer;">➕ Feriado general</button>';
    h += '</div>';
    h += '<div style="color:#888;font-size:10.5px;margin-bottom:8px;">Aplican a todos los empleados del sector. En cada empleado podés tildar ✓/✗ si lo cobra o no.</div>';
    if (_genFer.length === 0) {
        h += '<div style="color:#666;font-size:11px;font-style:italic;">Sin feriados generales cargados.</div>';
    } else {
        for (let i = 0; i < _genFer.length; i++) {
            const g = _genFer[i] || {};
            h += '<div data-emp-genfer="' + i + '" style="display:grid;grid-template-columns:140px 130px 1fr auto;gap:6px;margin-bottom:4px;align-items:center;">';
            h += '<input data-emp-genfer-field="dateKey" type="date" value="' + escapeHtml(g.dateKey || '') + '" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,170,102,0.25);color:#ffaa66;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;">';
            h += '<input data-emp-genfer-field="amountARS" type="number" min="0" step="1000" value="' + Number(g.amountARS || 0) + '" placeholder="0 = valor/día" title="0 = cada empleado lo cobra a su valor/día" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,170,102,0.25);color:#fff;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;text-align:right;">';
            h += '<input data-emp-genfer-field="note" type="text" value="' + escapeHtml(g.note || '') + '" placeholder="Detalle (ej: Día del trabajador)" maxlength="200" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#ddd;padding:4px 8px;border-radius:5px;font-size:11px;">';
            h += '<button onclick="removeEmpGeneralFeriado(' + i + ')" title="Sacar feriado general" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);padding:4px 8px;border-radius:5px;font-weight:800;font-size:11px;cursor:pointer;">✕</button>';
            h += '</div>';
        }
    }
    h += '<div style="display:flex;gap:9px;flex-wrap:wrap;align-items:center;margin-top:10px;padding-top:9px;border-top:1px dashed rgba(255,255,255,0.10);">';
    h += '<label style="color:#25d366;font-size:11px;font-weight:800;">💵 Valor del dólar (ARS = 1 USD):</label>';
    h += '<input id="empUsdRate" type="number" min="0" step="1" value="' + _usdRate + '" placeholder="ej: 1200" style="width:110px;background:rgba(0,0,0,0.40);border:1px solid rgba(37,211,102,0.35);color:#25d366;padding:5px 9px;border-radius:6px;font-size:12.5px;font-weight:800;text-align:right;">';
    h += '<button onclick="saveEmpSectorConfig()" style="background:rgba(37,211,102,0.16);color:#25d366;border:1px solid rgba(37,211,102,0.45);padding:6px 13px;border-radius:7px;font-weight:800;font-size:11.5px;cursor:pointer;">💾 Guardar config del sector</button>';
    h += '</div>';
    h += '</div>';

    // === Resumen general del sector (se ve completo una vez guardado) ===
    h += '<div style="background:rgba(155,48,255,0.06);border:1px solid rgba(155,48,255,0.30);border-radius:10px;padding:12px 14px;margin-bottom:14px;">';
    h += '<div style="color:#c89bff;font-weight:900;font-size:12.5px;letter-spacing:0.5px;margin-bottom:8px;">📊 RESUMEN GENERAL · ' + escapeHtml(_empSector.toUpperCase()) + '</div>';
    if (items.length === 0) {
        h += '<div style="color:#666;font-size:11px;font-style:italic;">Sin empleados en este sector.</div>';
    } else {
        h += '<div style="overflow-x:auto;"><table style="width:100%;border-collapse:collapse;font-size:11.5px;">';
        h += '<thead><tr style="color:#999;text-align:left;border-bottom:1px solid rgba(255,255,255,0.12);">';
        h += '<th style="padding:6px;">Empleado</th><th style="padding:6px;">Días que trabaja</th><th style="padding:6px;">Francos</th><th style="padding:6px;">Feriados generales</th><th style="padding:6px;text-align:right;">Cobró ARS</th><th style="padding:6px;text-align:right;">Cobró USD</th>';
        h += '</tr></thead><tbody>';
        let _tA = 0, _tU = 0;
        for (const e of items) {
            const rc = _empComputeLocal(e);
            const fd = Array.isArray(e.francoDays) ? e.francoDays : [];
            const trabaja = EMP_FRANCO_DAYS_UI.filter(d => fd.indexOf(d.key) < 0).map(d => d.short);
            const francos = EMP_FRANCO_DAYS_UI.filter(d => fd.indexOf(d.key) >= 0).map(d => d.short);
            const usd = _usdRate > 0 ? (rc.totalMensual / _usdRate) : 0;
            _tA += rc.totalMensual; _tU += usd;
            const inact = e.active === false;
            h += '<tr style="border-bottom:1px solid rgba(255,255,255,0.05);' + (inact ? 'opacity:0.5;' : '') + '">';
            h += '<td style="padding:6px;color:#fff;font-weight:700;">' + escapeHtml(e.name || '(sin nombre)') + (inact ? ' <span style="color:#ffaa66;font-size:9px;">INACTIVO</span>' : '') + '<br><span style="color:#888;font-size:10px;font-weight:600;">' + escapeHtml(_empRoleLabel(e.role || '')) + '</span></td>';
            h += '<td style="padding:6px;color:#25d366;font-weight:700;">' + (trabaja.length ? escapeHtml(trabaja.join(' ')) + ' <span style="color:#888;">(' + trabaja.length + ')</span>' : '—') + '</td>';
            h += '<td style="padding:6px;color:#0f0;font-weight:700;">' + (francos.length ? escapeHtml(francos.join(' ')) : '—') + '</td>';
            h += '<td style="padding:6px;">' + _empGeneralFeriadoChips(e) + '</td>';
            h += '<td style="padding:6px;text-align:right;color:#c89bff;font-weight:900;">' + formatMoney(Math.round(rc.totalMensual)) + '</td>';
            h += '<td style="padding:6px;text-align:right;color:#25d366;font-weight:900;">' + (_usdRate > 0 ? ('US$ ' + (Math.round(usd * 100) / 100).toLocaleString('es-AR')) : '—') + '</td>';
            h += '</tr>';
        }
        h += '<tr style="border-top:2px solid rgba(255,255,255,0.15);color:#fff;font-weight:900;">';
        h += '<td style="padding:7px 6px;" colspan="4">TOTAL SECTOR</td>';
        h += '<td style="padding:7px 6px;text-align:right;color:#c89bff;">' + formatMoney(Math.round(_tA)) + '</td>';
        h += '<td style="padding:7px 6px;text-align:right;color:#25d366;">' + (_usdRate > 0 ? ('US$ ' + (Math.round(_tU * 100) / 100).toLocaleString('es-AR')) : '—') + '</td>';
        h += '</tr>';
        h += '</tbody></table></div>';
        if (_usdRate <= 0) {
            h += '<div style="color:#ffaa66;font-size:10.5px;margin-top:6px;">💡 Cargá el valor del dólar arriba y guardá para ver los totales en USD.</div>';
        }
    }
    h += '</div>';

    // === Crear empleado / agregar puesto nuevo ===
    h += '<div style="background:rgba(255,255,255,0.03);border:1px dashed rgba(255,255,255,0.20);border-radius:9px;padding:11px 14px;margin-bottom:14px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;">';
    h += '<button onclick="addEmpleado()" style="background:linear-gradient(135deg,#9b30ff 0%,#6e1bb3 100%);color:#fff;border:none;padding:8px 16px;border-radius:8px;font-weight:900;font-size:12.5px;cursor:pointer;letter-spacing:0.4px;">➕ Agregar empleado</button>';
    h += '<span style="color:#888;font-size:11px;">Podés tipear cualquier puesto o usar los sugeridos.</span>';
    h += '</div>';

    if (items.length === 0) {
        h += '<div style="background:rgba(255,255,255,0.03);border:1px dashed rgba(255,255,255,0.15);border-radius:10px;padding:30px;text-align:center;color:#888;font-size:13px;">Todavía no hay empleados cargados en este sector. Tocá "➕ Agregar empleado" para empezar.</div>';
        body.innerHTML = h;
        return;
    }

    // === Agrupar por puesto ===
    const byRole = {};
    for (const e of items) {
        const r = e.role || 'sin_puesto';
        if (!byRole[r]) byRole[r] = [];
        byRole[r].push(e);
    }
    // Ordenar puestos: primero los defaults en orden, después los custom alfabético
    const roleOrder = EMP_DEFAULT_ROLES.map(r => r.key);
    const sortedRoles = Object.keys(byRole).sort((a, b) => {
        const ia = roleOrder.indexOf(a), ib = roleOrder.indexOf(b);
        if (ia >= 0 && ib >= 0) return ia - ib;
        if (ia >= 0) return -1;
        if (ib >= 0) return 1;
        return a.localeCompare(b);
    });

    for (const role of sortedRoles) {
        const arr = byRole[role];
        const roleTotal = arr.reduce((a, e) => a + _empComputeLocal(e).totalMensual, 0);
        const roleSueldo = arr.reduce((a, e) => a + Number(e.sueldoARS || 0), 0);
        h += '<div style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.08);border-radius:10px;margin-bottom:12px;overflow:hidden;">';
        h += '<div style="padding:10px 14px;background:rgba(155,48,255,0.06);border-bottom:1px solid rgba(255,255,255,0.06);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">';
        h += '<div style="color:#c89bff;font-weight:900;font-size:13px;letter-spacing:0.5px;">👤 ' + escapeHtml(_empRoleLabel(role)) + ' <span style="color:#888;font-size:11px;font-weight:700;">· ' + arr.length + (arr.length === 1 ? ' persona' : ' personas') + '</span></div>';
        h += '<div style="color:#fff;font-weight:900;font-size:13.5px;">' + formatMoney(Math.round(roleTotal)) + ' <span style="color:#888;font-size:10.5px;font-weight:700;">(sueldo: ' + formatMoney(Math.round(roleSueldo)) + ')</span></div>';
        h += '</div>';
        h += '<div>';
        for (const e of arr) {
            h += _renderEmpleadoRow(e);
        }
        h += '</div>';
        h += '</div>';
    }

    body.innerHTML = h;
}

function _renderEmpleadoRow(e) {
    const c = _empComputeLocal(e);
    const valorDia = c.valorDia;
    const isActive = e.active !== false;
    const bg = isActive ? 'rgba(0,0,0,0.20)' : 'rgba(255,80,80,0.05)';
    const eid = escapeHtml(e.id);
    const feriados = Array.isArray(e.feriados) ? e.feriados : [];
    const faltantes = Array.isArray(e.faltantes) ? e.faltantes : [];
    const descuentos = Array.isArray(e.descuentos) ? e.descuentos : [];
    const francoDays = Array.isArray(e.francoDays) ? e.francoDays : [];
    const lbl = 'color:#888;font-size:10px;font-weight:700;letter-spacing:0.4px;text-transform:uppercase;';
    const inp = 'width:100%;background:rgba(0,0,0,0.40);border:1px solid rgba(255,255,255,0.12);color:#fff;padding:6px 9px;border-radius:6px;font-size:12.5px;box-sizing:border-box;';

    let h = '<div id="emp_' + eid + '" style="padding:11px 14px;background:' + bg + ';border-bottom:1px solid rgba(255,255,255,0.04);">';

    // === Datos base ===
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px;align-items:end;">';
    h += '<div><label style="' + lbl + '">Nombre</label><input data-emp-field="name" type="text" value="' + escapeHtml(e.name || '') + '" placeholder="Nombre y apellido" maxlength="100" style="' + inp + 'font-weight:700;"></div>';
    h += '<div><label style="' + lbl + '">Horario</label><input data-emp-field="schedule" type="text" value="' + escapeHtml(e.schedule || '') + '" placeholder="Ej: lun-vie 10-18hs" maxlength="200" style="' + inp + '"></div>';
    h += '<div><label style="' + lbl + '">Puesto</label><input data-emp-field="role" type="text" value="' + escapeHtml(e.role || '') + '" maxlength="60" style="' + inp + 'border-color:rgba(155,48,255,0.30);color:#c89bff;font-weight:700;"></div>';
    h += '<div><label style="' + lbl + '">Sueldo base $</label><input data-emp-field="sueldoARS" type="number" min="0" step="1000" value="' + Number(e.sueldoARS || 0) + '" style="' + inp + 'border-color:rgba(0,212,255,0.30);color:#00d4ff;font-weight:800;text-align:right;"></div>';
    h += '<div><label style="' + lbl + '">Comisión transfer. (USD)</label><input data-emp-field="comisionUSD" type="number" min="0" step="0.5" value="' + Number(e.comisionUSD != null ? e.comisionUSD : 2) + '" style="' + inp + 'border-color:rgba(255,170,102,0.30);color:#ffaa66;font-weight:800;text-align:right;"></div>';
    h += '</div>';

    // === Francos + Trabajó hasta ===
    h += '<div style="margin-top:9px;display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:9px;align-items:end;">';
    h += '<div><label style="' + lbl + '">Francos / semana</label><input data-emp-field="francosPerWeek" type="number" min="0" max="7" step="1" value="' + Number(e.francosPerWeek || 0) + '" style="' + inp + 'border-color:rgba(0,255,102,0.25);color:#0f0;font-weight:800;text-align:right;"></div>';
    h += '<div><label style="' + lbl + '">Trabajó hasta</label><input data-emp-field="workedUntil" type="date" value="' + escapeHtml(e.workedUntil || '') + '" style="' + inp + 'border-color:rgba(255,170,102,0.25);color:#ffaa66;font-weight:700;"></div>';
    h += '</div>';
    // chips de días de franco
    h += '<div style="margin-top:7px;"><label style="' + lbl + '">Días de franco</label><div style="display:flex;gap:5px;flex-wrap:wrap;margin-top:4px;">';
    for (const d of EMP_FRANCO_DAYS_UI) {
        const on = francoDays.indexOf(d.key) >= 0;
        const st = on
            ? 'background:#0f0;color:#000;border:1.5px solid #0f0;'
            : 'background:rgba(255,255,255,0.04);color:#888;border:1.5px solid rgba(255,255,255,0.12);';
        h += '<button type="button" onclick="toggleEmpFrancoDay(\'' + eid + '\',\'' + d.key + '\')" style="' + st + 'padding:4px 10px;border-radius:6px;font-weight:800;font-size:11px;cursor:pointer;">' + d.short + '</button>';
    }
    h += '</div></div>';

    // === Feriados (suman) ===
    h += '<div style="margin-top:9px;padding-top:8px;border-top:1px dashed rgba(255,255,255,0.08);">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:6px;">';
    h += '<div style="color:#ffaa66;font-size:10.5px;font-weight:800;letter-spacing:0.4px;">🎉 FERIADOS TRABAJADOS (' + c.feriadosCount + ') · suma: +' + formatMoney(Math.round(c.feriadosTotal)) + '</div>';
    h += '<button onclick="addEmpFeriado(\'' + eid + '\')" style="background:rgba(255,170,102,0.12);color:#ffaa66;border:1px solid rgba(255,170,102,0.40);padding:4px 10px;border-radius:6px;font-weight:800;font-size:10.5px;cursor:pointer;">➕ Feriado</button>';
    h += '</div>';
    if (feriados.length === 0) {
        h += '<div style="color:#666;font-size:11px;font-style:italic;">Sin feriados cargados este mes.</div>';
    } else {
        for (let i = 0; i < feriados.length; i++) {
            const f = feriados[i] || {};
            h += '<div data-emp-feriado="' + i + '" style="display:grid;grid-template-columns:140px 130px 1fr auto;gap:6px;margin-bottom:4px;align-items:center;">';
            h += '<input data-emp-feriado-field="dateKey" type="date" value="' + escapeHtml(f.dateKey || '') + '" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,170,102,0.25);color:#ffaa66;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;">';
            h += '<input data-emp-feriado-field="amountARS" type="number" min="0" step="1000" value="' + Number(f.amountARS || 0) + '" placeholder="auto $' + Math.round(valorDia) + '" title="0 = paga el valor/día proporcional" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,170,102,0.25);color:#fff;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;text-align:right;">';
            h += '<input data-emp-feriado-field="note" type="text" value="' + escapeHtml(f.note || '') + '" placeholder="Detalle (opcional)" maxlength="200" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#ddd;padding:4px 8px;border-radius:5px;font-size:11px;">';
            h += '<button onclick="removeEmpFeriado(\'' + eid + '\',' + i + ')" title="Sacar feriado" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);padding:4px 8px;border-radius:5px;font-weight:800;font-size:11px;cursor:pointer;">✕</button>';
            h += '</div>';
        }
    }
    h += '</div>';

    // === Feriados generales del sector (tildá si lo cobra o no) ===
    h += '<div style="margin-top:9px;padding-top:8px;border-top:1px dashed rgba(255,255,255,0.08);">';
    h += '<div style="color:#ffd700;font-size:10.5px;font-weight:800;letter-spacing:0.4px;margin-bottom:6px;">🎌 FERIADOS GENERALES DEL SECTOR (' + c.feriadosGeneralesCount + ') · suma: +' + formatMoney(Math.round(c.feriadosGeneralesTotal)) + '</div>';
    h += _empGeneralFeriadoChips(e);
    h += '</div>';

    // === Faltas (descuentan un día) ===
    h += '<div style="margin-top:9px;padding-top:8px;border-top:1px dashed rgba(255,255,255,0.08);">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:6px;">';
    h += '<div style="color:#f55;font-size:10.5px;font-weight:800;letter-spacing:0.4px;">🚫 FALTAS DEL MES (' + c.faltantesCount + ') · descuenta: -' + formatMoney(Math.round(c.faltantesTotal)) + '</div>';
    h += '<button onclick="addEmpFaltante(\'' + eid + '\')" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.35);padding:4px 10px;border-radius:6px;font-weight:800;font-size:10.5px;cursor:pointer;">➕ Falta</button>';
    h += '</div>';
    if (faltantes.length === 0) {
        h += '<div style="color:#666;font-size:11px;font-style:italic;">Sin faltas este mes.</div>';
    } else {
        for (let i = 0; i < faltantes.length; i++) {
            const f = faltantes[i] || {};
            h += '<div data-emp-faltante="' + i + '" style="display:grid;grid-template-columns:140px 1fr auto;gap:6px;margin-bottom:4px;align-items:center;">';
            h += '<input data-emp-faltante-field="dateKey" type="date" value="' + escapeHtml(f.dateKey || '') + '" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,80,80,0.25);color:#f99;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;">';
            h += '<input data-emp-faltante-field="note" type="text" value="' + escapeHtml(f.note || '') + '" placeholder="Motivo (opcional) · descuenta $' + Math.round(valorDia) + '" maxlength="200" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#ddd;padding:4px 8px;border-radius:5px;font-size:11px;">';
            h += '<button onclick="removeEmpFaltante(\'' + eid + '\',' + i + ')" title="Sacar falta" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);padding:4px 8px;border-radius:5px;font-weight:800;font-size:11px;cursor:pointer;">✕</button>';
            h += '</div>';
        }
    }
    h += '</div>';

    // === Descuentos puntuales ===
    h += '<div style="margin-top:9px;padding-top:8px;border-top:1px dashed rgba(255,255,255,0.08);">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:6px;">';
    h += '<div style="color:#f55;font-size:10.5px;font-weight:800;letter-spacing:0.4px;">➖ DESCUENTOS (' + c.descuentosCount + ') · total: -' + formatMoney(Math.round(c.descuentosTotal)) + '</div>';
    h += '<button onclick="addEmpDescuento(\'' + eid + '\')" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.35);padding:4px 10px;border-radius:6px;font-weight:800;font-size:10.5px;cursor:pointer;">➕ Descuento</button>';
    h += '</div>';
    if (descuentos.length === 0) {
        h += '<div style="color:#666;font-size:11px;font-style:italic;">Sin descuentos puntuales.</div>';
    } else {
        for (let i = 0; i < descuentos.length; i++) {
            const d = descuentos[i] || {};
            h += '<div data-emp-descuento="' + i + '" style="display:grid;grid-template-columns:140px 130px 1fr auto;gap:6px;margin-bottom:4px;align-items:center;">';
            h += '<input data-emp-descuento-field="dateKey" type="date" value="' + escapeHtml(d.dateKey || '') + '" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,80,80,0.25);color:#f99;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;">';
            h += '<input data-emp-descuento-field="amountARS" type="number" min="0" step="500" value="' + Number(d.amountARS || 0) + '" placeholder="Monto $" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,80,80,0.25);color:#fff;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;text-align:right;">';
            h += '<input data-emp-descuento-field="note" type="text" value="' + escapeHtml(d.note || '') + '" placeholder="Detalle del descuento" maxlength="200" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#ddd;padding:4px 8px;border-radius:5px;font-size:11px;">';
            h += '<button onclick="removeEmpDescuento(\'' + eid + '\',' + i + ')" title="Sacar descuento" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);padding:4px 8px;border-radius:5px;font-weight:800;font-size:11px;cursor:pointer;">✕</button>';
            h += '</div>';
        }
    }
    h += '</div>';

    // === Ajustes manuales (+ o −) ===
    const _empAj = Array.isArray(e.ajustes) ? e.ajustes : [];
    h += '<div style="margin-top:9px;padding-top:8px;border-top:1px dashed rgba(255,255,255,0.08);">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:6px;margin-bottom:4px;">';
    h += '<div style="color:#00d4ff;font-size:10.5px;font-weight:800;letter-spacing:0.4px;">⇄ AJUSTES (' + c.ajustesCount + ') · total: ' + (c.ajustesTotal >= 0 ? '+' : '') + formatMoney(Math.round(c.ajustesTotal)) + '</div>';
    h += '<button onclick="addEmpAjuste(\'' + eid + '\')" style="background:rgba(0,212,255,0.10);color:#00d4ff;border:1px solid rgba(0,212,255,0.35);padding:4px 10px;border-radius:6px;font-weight:800;font-size:10.5px;cursor:pointer;">➕ Ajuste</button>';
    h += '</div>';
    h += '<div style="color:#888;font-size:10px;margin-bottom:6px;">Monto + o − con detalle. Ej: cambio de turno a mitad de mes, diferencia de sueldo.</div>';
    if (_empAj.length === 0) {
        h += '<div style="color:#666;font-size:11px;font-style:italic;">Sin ajustes.</div>';
    } else {
        for (let i = 0; i < _empAj.length; i++) {
            const a = _empAj[i] || {};
            h += '<div data-emp-ajuste="' + i + '" style="display:grid;grid-template-columns:140px 130px 1fr auto;gap:6px;margin-bottom:4px;align-items:center;">';
            h += '<input data-emp-ajuste-field="dateKey" type="date" value="' + escapeHtml(a.dateKey || '') + '" style="background:rgba(0,0,0,0.30);border:1px solid rgba(0,212,255,0.25);color:#9fe4ff;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;">';
            h += '<input data-emp-ajuste-field="amountARS" type="number" step="500" value="' + Number(a.amountARS || 0) + '" placeholder="Monto + o −" style="background:rgba(0,0,0,0.30);border:1px solid rgba(0,212,255,0.25);color:#fff;padding:4px 8px;border-radius:5px;font-size:11.5px;font-weight:700;text-align:right;">';
            h += '<input data-emp-ajuste-field="note" type="text" value="' + escapeHtml(a.note || '') + '" placeholder="Detalle del ajuste" maxlength="200" style="background:rgba(0,0,0,0.30);border:1px solid rgba(255,255,255,0.10);color:#ddd;padding:4px 8px;border-radius:5px;font-size:11px;">';
            h += '<button onclick="removeEmpAjuste(\'' + eid + '\',' + i + ')" title="Sacar ajuste" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);padding:4px 8px;border-radius:5px;font-weight:800;font-size:11px;cursor:pointer;">✕</button>';
            h += '</div>';
        }
    }
    h += '</div>';

    // === Resumen general ===
    const francoTxt = francoDays.length
        ? francoDays.map(k => (EMP_FRANCO_DAYS_UI.find(x => x.key === k) || {}).short || k).join(', ')
        : '—';
    h += '<div style="margin-top:10px;background:rgba(155,48,255,0.07);border:1px solid rgba(155,48,255,0.30);border-radius:9px;padding:10px 13px;">';
    h += '<div style="color:#c89bff;font-size:10.5px;font-weight:900;letter-spacing:0.6px;margin-bottom:6px;">📊 RESUMEN — valor/día: ' + formatMoney(Math.round(valorDia)) + ' · francos: ' + Number(e.francosPerWeek || 0) + '/sem (' + escapeHtml(francoTxt) + ')' + (e.workedUntil ? ' · trabajó hasta ' + escapeHtml(e.workedUntil) : '') + '</div>';
    h += '<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:6px;font-size:11.5px;">';
    h += '<div style="color:#aaa;">Sueldo base<br><span style="color:#fff;font-weight:800;">' + formatMoney(Math.round(c.sueldoARS)) + '</span></div>';
    h += '<div style="color:#aaa;">+ Feriados (' + c.feriadosCount + ')<br><span style="color:#ffaa66;font-weight:800;">+' + formatMoney(Math.round(c.feriadosTotal)) + '</span></div>';
    h += '<div style="color:#aaa;">+ Feriados grales (' + c.feriadosGeneralesCount + ')<br><span style="color:#ffd700;font-weight:800;">+' + formatMoney(Math.round(c.feriadosGeneralesTotal)) + '</span></div>';
    h += '<div style="color:#aaa;">− Faltas (' + c.faltantesCount + ')<br><span style="color:#f55;font-weight:800;">-' + formatMoney(Math.round(c.faltantesTotal)) + '</span></div>';
    h += '<div style="color:#aaa;">− Descuentos (' + c.descuentosCount + ')<br><span style="color:#f55;font-weight:800;">-' + formatMoney(Math.round(c.descuentosTotal)) + '</span></div>';
    h += '<div style="color:#aaa;">⇄ Ajustes (' + c.ajustesCount + ')<br><span style="color:#00d4ff;font-weight:800;">' + (c.ajustesTotal >= 0 ? '+' : '') + formatMoney(Math.round(c.ajustesTotal)) + '</span></div>';
    h += '<div style="color:#aaa;">= TOTAL MENSUAL<br><span style="color:#c89bff;font-weight:900;font-size:14px;">' + formatMoney(Math.round(c.totalMensual)) + '</span></div>';
    h += '<div style="color:#aaa;">+ Comisión transfer.<br><span style="color:#ffaa66;font-weight:800;">+' + formatMoney(Math.round(c.comisionARS)) + '</span> <span style="color:#666;font-size:10px;">(' + c.comisionUSD + ' USD)</span></div>';
    h += '<div style="color:#aaa;">= COSTO TOTAL<br><span style="color:#ffd700;font-weight:900;font-size:14px;">' + formatMoney(Math.round(c.costoTotal)) + '</span></div>';
    h += '</div></div>';

    // === Botones ===
    h += '<div style="margin-top:8px;display:flex;gap:6px;flex-wrap:wrap;">';
    h += '<button onclick="saveEmpleado(\'' + eid + '\')" style="background:rgba(0,212,255,0.18);color:#00d4ff;border:1px solid rgba(0,212,255,0.40);padding:6px 12px;border-radius:7px;font-weight:800;font-size:11.5px;cursor:pointer;">💾 Guardar</button>';
    h += '<button onclick="toggleEmpActive(\'' + eid + '\')" style="background:' + (isActive ? 'rgba(255,170,102,0.10)' : 'rgba(0,255,102,0.10)') + ';color:' + (isActive ? '#ffaa66' : '#0f0') + ';border:1px solid ' + (isActive ? 'rgba(255,170,102,0.35)' : 'rgba(0,255,102,0.35)') + ';padding:6px 12px;border-radius:7px;font-weight:800;font-size:11.5px;cursor:pointer;">' + (isActive ? '⏸ Inactivar' : '▶ Activar') + '</button>';
    h += '<button onclick="deleteEmpleado(\'' + eid + '\')" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);padding:6px 10px;border-radius:7px;font-weight:800;font-size:11.5px;cursor:pointer;">🗑</button>';
    if (!isActive) {
        h += '<span style="color:#ffaa66;font-size:11px;font-weight:700;align-self:center;">INACTIVO</span>';
    }
    h += '</div>';

    h += '</div>';
    return h;
}

function _collectEmpPayload(id) {
    const card = document.getElementById('emp_' + id);
    if (!card) return null;
    const get = (field) => {
        const el = card.querySelector('[data-emp-field="' + field + '"]');
        return el ? el.value : '';
    };
    const feriados = [];
    card.querySelectorAll('[data-emp-feriado]').forEach(row => {
        feriados.push({
            dateKey: (row.querySelector('[data-emp-feriado-field="dateKey"]') || {}).value || '',
            amountARS: Number((row.querySelector('[data-emp-feriado-field="amountARS"]') || {}).value || 0),
            note: (row.querySelector('[data-emp-feriado-field="note"]') || {}).value || ''
        });
    });
    const faltantes = [];
    card.querySelectorAll('[data-emp-faltante]').forEach(row => {
        faltantes.push({
            dateKey: (row.querySelector('[data-emp-faltante-field="dateKey"]') || {}).value || '',
            note: (row.querySelector('[data-emp-faltante-field="note"]') || {}).value || ''
        });
    });
    const descuentos = [];
    card.querySelectorAll('[data-emp-descuento]').forEach(row => {
        descuentos.push({
            dateKey: (row.querySelector('[data-emp-descuento-field="dateKey"]') || {}).value || '',
            amountARS: Number((row.querySelector('[data-emp-descuento-field="amountARS"]') || {}).value || 0),
            note: (row.querySelector('[data-emp-descuento-field="note"]') || {}).value || ''
        });
    });
    const ajustes = [];
    card.querySelectorAll('[data-emp-ajuste]').forEach(row => {
        ajustes.push({
            dateKey: (row.querySelector('[data-emp-ajuste-field="dateKey"]') || {}).value || '',
            amountARS: Number((row.querySelector('[data-emp-ajuste-field="amountARS"]') || {}).value || 0),
            note: (row.querySelector('[data-emp-ajuste-field="note"]') || {}).value || ''
        });
    });
    // francoDays y feriadosGeneralesExcluidos se togglean en el cache.
    const emp = (_empCache || []).find(x => x.id === id);
    const francoDays = (emp && Array.isArray(emp.francoDays)) ? emp.francoDays.slice() : [];
    const feriadosGeneralesExcluidos = (emp && Array.isArray(emp.feriadosGeneralesExcluidos)) ? emp.feriadosGeneralesExcluidos.slice() : [];
    return {
        name: get('name'),
        schedule: get('schedule'),
        role: (get('role') || '').toLowerCase().trim(),
        sueldoARS: Number(get('sueldoARS')) || 0,
        comisionUSD: Number(get('comisionUSD')) || 0,
        francosPerWeek: Number(get('francosPerWeek')) || 0,
        workedUntil: get('workedUntil') || '',
        feriados,
        faltantes,
        descuentos,
        ajustes,
        francoDays,
        feriadosGeneralesExcluidos
    };
}

async function addEmpleado() {
    const role = prompt('Puesto del nuevo empleado:\n\n(sugeridos: encargados, pagos, comunidad, cargas, recontactacion, revision_chat — o tipeá uno nuevo)', 'encargados');
    if (role == null) return;
    const role2 = (role || '').trim().toLowerCase();
    if (!role2) { showToast('Puesto requerido', 'error'); return; }
    try {
        const r = await authFetch('/api/admin/empleados', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ sector: _empSector, role: role2 })
        });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error al crear', 'error'); return; }
        showToast('✅ Empleado creado · completá los datos', 'success');
        loadEmpleados();
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

async function saveEmpleado(id) {
    const payload = _collectEmpPayload(id);
    if (!payload) return;
    try {
        const r = await authFetch('/api/admin/empleados/' + encodeURIComponent(id), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error al guardar', 'error'); return; }
        showToast('💾 Guardado', 'success');
        loadEmpleados();
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

function addEmpFeriado(id) {
    const emp = _empSyncFromDom(id);
    if (!emp) return;
    if (!Array.isArray(emp.feriados)) emp.feriados = [];
    emp.feriados.push({ dateKey: '', amountARS: 0, note: '' });
    _renderEmpleados();
    showToast('Cargá la fecha (monto 0 = valor/día), después 💾 Guardar', 'info');
}

function removeEmpFeriado(id, idx) {
    const emp = _empSyncFromDom(id);
    if (!emp || !Array.isArray(emp.feriados)) return;
    emp.feriados.splice(idx, 1);
    _renderEmpleados();
}

function addEmpFaltante(id) {
    const emp = _empSyncFromDom(id);
    if (!emp) return;
    if (!Array.isArray(emp.faltantes)) emp.faltantes = [];
    emp.faltantes.push({ dateKey: '', note: '' });
    _renderEmpleados();
    showToast('Cada falta descuenta un valor/día. Después 💾 Guardar', 'info');
}

function removeEmpFaltante(id, idx) {
    const emp = _empSyncFromDom(id);
    if (!emp || !Array.isArray(emp.faltantes)) return;
    emp.faltantes.splice(idx, 1);
    _renderEmpleados();
}

function addEmpDescuento(id) {
    const emp = _empSyncFromDom(id);
    if (!emp) return;
    if (!Array.isArray(emp.descuentos)) emp.descuentos = [];
    emp.descuentos.push({ dateKey: '', amountARS: 0, note: '' });
    _renderEmpleados();
    showToast('Cargá el monto y el detalle, después 💾 Guardar', 'info');
}

function removeEmpDescuento(id, idx) {
    const emp = _empSyncFromDom(id);
    if (!emp || !Array.isArray(emp.descuentos)) return;
    emp.descuentos.splice(idx, 1);
    _renderEmpleados();
}

function addEmpAjuste(id) {
    const emp = _empSyncFromDom(id);
    if (!emp) return;
    if (!Array.isArray(emp.ajustes)) emp.ajustes = [];
    emp.ajustes.push({ dateKey: '', amountARS: 0, note: '' });
    _renderEmpleados();
    showToast('Cargá el monto (+ o −) y el detalle, después 💾 Guardar', 'info');
}

function removeEmpAjuste(id, idx) {
    const emp = _empSyncFromDom(id);
    if (!emp || !Array.isArray(emp.ajustes)) return;
    emp.ajustes.splice(idx, 1);
    _renderEmpleados();
}

function toggleEmpFrancoDay(id, day) {
    const emp = _empSyncFromDom(id);
    if (!emp) return;
    if (!Array.isArray(emp.francoDays)) emp.francoDays = [];
    const i = emp.francoDays.indexOf(day);
    if (i >= 0) emp.francoDays.splice(i, 1);
    else emp.francoDays.push(day);
    _renderEmpleados();
}

// === Feriados generales del sector ===

// Chips ✓/✗ de los feriados generales del sector para un empleado.
// Se usan tanto en la tarjeta del empleado como en el resumen general.
function _empGeneralFeriadoChips(e) {
    const generales = ((_empSectorConfigs[e.sector] || {}).feriadosGenerales) || [];
    if (generales.length === 0) {
        return '<span style="color:#666;font-size:10.5px;font-style:italic;">Sin feriados generales</span>';
    }
    const excl = new Set(Array.isArray(e.feriadosGeneralesExcluidos) ? e.feriadosGeneralesExcluidos : []);
    let h = '<div style="display:flex;gap:4px;flex-wrap:wrap;">';
    for (const g of generales) {
        const cobra = !excl.has(g.id);
        const label = g.dateKey || g.note || 'feriado';
        const st = cobra
            ? 'background:rgba(37,211,102,0.15);color:#25d366;border:1px solid rgba(37,211,102,0.45);'
            : 'background:rgba(255,80,80,0.10);color:#f77;border:1px solid rgba(255,80,80,0.40);text-decoration:line-through;';
        h += '<button type="button" onclick="toggleEmpGeneralFeriado(\'' + escapeHtml(e.id) + '\',\'' + escapeHtml(g.id) + '\')" title="' + escapeHtml(g.note || '') + '" style="' + st + 'padding:2px 7px;border-radius:5px;font-weight:800;font-size:10px;cursor:pointer;">' + (cobra ? '✓' : '✗') + ' ' + escapeHtml(label) + '</button>';
    }
    h += '</div>';
    return h;
}

// Vuelca al cache los inputs de TODOS los empleados visibles, para no
// perder ediciones sin guardar al re-renderizar por un cambio de config.
function _empSyncAllFromDom() {
    for (const e of (_empCache || [])) {
        if (document.getElementById('emp_' + e.id)) {
            const p = _collectEmpPayload(e.id);
            if (p) Object.assign(e, p);
        }
    }
}

// Vuelca al cache los feriados generales y el valor USD del DOM.
function _empSyncSectorCfgFromDom() {
    const cfg = _empSectorConfigs[_empSector] || { feriadosGenerales: [], usdRate: 0 };
    const prev = Array.isArray(cfg.feriadosGenerales) ? cfg.feriadosGenerales : [];
    const list = [];
    document.querySelectorAll('[data-emp-genfer]').forEach((row, i) => {
        const ex = prev[i] || {};
        list.push({
            id: ex.id || ('fg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8)),
            dateKey: (row.querySelector('[data-emp-genfer-field="dateKey"]') || {}).value || '',
            amountARS: Number((row.querySelector('[data-emp-genfer-field="amountARS"]') || {}).value || 0),
            note: (row.querySelector('[data-emp-genfer-field="note"]') || {}).value || ''
        });
    });
    const usdEl = document.getElementById('empUsdRate');
    cfg.feriadosGenerales = list;
    cfg.usdRate = usdEl ? (Number(usdEl.value) || 0) : (cfg.usdRate || 0);
    _empSectorConfigs[_empSector] = cfg;
}

function addEmpGeneralFeriado() {
    _empSyncAllFromDom();
    _empSyncSectorCfgFromDom();
    const cfg = _empSectorConfigs[_empSector] || { feriadosGenerales: [], usdRate: 0 };
    if (!Array.isArray(cfg.feriadosGenerales)) cfg.feriadosGenerales = [];
    cfg.feriadosGenerales.push({
        id: 'fg_' + Date.now() + '_' + Math.random().toString(36).slice(2, 8),
        dateKey: '', amountARS: 0, note: ''
    });
    _empSectorConfigs[_empSector] = cfg;
    _renderEmpleados();
    showToast('Cargá la fecha y después 💾 Guardar config del sector', 'info');
}

function removeEmpGeneralFeriado(idx) {
    _empSyncAllFromDom();
    _empSyncSectorCfgFromDom();
    const cfg = _empSectorConfigs[_empSector];
    if (cfg && Array.isArray(cfg.feriadosGenerales)) cfg.feriadosGenerales.splice(idx, 1);
    _renderEmpleados();
}

async function saveEmpSectorConfig() {
    _empSyncSectorCfgFromDom();
    const cfg = _empSectorConfigs[_empSector] || { feriadosGenerales: [], usdRate: 0 };
    try {
        const r = await authFetch('/api/admin/empleados/sector-config', {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                sector: _empSector,
                feriadosGenerales: cfg.feriadosGenerales || [],
                usdRate: cfg.usdRate || 0
            })
        });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error al guardar', 'error'); return; }
        showToast('💾 Config del sector guardada', 'success');
        loadEmpleados();
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

function toggleEmpGeneralFeriado(empId, feriadoId) {
    _empSyncSectorCfgFromDom();
    _empSyncAllFromDom();
    const emp = (_empCache || []).find(e => e.id === empId);
    if (!emp) return;
    if (!Array.isArray(emp.feriadosGeneralesExcluidos)) emp.feriadosGeneralesExcluidos = [];
    const i = emp.feriadosGeneralesExcluidos.indexOf(feriadoId);
    if (i >= 0) emp.feriadosGeneralesExcluidos.splice(i, 1);
    else emp.feriadosGeneralesExcluidos.push(feriadoId);
    _renderEmpleados();
}

async function toggleEmpActive(id) {
    const emp = (_empCache || []).find(e => e.id === id);
    if (!emp) return;
    const newVal = !(emp.active !== false);
    try {
        const r = await authFetch('/api/admin/empleados/' + encodeURIComponent(id), {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ active: newVal })
        });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error', 'error'); return; }
        showToast(newVal ? '▶ Activado' : '⏸ Inactivado', 'success');
        loadEmpleados();
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

async function deleteEmpleado(id) {
    if (!confirm('¿Borrar este empleado? La acción no se puede deshacer.')) return;
    const pin = prompt('PIN para borrar el empleado:');
    if (pin == null) return;
    if (!pin) { showToast('PIN requerido', 'error'); return; }
    try {
        const r = await authFetch('/api/admin/empleados/' + encodeURIComponent(id) + '?pin=' + encodeURIComponent(pin), { method: 'DELETE' });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error', 'error'); return; }
        showToast('🗑 Eliminado', 'success');
        loadEmpleados();
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

// ============================================================
// PUBLICIDAD — publicistas, envíos de plata y cierres diarios
// ============================================================
// Cada publicista tiene envios[] (plata mandada, con detalle) y cierres[]
// diarios de campaña (consumo, mensajes, derivados, costo/msj). El % de
// conversión se calcula acá: derivados / mensajes × 100.
let _publicistasCache = [];
const _pubExpanded = {};
const _pubInp = 'background:rgba(0,0,0,0.45);border:1px solid rgba(255,255,255,0.14);color:#fff;padding:5px 7px;border-radius:5px;font-size:11.5px;box-sizing:border-box;width:100%;';

function _pubFmt(n) { return '$' + Math.round(Number(n) || 0).toLocaleString('es-AR'); }
function _pubToday() {
    return new Intl.DateTimeFormat('en-CA', { timeZone: 'America/Argentina/Buenos_Aires', year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date());
}

async function loadPublicistas() {
    const body = document.getElementById('publicidadBody');
    if (!body) return;
    body.innerHTML = '<div style="color:#aaa;text-align:center;padding:24px;">⏳ Cargando…</div>';
    try {
        const r = await authFetch('/api/admin/publicistas');
        const d = await r.json();
        if (!r.ok || !d.success) {
            body.innerHTML = '<div style="color:#ff8080;padding:14px;">❌ ' + escapeHtml(d.error || 'Error') + '</div>';
            return;
        }
        _publicistasCache = d.items || [];
        _renderPublicistas();
    } catch (e) {
        body.innerHTML = '<div style="color:#ff8080;padding:14px;">Error: ' + escapeHtml(e.message || '') + '</div>';
    }
}

function _renderPublicistas() {
    const body = document.getElementById('publicidadBody');
    if (!body) return;
    let h = '';
    h += '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:14px;">';
    h += '<input id="pubNuevoNombre" type="text" maxlength="100" placeholder="Nombre del publicista" onkeydown="if(event.key===\'Enter\')crearPublicista()" style="flex:1;min-width:200px;background:rgba(0,0,0,0.45);border:1px solid rgba(255,128,0,0.40);color:#fff;padding:9px 12px;border-radius:8px;font-size:13px;box-sizing:border-box;">';
    h += '<button type="button" onclick="crearPublicista()" style="background:linear-gradient(135deg,#ff8000,#ffaa44);color:#000;border:none;padding:9px 18px;border-radius:8px;font-weight:900;font-size:12.5px;cursor:pointer;">➕ Agregar publicista</button>';
    h += '</div>';
    if (_publicistasCache.length === 0) {
        h += '<div style="color:#888;text-align:center;padding:24px;font-size:12.5px;">No hay publicistas todavía. Agregá el primero arriba.</div>';
    } else {
        for (const p of _publicistasCache) h += _renderPublicistaCard(p);
    }
    body.innerHTML = h;
}

function _renderPublicistaCard(p) {
    const envios = Array.isArray(p.envios) ? p.envios : [];
    const cierres = Array.isArray(p.cierres) ? p.cierres : [];
    const totalEnviado = envios.reduce((s, e) => s + (Number(e.montoARS) || 0), 0);
    const totalConsumido = cierres.reduce((s, c) => s + (Number(c.consumoARS) || 0), 0);
    const expanded = !!_pubExpanded[p.id];
    const pid = escapeHtml(p.id);
    let h = '<div data-pub-card="' + pid + '" style="background:rgba(0,0,0,0.30);border:1.5px solid rgba(255,128,0,0.35);border-radius:11px;padding:13px;margin-bottom:12px;">';
    h += '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;">';
    h += '<span onclick="_pubToggle(\'' + pid + '\')" style="color:#ff8000;font-size:13px;cursor:pointer;">' + (expanded ? '▼' : '▶') + '</span>';
    h += '<input data-pub-field="nombre" type="text" value="' + escapeHtml(p.nombre || '') + '" maxlength="100" style="background:rgba(0,0,0,0.40);border:1px solid rgba(255,255,255,0.12);color:#fff;font-weight:900;font-size:13px;padding:5px 9px;border-radius:6px;flex:1;min-width:140px;">';
    h += '<span style="color:#ffaa66;font-size:11px;font-weight:800;white-space:nowrap;">📤 ' + _pubFmt(totalEnviado) + '</span>';
    h += '<span style="color:#aaffaa;font-size:11px;font-weight:800;white-space:nowrap;">🔥 ' + _pubFmt(totalConsumido) + '</span>';
    h += '<button type="button" onclick="borrarPublicista(\'' + pid + '\')" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);padding:4px 9px;border-radius:6px;font-weight:800;font-size:10.5px;cursor:pointer;">🗑</button>';
    h += '</div>';
    if (expanded) {
        h += _renderPubEnvios(p, envios);
        h += _renderPubCierres(p, cierres);
        h += '<div style="margin-top:10px;text-align:right;">';
        h += '<button type="button" onclick="guardarPublicista(\'' + pid + '\')" style="background:rgba(102,255,102,0.15);border:1px solid rgba(102,255,102,0.45);color:#aaffaa;padding:7px 18px;border-radius:8px;font-weight:900;font-size:12px;cursor:pointer;">💾 Guardar cambios</button>';
        h += '</div>';
    }
    h += '</div>';
    return h;
}

function _renderPubEnvios(p, envios) {
    const pid = escapeHtml(p.id);
    const cols = '120px 120px 1fr 30px';
    let h = '<div style="margin-top:12px;background:rgba(255,128,0,0.05);border:1px solid rgba(255,128,0,0.25);border-radius:9px;padding:10px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px;">';
    h += '<span style="color:#ffaa66;font-weight:900;font-size:11px;letter-spacing:0.5px;">📤 ENVÍOS DE PLATA</span>';
    h += '<button type="button" onclick="pubAddEnvio(\'' + pid + '\')" style="background:rgba(255,128,0,0.15);color:#ffaa66;border:1px solid rgba(255,128,0,0.45);padding:3px 10px;border-radius:6px;font-weight:800;font-size:10.5px;cursor:pointer;">➕ Envío</button>';
    h += '</div>';
    if (envios.length === 0) {
        h += '<div style="color:#777;font-size:10.5px;padding:3px;">Sin envíos cargados.</div>';
    } else {
        h += '<div style="display:grid;grid-template-columns:' + cols + ';gap:6px;font-size:9px;color:#888;text-transform:uppercase;font-weight:700;margin-bottom:4px;">';
        h += '<div>Fecha</div><div>Monto $</div><div>Detalle (líneas API, etc.)</div><div></div></div>';
        for (const e of envios) {
            const eid = escapeHtml(e.id);
            h += '<div style="display:grid;grid-template-columns:' + cols + ';gap:6px;margin-bottom:4px;">';
            h += '<input data-envio-id="' + eid + '" data-field="fecha" type="date" value="' + escapeHtml(e.fecha || '') + '" style="' + _pubInp + '">';
            h += '<input data-envio-id="' + eid + '" data-field="montoARS" type="number" min="0" step="1000" value="' + (Number(e.montoARS) || 0) + '" style="' + _pubInp + '">';
            h += '<input data-envio-id="' + eid + '" data-field="detalle" type="text" maxlength="200" value="' + escapeHtml(e.detalle || '') + '" placeholder="qué se pagó" style="' + _pubInp + '">';
            h += '<button type="button" onclick="pubDelEnvio(\'' + pid + '\',\'' + eid + '\')" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);border-radius:5px;cursor:pointer;font-size:10px;">✕</button>';
            h += '</div>';
        }
        const tot = envios.reduce((s, e) => s + (Number(e.montoARS) || 0), 0);
        h += '<div style="text-align:right;color:#ffaa66;font-size:11px;font-weight:900;margin-top:4px;">Total enviado: ' + _pubFmt(tot) + '</div>';
    }
    h += '</div>';
    return h;
}

function _renderPubCierres(p, cierres) {
    const pid = escapeHtml(p.id);
    const cols = '108px 110px 85px 85px 95px 70px 30px';
    let h = '<div style="margin-top:10px;background:rgba(0,212,255,0.05);border:1px solid rgba(0,212,255,0.25);border-radius:9px;padding:10px;">';
    h += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:7px;">';
    h += '<span style="color:#00d4ff;font-weight:900;font-size:11px;letter-spacing:0.5px;">📊 CIERRE DIARIO DE CAMPAÑA</span>';
    h += '<button type="button" onclick="pubAddCierre(\'' + pid + '\')" style="background:rgba(0,212,255,0.15);color:#00d4ff;border:1px solid rgba(0,212,255,0.45);padding:3px 10px;border-radius:6px;font-weight:800;font-size:10.5px;cursor:pointer;">➕ Día</button>';
    h += '</div>';
    if (cierres.length === 0) {
        h += '<div style="color:#777;font-size:10.5px;padding:3px;">Sin cierres cargados.</div>';
    } else {
        h += '<div style="display:grid;grid-template-columns:' + cols + ';gap:5px;font-size:8.5px;color:#888;text-transform:uppercase;font-weight:700;margin-bottom:4px;">';
        h += '<div>Fecha</div><div>Consumió $</div><div>Mensajes</div><div>Derivados</div><div>Costo/msj $</div><div>Conv. %</div><div></div></div>';
        for (const c of cierres) {
            const cid = escapeHtml(c.id);
            const mv = Number(c.mensajes) || 0, dv = Number(c.derivados) || 0;
            const conv = mv > 0 ? (dv / mv * 100) : 0;
            h += '<div style="display:grid;grid-template-columns:' + cols + ';gap:5px;margin-bottom:4px;">';
            h += '<input data-cierre-id="' + cid + '" data-field="fecha" type="date" value="' + escapeHtml(c.fecha || '') + '" style="' + _pubInp + '">';
            h += '<input data-cierre-id="' + cid + '" data-field="consumoARS" type="number" min="0" step="100" value="' + (Number(c.consumoARS) || 0) + '" style="' + _pubInp + '">';
            h += '<input data-cierre-id="' + cid + '" data-field="mensajes" type="number" min="0" step="1" value="' + mv + '" oninput="_pubRecalcConv(\'' + cid + '\')" style="' + _pubInp + '">';
            h += '<input data-cierre-id="' + cid + '" data-field="derivados" type="number" min="0" step="1" value="' + dv + '" oninput="_pubRecalcConv(\'' + cid + '\')" style="' + _pubInp + '">';
            h += '<input data-cierre-id="' + cid + '" data-field="costoMsjARS" type="number" min="0" step="1" value="' + (Number(c.costoMsjARS) || 0) + '" style="' + _pubInp + '">';
            h += '<div id="pubConv_' + cid + '" style="display:flex;align-items:center;justify-content:center;color:#aaffaa;font-weight:900;font-size:11px;">' + conv.toFixed(1) + '%</div>';
            h += '<button type="button" onclick="pubDelCierre(\'' + pid + '\',\'' + cid + '\')" style="background:rgba(255,80,80,0.10);color:#f55;border:1px solid rgba(255,80,80,0.30);border-radius:5px;cursor:pointer;font-size:10px;">✕</button>';
            h += '</div>';
        }
    }
    h += '</div>';
    return h;
}

function _pubRecalcConv(cierreId) {
    const m = document.querySelector('[data-cierre-id="' + cierreId + '"][data-field="mensajes"]');
    const d = document.querySelector('[data-cierre-id="' + cierreId + '"][data-field="derivados"]');
    const out = document.getElementById('pubConv_' + cierreId);
    if (!m || !d || !out) return;
    const mv = Number(m.value) || 0, dv = Number(d.value) || 0;
    out.textContent = (mv > 0 ? (dv / mv * 100) : 0).toFixed(1) + '%';
}

// Lee los inputs de una tarjeta y vuelca los valores al cache.
function _pubCollectCard(id) {
    const p = _publicistasCache.find(x => x.id === id);
    if (!p) return null;
    const card = document.querySelector('[data-pub-card="' + id + '"]');
    if (!card) return p;
    const nombreEl = card.querySelector('[data-pub-field="nombre"]');
    if (nombreEl) p.nombre = nombreEl.value;
    if (!_pubExpanded[id]) return p; // colapsada: no hay inputs de envíos/cierres
    const envMap = {};
    card.querySelectorAll('[data-envio-id]').forEach(el => {
        const eid = el.getAttribute('data-envio-id');
        if (!envMap[eid]) envMap[eid] = { id: eid };
        envMap[eid][el.getAttribute('data-field')] = el.value;
    });
    p.envios = Object.values(envMap).map(e => ({
        id: e.id, fecha: e.fecha || '', montoARS: Number(e.montoARS) || 0, detalle: e.detalle || ''
    }));
    const cieMap = {};
    card.querySelectorAll('[data-cierre-id]').forEach(el => {
        const cid = el.getAttribute('data-cierre-id');
        if (!cieMap[cid]) cieMap[cid] = { id: cid };
        cieMap[cid][el.getAttribute('data-field')] = el.value;
    });
    p.cierres = Object.values(cieMap).map(c => ({
        id: c.id, fecha: c.fecha || '', consumoARS: Number(c.consumoARS) || 0,
        mensajes: Number(c.mensajes) || 0, derivados: Number(c.derivados) || 0,
        costoMsjARS: Number(c.costoMsjARS) || 0
    }));
    return p;
}

function _pubCollectAll() {
    for (const p of _publicistasCache) _pubCollectCard(p.id);
}

function _pubToggle(id) {
    _pubCollectAll();
    _pubExpanded[id] = !_pubExpanded[id];
    _renderPublicistas();
}

function pubAddEnvio(id) {
    _pubCollectAll();
    const p = _publicistasCache.find(x => x.id === id);
    if (!p) return;
    p.envios = p.envios || [];
    p.envios.push({ id: 'env_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7), fecha: _pubToday(), montoARS: 0, detalle: '' });
    _pubExpanded[id] = true;
    _renderPublicistas();
}

function pubAddCierre(id) {
    _pubCollectAll();
    const p = _publicistasCache.find(x => x.id === id);
    if (!p) return;
    p.cierres = p.cierres || [];
    p.cierres.push({ id: 'cie_' + Date.now() + '_' + Math.random().toString(36).slice(2, 7), fecha: _pubToday(), consumoARS: 0, mensajes: 0, derivados: 0, costoMsjARS: 0 });
    _pubExpanded[id] = true;
    _renderPublicistas();
}

function pubDelEnvio(id, envioId) {
    _pubCollectAll();
    const p = _publicistasCache.find(x => x.id === id);
    if (!p) return;
    p.envios = (p.envios || []).filter(e => e.id !== envioId);
    _renderPublicistas();
}

function pubDelCierre(id, cierreId) {
    _pubCollectAll();
    const p = _publicistasCache.find(x => x.id === id);
    if (!p) return;
    p.cierres = (p.cierres || []).filter(c => c.id !== cierreId);
    _renderPublicistas();
}

async function crearPublicista() {
    const el = document.getElementById('pubNuevoNombre');
    const nombre = ((el && el.value) || '').trim();
    if (!nombre) { showToast('Poné un nombre para el publicista', 'error'); return; }
    try {
        const r = await authFetch('/api/admin/publicistas', {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nombre })
        });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error', 'error'); return; }
        showToast('✅ Publicista agregado', 'success');
        _pubCollectAll();
        if (d.item) {
            _publicistasCache.push(d.item);
            _pubExpanded[d.item.id] = true;
        }
        _renderPublicistas();
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

async function guardarPublicista(id) {
    _pubCollectAll();
    const p = _publicistasCache.find(x => x.id === id);
    if (!p) return;
    try {
        const r = await authFetch('/api/admin/publicistas/' + encodeURIComponent(id), {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nombre: p.nombre, notas: p.notas || '', envios: p.envios || [], cierres: p.cierres || [] })
        });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error al guardar', 'error'); return; }
        showToast('✅ Guardado', 'success');
        _renderPublicistas();
    } catch (e) {
        showToast('Error al guardar', 'error');
    }
}

async function borrarPublicista(id) {
    const p = _publicistasCache.find(x => x.id === id);
    if (!confirm('¿Borrar el publicista "' + ((p && p.nombre) || '') + '" con todos sus envíos y cierres?')) return;
    const pin = prompt('PIN para borrar:');
    if (pin == null) return;
    if (!pin) { showToast('PIN requerido', 'error'); return; }
    try {
        const r = await authFetch('/api/admin/publicistas/' + encodeURIComponent(id) + '?pin=' + encodeURIComponent(pin), { method: 'DELETE' });
        const d = await r.json();
        if (!r.ok || !d.success) { showToast(d.error || 'Error', 'error'); return; }
        showToast('🗑 Publicista borrado', 'success');
        _pubCollectAll();
        _publicistasCache = _publicistasCache.filter(x => x.id !== id);
        delete _pubExpanded[id];
        _renderPublicistas();
    } catch (e) {
        showToast('Error de conexión', 'error');
    }
}

