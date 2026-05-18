// ⚠️ ARCHIVO EN PROCESO DE MIGRACIÓN
// La arquitectura modular refactorizada está en server-new.js + /src/
// Este archivo se mantiene como entry point principal hasta completar la migración.
// NO agregar funcionalidad nueva aquí — usar /src/controllers/ y /src/routes/

// Cargar .env primero (Render / dev local). En AWS EB con SSM_PATH, las vars
// sensibles se cargarán desde Parameter Store en el bootstrap async de abajo.
require('dotenv').config();

const { loadSecretsFromSSM } = require('./src/config/loadSecrets');

const express = require('express');
const http = require('http');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const winston = require('winston');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss-clean');

// ============================================
// LOGGER (Winston)
// ============================================
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || (process.env.NODE_ENV === 'production' ? 'info' : 'debug'),
  format: winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.printf(({ timestamp, level, message }) => `${timestamp} [${level.toUpperCase()}] ${message}`)
  ),
  transports: [new winston.transports.Console()]
});

// ============================================
// IMPORTAR MODELOS DE MONGODB
// ============================================
const {
  connectDB,
  User,
  Command,
  Config,
  RefundClaim,
  PlayerStats,
  DailyAppOpen,
  getConfig,
  setConfig
} = require('./config/database');

// ============================================
// SEGURIDAD - RATE LIMITING
// NOTE: Uses in-memory store per instance. In multi-instance deployments each
// instance counts independently. For consistent distributed rate limiting,
// configure a Redis store (e.g. rate-limit-redis) via REDIS_URL.
// ============================================
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Intenta más tarde.' }
});

// Subido a 40/min porque varios users pueden compartir IP (NAT casero,
// móvil 4G, oficinas). Antes era 10/min y bloqueaba a usuarios reales
// cuando había una ola de re-logins (e.g. después de un deploy donde
// algunos vieron 5xx y reintentaron). El login es username-only sin
// password, así que no hay riesgo de brute-force de credenciales —
// solo evita enumeración masiva.
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 40,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Demasiados intentos de autenticación. Intenta más tarde.' }
});

/**
 * Creates an IP-based rate limiting middleware using an in-memory Map.
 * @param {Map} store - The Map used to track IP -> timestamps
 * @param {number} windowMs - Time window in milliseconds
 * @param {number} max - Maximum number of requests per window
 * @param {string} message - Error message to return when limit is exceeded
 */

// ============================================
// SEGURIDAD - HEADERS DE SEGURIDAD
// ============================================
function securityHeaders(req, res, next) {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=(), payment=()');
  // HSTS: only set in production (HTTPS). In development the server may run
  // on plain HTTP where HSTS would cause the browser to block future HTTP requests.
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }
  // CSP compatible con Firebase Auth, FCM, Socket.IO WebSocket y PWA service workers.
  // 'unsafe-inline' en script-src/style-src es necesario por el stack actual de frontend.
  // worker-src incluye blob: para Workbox/sw.js generados en runtime.
  // connect-src incluye wss: para Socket.IO WebSocket y dominios Firebase necesarios.
  res.setHeader('Content-Security-Policy', [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://www.gstatic.com https://www.google.com https://apis.google.com https://cdn.jsdelivr.net https://unpkg.com https://connect.facebook.net",
    "script-src-elem 'self' 'unsafe-inline' https://www.gstatic.com https://www.google.com https://apis.google.com https://cdn.jsdelivr.net https://unpkg.com https://connect.facebook.net",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob: https:",
    "font-src 'self'",
    "connect-src 'self' https://*.googleapis.com https://*.firebaseio.com https://*.google.com https://identitytoolkit.googleapis.com https://securetoken.googleapis.com https://fcm.googleapis.com https://firebaseinstallations.googleapis.com https://www.facebook.com https://connect.facebook.net",
    "frame-src 'self' https://*.firebaseapp.com https://*.google.com https://www.youtube-nocookie.com https://www.youtube.com",
    "worker-src 'self' blob:",
    "manifest-src 'self'",
    "media-src 'self' data: blob:"
  ].join('; '));
  next();
}

// ============================================
// SEGURIDAD - VALIDACIÓN DE INPUT
// ============================================

// Helper para comparación segura de strings (previene timing attacks).
// Usa HMAC con clave aleatoria por llamada: ambos HMACs son siempre de 32 bytes,
// por lo que timingSafeEqual nunca revela diferencias de longitud ni de contenido.
function safeCompare(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  // A random per-call key ensures the attacker cannot predict the HMAC output
  // and prevents multi-call timing oracle attacks.
  const key = crypto.randomBytes(32);
  const hmacA = crypto.createHmac('sha256', key).update(a).digest();
  const hmacB = crypto.createHmac('sha256', key).update(b).digest();
  return crypto.timingSafeEqual(hmacA, hmacB);
}

// Escapar caracteres especiales de regex para evitar ReDoS/inyección
function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// Calcula la clave de periodo (TZ Argentina) que identifica univocamente
// el reembolso reclamable en este momento. Combinada con el indice unique
// { userId, type, periodKey } del modelo RefundClaim, garantiza que MongoDB
// rechace cualquier insert duplicado, incluso si el lock de Redis falla
// (por ejemplo, multiples instancias EB sin Redis configurado).
//
// IMPORTANTE: usa Intl.DateTimeFormat para que la conversion a TZ Argentina
// sea coherente con _argDateString() de models/refunds.js (que tambien usa
// Intl). Si Argentina cambia su offset alguna vez, ambos seguiran la tzdata
// del SO sin divergencias entre el check canClaim y el periodKey.
function _getArgentinaParts(date = new Date()) {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: 'America/Argentina/Buenos_Aires',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  const parts = fmt.formatToParts(date);
  const get = (t) => parts.find(p => p.type === t).value;
  return {
    year: parseInt(get('year'), 10),
    month: parseInt(get('month'), 10),
    day: parseInt(get('day'), 10)
  };
}

// Backfill de periodKey en RefundClaims viejos creados antes de que el campo
// fuera obligatorio. Solo se ejecuta una vez por arranque y solo procesa los
// rows que tienen periodKey null o ausente. Es necesario para que el indice
// unique partial (que indexa SOLO rows con periodKey string) tenga cobertura
// completa hacia atras y prevenga retro-claims duplicados de periodos pasados.
async function backfillRefundClaimPeriodKeys() {
  try {
    const RefundClaim = require('./src/models/RefundClaim');
    const cursor = RefundClaim.find({ periodKey: { $in: [null, undefined] } }).cursor();
    let scanned = 0, updated = 0;
    for (let doc = await cursor.next(); doc != null; doc = await cursor.next()) {
      scanned++;
      if (!doc.claimedAt || !doc.type) continue;
      const parts = _getArgentinaParts(new Date(doc.claimedAt));
      const yyyy = String(parts.year);
      const mm = String(parts.month).padStart(2, '0');
      const dd = String(parts.day).padStart(2, '0');
      let pk = null;
      if (doc.type === 'daily') pk = `${yyyy}-${mm}-${dd}`;
      else if (doc.type === 'monthly') pk = `${yyyy}-${mm}`;
      else if (doc.type === 'weekly') {
        const t = new Date(Date.UTC(parts.year, parts.month - 1, parts.day));
        const dayNum = (t.getUTCDay() + 6) % 7;
        t.setUTCDate(t.getUTCDate() - dayNum + 3);
        const ft = new Date(Date.UTC(t.getUTCFullYear(), 0, 4));
        const w = 1 + Math.round(((t.getTime() - ft.getTime()) / 86400000 - 3 + ((ft.getUTCDay() + 6) % 7)) / 7);
        pk = `${t.getUTCFullYear()}-W${String(w).padStart(2, '0')}`;
      }
      if (!pk) continue;
      try {
        await RefundClaim.updateOne({ _id: doc._id }, { $set: { periodKey: pk } });
        updated++;
      } catch (e) {
        if (e && e.code === 11000) {
          // El backfill encontro un duplicado historico real: dos claims del
          // mismo {user, type} en el mismo periodo (datos sucios pre-fix).
          // No podemos darles ambos el mismo periodKey porque rompe el indice.
          // Marcamos el mas viejo con un sufijo para que no colisione, asi el
          // indice queda consistente y el admin puede revisar manualmente.
          try {
            await RefundClaim.updateOne(
              { _id: doc._id },
              { $set: { periodKey: `${pk}-LEGACY-${doc._id.toString().slice(-6)}` } }
            );
            logger.warn(`[backfillRefundClaimPeriodKeys] duplicado historico marcado LEGACY para review: claim ${doc._id} (${doc.username} ${doc.type} ${pk})`);
          } catch (e2) { /* best-effort */ }
        }
      }
    }
    if (scanned > 0) {
      logger.info(`[backfillRefundClaimPeriodKeys] scaneados=${scanned} actualizados=${updated}`);
    }
  } catch (err) {
    logger.error(`[backfillRefundClaimPeriodKeys] error: ${err.message}`);
  }
}

const app = express();
// Trust the first proxy hop (AWS ALB / Elastic Beanstalk / Cloudflare) so that
// Express sees the real client IP and HTTPS status from X-Forwarded-* headers.
// Without this, req.ip returns the internal LB address and Socket.IO/CORS may
// behave incorrectly when accessed through a custom domain like vipcargas.com.
app.set('trust proxy', 1);

// ============================================
// CORS ORIGIN RESOLVER (centralizado)
// ============================================
// En producción: usa la allowlist de ALLOWED_ORIGINS (obligatorio).
// Si no se configura, restringe a mismo origen (no wildcard).
// En desarrollo: acepta localhost como fallback seguro.
const DEV_ORIGINS = ['http://localhost:3000', 'http://localhost:5173', 'http://localhost:10000'];
function resolveAllowedOrigins() {
  if (process.env.ALLOWED_ORIGINS) {
    return process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim()).filter(Boolean);
  }
  if (process.env.NODE_ENV === 'production') {
    // En producción sin ALLOWED_ORIGINS, no permitir orígenes cruzados.
    // Las peticiones same-origin (sin cabecera Origin) siempre pasan.
    return [];
  }
  return DEV_ORIGINS;
}

function corsOriginFn(origin, callback) {
  const allowed = resolveAllowedOrigins();
  // Requests sin cabecera Origin (curl, mobile native, same-origin GET) siempre se permiten.
  if (!origin) return callback(null, true);
  if (allowed.includes(origin)) return callback(null, true);
  // En producción sin ALLOWED_ORIGINS configurado, igual aceptamos el propio origin.
  // Sin esto, el browser bloquea sus propias requests (mismo dominio) porque
  // siempre manda Origin en POST y la allowlist vacía rechaza todo.
  // No tiramos un Error (pasa al error handler global → 500): devolvemos
  // false para que cors no agregue headers, pero la request se procesa normal
  // (las requests same-origin no necesitan headers CORS).
  logger.warn(`CORS sin allowlist match para origen: ${origin} (la request continúa sin headers CORS)`);
  return callback(null, false);
}

// Middleware que permite el propio origen en producción aunque ALLOWED_ORIGINS
// esté vacío. El browser siempre manda Origin para POST/PUT/DELETE incluso
// same-origin, y CORS sin allowlist los bloquea. Detectamos same-origin
// comparando Origin con Host (incluyendo X-Forwarded-Host del proxy de Render).
function sameOriginAllowMiddleware(req, res, next) {
  const origin = req.headers.origin;
  if (!origin) return next();
  try {
    const originHost = new URL(origin).host.toLowerCase();
    const reqHost = (req.headers['x-forwarded-host'] || req.headers.host || '').toLowerCase();
    if (originHost && reqHost && originHost === reqHost) {
      // Misma URL → permitir y proveer headers CORS para que el browser acepte.
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Credentials', 'true');
      if (req.method === 'OPTIONS') {
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,X-Requested-With,Accept,Origin');
        return res.status(204).end();
      }
    }
  } catch (_) { /* ignore malformed Origin */ }
  next();
}

const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
// JWT_SECRET se valida dentro del bootstrap async (después de cargar SSM).
let JWT_SECRET;

// ============================================
// MIDDLEWARE DE SEGURIDAD
// ============================================
const compression = require('compression');
app.use(compression({
  threshold: 1024,
  filter: (req, res) => {
    if (req.headers['x-no-compression']) return false;
    return compression.filter(req, res);
  }
}));
app.use(securityHeaders);
if (!process.env.ALLOWED_ORIGINS && process.env.NODE_ENV === 'production') {
  logger.warn('⚠️ SEGURIDAD: ALLOWED_ORIGINS no configurado en producción. CORS rechazará orígenes cruzados.');
}
app.use(sameOriginAllowMiddleware);
app.use(cors({
  origin: corsOriginFn,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'Accept', 'Origin'],
  exposedHeaders: ['X-Total-Count', 'X-RateLimit-Remaining']
}));
app.use('/api/', generalLimiter);
app.use(express.json({ limit: '25mb' }));
app.use(mongoSanitize());
app.use(xss());

// Fields exposed to the authenticated user about their own profile.
// Keep this list minimal – internal fields (jugaygana IDs, FCM tokens, etc.)
// are excluded intentionally to reduce accidental data exposure.
const USER_PUBLIC_FIELDS = 'id username email phone phoneVerified whatsapp accountNumber role balance isActive referralCode referredByUserId referralStatus createdAt lastLogin mustChangePassword';

// Admin roles are internal VIPCARGAS accounts that have NO counterpart in
// JUGAYGANA. They must never be routed through any JUGAYGANA sync, default-
// password detection, or mustChangePassword flow.
// 'closings_viewer' is an admin-class role restricted to the /cierresgeneral
// page — can read/write closings only. Counts as admin for password/cookie
// handling but is rejected by adminMiddleware (which is for full admins).
const ADMIN_ROLES = ['admin', 'depositor', 'withdrawer', 'closings_viewer'];
const isAdminRole = (role) => ADMIN_ROLES.includes(role);
const CLOSINGS_ACCESS_ROLES = ['admin', 'closings_viewer'];

// Middleware: allow only roles that can access /api/admin/closings*.
// Full admins always allowed; closings_viewer is restricted to these endpoints.
const closingsAccessMiddleware = (req, res, next) => {
  if (!CLOSINGS_ACCESS_ROLES.includes(req.user && req.user.role)) {
    return res.status(403).json({ error: 'Acceso denegado.' });
  }
  next();
};

// Cache-Control: no-store para rutas sensibles de autenticación y administración.
// Evita que proxies, CDNs o el browser cacheen respuestas con datos personales o tokens.
app.use(['/api/auth', '/api/admin', '/api/users/me'], (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ============================================
// ADMIN PAGE SECURITY
// ============================================

// ADMIN_HOST: if set, admin pages are ONLY served when the request Host matches.
// Configuring this env var is the primary server-side control to prevent the
// public domain from ever serving the admin panel.
const ADMIN_HOST = process.env.ADMIN_HOST || null;

// Legacy / debug HTML files that must never be served publicly.
// Use a Set for O(1) look-ups on every request.
const BLOCKED_LEGACY_ADMIN_PATHS = new Set([
  '/admin-masivo.html',
  '/admin-masivo-simple.html',
  '/admin-notificaciones-v2.html',
  '/admin-notifications.html',
  '/admin-panel.html',
  '/diagnostico-fcm.html',
  '/test-firebase.html',
  '/test-pwa.html',
]);

// Helper: parse the admin_api_session httpOnly cookie value (Path=/api).
function getAdminApiSessionCookie(req) {
  const cookieHeader = req.headers.cookie || '';
  for (const part of cookieHeader.split(';')) {
    const eqIdx = part.indexOf('=');
    if (eqIdx === -1) continue;
    const key = part.slice(0, eqIdx).trim();
    const val = part.slice(eqIdx + 1).trim();
    if (key === 'admin_api_session') return val;
  }
  return null;
}

// Helper: extract the bare hostname (without port) from a request.
function parseRequestHost(req) {
  const rawHost = req.hostname || (req.headers.host || '');
  return rawHost.split(':')[0].toLowerCase();
}

// Helper: build the Set-Cookie header values for the admin session cookies.
// Returns an array: [page-scoped cookie, api-scoped cookie].
function buildAdminSessionCookieHeaders(token) {
  const maxAge = 8 * 60 * 60; // 8 hours in seconds
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  return [
    `admin_session=${token}; HttpOnly; SameSite=Strict; Max-Age=${maxAge}; Path=/${secure}`,
    `admin_api_session=${token}; HttpOnly; SameSite=Strict; Max-Age=${maxAge}; Path=/api${secure}`
  ];
}

// Middleware: check ADMIN_HOST restriction.
// Returns 404 (not 403) to avoid revealing that an admin endpoint exists.
function adminHostCheck(req, res, next) {
  if (!ADMIN_HOST) return next();
  if (parseRequestHost(req) !== ADMIN_HOST.toLowerCase()) {
    return res.status(404).send('Not found');
  }
  next();
}

// Block legacy admin HTML files before express.static can serve them.
app.use((req, res, next) => {
  if (BLOCKED_LEGACY_ADMIN_PATHS.has(req.path.toLowerCase())) {
    return res.status(404).send('Not found');
  }
  next();
});

// La pagina principal sirve el panel Central Control.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use(express.static(path.join(__dirname, 'public'), {
  dotfiles: 'deny',
  index: false,
  // Default: cache static assets for 1 day. HTML, JS, CSS and service-worker
  // files override this below so that a redeploy is picked up immediately by
  // installed PWAs and browsers without waiting 24 hours.
  maxAge: '1d',
  setHeaders: (res, filePath) => {
    // Never cache files that change with every deploy so installed PWAs always
    // get fresh code after a redeploy on AWS Elastic Beanstalk.
    const noCache =
      filePath.endsWith('.html') ||
      filePath.endsWith('.js') ||
      filePath.endsWith('.css') ||
      filePath.includes('firebase-messaging-sw') ||
      filePath.includes('user-sw') ||
      filePath.includes('admin-sw') ||
      filePath.includes('manifest.json');
    if (noCache) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
    // Serve manifest.json with the correct Content-Type for PWA installability.
    // Chrome requires application/manifest+json (or application/json) to recognise
    // the file as a Web App Manifest. Express static defaults to application/json
    // which Chrome accepts, but setting the canonical type is best practice.
    if (path.basename(filePath) === 'manifest.json') {
      res.setHeader('Content-Type', 'application/manifest+json; charset=utf-8');
    }
  }
}));

const { sendNotificationToUser: _sendPushToUser, pruneInvalidFcmTokens, sendNotificationToAllUsers } = require('./src/services/notificationService');
 // 24h

// ============================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================
// =====================================================================
// BLOQUEO USUARIOS VIP — su flujo es por VIPCARGAS, no aca.
// =====================================================================
// Cualquier user cuyo username empieza con 'vip' (case-insensitive) NO
// puede usar esta app. Le respondemos con 403 + redirectTo + mensaje
// claro. Los roles admin/depositor/withdrawer estan exentos por si
// algun staff tiene username con prefijo vip.
const VIP_REDIRECT_URL = 'https://vipcargas.com';
const VIP_BLOCK_RESPONSE = {
  error: 'Esta página no está disponible para usuarios VIP.',
  message: 'Tu reembolso está disponible solo en VIPCARGAS.',
  code: 'VIP_USER',
  redirectTo: VIP_REDIRECT_URL
};
function _isVipUser(username) {
  return String(username || '').toLowerCase().trim().startsWith('vip');
}

const authMiddleware = (req, res, next) => {
  // Token desde el header Authorization, o desde la cookie httpOnly admin_api_session.
  let token = req.headers.authorization?.split(' ')[1];
  if (!token) token = getAdminApiSessionCookie(req) || null;
  if (!token) {
    return res.status(401).json({ error: 'Token no proporcionado' });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido' });
  }
};

const adminMiddleware = (req, res, next) => {
  if (req.user.role !== 'admin' && req.user.role !== 'depositor' && req.user.role !== 'withdrawer') {
    return res.status(403).json({ error: 'Acceso denegado. Solo administradores.' });
  }
  next();
};

// Health check endpoint
app.get('/api/health', async (req, res) => {
  const mongoStates = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
  const mongoState = mongoose.connection.readyState;
  const mongoOk = mongoState === 1;
  res.json({
    status: mongoOk ? 'ok' : 'degraded',
    mongo: mongoStates[mongoState] || 'unknown',
    env: {
      // Sólo flags booleanos — NO se exponen valores reales para no filtrar secrets.
      hasMongoUri: !!process.env.MONGODB_URI,
      hasJwtSecret: !!process.env.JWT_SECRET,
      hasJgApiUrl: !!process.env.JG_API_URL,
      hasRedisUrl: !!process.env.REDIS_URL,
      hasS3Bucket: !!process.env.S3_BUCKET,
      nodeEnv: process.env.NODE_ENV || 'development',
      debugLogin: process.env.DEBUG_LOGIN === '1'
    },
    uptime: Math.round(process.uptime()),
    timestamp: new Date().toISOString()
  });
});

// Login
// Credenciales fijas de Central Control. Se ignoran a propósito las env
// vars ADMIN_USERNAME / ADMIN_PASSWORD para que el acceso sea siempre el
// mismo y no dependa de la configuración en Render.
//  - ignite1000: admin completo.
//  - crazy: rol acotado (sector_editor) — solo edita los nombres de los
//    sectores ganamos/publicidad/buffalo.
const _LOGIN_USERS = [
  { username: 'ignite1000', password: 'pepsi100', role: 'admin' },
  { username: 'crazy',      password: 'crazy100', role: 'sector_editor' }
];

app.post('/api/auth/login', authLimiter, async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
    }
    let matched = null;
    for (const u of _LOGIN_USERS) {
      if (safeCompare(String(username), u.username) &&
          safeCompare(String(password), u.password)) {
        matched = u;
        break;
      }
    }
    if (!matched) {
      return res.status(401).json({ error: 'Credenciales invalidas' });
    }
    const payload = { username: matched.username, role: matched.role };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
    const cookieToken = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' });
    res.setHeader('Set-Cookie', buildAdminSessionCookieHeaders(cookieToken));
    logger.info(`[login] Acceso a Central Control: ${matched.username} (${matched.role})`);
    res.json({
      message: 'Login exitoso',
      token,
      user: { username: matched.username, role: matched.role }
    });
  } catch (error) {
    logger.error(`[login] ${error.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', [
    `admin_session=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/${secure}`,
    `admin_api_session=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/api${secure}`
  ]);
  res.json({ success: true });
});

// Admin logout — clears both admin httpOnly cookies.
// No authentication required: clearing a cookie is harmless.
app.post('/api/auth/admin-logout', (req, res) => {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', [
    `admin_session=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/${secure}`,
    `admin_api_session=; HttpOnly; SameSite=Strict; Max-Age=0; Path=/api${secure}`
  ]);
  res.json({ success: true });
});

// Verify token
app.get('/api/auth/verify', authMiddleware, (req, res) => {
  res.json({
    valid: true,
    user: { username: req.user.username, role: req.user.role }
  });
});

// Obtener información del usuario actual
app.get('/api/users/me', authMiddleware, (req, res) => {
  res.json({ username: req.user.username, role: req.user.role });
});

/**
 * Valida un número de teléfono para envío masivo y devuelve la razón si es inválido.
 * @param {string} phone
 * @returns {{ valid: boolean, reason?: string }}
 */

/**
 * Construye el query de Mongoose para los filtros de bulk SMS.
 * Solo se permiten claves específicas con valores primitivos para evitar inyección NoSQL.
 *
 * Por defecto incluye TODOS los usuarios con teléfono cargado (verificados o no).
 * Si `onlyVerified === true`, restringe a usuarios con `phoneVerified: true` y `smsConsent: true`
 * (modo estricto, equivalente al comportamiento histórico).
 */

// ============================================
// REEMBOLSOS (DIARIO, SEMANAL, MENSUAL)
// ============================================

/**
 * Obtener total de créditos no-depósito (bonus, reembolsos previos, comisiones, fire rewards)
 * para un usuario en un período. Se restan del NETWIN antes de calcular reembolsos.
 */

// ============================================
// SOCKET.IO - CHAT EN TIEMPO REAL
// ============================================

const connectedUsers = new Map();
const connectedAdmins = new Map();

// NOTE: /adminprivado2026 routes are now registered early, BEFORE the
// express.static middleware, so they can enforce ADMIN_HOST and cookie
// checks before the file system is touched.  The old (unguarded) copies
// that lived here have been removed.

// ============================================
// INICIALIZAR DATOS DE PRUEBA
// ============================================

async function initializeData() {
  // Conectar a MongoDB
  const dbConnected = await connectDB();
  if (!dbConnected) {
    console.error('❌ No se pudo conectar a MongoDB');
    return;
  }

  // One-shot migration: clear stale mustChangePassword flag from admin accounts.
  // This fixes admins that were marked before the role-isolation fix (PR #286)
  // and would otherwise be permanently blocked by authMiddleware.
  try {
    const result = await User.updateMany(
      { role: { $in: ADMIN_ROLES }, mustChangePassword: true },
      { $set: { mustChangePassword: false } }
    );
    if (result.modifiedCount > 0) {
      logger.info(`[startup-migration] Cleared mustChangePassword flag from ${result.modifiedCount} admin accounts`);
    }
  } catch (e) {
    logger.error(`[startup-migration] Failed to clear admin mustChangePassword: ${e.message}`);
  }
  
  
  // Verificar/crear admin principal
  // Usar variables de entorno para credenciales del admin.
  // ADMIN_USERNAME y ADMIN_PASSWORD deben configurarse en producción.
  const adminUsername = process.env.ADMIN_USERNAME;
  if (!adminUsername) {
    logger.warn('⚠️ ADMIN_USERNAME no configurado. El admin inicial no será creado/verificado automáticamente.');
  }
  const adminInitialPassword = process.env.ADMIN_PASSWORD;

  if (!adminInitialPassword) {
    logger.error('⛔ SEGURIDAD: ADMIN_PASSWORD no configurado en variables de entorno. El admin inicial NO será creado/actualizado automáticamente en producción. Configúralo antes de desplegar.');
  }

  if (adminUsername) {
  let adminExists = await User.findOne({ username: adminUsername });
  if (!adminExists) {
    if (!adminInitialPassword) {
      logger.warn('⚠️ No se creó el admin inicial porque ADMIN_PASSWORD no está configurado. Crealo manualmente vía API o configura la variable de entorno.');
    } else {
      const adminPassword = await bcrypt.hash(adminInitialPassword, 12);
      await User.create({
        id: uuidv4(),
        username: adminUsername,
        password: adminPassword,
        email: 'admin@saladejuegos.com',
        phone: null,
        role: 'admin',
        accountNumber: 'ADMIN001',
        balance: 0,
        createdAt: new Date(),
        lastLogin: null,
        isActive: true,
        jugayganaUserId: null,
        jugayganaUsername: null,
        jugayganaSyncStatus: 'not_applicable'
      });
      console.log(`✅ Admin creado: ${adminUsername}`);
    }
  } else {
    // Admin ya existe: solo asegurar que sigue activo y con el rol correcto.
    // NO se sobrescribe la contraseña para preservar cambios realizados en producción.
    let changed = false;
    if (adminExists.role !== 'admin') { adminExists.role = 'admin'; changed = true; }
    if (!adminExists.isActive) { adminExists.isActive = true; changed = true; }
    if (changed) await adminExists.save();
    console.log(`✅ Admin verificado: ${adminUsername}`);
  }
  } // end if (adminUsername)

  // Seed del usuario 'cierresgeneral' (rol closings_viewer) — acceso
  // restringido al panel /cierresgeneral. La contraseña SE SOBRESCRIBE
  // siempre con el valor configurado abajo, para que cambiar la
  // constante y redeployar actualice el password en producción.
  //
  // IMPORTANTE: NO hashear con bcrypt.hash() antes de pasarlo al modelo —
  // el pre('save') hook de User.js ya hashea automáticamente. Si pasamos
  // un hash, se rehashea (doble bcrypt) y bcrypt.compare en login falla.
  try {
    const CIERRES_USERNAME = 'cierresgeneral';
    const CIERRES_PASSWORD = 'asd123';
    let cierresUser = await User.findOne({ username: CIERRES_USERNAME });
    if (!cierresUser) {
      await User.create({
        id: uuidv4(),
        username: CIERRES_USERNAME,
        password: CIERRES_PASSWORD,    // raw — el hook hashea
        email: 'cierres@saladejuegos.com',
        phone: null,
        role: 'closings_viewer',
        accountNumber: 'CIERRES01',
        balance: 0,
        createdAt: new Date(),
        lastLogin: null,
        isActive: true,
        jugayganaUserId: null,
        jugayganaUsername: null,
        jugayganaSyncStatus: 'not_applicable'
      });
      console.log(`✅ Usuario '${CIERRES_USERNAME}' creado (rol: closings_viewer)`);
    } else {
      cierresUser.password = CIERRES_PASSWORD;  // raw — el hook hashea al save()
      cierresUser.role = 'closings_viewer';
      cierresUser.isActive = true;
      cierresUser.mustChangePassword = false;
      await cierresUser.save();
      console.log(`✅ Usuario '${CIERRES_USERNAME}' actualizado (password resync)`);
    }
  } catch (e) {
    logger.warn(`No se pudo seedear 'cierresgeneral': ${e.message}`);
  }

  // Backfill de periodKey en RefundClaim viejos: necesario para que el indice
  // unique partial cubra retroactivamente los reembolsos anteriores al fix.
  // Idempotente y barato si no hay rows con periodKey null.
  await backfillRefundClaimPeriodKeys();

  // Verificar/crear configuración CBU por defecto
  const cbuConfig = await getConfig('cbu');
  if (!cbuConfig) {
    await setConfig('cbu', {
      number: '0000000000000000000000',
      alias: 'mi.alias.cbu',
      bank: 'Banco Ejemplo',
      titular: 'Sala de Juegos'
    });
    console.log('✅ Configuración CBU por defecto creada');
  }

  // Verificar/crear comandos de sistema (mensajes automáticos editables desde COMANDOS)
  const systemCmds = [
    {
      name: '/sys_deposit',
      description: 'Mensaje automático al realizar un depósito sin bonus. Variables disponibles: ${amount}, ${balance}',
      type: 'message',
      response: '🔒💰 Depósito de ${amount} acreditado con éxito. ✅ \n💸 Tu nuevo saldo es ${balance} 💸\n\nPuedes verificarlo en: https://jugaygana.bet\n\n🔥 Mañana podes revisar si tenes reembolso para reclamar de forma automatica 🔥'
    },
    {
      name: '/sys_deposit_bonus',
      description: 'Mensaje automático al realizar un depósito con bonus. Variables disponibles: ${amount}, ${bonus}, ${balance}',
      type: 'message',
      response: '🔒💰 Depósito de ${amount} (incluye ${bonus} de bonificación) acreditado con éxito. ✅ \n💸 Tu nuevo saldo es ${balance} 💸\n\nPuedes verificarlo en: https://jugaygana.bet\n\n🔥 Mañana podes revisar si tenes reembolso para reclamar de forma automatica 🔥'
    },
    {
      name: '/sys_bonus',
      description: 'Mensaje automático al aplicar una bonificación. Variables disponibles: ${amount}, ${balance}',
      type: 'message',
      response: '🎁 ¡Bonificación de ${amount} acreditada en tu cuenta! ✅\n💸 Tu saldo actual es ${balance} 💸\n\nPuedes verificarlo en: https://www.jugaygana44.bet'
    },
    {
      name: '/sys_withdrawal',
      description: 'Mensaje automático al realizar un retiro. Variables disponibles: ${amount}, ${balance}',
      type: 'message',
      response: '🔒💸 Retiro de ${amount} realizado correctamente. \n💸 Tu nuevo saldo es ${balance} 💸\nSu pago se está procesando. Por favor, aguarde un momento.'
    },
    {
      name: '/sys_reminder',
      description: 'Mensaje recordatorio enviado después de cada depósito (sin variables de monto por defecto).',
      type: 'message',
      response: '🎮 ¡Recuerda!\nPara cargar o cobrar, ingresa a 🌐 www.vipcargas.com.\n🔥 ¡Ya tienes el acceso guardado, así que te queda más fácil y rápido cada vez que entres!  \n🕹️ ¡No olvides guardarla y mantenerla a mano!\n\nwww.vipcargas.com'
    }
  ];
  for (const cmd of systemCmds) {
    await Command.findOneAndUpdate(
      { name: cmd.name },
      {
        $set: { isSystem: true },
        $setOnInsert: {
          name: cmd.name,
          description: cmd.description,
          type: cmd.type,
          response: cmd.response,
          isActive: true,
          usageCount: 0
        }
      },
      { upsert: true }
    );
  }
  console.log('✅ Comandos de sistema verificados');

  console.log('✅ Datos inicializados correctamente');
}
 // ~15 hojas × 3000 filas, holgado.
 // 7 días

// GET /api/admin/users/search?q=<text>&limit=50
// Busca usuarios por substring del username (case-insensitive) y devuelve
// info básica + tags Callbell + favorito. Limit hard 100. Pensado para el
// buscador de la sección Recontactación: el admin teclea, ve resultados, y
// puede tildar etiqueta/wa/favorito desde ahí mismo sin subir XLSX.
// ============================================================
// CLAVES PARA SECCIONES PROTEGIDAS (CENTRAL / Números vigentes)
// ============================================================
// Cada sección protegida tiene su PIN (default 1818). Se guarda en Config con
// key='admin_section_pins'. El admin ya pasó por authMiddleware/adminMiddleware,
// el PIN es una capa extra de friccion antes de tocar settings sensibles
// (números, equipos). El PIN se almacena en plaintext porque ya está dentro
// del admin; no es un secret externo.

const _DEFAULT_SECTION_PIN = '1818';
// Defaults específicos por sección — overridean _DEFAULT_SECTION_PIN.
// Útil para que distintas secciones empiecen con PIN distinto sin que el
// admin tenga que ir a cambiarlos a mano.
const _SECTION_DEFAULT_PINS = { closings: '3333', empleados: '2020' };
// PINs previos seedeados por defecto en deploys anteriores. Si el valor en
// la DB todavía es uno de estos, se rotará al default nuevo en el próximo
// _getSectionPins(). Si el owner ya cambió la clave a otro valor distinto,
// no se toca. Esto evita que el dueño tenga que pasar por "Cambiar clave"
// cada vez que se actualiza el default vía deploy.
const _SECTION_LEGACY_PINS = { closings: ['1515', '1818'] };
const _defaultPinForSection = (s) => _SECTION_DEFAULT_PINS[s] || _DEFAULT_SECTION_PIN;
// 'teams' está protegido — el detalle por equipo (stats agregados, líneas,
// usuarios) requiere PIN. Las features que solo necesitan el listado de
// nombres de equipo (líneas caídas, refund-reminders) usan /teams/names
// que NO está gateado.
// 'backupPhones' protege el listado de números de respaldo.
// 'closings' protege la sección CIERRES GENERAL en el panel admin (es solo
// frontend-gate: los endpoints /api/admin/closings* NO requieren el token
// de section-pin porque también los usa el rol closings_viewer que no es
// full admin y no puede llamar a /section-pins/verify).
const _PROTECTED_SECTIONS = ['closings', 'empleados'];

async function _getSectionPins() {
  let v = await getConfig('admin_section_pins', null);
  let changed = false;
  if (!v || typeof v !== 'object') { v = {}; changed = true; }
  // Asegurar que toda sección protegida tenga PIN — completa con default si
  // falta (cubre el caso de secciones nuevas agregadas en deploys posteriores).
  for (const s of _PROTECTED_SECTIONS) {
    const def = _defaultPinForSection(s);
    if (!v[s]) {
      v[s] = def;
      changed = true;
    } else if (Array.isArray(_SECTION_LEGACY_PINS[s]) &&
               _SECTION_LEGACY_PINS[s].map(String).includes(String(v[s])) &&
               String(v[s]) !== String(def)) {
      // El valor en DB es un default viejo (no fue cambiado por el owner).
      // Rotamos al default nuevo para que el deploy refleje el cambio.
      v[s] = def;
      changed = true;
    }
  }
  if (changed) await setConfig('admin_section_pins', v);
  return v;
}

// POST verify — valida el PIN para una sección. Si coincide, emite un
// JWT corto (30 min) que el cliente debe mandar como X-Section-Pin-Token
// en las llamadas a endpoints protegidos. Sin ese token, el backend
// responde 403 aunque el admin esté autenticado.
app.post('/api/admin/section-pins/verify', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { section, pin } = req.body || {};
    if (!_PROTECTED_SECTIONS.includes(section)) return res.status(400).json({ error: 'section inválida' });
    const pins = await _getSectionPins();
    const expected = pins[section] || _defaultPinForSection(section);
    const valid = String(pin || '') === String(expected);
    if (!valid) return res.json({ valid: false });
    const token = _signSectionPinToken(section, req.user && req.user.username);
    res.json({ valid: true, token, expiresIn: _SECTION_PIN_TOKEN_TTL_SEC });
  } catch (err) {
    logger.error(`/api/admin/section-pins/verify: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// POST change — cambia el PIN. Requiere el PIN actual + el nuevo.
app.post('/api/admin/section-pins/change', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const { section, currentPin, newPin } = req.body || {};
    if (!_PROTECTED_SECTIONS.includes(section)) return res.status(400).json({ error: 'section inválida' });
    if (!/^\d{4,8}$/.test(String(newPin || ''))) return res.status(400).json({ error: 'El PIN nuevo debe tener 4-8 dígitos' });
    const pins = await _getSectionPins();
    const expected = pins[section] || _defaultPinForSection(section);
    if (String(currentPin || '') !== String(expected)) return res.status(403).json({ error: 'PIN actual incorrecto' });
    pins[section] = String(newPin);
    await setConfig('admin_section_pins', pins);
    logger.info(`[section-pins] ${section} cambiado por ${(req.user && req.user.username) || 'admin'}`);
    res.json({ success: true });
  } catch (err) {
    logger.error(`/api/admin/section-pins/change: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// GET sections — devuelve qué secciones tienen PIN activo (sin exponer el PIN).
app.get('/api/admin/section-pins/status', authMiddleware, adminMiddleware, async (req, res) => {
  try {
    const pins = await _getSectionPins();
    const out = {};
    for (const s of _PROTECTED_SECTIONS) out[s] = !!pins[s];
    res.json({ sections: out });
  } catch (err) {
    logger.error(`/api/admin/section-pins/status: ${err.message}`);
    res.status(500).json({ error: err.message });
  }
});

// ============================================================
// NOMBRES DE SECTORES (ganamos / publicidad / buffalo)
// ============================================================
// Las claves internas (ganamos/publicidad/buffalo) son fijas — son parte
// del modelo de datos. Lo editable es solo el nombre que se MUESTRA en el
// panel (Cierres General y Empleados). Se guarda en Config 'sector_names'.
// El usuario `crazy` (rol sector_editor) es quien los edita.
const _SECTOR_KEYS = ['ganamos', 'publicidad', 'buffalo'];
const _SECTOR_NAMES_DEFAULT = { ganamos: 'GANAMOS', publicidad: 'PUBLICIDAD', buffalo: 'BUFFALO' };

async function _getSectorNames() {
  let v = await getConfig('sector_names', null);
  if (!v || typeof v !== 'object') v = {};
  const out = {};
  for (const k of _SECTOR_KEYS) {
    out[k] = (typeof v[k] === 'string' && v[k].trim()) ? v[k].trim() : _SECTOR_NAMES_DEFAULT[k];
  }
  return out;
}

// GET — cualquier usuario logueado puede leer los nombres.
app.get('/api/admin/sector-names', authMiddleware, async (req, res) => {
  try {
    res.json({ success: true, names: await _getSectorNames() });
  } catch (err) {
    logger.error(`GET /api/admin/sector-names: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// PUT — solo admin o sector_editor pueden cambiar los nombres.
app.put('/api/admin/sector-names', authMiddleware, async (req, res) => {
  try {
    const role = req.user && req.user.role;
    if (role !== 'admin' && role !== 'sector_editor') {
      return res.status(403).json({ error: 'Acceso denegado' });
    }
    const body = (req.body && req.body.names) || req.body || {};
    const current = await _getSectorNames();
    const next = {};
    for (const k of _SECTOR_KEYS) {
      const raw = body[k];
      if (raw === undefined || raw === null) { next[k] = current[k]; continue; }
      const name = String(raw).trim();
      if (!name) return res.status(400).json({ error: `El nombre de "${k}" no puede estar vacío` });
      if (name.length > 24) return res.status(400).json({ error: `El nombre de "${k}" es muy largo (máx 24)` });
      next[k] = name;
    }
    await setConfig('sector_names', next);
    logger.info(`[sector-names] actualizado por ${(req.user && req.user.username) || '?'}: ${JSON.stringify(next)}`);
    res.json({ success: true, names: next });
  } catch (err) {
    logger.error(`PUT /api/admin/sector-names: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ============================================================
// PIN GATE BACKEND — defensa real, no sólo UI
// ============================================================
// Antes el PIN era cosmético: el frontend mostraba el modal pero el backend
// devolvía los datos sólo con auth+admin. Esto significa que un withdrawer
// con sesión válida (o un admin con cookie robada via XSS) podía bajar todo
// el directorio de números sin tocar el PIN.
//
// Fix: en /verify exitoso firmamos un JWT corto (scope='section-pin:<seccion>',
// exp 30 min) y se lo devolvemos al cliente. El cliente lo manda como header
// X-Section-Pin-Token. requireSectionPin valida que el token sea para la
// sección correcta, no expirado, y firmado con el mismo JWT_SECRET — sin
// eso, 403.
//
// El token caduca a los 30 min — el admin re-ingresa el PIN entonces. El
// trade-off de cosmético→funcional es 1 modal cada 30 min para el admin
// legítimo, a cambio de que un atacante sin el PIN no pueda bajar nada.

const _SECTION_PIN_TOKEN_TTL_SEC = 30 * 60; // 30 min

function _signSectionPinToken(section, username) {
  return jwt.sign(
    { scope: 'section-pin', section: String(section), u: String(username || '') },
    JWT_SECRET,
    { expiresIn: _SECTION_PIN_TOKEN_TTL_SEC }
  );
}
     // 5x el welcome bonus
   // $5M por giveaway
      // 1000 personas por giveaway

 // 7 dias entre pushes al mismo user
 // 60 seconds


// ============================================
// CIERRES DIARIOS (control financiero)
// ============================================
// Cierre diario por sector: ganamos, publicidad, buffalo (con 7 slots
// de equipo). Track depósitos, comisión banco, ventas a bajar, bajado,
// pendiente arrastre, bonos. Comprobantes (fotos) + 24h lock + edit
// history para auditoría.
const ClosingEntry = require('./src/models/ClosingEntry');

const CLOSING_SECTORS = ['ganamos', 'publicidad', 'buffalo'];
const CLOSING_LOCK_HOURS = 24;

function _closingComputeTotals(c) {
  const deposits = Number(c.depositsARS || 0);         // cargas totales (Σ de 7 equipos)
  // c.ventasARS guarda Σ DESCARGAS (cash-outs a clientes). El dueño definió
  // que en la UI esto se llama VENTA — no hacemos resta con depósitos.
  // Versión previa intentó VENTA = depósitos − descargas pero estaba mal.
  const ventas = Number(c.ventasARS || 0);
  const margin = Number(c.bankMarginPercent || 0);
  const bajada = Number(c.bajadaARS || 0);             // lo que efectivamente se bajó hoy
  const pendienteAnterior = Number(c.pendienteAnteriorARS || 0);
  const bonus = Number(c.bonusARS || 0);
  const ingresos = Number(c.ingresosARS || 0);         // plata que ENTRÓ extra (prestamos recibidos)
  const egresos = Number(c.egresosARS || 0);           // préstamos que HICIMOS (sale, vuelve después)
  const gastos = Number(c.gastosARS || 0);             // gastos del día (consumido, no vuelve)
  // saldoInicial REMOVIDO del modelo nuevo. El CVU 00 hs del día anterior
  // (que viene en pendienteAnteriorARS) ya refleja la realidad bancaria,
  // así que cualquier saldo "inicial" ya está contemplado ahí. Lo dejamos
  // leer del doc por backwards-compat con cierres viejos pero forzamos
  // a 0 para los nuevos.
  const saldoInicial = Number(c.saldoInicialARS || 0);
  const cvuActual = Number(c.cvuMidnightARS || 0);

  // Comisión: % sobre los DEPÓSITOS (cargas). El banco se queda con esta
  // tajada de cada depósito que entra. Es nuestro gasto fijo del día.
  // Se redondea a peso entero para evitar decimales que arrastren feo.
  const commission = Math.round(deposits * (margin / 100));

  // Neto del día = lo que efectivamente queda después de:
  //   venta (cash-out, lo que se pagó)
  //   − comisión (lo que el banco se llevó)
  //   − gastos (los gastos del día)
  //   − egresos (préstamos hechos)
  //   + ingresos (préstamos recibidos)
  const neto = ventas - commission - gastos - egresos + ingresos;

  // Total a bajar = Neto + pendiente anterior (lo que arrastraste).
  const totalABajar = neto + pendienteAnterior;

  // === Pendiente a bajar: realidad bancaria vs cálculo ===
  // Antes era `pendienteHoy = max(0, totalABajar - bajada)` (sólo cálculo).
  // El owner reportó que el cálculo siempre daba un valor distinto al CVU
  // real (porque hay diferencias menores en cada movimiento), generando
  // falsos faltantes que se arrastran.
  //
  // Modelo nuevo:
  //   - pendienteCalculado = lo que la matemática dice que debería quedar
  //   - pendienteHoy = el CVU 00 hs REAL (si el owner lo cargó); si no,
  //     cae al calculado. Es lo que se arrastra al día siguiente.
  //   - cvuDiscrepancy = diferencia entre realidad y cálculo (falta/sobra)
  const diff = totalABajar - bajada;            // según fórmula
  const pendienteCalculado = Math.max(0, diff); // legacy "esperado"
  const sobrepago = Math.max(0, -diff);
  // Si el dueño cargó el CVU 00 hs (>0), eso es la verdad — lo usamos
  // como pendienteHoy. Si no lo cargó todavía, usamos el calculado.
  const pendienteHoy = cvuActual > 0 ? cvuActual : pendienteCalculado;

  // netoSector legacy = -diff (sale positivo si sobraste, negativo si faltaste)
  const netoSector = -diff;

  // CVU esperado según el cálculo (qué debería quedar de pendiente si todo
  // cuadrara): pendienteCalculado + saldoInicial (saldoInicial casi siempre 0
  // en el modelo nuevo, queda para backwards-compat con cierres viejos).
  const cvuExpected = pendienteCalculado + saldoInicial;
  // Discrepancia: cvuActual - cvuExpected
  //   = 0  → perfecto (el banco coincide con los movimientos)
  //   > 0  → sobra plata (entró algo no registrado — revisar)
  //   < 0  → FALTA plata (problema serio: salió plata sin registrarse)
  const cvuDiscrepancy = cvuActual - cvuExpected;

  return {
    commission,
    depositsNet: deposits - commission,
    ventas,                        // Σ cash-outs (alias de descargas — UI lo llama "VENTA")
    bajada,
    bonus,
    ingresos,
    egresos,
    gastos,
    saldoInicial,                  // plata que ya estaba en CVU al arrancar
    neto,                          // venta - comisión - gastos - egresos + ingresos
    totalABajar,                   // neto + pendiente anterior
    pendienteHoy,                  // CVU 00hs real (si cargado) | calculado (fallback)
    pendienteCalculado,            // lo que la fórmula dice
    sobrepago,
    diff,
    netoSector,
    // Cash en banco después de pagar la venta neta = lo que sobra en
    // caja (no incluye bonus que sale por otro lado).
    cashEnBanco: deposits - bajada,
    bajadaShortfall: pendienteHoy,
    cvuExpected,
    cvuActual,
    cvuDiscrepancy
  };
}

function _closingIsLocked(c) {
  if (c.status !== 'confirmed' || !c.confirmedAt) return false;
  return (Date.now() - new Date(c.confirmedAt).getTime()) > (CLOSING_LOCK_HOURS * 3600 * 1000);
}

// Día YYYY-MM-DD hora Argentina
function _closingDateKeyART(now) {
  const d = now || new Date();
  return new Intl.DateTimeFormat('en-CA', {
    timeZone: 'America/Argentina/Buenos_Aires',
    year: 'numeric', month: '2-digit', day: '2-digit'
  }).format(d);
}

// GET /api/admin/closings?from=YYYY-MM-DD&to=YYYY-MM-DD[&sector=]
// Lista cierres con filtros. Default = últimos 30 días.
app.get('/api/admin/closings', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const today = _closingDateKeyART();
    const from = String(req.query.from || '').match(/^\d{4}-\d{2}-\d{2}$/) ? req.query.from : null;
    const to   = String(req.query.to   || '').match(/^\d{4}-\d{2}-\d{2}$/) ? req.query.to   : today;
    const sector = CLOSING_SECTORS.includes(String(req.query.sector)) ? req.query.sector : null;
    // lite=1 → no enviamos el campo `url` de comprobantes (puede ser data:base64
    // de varios MB cada uno). El listado solo necesita kind+note+teamSlot para
    // contar y mostrar resumen. Las URLs se piden on-demand vía
    // GET /api/admin/closings/:id (analyze view).
    const lite = String(req.query.lite || '') === '1';
    const filter = {};
    if (from || to) filter.dateKey = {};
    if (from) filter.dateKey.$gte = from;
    if (to)   filter.dateKey.$lte = to;
    if (sector) filter.sector = sector;
    const rows = await ClosingEntry.find(filter).sort({ dateKey: -1, sector: 1, teamSlot: 1 }).lean();
    const enriched = rows.map(r => {
      const comprobantes = lite && Array.isArray(r.comprobantes)
        ? r.comprobantes.map(c => ({
            kind: c.kind,
            teamSlot: c.teamSlot != null ? c.teamSlot : null,
            note: c.note || '',
            uploadedBy: c.uploadedBy || '',
            uploadedAt: c.uploadedAt || null
            // url omitido a propósito (lite mode)
          }))
        : r.comprobantes;
      return {
        ...r,
        comprobantes,
        computed: _closingComputeTotals(r),
        locked: _closingIsLocked(r)
      };
    });
    res.json({ success: true, rows: enriched, today, lite });
  } catch (err) {
    logger.error(`/api/admin/closings: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// GET /api/admin/closings/:id — fetch full closing row WITH comprobante URLs.
// Usado por el modal Analizar para mostrar las fotos. La lista general usa
// lite=1 (sin urls) para no chocar el browser con MB de base64.
app.get('/api/admin/closings/:id', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const r = await ClosingEntry.findOne({ id }).lean();
    if (!r) return res.status(404).json({ error: 'Cierre no encontrado' });
    res.json({
      success: true,
      row: { ...r, computed: _closingComputeTotals(r), locked: _closingIsLocked(r) }
    });
  } catch (err) {
    logger.error(`GET /api/admin/closings/:id: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Para Buffalo: normaliza el array `teams` que llega del front y calcula
// los totales (depositsARS, ventasARS, bonusARS, bonusCount, transactionsCount)
// como suma de los 7 equipos. bankMarginPercent/bajadaARS/pendienteAnteriorARS/
// withdrawalsCount son GENERALES (uno solo para todo Buffalo, porque la
// bajada se hace una sola vez desde el mismo banco).
function _normalizeBuffaloTeams(input) {
  const arr = Array.isArray(input) ? input : [];
  const out = [];
  for (let i = 0; i < 7; i++) {
    const src = arr.find(t => t && Number(t.slot) === i) || {};
    out.push({
      slot: i,
      name: String(src.name || '').trim().slice(0, 60),
      depositsARS: Math.max(0, Number(src.depositsARS) || 0),
      depositsCount: Math.max(0, Math.round(Number(src.depositsCount) || 0)),
      // VENTA acepta NEGATIVOS — si la operatoria del día cerró perdiendo
      // (cash-out > depósitos o devolvimos plata extra), el monto es negativo.
      ventasARS: Number(src.ventasARS) || 0,
      bonusARS: Math.max(0, Number(src.bonusARS) || 0),
      bonusCount: Math.max(0, Math.round(Number(src.bonusCount) || 0)),
      withdrawalsCount: Math.max(0, Math.round(Number(src.withdrawalsCount) || 0))
    });
  }
  return out;
}

function _aggregateBuffaloTeams(teams) {
  return teams.reduce((acc, t) => {
    acc.depositsARS += t.depositsARS || 0;
    acc.ventasARS += t.ventasARS || 0;
    acc.bonusARS += t.bonusARS || 0;
    acc.bonusCount += t.bonusCount || 0;
    acc.withdrawalsCount += t.withdrawalsCount || 0;
    return acc;
  }, { depositsARS: 0, ventasARS: 0, bonusARS: 0, bonusCount: 0, withdrawalsCount: 0 });
}

// POST /api/admin/closings — crear entrada (draft).
// Body común: { dateKey, sector, bankMarginPercent, bajadaARS,
//   pendienteAnteriorARS, withdrawalsCount, bonusNote, notes }
// Para ganamos/publicidad: incluir además { depositsARS, ventasARS,
//   bonusARS, bonusCount, transactionsCount }.
// Para buffalo: incluir { teams: [{slot,name,depositsARS,ventasARS,bonusARS,
//   bonusCount,transactionsCount}, ...] }.
app.post('/api/admin/closings', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const b = req.body || {};
    const sector = String(b.sector || '');
    if (!CLOSING_SECTORS.includes(sector)) {
      return res.status(400).json({ error: 'Sector inválido' });
    }
    const dateKey = String(b.dateKey || '').match(/^\d{4}-\d{2}-\d{2}$/) ? b.dateKey : _closingDateKeyART();

    // Buffalo tiene UNA sola entry por día (teamSlot=null) con teams[] embebido.
    // Ganamos/Publicidad también teamSlot=null.
    const teamSlot = null;

    // Auto-pull del pendiente del día anterior si no se mandó explícito.
    // Acepta el valor que mande el front (incluso negativo si el dueño lo edita).
    let pendienteAnterior = Number(b.pendienteAnteriorARS) || 0;
    if (!b.pendienteAnteriorARS && b.pendienteAnteriorARS !== 0) {
      const prevDateKey = new Date(new Date(dateKey).getTime() - 24 * 3600 * 1000).toISOString().slice(0, 10);
      const prev = await ClosingEntry.findOne({ dateKey: prevDateKey, sector, teamSlot: null }).lean();
      if (prev) {
        const c = _closingComputeTotals(prev);
        pendienteAnterior = c.pendienteHoy || 0;
      }
    }

    const doc = {
      id: uuidv4(),
      dateKey,
      sector,
      teamSlot,
      teamName: '',
      // Generales (válidos para los 3 sectores)
      bankMarginPercent: Math.max(0, Math.min(100, Number(b.bankMarginPercent) || 0)),
      bajadaARS: Math.max(0, Number(b.bajadaARS) || 0),
      pendienteAnteriorARS: pendienteAnterior,
      // Movimientos extra del día
      ingresosARS: Math.max(0, Number(b.ingresosARS) || 0),
      ingresosNote: String(b.ingresosNote || '').trim().slice(0, 300),
      egresosARS: Math.max(0, Number(b.egresosARS) || 0),
      egresosNote: String(b.egresosNote || '').trim().slice(0, 300),
      gastosARS: Math.max(0, Number(b.gastosARS) || 0),
      gastosNote: String(b.gastosNote || '').trim().slice(0, 300),
      saldoInicialARS: Math.max(0, Number(b.saldoInicialARS) || 0),
      saldoInicialNote: String(b.saldoInicialNote || '').trim().slice(0, 300),
      cvuMidnightARS: Math.max(0, Number(b.cvuMidnightARS) || 0),
      // transacciones totales: GENERAL en Buffalo (no se suma de teams).
      // En ganamos/publicidad sigue siendo el único campo.
      transactionsCount: Math.max(0, Math.round(Number(b.transactionsCount) || 0)),
      bonusNote: String(b.bonusNote || '').trim().slice(0, 200),
      notes: String(b.notes || '').trim().slice(0, 500),
      status: 'draft',
      createdBy: req.user.username || ''
    };

    // Los 3 sectores funcionan igual: 7 slots de equipo, totales = suma de teams.
    {
      const teams = _normalizeBuffaloTeams(b.teams);
      const agg = _aggregateBuffaloTeams(teams);
      doc.teams = teams;
      doc.depositsARS = agg.depositsARS;
      doc.ventasARS = agg.ventasARS;
      doc.bonusARS = agg.bonusARS;
      doc.bonusCount = agg.bonusCount;
      doc.withdrawalsCount = agg.withdrawalsCount;
    }

    try {
      const saved = await ClosingEntry.create(doc);
      res.json({
        success: true,
        row: { ...saved.toObject(), computed: _closingComputeTotals(saved), locked: false }
      });
    } catch (e) {
      if (String(e.message || '').includes('duplicate key')) {
        return res.status(409).json({ error: 'Ya existe un cierre para ese día/sector. Editá el existente.' });
      }
      throw e;
    }
  } catch (err) {
    logger.error(`POST /api/admin/closings: ${err.message}\nstack: ${err.stack}\nbody keys: ${Object.keys(req.body || {}).join(',')}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// PUT /api/admin/closings/:id — editar cierre (bloqueado si > 24h confirmado).
// Cualquier cambio queda en editHistory para auditoría.
app.put('/api/admin/closings/:id', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await ClosingEntry.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });
    if (_closingIsLocked(c)) {
      return res.status(403).json({
        error: `Cierre bloqueado — pasaron más de ${CLOSING_LOCK_HOURS}hs desde la confirmación. No se puede editar.`,
        locked: true
      });
    }
    // Los 3 sectores tienen teams[]: depositsARS/ventasARS/bonusARS/bonusCount/
    // withdrawalsCount se calculan del teams[]; transactionsCount es GENERAL
    // (input directo); bankMargin/bajada/pendienteAnt también generales.
    const editable = [
      'bankMarginPercent','bajadaARS','pendienteAnteriorARS',
      'ingresosARS','ingresosNote','egresosARS','egresosNote',
      'gastosARS','gastosNote','saldoInicialARS','saldoInicialNote','cvuMidnightARS',
      'transactionsCount','bonusNote','notes'
    ];
    const hasTeams = true;
    const b = req.body || {};
    const username = req.user.username || '';
    const changes = [];
    for (const f of editable) {
      if (!(f in b)) continue;
      let v = b[f];
      if (typeof v === 'string') v = v.trim();
      if (typeof v === 'number' || (typeof v === 'string' && f.endsWith('ARS')) || f === 'bankMarginPercent' || f === 'transactionsCount' || f === 'withdrawalsCount' || f === 'bonusCount') {
        v = Number(v) || 0;
        if (f === 'bankMarginPercent') v = Math.max(0, Math.min(100, v));
        else if (f === 'transactionsCount' || f === 'withdrawalsCount' || f === 'bonusCount') v = Math.max(0, Math.round(v));
        // pendienteAnteriorARS y ventasARS pueden ser NEGATIVOS — el dueño
        // edita pendienteAnt manualmente y la venta puede cerrar perdiendo.
        else if (f === 'pendienteAnteriorARS' || f === 'ventasARS') v = v; /* sin cap */
        else v = Math.max(0, v);
      } else if (typeof v === 'string') {
        // Cap a 300 chars para notes (ingresosNote, egresosNote, gastosNote, bonusNote, notes, teamName)
        v = v.slice(0, f === 'notes' ? 500 : (f === 'teamName' ? 60 : 300));
      }
      if (c[f] !== v) {
        changes.push({ editedAt: new Date(), editedBy: username, field: f, before: c[f], after: v });
        c[f] = v;
      }
    }
    // Buffalo o Ganamos: si llega teams[], normalizamos + recomputamos totales.
    if (hasTeams && Array.isArray(b.teams)) {
      const newTeams = _normalizeBuffaloTeams(b.teams);
      const before = c.teams
        ? c.teams.map(t => ({ slot:t.slot, name:t.name, depositsARS:t.depositsARS, depositsCount:t.depositsCount, ventasARS:t.ventasARS, bonusARS:t.bonusARS, bonusCount:t.bonusCount, withdrawalsCount:t.withdrawalsCount }))
        : [];
      const sameJson = JSON.stringify(before) === JSON.stringify(newTeams);
      if (!sameJson) {
        changes.push({ editedAt: new Date(), editedBy: username, field: 'teams', before, after: newTeams });
        c.teams = newTeams;
        const agg = _aggregateBuffaloTeams(newTeams);
        c.depositsARS = agg.depositsARS;
        c.ventasARS = agg.ventasARS;
        c.bonusARS = agg.bonusARS;
        c.bonusCount = agg.bonusCount;
        c.withdrawalsCount = agg.withdrawalsCount;
      }
    }
    if (changes.length === 0) {
      return res.json({ success: true, row: { ...c.toObject(), computed: _closingComputeTotals(c), locked: _closingIsLocked(c) }, message: 'Sin cambios' });
    }
    c.editHistory.push(...changes);
    await c.save();
    res.json({
      success: true,
      row: { ...c.toObject(), computed: _closingComputeTotals(c), locked: _closingIsLocked(c) },
      changesCount: changes.length
    });
  } catch (err) {
    logger.error(`PUT /api/admin/closings/:id: ${err.message}\nstack: ${err.stack}\nbody keys: ${Object.keys(req.body || {}).join(',')}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST /api/admin/closings/:id/confirm — pasa de draft a confirmed.
// Setea confirmedAt + lockedAt (24h después).
// REQUIERE: si quedó pendiente > 0, debe haber al menos 1 comprobante
// con kind='pendiente_bank' (foto del banco que muestre que la plata
// sigue ahí). Sin esto, se considera plata faltante y rechazamos.
app.post('/api/admin/closings/:id/confirm', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await ClosingEntry.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });
    if (c.status === 'confirmed') {
      return res.status(400).json({ error: 'Cierre ya estaba confirmado' });
    }
    const totals = _closingComputeTotals(c);
    if (totals.pendienteHoy > 0) {
      const hasProof = (c.comprobantes || []).some(p => p.kind === 'pendiente_bank');
      if (!hasProof) {
        return res.status(400).json({
          error: `Quedaron $${totals.pendienteHoy.toLocaleString('es-AR')} pendientes para bajar. Tenés que adjuntar un comprobante del banco mostrando que la plata sigue en la cuenta antes de confirmar (sino se considera plata faltante).`,
          missingBankProof: true,
          pendienteARS: totals.pendienteHoy
        });
      }
    }
    const now = new Date();
    c.status = 'confirmed';
    c.confirmedAt = now;
    c.confirmedBy = req.user.username || '';
    c.lockedAt = new Date(now.getTime() + CLOSING_LOCK_HOURS * 3600 * 1000);
    await c.save();
    res.json({ success: true, row: { ...c.toObject(), computed: _closingComputeTotals(c), locked: false } });
  } catch (err) {
    logger.error(`POST /api/admin/closings/:id/confirm: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST /api/admin/closings/:id/verify — toggle del tilde "verificado"
// (el owner revisó el análisis y dió OK manual). Sólo si está confirmado.
app.post('/api/admin/closings/:id/verify', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await ClosingEntry.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });
    if (c.status !== 'confirmed') {
      return res.status(400).json({ error: 'Confirmá el cierre antes de verificarlo' });
    }
    const username = req.user.username || '';
    if (c.verifiedAt) {
      // toggle off
      c.editHistory.push({ editedAt: new Date(), editedBy: username, field: 'verified', before: true, after: false });
      c.verifiedAt = null;
      c.verifiedBy = '';
    } else {
      c.verifiedAt = new Date();
      c.verifiedBy = username;
      c.editHistory.push({ editedAt: new Date(), editedBy: username, field: 'verified', before: false, after: true });
    }
    await c.save();
    res.json({ success: true, row: { ...c.toObject(), computed: _closingComputeTotals(c), locked: _closingIsLocked(c) } });
  } catch (err) {
    logger.error(`POST verify: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST /api/admin/closings/:id/comprobante — adjuntar foto (URL ya subida)
// Body: { url, kind: 'bajada'|'pendiente_bank', note }
app.post('/api/admin/closings/:id/comprobante', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await ClosingEntry.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });
    if (_closingIsLocked(c)) {
      return res.status(403).json({ error: 'Cierre bloqueado por 24h', locked: true });
    }
    const url = String((req.body && req.body.url) || '').trim();
    // Aceptamos http(s):// (foto en S3 o externa) o data:image/...;base64,...
    // El fallback del cliente usa data URI cuando S3 no está configurado.
    const isHttp = /^https?:\/\//i.test(url);
    const isDataImg = /^data:image\/(jpeg|png|gif|webp);base64,/i.test(url);
    if (!url || !(isHttp || isDataImg)) {
      return res.status(400).json({ error: 'URL inválida (esperado http(s):// o data:image/...;base64,)' });
    }
    // Sanity check: data URIs muy grandes podrían reventar el doc de Mongo
    // (límite de 16MB total). 8MB de data URI ya es ~6MB de imagen real.
    if (isDataImg && url.length > 8 * 1024 * 1024) {
      return res.status(413).json({ error: 'Imagen demasiado grande — máx 8MB en base64' });
    }
    const validKinds = ['deposito', 'venta', 'bonificacion', 'bajada', 'pendiente_bank', 'ingreso', 'egreso', 'gasto'];
    const kind = validKinds.includes(req.body && req.body.kind) ? req.body.kind : 'deposito';
    const note = String((req.body && req.body.note) || '').trim().slice(0, 200);
    const slotRaw = req.body && req.body.teamSlot;
    const teamSlot = (Number.isInteger(slotRaw) && slotRaw >= 0 && slotRaw <= 6) ? slotRaw : null;
    c.comprobantes.push({ url, kind, teamSlot, note, uploadedBy: req.user.username || '' });
    c.editHistory.push({
      editedAt: new Date(),
      editedBy: req.user.username || '',
      field: 'comprobante_add',
      before: null,
      after: { url, kind, teamSlot }
    });
    await c.save();
    res.json({ success: true, row: { ...c.toObject(), computed: _closingComputeTotals(c), locked: false } });
  } catch (err) {
    logger.error(`POST comprobante: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// DELETE /api/admin/closings/:id/comprobante/:idx — sacar un comprobante.
app.delete('/api/admin/closings/:id/comprobante/:idx', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const idx = parseInt(req.params.idx, 10);
    const c = await ClosingEntry.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });
    if (_closingIsLocked(c)) {
      return res.status(403).json({ error: 'Cierre bloqueado por 24h', locked: true });
    }
    if (!Number.isInteger(idx) || idx < 0 || idx >= c.comprobantes.length) {
      return res.status(400).json({ error: 'Índice inválido' });
    }
    const removed = c.comprobantes.splice(idx, 1)[0];
    c.editHistory.push({
      editedAt: new Date(),
      editedBy: req.user.username || '',
      field: 'comprobante_remove',
      before: removed,
      after: null
    });
    await c.save();
    res.json({ success: true, row: { ...c.toObject(), computed: _closingComputeTotals(c), locked: false } });
  } catch (err) {
    logger.error(`DELETE comprobante: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// DELETE /api/admin/closings/:id — borrar cierre completo.
// REQUIERE PIN ('1818') — pasa como ?pin=1818 o en el body.
// Funciona incluso si el cierre está confirmado/locked (es un override
// manual del owner para casos donde hay que limpiar/empezar de cero).
const CLOSING_DELETE_PIN = '1818';
app.delete('/api/admin/closings/:id', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const pin = String(
      (req.query && req.query.pin) ||
      (req.body && req.body.pin) ||
      (req.headers && req.headers['x-delete-pin']) ||
      ''
    );
    if (pin !== CLOSING_DELETE_PIN) {
      return res.status(403).json({ error: 'PIN incorrecto' });
    }
    const c = await ClosingEntry.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });
    const snapshot = {
      dateKey: c.dateKey, sector: c.sector, status: c.status,
      depositsARS: c.depositsARS, ventasARS: c.ventasARS,
      bajadaARS: c.bajadaARS, deletedBy: req.user.username || ''
    };
    await ClosingEntry.deleteOne({ id });
    logger.warn(`DELETE closing ${id} (PIN OK) by ${req.user.username}: ${JSON.stringify(snapshot)}`);
    res.json({ success: true });
  } catch (err) {
    logger.error(`DELETE /api/admin/closings/:id: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// GET /api/admin/closings/summary?from=&to= — totales agregados.
app.get('/api/admin/closings/summary', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const today = _closingDateKeyART();
    const from = String(req.query.from || '').match(/^\d{4}-\d{2}-\d{2}$/) ? req.query.from : null;
    const to   = String(req.query.to   || '').match(/^\d{4}-\d{2}-\d{2}$/) ? req.query.to   : today;
    const sector = CLOSING_SECTORS.includes(String(req.query.sector)) ? req.query.sector : null;
    const filter = {};
    if (from || to) filter.dateKey = {};
    if (from) filter.dateKey.$gte = from;
    if (to)   filter.dateKey.$lte = to;
    if (sector) filter.sector = sector;
    const rows = await ClosingEntry.find(filter).lean();
    const bySector = {};
    for (const r of rows) {
      const c = _closingComputeTotals(r);
      const k = r.sector;
      if (!bySector[k]) {
        bySector[k] = {
          sector: k,
          depositsARS: 0, commission: 0, depositsNet: 0,
          ventasARS: 0, bajadaARS: 0, pendienteHoy: 0,
          bonusARS: 0, netoSector: 0, transactionsCount: 0,
          withdrawalsCount: 0, bonusCount: 0, entries: 0
        };
      }
      const s = bySector[k];
      s.depositsARS += r.depositsARS || 0;
      s.commission += c.commission;
      s.depositsNet += c.depositsNet;
      s.ventasARS += r.ventasARS || 0;
      s.pendienteAnteriorARS += r.pendienteAnteriorARS || 0;
      s.bajadaARS += r.bajadaARS || 0;
      s.pendienteHoy += c.pendienteHoy;
      s.bonusARS += r.bonusARS || 0;
      s.netoSector += c.netoSector;
      s.neto += (c.neto || 0);
      s.transactionsCount += r.transactionsCount || 0;
      s.withdrawalsCount += r.withdrawalsCount || 0;
      s.bonusCount += r.bonusCount || 0;
      s.entries += 1;
    }
    const totals = {
      depositsARS: 0, commission: 0, depositsNet: 0,
      ventasARS: 0, pendienteAnteriorARS: 0, bajadaARS: 0, pendienteHoy: 0,
      bonusARS: 0, netoSector: 0, neto: 0,
      transactionsCount: 0, withdrawalsCount: 0, bonusCount: 0
    };
    for (const s of Object.values(bySector)) {
      totals.depositsARS += s.depositsARS;
      totals.commission += s.commission;
      totals.depositsNet += s.depositsNet;
      totals.ventasARS += s.ventasARS;
      totals.pendienteAnteriorARS += s.pendienteAnteriorARS || 0;
      totals.bajadaARS += s.bajadaARS;
      totals.pendienteHoy += s.pendienteHoy;
      totals.bonusARS += s.bonusARS;
      totals.netoSector += s.netoSector;
      totals.neto += (s.neto || 0);
      totals.transactionsCount += s.transactionsCount;
      totals.withdrawalsCount += s.withdrawalsCount;
      totals.bonusCount += s.bonusCount;
    }
    res.json({ success: true, bySector: Object.values(bySector), totals, from, to });
  } catch (err) {
    logger.error(`/api/admin/closings/summary: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// GET /api/admin/closings/analysis?period=day|week|month[&sector=&teamSlot=]
// Devuelve totales del período actual vs el anterior + deltas para
// comparativa empresarial. Acepta filtro opcional por sector/equipo.
app.get('/api/admin/closings/analysis', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const period = ['day','week','month'].includes(String(req.query.period)) ? req.query.period : 'month';
    const sector = CLOSING_SECTORS.includes(String(req.query.sector)) ? req.query.sector : null;
    const teamSlotRaw = req.query.teamSlot;
    const teamSlot = (teamSlotRaw !== undefined && teamSlotRaw !== '' && Number.isFinite(parseInt(teamSlotRaw, 10)))
      ? parseInt(teamSlotRaw, 10)
      : null;

    const today = _closingDateKeyART();
    // Calcular rangos current vs previous
    function dateMinusDays(dateKey, days) {
      const d = new Date(dateKey + 'T00:00:00Z');
      d.setUTCDate(d.getUTCDate() - days);
      return d.toISOString().slice(0, 10);
    }
    let curFrom, curTo, prevFrom, prevTo;
    if (period === 'day') {
      curFrom = curTo = today;
      prevFrom = prevTo = dateMinusDays(today, 1);
    } else if (period === 'week') {
      curTo = today;
      curFrom = dateMinusDays(today, 6);     // últimos 7 días
      prevTo = dateMinusDays(today, 7);
      prevFrom = dateMinusDays(today, 13);
    } else {
      curTo = today;
      curFrom = dateMinusDays(today, 29);    // últimos 30 días
      prevTo = dateMinusDays(today, 30);
      prevFrom = dateMinusDays(today, 59);
    }

    function buildFilter(from, to) {
      const f = { dateKey: { $gte: from, $lte: to } };
      if (sector) f.sector = sector;
      if (sector === 'buffalo' && teamSlot != null) f.teamSlot = teamSlot;
      return f;
    }

    function aggregate(rows) {
      const out = {
        depositsARS: 0, commission: 0, depositsNet: 0,
        ventasARS: 0, bajadaARS: 0, pendienteHoy: 0,
        bonusARS: 0, netoSector: 0, transactionsCount: 0,
        withdrawalsCount: 0, bonusCount: 0,
        days: 0, entries: 0
      };
      const dayKeys = new Set();
      for (const r of rows) {
        const c = _closingComputeTotals(r);
        out.depositsARS += r.depositsARS || 0;
        out.commission += c.commission;
        out.depositsNet += c.depositsNet;
        out.ventasARS += r.ventasARS || 0;
        out.bajadaARS += r.bajadaARS || 0;
        out.pendienteHoy += c.pendienteHoy;
        out.bonusARS += r.bonusARS || 0;
        out.netoSector += c.netoSector;
        out.transactionsCount += r.transactionsCount || 0;
        out.withdrawalsCount += r.withdrawalsCount || 0;
        out.bonusCount += r.bonusCount || 0;
        out.entries += 1;
        dayKeys.add(r.dateKey);
      }
      out.days = dayKeys.size;
      // KPIs derivados / promedios
      out.avgTicket = out.transactionsCount > 0 ? out.depositsARS / out.transactionsCount : 0;
      out.avgNetoDiario = out.days > 0 ? out.netoSector / out.days : 0;
      out.avgVentasDiario = out.days > 0 ? out.ventasARS / out.days : 0;
      out.avgWithdrawal = out.withdrawalsCount > 0 ? out.bajadaARS / out.withdrawalsCount : 0;
      out.avgBonus = out.bonusCount > 0 ? out.bonusARS / out.bonusCount : 0;
      // % de cost-to-revenue (bonos sobre depósitos netos)
      out.bonusCostPct = out.depositsNet > 0 ? (out.bonusARS / out.depositsNet) * 100 : 0;
      return out;
    }

    const [currentRows, previousRows] = await Promise.all([
      ClosingEntry.find(buildFilter(curFrom, curTo)).lean(),
      ClosingEntry.find(buildFilter(prevFrom, prevTo)).lean()
    ]);

    const current = aggregate(currentRows);
    const previous = aggregate(previousRows);

    function deltaPct(a, b) {
      if (!b) return a > 0 ? 100 : 0;
      return ((a - b) / Math.abs(b)) * 100;
    }
    const deltas = {
      depositsARS: { abs: current.depositsARS - previous.depositsARS, pct: deltaPct(current.depositsARS, previous.depositsARS) },
      ventasARS:   { abs: current.ventasARS - previous.ventasARS,     pct: deltaPct(current.ventasARS, previous.ventasARS) },
      bajadaARS:   { abs: current.bajadaARS - previous.bajadaARS,     pct: deltaPct(current.bajadaARS, previous.bajadaARS) },
      bonusARS:    { abs: current.bonusARS - previous.bonusARS,       pct: deltaPct(current.bonusARS, previous.bonusARS) },
      netoSector:  { abs: current.netoSector - previous.netoSector,   pct: deltaPct(current.netoSector, previous.netoSector) },
      pendienteHoy:{ abs: current.pendienteHoy - previous.pendienteHoy, pct: deltaPct(current.pendienteHoy, previous.pendienteHoy) },
      transactionsCount: { abs: current.transactionsCount - previous.transactionsCount, pct: deltaPct(current.transactionsCount, previous.transactionsCount) },
      withdrawalsCount:  { abs: current.withdrawalsCount - previous.withdrawalsCount,   pct: deltaPct(current.withdrawalsCount, previous.withdrawalsCount) },
      bonusCount:        { abs: current.bonusCount - previous.bonusCount,               pct: deltaPct(current.bonusCount, previous.bonusCount) },
      avgTicket:    { abs: current.avgTicket - previous.avgTicket,         pct: deltaPct(current.avgTicket, previous.avgTicket) },
      avgWithdrawal:{ abs: current.avgWithdrawal - previous.avgWithdrawal, pct: deltaPct(current.avgWithdrawal, previous.avgWithdrawal) },
      avgBonus:     { abs: current.avgBonus - previous.avgBonus,           pct: deltaPct(current.avgBonus, previous.avgBonus) },
      bonusCostPct: { abs: current.bonusCostPct - previous.bonusCostPct,   pct: deltaPct(current.bonusCostPct, previous.bonusCostPct) }
    };

    // Conteo de alertas en el período actual
    let rojos = 0, faltantes = 0, sobrepagos = 0, pendOK = 0;
    for (const r of currentRows) {
      const c = _closingComputeTotals(r);
      const hasBank = (r.comprobantes || []).some(p => p.kind === 'pendiente_bank');
      if (r.bajadaARS > c.totalABajar) sobrepagos++;
      else if (c.pendienteHoy > 0) {
        if (r.status === 'confirmed' && !hasBank) faltantes++;
        else pendOK++;
      } else if (r.status === 'confirmed' && c.netoSector < 0) rojos++;
    }

    res.json({
      success: true,
      period,
      current: { ...current, from: curFrom, to: curTo },
      previous: { ...previous, from: prevFrom, to: prevTo },
      deltas,
      alerts: { rojos, faltantes, sobrepagos, pendOK }
    });
  } catch (err) {
    logger.error(`/api/admin/closings/analysis: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ============================================
// COTIZACIONES SEMANALES
// ============================================
// Cada lunes (o cuando el owner lo decida) se cierra una cotización por
// equipo (hasta 10) y se cotiza al valor del USDT del día.
//   precio_equipo = total_ARS_equipo / usdt_rate
// El owner marca con tilde (✓) cuando ya cotizó, o cruz (✗) si no.

const CotizacionEntry = require('./src/models/CotizacionEntry');
const CotizacionExternaEntry = require('./src/models/CotizacionExternaEntry');
const COT_DELETE_PIN = '1818';

function _cotizacionCompute(c) {
  const rate = Number(c.usdtRate || 0);
  const teams = Array.isArray(c.teams) ? c.teams : [];
  let totalARS = 0;
  let totalCommissionARS = 0;
  let totalNetARS = 0;
  let totalCotizadoNetARS = 0;
  let totalPendienteNetARS = 0;
  let teamsCotizadasN = 0;
  let teamsPendientesN = 0;
  const priced = teams.map((t) => {
    const totARS = Number(t.totalARS || 0);
    const pct = Math.max(0, Math.min(100, Number(t.commissionPercent || 0)));
    const commissionARS = Math.round(totARS * (pct / 100));
    const netARS = Math.max(0, totARS - commissionARS);
    const isCotizado = !!t.cotizado;
    totalARS += totARS;
    totalCommissionARS += commissionARS;
    totalNetARS += netARS;
    if (totARS > 0) {
      // Sólo contamos equipos con monto > 0 — los slots vacíos no son
      // ni cotizados ni pendientes, simplemente no existen.
      if (isCotizado) {
        teamsCotizadasN += 1;
        totalCotizadoNetARS += netARS;
      } else {
        teamsPendientesN += 1;
        totalPendienteNetARS += netARS;
      }
    }
    const precioUSDT = rate > 0 ? +(netARS / rate).toFixed(2) : 0;
    return {
      slot: t.slot,
      name: t.name || '',
      totalARS: totARS,
      commissionPercent: pct,
      commissionARS,
      netARS,
      photoUrl: t.photoUrl || '',
      precioUSDT,
      cotizado: isCotizado,
      cotizedAt: t.cotizedAt || null,
      cotizedBy: t.cotizedBy || ''
    };
  });
  const totalUSDT = rate > 0 ? +(totalNetARS / rate).toFixed(2) : 0;
  const totalCotizadoUSDT = rate > 0 ? +(totalCotizadoNetARS / rate).toFixed(2) : 0;
  const totalPendienteUSDT = rate > 0 ? +(totalPendienteNetARS / rate).toFixed(2) : 0;
  // Derivado: la cotización está "toda cotizada" cuando hay al menos un
  // equipo con monto y todos los que tienen monto están cotizados.
  const allCotizadas = (teamsCotizadasN > 0) && (teamsPendientesN === 0);
  return {
    teams: priced,
    totalARS, totalCommissionARS, totalNetARS, totalUSDT,
    totalCotizadoNetARS, totalCotizadoUSDT,
    totalPendienteNetARS, totalPendienteUSDT,
    teamsCotizadasN, teamsPendientesN,
    allCotizadas,
    usdtRate: rate
  };
}

// GET /api/admin/cotizaciones?from=YYYY-MM-DD&to=YYYY-MM-DD
// Factory: monta los endpoints CRUD de cotizaciones en `prefix` (sin slash
// trailing), usando `Model` como modelo de mongoose y `label` como nombre
// humano para logs. Lo usamos dos veces: una para /api/admin/cotizaciones
// (CotizacionEntry) y otra para /api/admin/cotizaciones-externo
// (CotizacionExternaEntry). Misma lógica, distinta collection.
function _mountCotizacionRoutes(prefix, Model, label) {

app.get(prefix, authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const today = _closingDateKeyART();
    const from = String(req.query.from || '').match(/^\d{4}-\d{2}-\d{2}$/) ? req.query.from : null;
    const to   = String(req.query.to   || '').match(/^\d{4}-\d{2}-\d{2}$/) ? req.query.to   : today;
    const filter = {};
    if (from || to) filter.dateKey = {};
    if (from) filter.dateKey.$gte = from;
    if (to)   filter.dateKey.$lte = to;
    const rows = await Model.find(filter).sort({ dateKey: -1 }).lean();
    const enriched = rows.map((r) => {
      const calc = _cotizacionCompute(r);
      return {
        id: r.id,
        dateKey: r.dateKey,
        usdtRate: calc.usdtRate,
        teams: calc.teams,
        totalARS: calc.totalARS,
        totalCommissionARS: calc.totalCommissionARS,
        totalNetARS: calc.totalNetARS,
        totalUSDT: calc.totalUSDT,
        totalCotizadoNetARS: calc.totalCotizadoNetARS,
        totalCotizadoUSDT: calc.totalCotizadoUSDT,
        totalPendienteNetARS: calc.totalPendienteNetARS,
        totalPendienteUSDT: calc.totalPendienteUSDT,
        teamsCotizadasN: calc.teamsCotizadasN,
        teamsPendientesN: calc.teamsPendientesN,
        allCotizadas: calc.allCotizadas,
        status: r.status || 'draft',
        closedAt: r.closedAt || null,
        closedBy: r.closedBy || '',
        cotizado: !!r.cotizado,
        cotizedAt: r.cotizedAt,
        cotizedBy: r.cotizedBy || '',
        notes: r.notes || '',
        createdBy: r.createdBy || '',
        createdAt: r.createdAt,
        updatedAt: r.updatedAt
      };
    });
    res.json({ success: true, items: enriched });
  } catch (err) {
    logger.error(`GET ${prefix} (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// Config key para guardar la plantilla de equipos (nombres + % comisión)
// por scope. Cuando se crea una cotización nueva, si hay plantilla, se
// pre-rellena con ella así el dueño no tiene que tipear todo de nuevo.
const _defaultsConfigKey = (lbl) => 'cotizacion_defaults_' + lbl;

// GET <prefix>/defaults — leer la plantilla guardada
app.get(prefix + '/defaults', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const v = await getConfig(_defaultsConfigKey(label), null);
    res.json({ success: true, defaults: v || { teams: [] } });
  } catch (err) {
    logger.error(`GET ${prefix}/defaults (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST <prefix>/defaults — guardar plantilla desde el body.
// Body: { teams: [{slot, name, commissionPercent}, ...] }
app.post(prefix + '/defaults', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const teamsIn = Array.isArray(req.body && req.body.teams) ? req.body.teams : [];
    const teams = [];
    for (let i = 0; i < 10; i++) {
      const src = teamsIn.find(t => Number(t && t.slot) === i) || {};
      teams.push({
        slot: i,
        name: String(src.name || '').trim().slice(0, 80),
        commissionPercent: Math.max(0, Math.min(100, Number(src.commissionPercent) || 0))
      });
    }
    await setConfig(_defaultsConfigKey(label), { teams, savedAt: new Date(), savedBy: (req.user && req.user.username) || '' });
    res.json({ success: true });
  } catch (err) {
    logger.error(`POST ${prefix}/defaults (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST <prefix> — crear una cotización para una fecha.
app.post(prefix, authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const body = req.body || {};
    const dateKey = String(body.dateKey || '').match(/^\d{4}-\d{2}-\d{2}$/) ? body.dateKey : null;
    if (!dateKey) return res.status(400).json({ error: 'Fecha inválida' });

    const existing = await Model.findOne({ dateKey });
    if (existing) return res.status(409).json({ error: 'Ya existe una cotización para esa fecha' });

    // Pre-rellenar con la plantilla guardada (si existe) — nombres y %
    // comisión. Los montos siempre arrancan en 0 (los carga el dueño).
    const defaults = await getConfig(_defaultsConfigKey(label), null);
    const defTeams = (defaults && Array.isArray(defaults.teams)) ? defaults.teams : [];
    const teams = Array.from({ length: 10 }, (_, i) => {
      const def = defTeams.find(t => Number(t.slot) === i) || {};
      return {
        slot: i,
        name: def.name || '',
        totalARS: 0,
        commissionPercent: Math.max(0, Math.min(100, Number(def.commissionPercent) || 0)),
        photoUrl: ''
      };
    });

    const doc = {
      id: `cot_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      dateKey,
      teams,
      usdtRate: Number(body.usdtRate || 0),
      cotizado: false,
      notes: String(body.notes || '').slice(0, 500),
      createdBy: (req.user && req.user.username) || ''
    };
    const saved = await Model.create(doc);
    res.json({ success: true, item: { id: saved.id, dateKey: saved.dateKey } });
  } catch (err) {
    if (err && err.code === 11000) {
      return res.status(409).json({ error: 'Ya existe una cotización para esa fecha' });
    }
    logger.error(`POST ${prefix} (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// PUT <prefix>/:id — actualiza campos editables. Si la cotización está
// cerrada (status='closed') sólo se permite editar las notas. Para
// modificar equipos/rate/fecha hay que reabrirla primero con /:id/reopen.
app.put(prefix + '/:id', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await Model.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cotización no encontrada' });
    const isClosed = c.status === 'closed';

    const b = req.body || {};
    if (b.dateKey !== undefined) {
      if (isClosed) return res.status(403).json({ error: 'Cotización cerrada — reabrila para cambiar la fecha' });
      const dk = String(b.dateKey || '').match(/^\d{4}-\d{2}-\d{2}$/) ? b.dateKey : null;
      if (!dk) return res.status(400).json({ error: 'Fecha inválida' });
      if (dk !== c.dateKey) {
        const collide = await Model.findOne({ dateKey: dk, id: { $ne: id } });
        if (collide) return res.status(409).json({ error: 'Ya existe una cotización para esa fecha' });
        c.dateKey = dk;
      }
    }
    if (b.usdtRate !== undefined) {
      if (isClosed) return res.status(403).json({ error: 'Cotización cerrada — reabrila para cambiar el USDT' });
      c.usdtRate = Math.max(0, Number(b.usdtRate) || 0);
    }
    if (b.notes !== undefined) c.notes = String(b.notes || '').slice(0, 500);

    if (Array.isArray(b.teams)) {
      if (isClosed) return res.status(403).json({ error: 'Cotización cerrada — reabrila para cambiar los equipos' });
      const map = new Map(c.teams.map((t) => [t.slot, t]));
      for (const t of b.teams) {
        const slot = Number(t.slot);
        if (!Number.isInteger(slot) || slot < 0 || slot > 9) continue;
        const cur = map.get(slot) || { slot, name: '', totalARS: 0, commissionPercent: 0, photoUrl: '' };
        if (t.name !== undefined) cur.name = String(t.name || '').slice(0, 80);
        if (t.totalARS !== undefined) cur.totalARS = Math.max(0, Number(t.totalARS) || 0);
        if (t.commissionPercent !== undefined) cur.commissionPercent = Math.max(0, Math.min(100, Number(t.commissionPercent) || 0));
        if (t.photoUrl !== undefined) cur.photoUrl = String(t.photoUrl || '');
        map.set(slot, cur);
      }
      const merged = [];
      for (let i = 0; i < 10; i++) {
        merged.push(map.get(i) || { slot: i, name: '', totalARS: 0, commissionPercent: 0, photoUrl: '' });
      }
      c.teams = merged;
    }

    await c.save();
    res.json({ success: true });
  } catch (err) {
    logger.error(`PUT ${prefix}/:id (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST <prefix>/:id/close
app.post(prefix + '/:id/close', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await Model.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cotización no encontrada' });
    if (c.status === 'closed') return res.json({ success: true, status: 'closed', alreadyClosed: true });
    c.status = 'closed';
    c.closedAt = new Date();
    c.closedBy = (req.user && req.user.username) || '';
    await c.save();
    res.json({ success: true, status: 'closed' });
  } catch (err) {
    logger.error(`POST ${prefix}/:id/close (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST <prefix>/:id/reopen
app.post(prefix + '/:id/reopen', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await Model.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cotización no encontrada' });
    if (c.status !== 'closed') return res.json({ success: true, status: c.status || 'draft' });
    c.status = 'draft';
    c.closedAt = null;
    c.closedBy = '';
    await c.save();
    res.json({ success: true, status: 'draft' });
  } catch (err) {
    logger.error(`POST ${prefix}/:id/reopen (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST <prefix>/:id/toggle — alterna el tilde cotizado a NIVEL ENTRADA.
// Marca/desmarca TODOS los equipos con monto > 0. Útil para "marcar todo
// cotizado de una" cuando ya pagaron todos juntos.
app.post(prefix + '/:id/toggle', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await Model.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cotización no encontrada' });
    const newVal = !c.cotizado;
    const now = new Date();
    const who = (req.user && req.user.username) || '';
    c.cotizado = newVal;
    c.cotizedAt = newVal ? now : null;
    c.cotizedBy = newVal ? who : '';
    // Sincronizar con los equipos (sólo los que tienen monto).
    if (Array.isArray(c.teams)) {
      for (const t of c.teams) {
        if (Number(t.totalARS || 0) <= 0) continue;
        t.cotizado = newVal;
        t.cotizedAt = newVal ? now : null;
        t.cotizedBy = newVal ? who : '';
      }
    }
    await c.save();
    res.json({ success: true, cotizado: c.cotizado });
  } catch (err) {
    logger.error(`POST ${prefix}/:id/toggle (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST <prefix>/:id/team/:slot/toggle — tilde por equipo individual.
// El owner marca un equipo a la vez, a medida que cotiza. Cuando se tildan
// todos los que tienen monto, la cotización completa pasa a "cotizada".
app.post(prefix + '/:id/team/:slot/toggle', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const slot = Number(req.params.slot);
    if (!Number.isInteger(slot) || slot < 0 || slot > 9) {
      return res.status(400).json({ error: 'Slot inválido' });
    }
    const c = await Model.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cotización no encontrada' });
    const teams = Array.isArray(c.teams) ? c.teams : [];
    const idx = teams.findIndex(t => Number(t.slot) === slot);
    if (idx < 0) return res.status(404).json({ error: 'Equipo no encontrado en esa cotización' });
    const t = teams[idx];
    if (Number(t.totalARS || 0) <= 0) {
      return res.status(400).json({ error: 'No se puede cotizar un equipo sin monto cargado' });
    }
    const newVal = !t.cotizado;
    t.cotizado = newVal;
    t.cotizedAt = newVal ? new Date() : null;
    t.cotizedBy = newVal ? ((req.user && req.user.username) || '') : '';
    // Sincronizar el flag de entry: queda "cotizada" si todos los equipos
    // con monto están cotizados.
    const anyPending = teams.some(x => Number(x.totalARS || 0) > 0 && !x.cotizado);
    const anyCotizado = teams.some(x => Number(x.totalARS || 0) > 0 && x.cotizado);
    c.cotizado = anyCotizado && !anyPending;
    c.cotizedAt = c.cotizado ? new Date() : null;
    c.cotizedBy = c.cotizado ? ((req.user && req.user.username) || '') : '';
    await c.save();
    res.json({
      success: true,
      slot,
      teamCotizado: t.cotizado,
      allCotizadas: c.cotizado
    });
  } catch (err) {
    logger.error(`POST ${prefix}/:id/team/:slot/toggle (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST <prefix>/:id/confirm — fija cotizado=true (idempotente).
app.post(prefix + '/:id/confirm', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const c = await Model.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cotización no encontrada' });
    if (!c.cotizado) {
      c.cotizado = true;
      c.cotizedAt = new Date();
      c.cotizedBy = (req.user && req.user.username) || '';
      await c.save();
    }
    res.json({ success: true, cotizado: true });
  } catch (err) {
    logger.error(`POST ${prefix}/:id/confirm (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// DELETE <prefix>/:id — borra (requiere PIN 1818).
app.delete(prefix + '/:id', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const pin = String(
      (req.query && req.query.pin) ||
      (req.body && req.body.pin) ||
      (req.headers && req.headers['x-delete-pin']) ||
      ''
    );
    if (pin !== COT_DELETE_PIN) return res.status(403).json({ error: 'PIN incorrecto' });
    const c = await Model.findOne({ id });
    if (!c) return res.status(404).json({ error: 'Cotización no encontrada' });
    await Model.deleteOne({ id });
    logger.warn(`DELETE ${label} ${id} by ${req.user && req.user.username}`);
    res.json({ success: true });
  } catch (err) {
    logger.error(`DELETE ${prefix}/:id (${label}): ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

} // _mountCotizacionRoutes

// Montar las dos versiones: interna (Cotizaciones) y externa (Cotizaciones Externo)
_mountCotizacionRoutes('/api/admin/cotizaciones', CotizacionEntry, 'cotizacion');
_mountCotizacionRoutes('/api/admin/cotizaciones-externo', CotizacionExternaEntry, 'cotizacion-externa');

// GET /api/admin/active-users-count — count de users conectados por socket
// AHORA. Para el badge verde pulsante en el sidebar del admin. Pollea cada
// 10s desde el frontend. Súper liviano — solo retorna .size del Map.
app.get('/api/admin/active-users-count', authMiddleware, adminMiddleware, (req, res) => {
  try {
    res.json({
      success: true,
      count: connectedUsers ? connectedUsers.size : 0,
      admins: connectedAdmins ? connectedAdmins.size : 0,
      ts: Date.now()
    });
  } catch (err) {
    res.status(500).json({ error: 'Error del servidor', count: 0 });
  }
});

// ============================================
// EMPLEADOS POR ESTRUCTURA
// ============================================
// Personal de los 3 sectores financieros (ganamos / publicidad / buffalo)
// agrupado por puesto. Sueldo base mensual + pagos extra por feriados.
// Usa el mismo gate (closingsAccessMiddleware) que los cierres y las
// cotizaciones, porque comparte rol financiero.

const EmployeeEntry = require('./src/models/EmployeeEntry');
const EmployeeSectorConfig = require('./src/models/EmployeeSectorConfig');
const EmployeeClosing = require('./src/models/EmployeeClosing');
const EMP_DELETE_PIN = '1818';
const EMP_SECTORS = ['ganamos', 'publicidad', 'buffalo'];
const EMP_DIAS_MES = 30;
const EMP_FRANCO_DAYS = ['lunes', 'martes', 'miercoles', 'jueves', 'viernes', 'sabado', 'domingo'];

// Calcula el pago de un empleado. `sectorCfg` trae los feriados generales
// del sector — se suman salvo los que el empleado tenga excluidos.
function _empCompute(e, sectorCfg) {
  const sueldo = Number(e.sueldoARS || 0);
  const valorDia = sueldo / EMP_DIAS_MES;
  const feriados = Array.isArray(e.feriados) ? e.feriados : [];
  const faltantes = Array.isArray(e.faltantes) ? e.faltantes : [];
  const descuentos = Array.isArray(e.descuentos) ? e.descuentos : [];
  // Feriado trabajado: monto manual si se cargó, si no el valor/día.
  const feriadosTotal = feriados.reduce((s, f) => {
    const a = Number(f.amountARS || 0);
    return s + (a > 0 ? a : valorDia);
  }, 0);
  // Feriados generales del sector que el empleado SÍ cobra (no excluidos).
  const excluidos = new Set(Array.isArray(e.feriadosGeneralesExcluidos) ? e.feriadosGeneralesExcluidos : []);
  const generales = (sectorCfg && Array.isArray(sectorCfg.feriadosGenerales)) ? sectorCfg.feriadosGenerales : [];
  let feriadosGeneralesTotal = 0;
  let feriadosGeneralesCount = 0;
  for (const g of generales) {
    if (excluidos.has(g.id)) continue;
    const a = Number(g.amountARS || 0);
    feriadosGeneralesTotal += (a > 0 ? a : valorDia);
    feriadosGeneralesCount++;
  }
  const faltantesTotal = faltantes.length * valorDia;
  const descuentosTotal = descuentos.reduce((s, d) => s + Number(d.amountARS || 0), 0);
  // Ajustes manuales: pueden ser + o − (ej. diferencia por cambio de turno).
  const ajustes = Array.isArray(e.ajustes) ? e.ajustes : [];
  const ajustesTotal = ajustes.reduce((s, a) => s + Number(a.amountARS || 0), 0);
  // Comisión: costo fijo de transferencia en USD → ARS con la cotización
  // del sector. Es un gasto aparte del sueldo (no lo recibe el empleado).
  const comisionUSD = Number(e.comisionUSD != null ? e.comisionUSD : 2);
  const usdRate = Number((sectorCfg && sectorCfg.usdRate) || 0);
  const comisionARS = comisionUSD * usdRate;
  const totalMensual = sueldo + feriadosTotal + feriadosGeneralesTotal
    - faltantesTotal - descuentosTotal + ajustesTotal;
  return {
    sueldoARS: sueldo,
    valorDia,
    feriadosTotal,
    feriadosCount: feriados.length,
    feriadosGeneralesTotal,
    feriadosGeneralesCount,
    faltantesTotal,
    faltantesCount: faltantes.length,
    descuentosTotal,
    descuentosCount: descuentos.length,
    ajustesTotal,
    ajustesCount: ajustes.length,
    comisionUSD,
    comisionARS,
    totalMensual,
    costoTotal: totalMensual + comisionARS
  };
}

// Trae las 3 configs de sector. Si una no existe todavía la devuelve
// vacía en memoria (no persiste hasta que el owner la guarde).
async function _empLoadSectorConfigs() {
  const docs = await EmployeeSectorConfig.find({}).lean();
  const map = {};
  for (const s of EMP_SECTORS) {
    map[s] = docs.find(d => d.sector === s) || { sector: s, feriadosGenerales: [], usdRate: 0 };
  }
  return map;
}

// GET /api/admin/empleados[?sector=…]
app.get('/api/admin/empleados', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const filter = {};
    if (EMP_SECTORS.includes(req.query.sector)) filter.sector = req.query.sector;
    const [rows, sectorConfigs] = await Promise.all([
      EmployeeEntry.find(filter).sort({ sector: 1, role: 1, name: 1 }).lean(),
      _empLoadSectorConfigs()
    ]);
    const items = rows.map(r => ({ ...r, computed: _empCompute(r, sectorConfigs[r.sector]) }));
    res.json({ success: true, items, sectorConfigs });
  } catch (err) {
    logger.error(`GET /api/admin/empleados: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST /api/admin/empleados — crear empleado
app.post('/api/admin/empleados', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const b = req.body || {};
    const sector = String(b.sector || '');
    if (!EMP_SECTORS.includes(sector)) return res.status(400).json({ error: 'Sector inválido' });
    const role = String(b.role || '').trim().toLowerCase().slice(0, 60);
    if (!role) return res.status(400).json({ error: 'Puesto requerido' });
    const doc = {
      id: `emp_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      sector,
      role,
      name: String(b.name || '').trim().slice(0, 100),
      schedule: String(b.schedule || '').trim().slice(0, 200),
      sueldoARS: Math.max(0, Number(b.sueldoARS) || 0),
      comisionUSD: (b.comisionUSD != null ? Math.max(0, Number(b.comisionUSD) || 0) : 2),
      feriados: [],
      faltantes: [],
      descuentos: [],
      ajustes: [],
      feriadosGeneralesExcluidos: [],
      francosPerWeek: 0,
      francoDays: [],
      workedUntil: '',
      notes: String(b.notes || '').slice(0, 500),
      active: b.active !== false,
      createdBy: (req.user && req.user.username) || ''
    };
    const saved = await EmployeeEntry.create(doc);
    res.json({ success: true, item: { id: saved.id } });
  } catch (err) {
    logger.error(`POST /api/admin/empleados: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// GET /api/admin/empleados/sector-config — feriados generales + USD por sector.
// Registrado ANTES de /:id para que no lo capture la ruta con parámetro.
app.get('/api/admin/empleados/sector-config', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const configs = await _empLoadSectorConfigs();
    res.json({ success: true, configs });
  } catch (err) {
    logger.error(`GET /api/admin/empleados/sector-config: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// PUT /api/admin/empleados/sector-config — guardar config de un sector.
app.put('/api/admin/empleados/sector-config', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const b = req.body || {};
    const sector = String(b.sector || '');
    if (!EMP_SECTORS.includes(sector)) return res.status(400).json({ error: 'Sector inválido' });
    const feriadosGenerales = Array.isArray(b.feriadosGenerales) ? b.feriadosGenerales.map(f => ({
      id: String((f && f.id) || `fg_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`).slice(0, 60),
      dateKey: String((f && f.dateKey) || '').slice(0, 10),
      amountARS: Math.max(0, Number((f && f.amountARS) || 0)),
      note: String((f && f.note) || '').slice(0, 200)
    })) : [];
    const usdRate = Math.max(0, Number(b.usdRate) || 0);
    await EmployeeSectorConfig.findOneAndUpdate(
      { sector },
      { $set: { feriadosGenerales, usdRate } },
      { upsert: true, new: true }
    );
    res.json({ success: true });
  } catch (err) {
    logger.error(`PUT /api/admin/empleados/sector-config: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ===================== CIERRES DE EMPLEADOS =====================
// Registrados ANTES de /:id para que la ruta con parámetro no los capture.

// POST /api/admin/empleados/cierre — congela el período actual como
// historial y deja la hoja viva limpia de movimientos para el siguiente.
app.post('/api/admin/empleados/cierre', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const [rows, sectorConfigs] = await Promise.all([
      EmployeeEntry.find({}).sort({ sector: 1, role: 1, name: 1 }).lean(),
      _empLoadSectorConfigs()
    ]);
    if (rows.length === 0) return res.status(400).json({ error: 'No hay empleados para cerrar.' });

    const employees = rows.map(r => ({
      empId: r.id, sector: r.sector, role: r.role, name: r.name,
      schedule: r.schedule || '', sueldoARS: r.sueldoARS || 0,
      feriados: r.feriados || [], faltantes: r.faltantes || [], descuentos: r.descuentos || [],
      feriadosGeneralesExcluidos: r.feriadosGeneralesExcluidos || [],
      francosPerWeek: r.francosPerWeek || 0, francoDays: r.francoDays || [],
      workedUntil: r.workedUntil || '', notes: r.notes || '',
      computed: _empCompute(r, sectorConfigs[r.sector])
    }));
    const bySector = {};
    let grandTotalARS = 0;
    let comisionesTotalARS = 0;
    for (const e of employees) {
      const t = Number(e.computed && e.computed.totalMensual) || 0;
      const com = Number(e.computed && e.computed.comisionARS) || 0;
      grandTotalARS += t;
      comisionesTotalARS += com;
      bySector[e.sector] = (bySector[e.sector] || 0) + t;
    }

    const closing = await EmployeeClosing.create({
      id: `empc_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
      periodLabel: String((req.body && req.body.periodLabel) || '').trim().slice(0, 80),
      closedAt: new Date(),
      closedBy: (req.user && req.user.username) || '',
      employees,
      employeeCount: employees.length,
      grandTotalARS,
      comisionesTotalARS,
      costoTotalARS: grandTotalARS + comisionesTotalARS,
      bySector,
      sectorConfigs
    });

    // Hoja nueva: se conservan empleados, sueldos, francos y roles; se
    // resetean los movimientos del período (feriados/faltantes/descuentos)
    // y las exclusiones de feriados generales. Los feriados generales del
    // sector también pertenecen al período cerrado, así que se limpian.
    await EmployeeEntry.updateMany({}, {
      $set: { feriados: [], faltantes: [], descuentos: [], feriadosGeneralesExcluidos: [] }
    });
    await EmployeeSectorConfig.updateMany({}, { $set: { feriadosGenerales: [] } });

    logger.info(`[empleados] cierre ${closing.id} por ${(req.user && req.user.username) || '?'} — ${employees.length} empleados · total $${grandTotalARS}`);
    res.json({ success: true, id: closing.id, employeeCount: employees.length, grandTotalARS });
  } catch (err) {
    logger.error(`POST /api/admin/empleados/cierre: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// GET /api/admin/empleados/cierres — historial (resumen, sin el detalle).
app.get('/api/admin/empleados/cierres', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const rows = await EmployeeClosing.find({}, {
      id: 1, periodLabel: 1, closedAt: 1, closedBy: 1, paid: 1, paidAt: 1,
      employeeCount: 1, grandTotalARS: 1, comisionesTotalARS: 1, costoTotalARS: 1,
      bySector: 1, _id: 0
    }).sort({ closedAt: -1 }).limit(120).lean();
    res.json({ success: true, items: rows });
  } catch (err) {
    logger.error(`GET /api/admin/empleados/cierres: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// GET /api/admin/empleados/cierres/:id — detalle completo de un cierre.
app.get('/api/admin/empleados/cierres/:id', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const c = await EmployeeClosing.findOne({ id: String(req.params.id || '') }).lean();
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });
    res.json({ success: true, closing: c });
  } catch (err) {
    logger.error(`GET /api/admin/empleados/cierres/:id: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST /api/admin/empleados/cierres/:id/paid — tildar/destildar pagado.
app.post('/api/admin/empleados/cierres/:id/paid', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const paid = !!(req.body && req.body.paid);
    const c = await EmployeeClosing.findOneAndUpdate(
      { id: String(req.params.id || '') },
      { $set: { paid, paidAt: paid ? new Date() : null, paidBy: paid ? ((req.user && req.user.username) || '') : '' } },
      { new: true }
    );
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });
    res.json({ success: true, paid: c.paid, paidAt: c.paidAt });
  } catch (err) {
    logger.error(`POST /api/admin/empleados/cierres/:id/paid: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// POST /api/admin/empleados/cierres/:id/reabrir — deshace un cierre: vuelve
// a poner en la hoja viva los movimientos de ese período y lo saca del
// historial. Para usar si se cerró con un error.
app.post('/api/admin/empleados/cierres/:id/reabrir', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const c = await EmployeeClosing.findOne({ id: String(req.params.id || '') }).lean();
    if (!c) return res.status(404).json({ error: 'Cierre no encontrado' });

    // Restaurar en cada empleado los movimientos que el cierre había
    // limpiado. Si un empleado fue borrado desde entonces, se saltea.
    let restored = 0;
    for (const e of (c.employees || [])) {
      if (!e || !e.empId) continue;
      const r = await EmployeeEntry.updateOne(
        { id: e.empId },
        { $set: {
          feriados: e.feriados || [],
          faltantes: e.faltantes || [],
          descuentos: e.descuentos || [],
          feriadosGeneralesExcluidos: e.feriadosGeneralesExcluidos || []
        } }
      );
      if (r && (r.matchedCount || r.n)) restored++;
    }
    // Restaurar feriados generales por sector.
    const scfg = c.sectorConfigs || {};
    for (const sector of Object.keys(scfg)) {
      const fg = (scfg[sector] && Array.isArray(scfg[sector].feriadosGenerales))
        ? scfg[sector].feriadosGenerales : [];
      await EmployeeSectorConfig.findOneAndUpdate(
        { sector },
        { $set: { feriadosGenerales: fg } },
        { upsert: true }
      ).catch(() => {});
    }
    // El período vuelve a estar abierto — se quita del historial.
    await EmployeeClosing.deleteOne({ id: c.id });

    logger.info(`[empleados] cierre ${c.id} REABIERTO por ${(req.user && req.user.username) || '?'} — ${restored} empleados restaurados`);
    res.json({ success: true, restored });
  } catch (err) {
    logger.error(`POST /api/admin/empleados/cierres/:id/reabrir: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// PUT /api/admin/empleados/:id — actualizar
app.put('/api/admin/empleados/:id', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const e = await EmployeeEntry.findOne({ id });
    if (!e) return res.status(404).json({ error: 'Empleado no encontrado' });
    const b = req.body || {};
    if (b.sector !== undefined) {
      if (!EMP_SECTORS.includes(b.sector)) return res.status(400).json({ error: 'Sector inválido' });
      e.sector = b.sector;
    }
    if (b.role !== undefined) {
      const r = String(b.role || '').trim().toLowerCase().slice(0, 60);
      if (!r) return res.status(400).json({ error: 'Puesto requerido' });
      e.role = r;
    }
    if (b.name !== undefined) e.name = String(b.name || '').trim().slice(0, 100);
    if (b.schedule !== undefined) e.schedule = String(b.schedule || '').trim().slice(0, 200);
    if (b.sueldoARS !== undefined) e.sueldoARS = Math.max(0, Number(b.sueldoARS) || 0);
    if (b.notes !== undefined) e.notes = String(b.notes || '').slice(0, 500);
    if (b.active !== undefined) e.active = !!b.active;
    if (Array.isArray(b.feriados)) {
      e.feriados = b.feriados.map(f => ({
        dateKey: String((f && f.dateKey) || '').slice(0, 10),
        amountARS: Math.max(0, Number((f && f.amountARS) || 0)),
        note: String((f && f.note) || '').slice(0, 200)
      }));
    }
    if (Array.isArray(b.faltantes)) {
      e.faltantes = b.faltantes.map(f => ({
        dateKey: String((f && f.dateKey) || '').slice(0, 10),
        note: String((f && f.note) || '').slice(0, 200)
      }));
    }
    if (Array.isArray(b.descuentos)) {
      e.descuentos = b.descuentos.map(d => ({
        dateKey: String((d && d.dateKey) || '').slice(0, 10),
        amountARS: Math.max(0, Number((d && d.amountARS) || 0)),
        note: String((d && d.note) || '').slice(0, 200)
      }));
    }
    if (Array.isArray(b.ajustes)) {
      e.ajustes = b.ajustes.map(a => ({
        dateKey: String((a && a.dateKey) || '').slice(0, 10),
        amountARS: Number((a && a.amountARS) || 0), // + o −
        note: String((a && a.note) || '').slice(0, 200)
      }));
    }
    if (b.comisionUSD !== undefined) {
      e.comisionUSD = Math.max(0, Number(b.comisionUSD) || 0);
    }
    if (b.francosPerWeek !== undefined) {
      e.francosPerWeek = Math.min(7, Math.max(0, Math.round(Number(b.francosPerWeek) || 0)));
    }
    if (Array.isArray(b.francoDays)) {
      e.francoDays = b.francoDays
        .map(d => String(d || '').toLowerCase().trim())
        .filter(d => EMP_FRANCO_DAYS.includes(d));
    }
    if (b.workedUntil !== undefined) {
      e.workedUntil = String(b.workedUntil || '').slice(0, 10);
    }
    if (Array.isArray(b.feriadosGeneralesExcluidos)) {
      e.feriadosGeneralesExcluidos = b.feriadosGeneralesExcluidos
        .map(x => String(x || '').slice(0, 60))
        .filter(Boolean);
    }
    await e.save();
    res.json({ success: true });
  } catch (err) {
    logger.error(`PUT /api/admin/empleados/:id: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// DELETE /api/admin/empleados/:id — borrar (requiere PIN 1818)
app.delete('/api/admin/empleados/:id', authMiddleware, closingsAccessMiddleware, async (req, res) => {
  try {
    const id = String(req.params.id || '');
    const pin = String(
      (req.query && req.query.pin) ||
      (req.body && req.body.pin) ||
      (req.headers && req.headers['x-delete-pin']) ||
      ''
    );
    if (pin !== EMP_DELETE_PIN) return res.status(403).json({ error: 'PIN incorrecto' });
    const e = await EmployeeEntry.findOne({ id });
    if (!e) return res.status(404).json({ error: 'Empleado no encontrado' });
    await EmployeeEntry.deleteOne({ id });
    res.json({ success: true });
  } catch (err) {
    logger.error(`DELETE /api/admin/empleados/:id: ${err.message}`);
    res.status(500).json({ error: 'Error del servidor' });
  }
});

// ============================================
// MANEJADOR DE ERRORES CENTRALIZADO
// ============================================

const errorHandler = require('./src/middlewares/errorHandler');
app.use(errorHandler);

// ============================================
// INICIAR SERVIDOR
// ============================================

if (process.env.VERCEL) {
  initializeData().then(() => {
    logger.info('Data initialized for Vercel');
  });
  
  module.exports = app;
} else {
  (async () => {
    try {
      await loadSecretsFromSSM();
    } catch (err) {
      console.error('[BOOT] No se pudo cargar la configuración desde SSM. Abortando.');
      process.exit(1);
    }

    // Validar JWT_SECRET ahora que SSM ya cargó las vars
    JWT_SECRET = process.env.JWT_SECRET;
    if (!JWT_SECRET) {
      console.error('⛔ FATAL: JWT_SECRET no configurado. El servidor no puede arrancar.');
      process.exit(1);
    }

    await initializeData();
    /* redis adapter removido */
    server.listen(PORT, () => {
      logger.info(`Server started on port ${PORT} (${process.env.NODE_ENV || 'development'})`);
    });
  })();
}