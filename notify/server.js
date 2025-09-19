require('dotenv').config();

const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const axios = require('axios');
const jwt = require('jsonwebtoken');

// === Config ===
const PORT = Number(process.env.PORT || 3001);
const CORS_ORIGINS = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
const SOCKET_TOKEN = process.env.SOCKET_TOKEN || '';
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY || '';
const INTROSPECT_URL = process.env.LARAVEL_INTROSPECT_URL || '';
const INTROSPECT_BEARER = process.env.LARAVEL_INTROSPECT_BEARER || '';
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || '';

// === App/Server/IO ===
const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors({ origin: CORS_ORIGINS.length ? CORS_ORIGINS : true, credentials: true }));

const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: CORS_ORIGINS.length ? CORS_ORIGINS : true, credentials: true },
  transports: ['websocket', 'polling'] // permite ambos transportes
});

app.set('trust proxy', true); // usa X-Forwarded-For si estás detrás de proxy

// === Helpers de auth ===
async function authFromLaravel(token) {
  if (!INTROSPECT_URL) return null;
  try {
    const r = await axios.get(INTROSPECT_URL, {
      headers: { Authorization: `Bearer ${token}`, 'X-Internal-Auth': INTROSPECT_BEARER }
    });
    const userId = String(r?.data?.id || r?.data?.user?.id || '');
    return userId || null;
  } catch {
    return null;
  }
}

function authFromJwt(token) {
  if (!JWT_PUBLIC_KEY) return null;
  try {
    const payload = jwt.verify(token, JWT_PUBLIC_KEY, { algorithms: ['RS256'] });
    return String(payload.sub || payload.id || payload.user_id || '');
  } catch {
    return null;
  }
}

async function resolveUserIdFromHandshake(socket) {
  const bearer = socket.handshake.auth?.token
    || (socket.handshake.headers.authorization || '').replace(/^Bearer\s+/i, '');

  // 1) Modo token compartido + userId explícito (rápido para arrancar)
  if (SOCKET_TOKEN && bearer === SOCKET_TOKEN) {
    const uid = socket.handshake.auth?.userId || '';
    return uid ? String(uid) : null;
  }

  // 2) Modo JWT con clave pública
  const jwtUid = authFromJwt(bearer);
  if (jwtUid) return jwtUid;

  // 3) Modo introspección contra Laravel
  const laravelUid = await authFromLaravel(bearer);
  if (laravelUid) return laravelUid;

  return null;
}

// === Auth de sockets ===
io.use(async (socket, next) => {
  try {
    const userId = await resolveUserIdFromHandshake(socket);
    if (!userId) return next(new Error('unauthorized'));
    socket.data.userId = userId;
    next();
  } catch (e) {
    next(new Error('auth_error'));
  }
});

// === Conexión ===
io.on('connection', (socket) => {
  const userId = socket.data.userId;
  const ip = socket.handshake.headers['x-forwarded-for'] || socket.handshake.address;

  // Une al usuario a su room
  const room = `user:${userId}`;
  socket.join(room);

  console.log(`[connect] user=${userId} sid=${socket.id} ip=${ip}`);

  // Eco opcional
  socket.on('ping:client', () => socket.emit('pong:server', { ts: Date.now() }));

  socket.on('disconnect', (reason) => {
    console.log(`[disconnect] user=${userId} sid=${socket.id} reason=${reason}`);
  });
});

// === API REST mínima para probar emisiones ===
function requireInternalAuth(req, res, next) {
  const token = req.headers['x-internal-auth'];
  if (!INTERNAL_TOKEN || token === INTERNAL_TOKEN) return next();
  return res.status(401).json({ ok: false, error: 'unauthorized_internal' });
}

app.get('/v1/health', (req, res) => res.json({ ok: true, ts: Date.now() }));

// Emitir a un usuario (pruebas y hooks desde Laravel)
app.post('/v1/emit', requireInternalAuth, (req, res) => {
  const { userId, title, body, data } = req.body || {};
  if (!userId) return res.status(400).json({ ok: false, error: 'missing_userId' });

  const payload = { title: title || 'Aviso', body: body || '', data: data || {} };
  io.to(`user:${userId}`).emit('notify', payload);

  return res.json({ ok: true, delivered: true });
});

// Saber si un usuario está online (tamaño del room)
app.get('/v1/online/:userId', (req, res) => {
  const room = io.sockets.adapter.rooms.get(`user:${req.params.userId}`) || new Set();
  res.json({ ok: true, sockets: room.size });
});

// === Start ===
server.listen(PORT, () => {
  console.log(`notif-sockets (Express+Socket.IO) escuchando en :${PORT}`);
});
