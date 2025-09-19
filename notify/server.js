require("dotenv").config();

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const helmet = require("helmet");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");

// === Config ===
const PORT = Number(process.env.PORT || 3001);
const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
	.split(",")
	.map((s) => s.trim())
	.filter(Boolean);
const SOCKET_TOKEN = process.env.SOCKET_TOKEN || "";
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY || "";
const INTROSPECT_URL = process.env.LARAVEL_INTROSPECT_URL || "";
const INTROSPECT_BEARER = process.env.LARAVEL_INTROSPECT_BEARER || "";
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || "";
const MONGO_URI = process.env.MONGO_URI || "";

// === App/Server/IO ===
const app = express();
app.use(express.json());
app.use(helmet());
app.use(
	cors({ origin: CORS_ORIGINS.length ? CORS_ORIGINS : true, credentials: true })
);

const server = http.createServer(app);
const io = new Server(server, {
	cors: {
		origin: CORS_ORIGINS.length ? CORS_ORIGINS : true,
		credentials: true,
	},
	transports: ["websocket", "polling"], // permite ambos transportes
});

// ===== Mongoose Models =====
let Notification;
let Idempotency;
try {
	// Reusar si ya existe (hot-reload)
	Notification = mongoose.model("Notification");
} catch {
	const NotificationSchema = new mongoose.Schema(
		{
			userId: { type: String, index: true, required: true },
			title: {
				type: String,
				default: "Aviso",
				enum: ["Aviso", "Error", "Warning", "Info"],
			},
			body: { type: String, default: "" },
			status: {
				type: String,
				default: "unread",
				enum: ["read", "unread", "hidden"],
			},
			data: { type: mongoose.Schema.Types.Mixed, default: {} },
      deliveredAt: { type: Date, default: null },
      readAt: { type: Date, default: null },
		},
		{ timestamps: { createdAt: "createdAt", updatedAt: false } },
	);

	NotificationSchema.index({ userId: 1, createdAt: -1 });
	Notification = mongoose.model("Notification", NotificationSchema);
}

try {
  Idempotency = mongoose.model('Idempotency');
} catch {
  const IdempotencySchema = new mongoose.Schema(
    {
      key: { type: String, required: true, unique: true, index: true },
      notificationId: { type: mongoose.Schema.Types.ObjectId, required: true },
    },
    { timestamps: { createdAt: 'createdAt', updatedAt: false } }
  );
  // TTL de 24h
  IdempotencySchema.index({ createdAt: 1 }, { expireAfterSeconds: 86400 });
  Idempotency = mongoose.model('Idempotency', IdempotencySchema);
}

app.set("trust proxy", true); // usa X-Forwarded-For si estás detrás de proxy

// === Helpers de auth ===
async function authFromLaravel(token) {
	if (!INTROSPECT_URL) return null;
	try {
		const r = await axios.get(INTROSPECT_URL, {
			headers: {
				Authorization: `Bearer ${token}`,
				"X-Internal-Auth": INTROSPECT_BEARER,
			},
		});
		const userId = String(r?.data?.id || r?.data?.user?.id || "");
		return userId || null;
	} catch {
		return null;
	}
}

function authFromJwt(token) {
	if (!JWT_PUBLIC_KEY) return null;
	try {
		const payload = jwt.verify(token, JWT_PUBLIC_KEY, {
			algorithms: ["RS256"],
		});
		return String(payload.sub || payload.id || payload.user_id || "");
	} catch {
		return null;
	}
}

async function resolveUserIdFromHandshake(socket) {
	const bearer =
		socket.handshake.auth?.token ||
		(socket.handshake.headers.authorization || "").replace(/^Bearer\s+/i, "");

	// 1) Modo token compartido + userId explícito (rápido para arrancar)
	if (SOCKET_TOKEN && bearer === SOCKET_TOKEN) {
		const uid = socket.handshake.auth?.userId || "";
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
		if (!userId) return next(new Error("unauthorized"));
		socket.data.userId = userId;
		next();
	} catch (e) {
		next(new Error("auth_error"));
	}
});

// === Conexión ===
io.on("connection", (socket) => {
	const userId = socket.data.userId;
	const ip =
		socket.handshake.headers["x-forwarded-for"] || socket.handshake.address;

	// Une al usuario a su room
	const room = `user:${userId}`;
	socket.join(room);

	console.log(`[connect] user=${userId} sid=${socket.id} ip=${ip}`);

	// Cliente confirma que le llegó (entregada al dispositivo)
	socket.on("notify:ack", async ({ id }) => {
		try {
			if (!id || mongoose.connection?.readyState !== 1) return;
			await Notification.findByIdAndUpdate(id, { deliveredAt: new Date() }).exec();
		} catch (_) {
			// swallow, no romper flujo de socket
		}
	});

	// Cliente marca como leída
	socket.on("notify:read", async ({ id }) => {
		try {
			if (!id || mongoose.connection?.readyState !== 1) return;
			await Notification.findByIdAndUpdate(id, { status: "read", readAt: new Date() }).exec();
		} catch (_) {
			// swallow
		}
	});

	// Eco opcional
	socket.on("ping:client", () =>
		socket.emit("pong:server", { ts: Date.now() })
	);

	socket.on("disconnect", (reason) => {
		console.log(
			`[disconnect] user=${userId} sid=${socket.id} reason=${reason}`
		);
	});
});

// === API REST mínima para probar emisiones ===
function requireInternalAuth(req, res, next) {
	const token = req.headers["x-internal-auth"];
	if (!INTERNAL_TOKEN || token === INTERNAL_TOKEN) return next();
	return res.status(401).json({ ok: false, error: "unauthorized_internal" });
}

app.get("/v1/health", (req, res) => res.json({ ok: true, ts: Date.now() }));

// Emitir a un usuario (pruebas y hooks desde Laravel)
app.post("/v1/emit", requireInternalAuth, async (req, res) => {
	const { userId, title, body, data } = req.body || {};
	if (!userId)
		return res.status(400).json({ ok: false, error: "missing_userId" });

	const idemKey = (req.headers["idempotency-key"] || "").toString();
	const payload = {
		title: title || "Aviso",
		body: body || "",
		data: data || {},
		status: "unread",
	};

	// Persistir en Mongo si está configurado
	let saved = null;
	if (MONGO_URI && mongoose.connection?.readyState === 1) {
		// Idempotencia: si hay llave y ya existe, devolver mismo id
		if (idemKey) {
			try {
				const existing = await Idempotency.findOne({ key: idemKey }).lean();
        console.log('existing', existing);
				if (existing?.notificationId && existing.notificationId !== null) {
					return res.json({ ok: true, delivered: true, id: existing.notificationId });
				}
			} catch (_) {}
		}
		try {
      console.log('payload', payload);
			saved = await Notification.create({ userId: String(userId), ...payload });
      console.log('saved', saved);
			// Guardar mapping de idempotencia si corresponde
			if (idemKey) {
				try {
					await Idempotency.create({ key: idemKey, notificationId: saved._id });
				} catch (_) {
					// si hay conflicto de clave, alguien creó antes: devolver el existente
					try {
						const existing = await Idempotency.findOne({ key: idemKey }).lean();
						if (existing?.notificationId) {
							return res.json({ ok: true, delivered: true, id: existing.notificationId });
						}
					} catch (_) {}
				}
			}
		} catch (e) {
      console.log('e', e);
			// no bloquear por error de persistencia
		}
	}

	io.to(`user:${userId}`).emit("notify", {
		...payload,
		id: saved?._id || undefined,
		createdAt: saved?.createdAt || Date.now(),
	});

	return res.json({ ok: true, delivered: true, id: saved?._id || null });
});

// Saber si un usuario está online (tamaño del room)
app.get("/v1/online/:userId", (req, res) => {
	const room =
		io.sockets.adapter.rooms.get(`user:${req.params.userId}`) || new Set();
	res.json({ ok: true, sockets: room.size });
});

// Listar notificaciones de un usuario
app.get("/v1/notifications/:userId", async (req, res) => {
	if (!MONGO_URI)
		return res.status(503).json({ ok: false, error: "mongo_disabled" });
	if (mongoose.connection?.readyState !== 1)
		return res.status(503).json({ ok: false, error: "mongo_disconnected" });

	const { userId } = req.params;
	const page = Math.max(1, Number(req.query.page || 1));
	const limit = Math.min(100, Math.max(1, Number(req.query.limit || 20)));
	const skip = (page - 1) * limit;

	try {
		const [items, total] = await Promise.all([
			Notification.find({ userId: String(userId) })
				.sort({ createdAt: -1 })
				.skip(skip)
				.limit(limit)
				.lean(),
			Notification.countDocuments({ userId: String(userId) }),
		]);

		res.json({ ok: true, page, limit, total, items });
	} catch (e) {
		res.status(500).json({ ok: false, error: "mongo_query_error" });
	}
});

app.post('/v1/notifications/:id/read', requireInternalAuth, async (req, res) => {
  try {
    await Notification.findByIdAndUpdate(req.params.id, { status:'read', readAt:new Date() }).exec();
    res.json({ ok: true });
  } catch { res.status(500).json({ ok:false }); }
});

app.post('/v1/notifications/:id/hide', requireInternalAuth, async (req, res) => {
  try {
    await Notification.findByIdAndUpdate(req.params.id, { status:'hidden' }).exec();
    res.json({ ok: true });
  } catch { res.status(500).json({ ok:false }); }
});


// === Start ===
async function start() {
	// Conectar a Mongo si hay URI
	if (MONGO_URI) {
		try {
			await mongoose.connect(MONGO_URI, {
				serverSelectionTimeoutMS: 5000,
			});
			console.log("[mongo] conectado");
		} catch (e) {
			console.error("[mongo] no se pudo conectar:", e?.message);
		}
	} else {
		console.log("[mongo] MONGO_URI no configurado, persistencia deshabilitada");
	}

	server.listen(PORT, () => {
		console.log(`notif-sockets (Express+Socket.IO) escuchando en :${PORT}`);
	});
}

start();
