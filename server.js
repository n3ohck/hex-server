require("dotenv").config();

const express = require("express");
const http = require("http");
const net = require("net");
const fs = require("fs");
const path = require("path");
const { Server } = require("socket.io");
const cors = require("cors");
const helmet = require("helmet");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const https = require('https');


// === Config ===
const PORT = Number(process.env.PORT || 3001);               // Express + Socket.IO
const HTTP_INGEST_PORT = parseInt(process.env.HTTP_INGEST_PORT || "9000", 10); // HTTP crudo
const TCP_PORT = parseInt(process.env.TCP_PORT || "9100", 10);
const LOG_DIR = process.env.LOG_DIR || "/var/www/html/hex-server";
const MAX_HTTP_BODY = 5 * 1024 * 1024;

const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
    .split(",").map(s => s.trim()).filter(Boolean);

const SOCKET_TOKEN = process.env.SOCKET_TOKEN || "";
const JWT_PUBLIC_KEY = process.env.JWT_PUBLIC_KEY || "";
const INTROSPECT_URL = process.env.LARAVEL_INTROSPECT_URL || "";
const INTROSPECT_BEARER = process.env.LARAVEL_INTROSPECT_BEARER || "";
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || "";
const MONGO_URI = process.env.MONGO_URI || "";

const LARAVEL_INGEST_URL = process.env.LARAVEL_INGEST_URL || "";
const LARAVEL_INGEST_BEARER = process.env.LARAVEL_INGEST_BEARER || "";
const LARAVEL_TIMEOUT_MS = parseInt(process.env.LARAVEL_TIMEOUT_MS || "5000", 10);
const LARAVEL_MAX_RETRIES = parseInt(process.env.LARAVEL_MAX_RETRIES || "2", 10);

const startTs = new Date().toISOString();

// --- log helpers ---
const log  = (...a) => console.log("[INFO ]", ...a);
const warn = (...a) => console.warn("[WARN ]", ...a);
const err  = (...a) => console.error("[ERROR]", ...a);

const sanitizeIp = (addr = "unknown") =>
    addr.replace(/[:.]/g, "_").replace(/^_+ffff_/, "");
const isPrintable = (b) => b >= 0x20 && b <= 0x7e;
const logLine = (clientIP, buf, tag = "") => {
    const now = new Date().toISOString();
    const hex = buf.toString("hex").toUpperCase();
    const ascii = Array.from(buf)
        .map((b) => (isPrintable(b) ? String.fromCharCode(b) : "."))
        .join("");
    return `[${now}] ${tag} IP=${clientIP} LEN=${buf.length} HEX=${hex} ASCII=${ascii}`;
};
function safeAppend(file, text) {
    try { fs.appendFileSync(file, text + "\n", { flag: "a" }); }
    catch (e) { err(`append fail (${file}): ${e.message}`); }
}

// --- prepara LOG_DIR ---
try {
    if (!fs.existsSync(LOG_DIR)) {
        fs.mkdirSync(LOG_DIR, { recursive: true });
        log(`LOG_DIR created: ${LOG_DIR}`);
    }
    fs.accessSync(LOG_DIR, fs.constants.W_OK);
    log(`LOG_DIR writable: ${LOG_DIR}`);
} catch (e) {
    err(`LOG_DIR not writable (${LOG_DIR}): ${e.message}`);
}

// === App/Server/IO ===
const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors({ origin: CORS_ORIGINS.length ? CORS_ORIGINS : true, credentials: true }));
app.set("trust proxy", true);
const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin: CORS_ORIGINS.length ? CORS_ORIGINS : true, credentials: true },
    transports: ["websocket", "polling"],
});

// ===== Mongoose Models (opcionales para notificaciones) =====
let Notification, Idempotency;
try { Notification = mongoose.model("Notification"); }
catch {
    const NotificationSchema = new mongoose.Schema({
        userId: { type: String, index: true, required: true },
        title: { type: String, default: "Aviso", enum: ["Aviso", "Error", "Warning", "Info"] },
        body: { type: String, default: "" },
        status: { type: String, default: "unread", enum: ["read", "unread", "hidden"] },
        data: { type: mongoose.Schema.Types.Mixed, default: {} },
        deliveredAt: { type: Date, default: null },
        readAt: { type: Date, default: null },
    }, { timestamps: { createdAt: "createdAt", updatedAt: false } });
    NotificationSchema.index({ userId: 1, createdAt: -1 });
    Notification = mongoose.model("Notification", NotificationSchema);
}
try { Idempotency = mongoose.model("Idempotency"); }
catch {
    const IdempotencySchema = new mongoose.Schema({
        key: { type: String, required: true, unique: true, index: true },
        notificationId: { type: mongoose.Schema.Types.ObjectId, required: true },
    }, { timestamps: { createdAt: "createdAt", updatedAt: false } });
    IdempotencySchema.index({ createdAt: 1 }, { expireAfterSeconds: 86400 });
    Idempotency = mongoose.model("Idempotency", IdempotencySchema);
}

// === Auth helpers ===
async function authFromLaravel(token) {
    if (!INTROSPECT_URL) return null;
    try {
        const r = await axios.get(INTROSPECT_URL, {
            headers: { Authorization: `Bearer ${token}`, "X-Internal-Auth": INTROSPECT_BEARER },
            timeout: 3000,
        });
        const userId = String(r?.data?.id || r?.data?.user?.id || "");
        return userId || null;
    } catch { return null; }
}
function authFromJwt(token) {
    if (!JWT_PUBLIC_KEY) return null;
    try {
        const payload = jwt.verify(token, JWT_PUBLIC_KEY, { algorithms: ["RS256"] });
        return String(payload.sub || payload.id || payload.user_id || "");
    } catch { return null; }
}
async function resolveUserIdFromHandshake(socket) {
    const bearer =
        socket.handshake.auth?.token ||
        (socket.handshake.headers.authorization || "").replace(/^Bearer\s+/i, "");
    if (SOCKET_TOKEN && bearer === SOCKET_TOKEN) {
        const uid = socket.handshake.auth?.userId || "";
        return uid ? String(uid) : null;
    }
    const jwtUid = authFromJwt(bearer);
    if (jwtUid) return jwtUid;
    const laravelUid = await authFromLaravel(bearer);
    if (laravelUid) return laravelUid;
    return null;
}

// === Socket.IO auth ===
io.use(async (socket, next) => {
    try {
        const userId = await resolveUserIdFromHandshake(socket);
        if (!userId) return next(new Error("unauthorized"));
        socket.data.userId = userId;
        next();
    } catch (e) { next(new Error("auth_error")); }
});

// === Conexión sockets ===
io.on("connection", (socket) => {
    const userId = socket.data.userId;
    const ip = socket.handshake.headers["x-forwarded-for"] || socket.handshake.address;
    const room = `user:${userId}`;
    socket.join(room);
    log(`[connect] user=${userId} sid=${socket.id} ip=${ip}`);

    socket.on("notify:ack", async ({ id }) => {
        try {
            if (!id || mongoose.connection?.readyState !== 1) return;
            await Notification.findByIdAndUpdate(id, { deliveredAt: new Date() }).exec();
        } catch {}
    });
    socket.on("notify:read", async ({ id }) => {
        try {
            if (!id || mongoose.connection?.readyState !== 1) return;
            await Notification.findByIdAndUpdate(id, { status: "read", readAt: new Date() }).exec();
        } catch {}
    });
    socket.on("ping:client", () => socket.emit("pong:server", { ts: Date.now() }));
    socket.on("disconnect", (reason) => log(`[disconnect] user=${userId} sid=${socket.id} reason=${reason}`));
});

// === Utils: enviar notificación ===
async function emitNotification({ userId, title = "Aviso", body = "", data = {}, idempotencyKey = "" }) {
    const payload = { title, body, data, status: "unread" };
    let saved = null;

    if (MONGO_URI && mongoose.connection?.readyState === 1) {
        if (idempotencyKey) {
            try {
                const existing = await Idempotency.findOne({ key: idempotencyKey }).lean();
                if (existing?.notificationId) {
                    io.to(`user:${userId}`).emit("notify", { ...payload, id: existing.notificationId, createdAt: Date.now() });
                    return existing.notificationId;
                }
            } catch {}
        }
        try {
            saved = await Notification.create({ userId: String(userId), ...payload });
            if (idempotencyKey) {
                try { await Idempotency.create({ key: idempotencyKey, notificationId: saved._id }); }
                catch {
                    try {
                        const ex = await Idempotency.findOne({ key: idempotencyKey }).lean();
                        if (ex?.notificationId) {
                            io.to(`user:${userId}`).emit("notify", { ...payload, id: ex.notificationId, createdAt: Date.now() });
                            return ex.notificationId;
                        }
                    } catch {}
                }
            }
        } catch (e) { warn("notification persist error:", e?.message); }
    }

    io.to(`user:${userId}`).emit("notify", { ...payload, id: saved?._id, createdAt: saved?.createdAt || Date.now() });
    return saved?._id || null;
}


// === Reenvío a Laravel ===
// Contrato esperado de respuesta de Laravel:
// { ok: true|false, notify?: { userId, title, body, data, idempotencyKey? } }
async function forwardToLaravel(buffer, meta) {
    if (!LARAVEL_INGEST_URL) return { ok: false, error: "missing_ingest_url" };

    const body = {
        hex: buffer.toString("hex").toUpperCase(),
        received_at: new Date().toISOString()
    };

    let lastErr = null;
    for (let attempt = 0; attempt <= LARAVEL_MAX_RETRIES; attempt++) {
        try {
            const res = await axios.post(LARAVEL_INGEST_URL, body, {
                headers: { Authorization: LARAVEL_INGEST_BEARER, "Content-Type": "application/json" },
                timeout: LARAVEL_TIMEOUT_MS,
                httpsAgent: new https.Agent({
                    rejectUnauthorized: process.env.NODE_ENV === 'production'
                })
            });
            console.log({
                response:res
            })
            return res.data;
        } catch (e) {
            console.log({
                error: e
            })
            lastErr = e;
            warn(`forwardToLaravel attempt ${attempt + 1} failed: ${e?.message}`);
            if (attempt < LARAVEL_MAX_RETRIES) await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
        }
    }
    return { ok: false, error: lastErr?.message || "laravel_forward_failed" };
}

// === API REST mínima existente ===
function requireInternalAuth(req, res, next) {
    const token = req.headers["x-internal-auth"];
    if (!INTERNAL_TOKEN || token === INTERNAL_TOKEN) return next();
    return res.status(401).json({ ok: false, error: "unauthorized_internal" });
}
app.get("/v1/health", (req, res) => res.json({ ok: true, ts: Date.now() }));
app.post("/v1/emit", requireInternalAuth, async (req, res) => {
    const { userId, title, body, data } = req.body || {};
    if (!userId) return res.status(400).json({ ok: false, error: "missing_userId" });
    const id = await emitNotification({ userId, title, body, data, idempotencyKey: req.headers["idempotency-key"] || "" });
    res.json({ ok: true, delivered: true, id });
});
app.get("/v1/online/:userId", (req, res) => {
    const room = io.sockets.adapter.rooms.get(`user:${req.params.userId}`) || new Set();
    res.json({ ok: true, sockets: room.size });
});
app.get("/v1/notifications/:userId", async (req, res) => {
    if (!MONGO_URI) return res.status(503).json({ ok: false, error: "mongo_disabled" });
    if (mongoose.connection?.readyState !== 1) return res.status(503).json({ ok: false, error: "mongo_disconnected" });
    const { userId } = req.params;
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(100, Math.max(1, Number(req.query.limit || 20)));
    const skip = (page - 1) * limit;
    try {
        const [items, total] = await Promise.all([
            Notification.find({ userId: String(userId) }).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
            Notification.countDocuments({ userId: String(userId) }),
        ]);
        res.json({ ok: true, page, limit, total, items });
    } catch { res.status(500).json({ ok: false, error: "mongo_query_error" }); }
});
app.post("/v1/notifications/:id/read", requireInternalAuth, async (req, res) => {
    try { await Notification.findByIdAndUpdate(req.params.id, { status: "read", readAt: new Date() }).exec(); res.json({ ok: true }); }
    catch { res.status(500).json({ ok: false }); }
});
app.post("/v1/notifications/:id/hide", requireInternalAuth, async (req, res) => {
    try { await Notification.findByIdAndUpdate(req.params.id, { status: "hidden" }).exec(); res.json({ ok: true }); }
    catch { res.status(500).json({ ok: false }); }
});

// === HTTP INGEST (Express vía /ingest-raw para aceptar binario) ===
// Si prefieres NO usar el servidor HTTP crudo, puedes mandar tus dispositivos a POST https://notify.tu.com/ingest-raw
app.post("/ingest-raw", express.raw({ type: "*/*", limit: MAX_HTTP_BODY }), async (req, res) => {
    try {
        const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
        const ipSan = sanitizeIp(ip);
        const connTs = new Date().toISOString().replace(/[:.]/g, "-");
        const logFile = path.join(LOG_DIR, `http-${ipSan}-${connTs}.log`);

        const header = `${new Date().toISOString()} ${req.method} ${req.url} from ${ip} (${req.body.length} bytes)`;
        const line = logLine(ip, Buffer.from(req.body || []), "HTTP");
        safeAppend(logFile, header + "\n" + line);

        const meta = { ip, proto: "HTTP", headers: { "user-agent": req.headers["user-agent"] || "" }, path: req.url, method: req.method };
        const laravelRes = await forwardToLaravel(Buffer.from(req.body || []), meta);

        // Si Laravel trae notify, emitimos
        if (laravelRes?.ok && laravelRes?.notify?.userId) {
            await emitNotification({
                userId: String(laravelRes.notify.userId),
                title: laravelRes.notify.title || "Aviso",
                body: laravelRes.notify.body || "",
                data: laravelRes.notify.data || {},
                idempotencyKey: laravelRes.notify.idempotencyKey || ""
            });
        }
        res.status(200).json({ ok: true, laravel: laravelRes });
    } catch (e) {
        err("ingest-raw error:", e?.message);
        res.status(500).json({ ok: false, error: "ingest_error" });
    }
});

// === HTTP crudo (puerto separado, comportamiento original) ===
const httpIngestServer = http.createServer((req, res) => {
    const ip = req.socket.remoteAddress || "unknown";
    const ipSan = sanitizeIp(ip);
    const connTs = new Date().toISOString().replace(/[:.]/g, "-");
    const logFile = path.join(LOG_DIR, `http-${ipSan}-${connTs}.log`);

    let bytes = 0;
    const chunks = [];
    req.on("data", (c) => {
        bytes += c.length;
        if (bytes > MAX_HTTP_BODY) {
            warn(`HTTP body too large from ${ip} (${bytes} bytes) - aborting`);
            res.writeHead(413); res.end("Payload Too Large"); req.destroy(); return;
        }
        chunks.push(c);
    });
    req.on("end", async () => {
        const body = Buffer.concat(chunks);
        const header = `${new Date().toISOString()} ${req.method} ${req.url} from ${ip} (${bytes} bytes)`;
        const line = logLine(ip, body, "HTTP");
        safeAppend(logFile, header + "\n" + line);

        const meta = { ip, proto: "HTTP", path: req.url, method: req.method };
        const laravelRes = await forwardToLaravel(body, meta);
        if (laravelRes?.ok && laravelRes?.notify?.userId) {
            await emitNotification({
                userId: String(laravelRes.notify.userId),
                title: laravelRes.notify.title || "Aviso",
                body: laravelRes.notify.body || "",
                data: laravelRes.notify.data || {},
                idempotencyKey: laravelRes.notify.idempotencyKey || ""
            });
        }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, laravel: laravelRes, ts: new Date().toISOString() }));
    });
    req.on("error", (e) => err(`HTTP req error from ${ip}: ${e.message}`));
});

// === TCP server ===
const tcpServer = net.createServer((socket) => {
    const ip = socket.remoteAddress || "unknown";
    const ipSan = sanitizeIp(ip);
    const connTs = new Date().toISOString().replace(/[:.]/g, "-");
    const logFile = path.join(LOG_DIR, `tcp-${ipSan}-${connTs}.log`);

    socket.setKeepAlive(true, 30_000);
    socket.setNoDelay(true);
    socket.setTimeout(300_000);

    safeAppend(logFile, `# OPEN ${new Date().toISOString()} from ${ip}`);
    log(`TCP conn from ${ip} -> ${path.basename(logFile)}`);

    socket.on("data", async (buf) => {
        const line = logLine(ip, buf, "TCP");
        safeAppend(logFile, line);

        // forward a Laravel y notifica si aplica
        const meta = { ip, proto: "TCP" };
        const laravelRes = await forwardToLaravel(buf, meta);
        if (laravelRes?.ok && laravelRes?.notify?.userId) {
            await emitNotification({
                userId: String(laravelRes.notify.userId),
                title: laravelRes.notify.title || "Aviso",
                body: laravelRes.notify.body || "",
                data: laravelRes.notify.data || {},
                idempotencyKey: laravelRes.notify.idempotencyKey || ""
            });
        }
    });

    socket.on("timeout", () => { safeAppend(logFile, `# TIMEOUT ${new Date().toISOString()}`); warn(`TCP timeout ${ip}`); socket.end(); });
    socket.on("end", () => { safeAppend(logFile, `# CLOSE ${new Date().toISOString()}`); log(`TCP close ${ip}`); });
    socket.on("error", (e) => { safeAppend(logFile, `# ERROR ${new Date().toISOString()} ${e.message}`); err(`TCP socket error ${ip}: ${e.message}`); });
});

httpIngestServer.on("listening", () => log(`HTTP ingest listening on ${HTTP_INGEST_PORT}`));
httpIngestServer.on("error", (e) => err(`HTTP ingest error: ${e.message}`));
tcpServer.on("listening", () => log(`TCP listening on ${TCP_PORT}`));
tcpServer.on("error", (e) => err(`TCP server error: ${e.message}`));

// === Start ===
async function start() {
    if (MONGO_URI) {
        try { await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 }); log("[mongo] conectado"); }
        catch (e) { err("[mongo] no se pudo conectar:", e?.message); }
    } else { log("[mongo] MONGO_URI no configurado, persistencia deshabilitada"); }

    httpIngestServer.listen(HTTP_INGEST_PORT);
    tcpServer.listen(TCP_PORT);

    server.listen(PORT, () => log(`Unified server (Express+Socket.IO) :${PORT}`));
}
start();

// Global errors
process.on("uncaughtException", (e) => err("uncaughtException:", e?.stack || e));
process.on("unhandledRejection", (e) => err("unhandledRejection:", e?.stack || e));