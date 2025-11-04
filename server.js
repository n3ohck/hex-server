require("dotenv").config();

const express = require("express");
const http = require("http");
const net = require("net");
const fs = require("fs");
const path = require("path");
const {Server} = require("socket.io");
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
const LOG_SENT_DIR = process.env.LOG_SENT_DIR || path.join(LOG_DIR, "logs_sent");
const MAX_HTTP_BODY = 5 * 1024 * 1024;

const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
    .split(",").map(s => s.trim()).filter(Boolean);

const corsOptions = {
    origin: true, // refleja cualquier origen
    credentials: true,
    methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allowedHeaders: ["Content-Type","Authorization","X-Internal-Auth","Idempotency-Key"],
    exposedHeaders: ["Idempotency-Key"],
    maxAge: 600
};

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

const LARAVEL_LOG_URL = process.env.LARAVEL_LOG_URL || "";
const LARAVEL_LOG_BEARER = process.env.LARAVEL_LOG_BEARER || "";

const startTs = new Date().toISOString();

// --- log helpers ---
const log = (...a) => console.log("[INFO ]", ...a);
const warn = (...a) => console.warn("[WARN ]", ...a);
const err = (...a) => console.error("[ERROR]", ...a);

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

function sentLogFile(meta = {}, prefix = "sent") {
    // Asegura carpeta por día dentro de LOG_SENT_DIR
    const day = new Date().toISOString().slice(0, 10); // YYYY-MM-DD
    const dir = path.join(LOG_SENT_DIR, day);
    try { fs.mkdirSync(dir, { recursive: true }); } catch {}

    const ipSan = sanitizeIp(meta?.ip || "unknown");
    const ts = new Date().toISOString().replace(/[:.]/g, "-");
    // ejemplo: tcp-sent-189_237_97_176-2025-11-04T18-22-33-123Z.log
    return path.join(dir, `${prefix}-${ipSan}-${ts}.log`);
}

function safeAppend(file, text) {
    try {
        fs.appendFileSync(file, text + "\n", {flag: "a"});
    } catch (e) {
        err(`append fail (${file}): ${e.message}`);
    }
}

// Devuelve un array de segmentos HEX (MAYÚSCULAS) extraídos del buffer.
// 1) Si hay "HEX=..." o "HEX: ..." en el texto, devuelve cada ocurrencia.
// 2) Si no los hay, intenta usar TODO el contenido como una sola cadena HEX.
// Segmentos con longitud impar (nibble perdido) se descartan.
function extractHexSegments(buf) {
    if (!buf || !buf.length) return [];
    const s = buf.toString("utf8");

    // Captura HEX=... u HEX: ... sin arrastrar ASCII=...
    const matches = [...s.matchAll(/HEX\s*[:=]\s*([0-9A-Fa-f]+)(?=\s|$|ASCII\s*[:=])/g)];
    let segs = matches.map(m => m[1].toUpperCase());

    if (segs.length === 0) {
        const clean = s.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
        if (clean) segs = [clean];
    }

    segs = segs.filter(h => h.length % 2 === 0);
    return segs;
}

// --- split por delimitadores 7E..7E ---
function splitFramesFromHex(hex) {
    const clean = String(hex).replace(/[^0-9A-F]/gi, "").toUpperCase();
    if (!clean) return [];
    const re = /7E(?:[0-9A-F]{2})+?7E/g; // mínimo 1 byte entre 7E y 7E
    const m = clean.match(re);
    return m && m.length ? m : [clean]; // si no hay 7E..7E, manda el bloque completo como 1 frame
}

function collectNotifies(laravelRes) {
    const list = [];
    if (!laravelRes || typeof laravelRes !== "object") return list;

    if (laravelRes.notify && laravelRes.notify.userId) {
        list.push(laravelRes.notify);
    }
    if (Array.isArray(laravelRes.results)) {
        for (const it of laravelRes.results) {
            if (it && it.notify && it.notify.userId) list.push(it.notify);
        }
    }
    return list;
}

// --- enviar 1 frame en hex a Laravel (guarda logs_sent) ---
async function forwardHexToLaravel(hex, meta) {
    if (!LARAVEL_INGEST_URL) return {ok: false, error: "missing_ingest_url"};
    if (!has7eFlags(hex)) {
        await postIngestLogToLaravel({
            proto: meta?.proto || "?",
            ip: meta?.ip || "unknown",
            endpoint: LARAVEL_INGEST_URL,
            attempt: 0,
            hex,
            hex_len: (hex || "").length,
            meta,
            ok: false,
            http_status: 422,
            error: "no_7E_flags",
            action: "drop_no_7e",
            has_7e: false,
            hex_preview: String(hex || "").slice(0, 120),
        });
        return { ok: false, error: "no_7E_flags" };
    }
    const body = {hex, received_at: new Date().toISOString()};
    const sfile = sentLogFile(meta, meta?.proto === "TCP" ? "tcp-sent" : "http-sent");
    const maskedAuth = maskBearer(LARAVEL_INGEST_BEARER);

    const headers = {"Content-Type": "application/json"};
    if (LARAVEL_INGEST_BEARER) headers.Authorization = LARAVEL_INGEST_BEARER;

    safeAppend(
        sfile,
        `[${new Date().toISOString()}] POST ${LARAVEL_INGEST_URL} ip=${meta?.ip || "unknown"} ` +
        `proto=${meta?.proto || "?"} hex_len=${hex.length} auth=${maskedAuth}`
    );

    let lastErr = null;
    for (let attempt = 0; attempt <= LARAVEL_MAX_RETRIES; attempt++) {
        try {
            const res = await axios.post(LARAVEL_INGEST_URL, body, {
                headers,
                timeout: LARAVEL_TIMEOUT_MS,
                httpsAgent: new https.Agent({
                    rejectUnauthorized: process.env.NODE_ENV === "production",
                }),
            });
            const preview = typeof res.data === "string"
                ? res.data.slice(0, 400)
                : JSON.stringify(res.data).slice(0, 400);

            const fullFile = sfile.replace(/\.log$/, ".json");
            fs.writeFileSync(fullFile, JSON.stringify(res.data, null, 2));
            await postIngestLogToLaravel({
                proto: meta?.proto || "?",
                ip: meta?.ip || "unknown",
                endpoint: LARAVEL_INGEST_URL,
                attempt: attempt + 1,
                hex,
                hex_len: hex.length,
                meta,
                ok: !!res?.data?.ok,
                http_status: 200,
                response: res?.data || null,
                response_preview: preview,
                notifies: Array.isArray(res?.data?.results) ? res.data.results.map(r => r?.notify).filter(Boolean) : (res?.data?.notify ? [res.data.notify] : []),
                action: "forward_ingest",
                has_7e: true,
                hex_preview: hex.slice(0, 120),
            });

            return res.data;
        } catch (e) {
            console.log(e)
            lastErr = e;
            const status = e?.response?.status || "no_status";
            const edata = e?.response?.data
                ? JSON.stringify(e.response.data).slice(0, 400)
                : (e?.message || "error").slice(0, 400);

            warn(`forwardHexToLaravel attempt ${attempt + 1} failed: ${e?.message}`);
            safeAppend(sfile, `[${new Date().toISOString()}] ERROR attempt=${attempt + 1} status=${status} detail=${edata}`);
            await postIngestLogToLaravel({
                proto: meta?.proto || "?",
                ip: meta?.ip || "unknown",
                endpoint: LARAVEL_INGEST_URL,
                attempt: attempt + 1,
                hex,
                hex_len: hex.length,
                meta,
                ok: false,
                http_status: typeof status === "number" ? status : null,
                error: e?.message || "laravel_forward_failed",
                response_preview: edata,
                action: "forward_ingest_error",
                has_7e: has7eFlags(hex),
                hex_preview: hex.slice(0, 120),
            });
            if (attempt < LARAVEL_MAX_RETRIES) await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
        }
    }
    await postIngestLogToLaravel({
        proto: meta?.proto || "?",
        ip: meta?.ip || "unknown",
        endpoint: LARAVEL_INGEST_URL,
        attempt: LARAVEL_MAX_RETRIES + 1,
        hex,
        hex_len: hex.length,
        meta,
        ok: false,
        http_status: lastErr?.response?.status || null,
        error: lastErr?.message || "laravel_forward_failed",
        action: "forward_ingest_failed",
        has_7e: has7eFlags(hex),
        hex_preview: hex.slice(0, 120),
    });
    return {ok: false, error: lastErr?.message || "laravel_forward_failed"};
}

function maskBearer(b) {
    if (!b) return "";
    const s = String(b);
    if (s.length <= 12) return s[0] + "***" + s.slice(-1);
    return s.slice(0, 6) + "***" + s.slice(-4);
}

// genera nombre de archivo por cada envío a Laravel
function has7eFlags(hex) {
    const s = String(hex || "").toUpperCase().replace(/[^0-9A-F]/g, "");
    return s.startsWith("7E") && s.endsWith("7E");
}

async function postIngestLogToLaravel(payload = {}) {
    if (!LARAVEL_LOG_URL) return { ok: false, error: "missing_log_url" };
    try {
        const headers = { "Content-Type": "application/json" };
        if (LARAVEL_LOG_BEARER) headers.Authorization = LARAVEL_LOG_BEARER;
        const res = await axios.post(LARAVEL_LOG_URL, payload, { headers, timeout: 5000 });
        return res.data;
    } catch (e) {
        console.log(e)
        // no romper el flujo si falla el log
        warn("postIngestLogToLaravel fail:", e?.response?.status, e?.message);
        return { ok: false, error: e?.message || "log_post_failed" };
    }
}

// --- prepara LOG_DIR ---
try {
    if (!fs.existsSync(LOG_DIR)) {
        fs.mkdirSync(LOG_DIR, {recursive: true});
        log(`LOG_DIR created: ${LOG_DIR}`);
    }
    fs.accessSync(LOG_DIR, fs.constants.W_OK);
    log(`LOG_DIR writable: ${LOG_DIR}`);
} catch (e) {
    err(`LOG_DIR not writable (${LOG_DIR}): ${e.message}`);
}

// --- prepara LOG_SENT_DIR ---
try {
    if (!fs.existsSync(LOG_SENT_DIR)) {
        fs.mkdirSync(LOG_SENT_DIR, {recursive: true});
        log(`LOG_SENT_DIR created: ${LOG_SENT_DIR}`);
    }
    fs.accessSync(LOG_SENT_DIR, fs.constants.W_OK);
    log(`LOG_SENT_DIR writable: ${LOG_SENT_DIR}`);
} catch (e) {
    err(`LOG_SENT_DIR not writable (${LOG_SENT_DIR}): ${e.message}`);
}

// === App/Server/IO ===
const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors(corsOptions));
// importante para preflight
app.options(/.*/, cors(corsOptions));   // o /^.*$/
app.set("trust proxy", true);
const server = http.createServer(app);
const io = new Server(server, {
    cors: {
        origin: true,                  // permite cualquier origen
        credentials: true,
        methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
        allowedHeaders: ["Content-Type","Authorization","X-Internal-Auth","Idempotency-Key"]
    },
    transports: ["websocket", "polling"],
});

// ===== Mongoose Models (opcionales para notificaciones) =====
let Notification, Idempotency;
try {
    Notification = mongoose.model("Notification");
} catch {
    const NotificationSchema = new mongoose.Schema({
        userId: {type: String, index: true, required: true},
        title: {type: String, default: "Aviso", enum: ["Aviso", "Error", "Warning", "Info","Dispositivo"]},
        body: {type: String, default: ""},
        status: {type: String, default: "unread", enum: ["read", "unread", "hidden"]},
        data: {type: mongoose.Schema.Types.Mixed, default: {}},
        deliveredAt: {type: Date, default: null},
        readAt: {type: Date, default: null},
    }, {timestamps: {createdAt: "createdAt", updatedAt: false}});
    NotificationSchema.index({userId: 1, createdAt: -1});
    Notification = mongoose.model("Notification", NotificationSchema);
}
try {
    Idempotency = mongoose.model("Idempotency");
} catch {
    const IdempotencySchema = new mongoose.Schema({
        key: {type: String, required: true, unique: true, index: true},
        notificationId: {type: mongoose.Schema.Types.ObjectId, required: true},
    }, {timestamps: {createdAt: "createdAt", updatedAt: false}});
    IdempotencySchema.index({createdAt: 1}, {expireAfterSeconds: 86400});
    Idempotency = mongoose.model("Idempotency", IdempotencySchema);
}

// === Auth helpers ===
async function authFromLaravel(token) {
    if (!INTROSPECT_URL) return null;
    try {
        const r = await axios.get(INTROSPECT_URL, {
            headers: {Authorization: `Bearer ${token}`, "X-Internal-Auth": INTROSPECT_BEARER},
            timeout: 3000,
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
        const payload = jwt.verify(token, JWT_PUBLIC_KEY, {algorithms: ["RS256"]});
        return String(payload.sub || payload.id || payload.user_id || "");
    } catch {
        return null;
    }
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
    } catch (e) {
        next(new Error("auth_error"));
    }
});

// === Conexión sockets ===
io.on("connection", (socket) => {
    const userId = socket.data.userId;
    const ip = socket.handshake.headers["x-forwarded-for"] || socket.handshake.address;
    const room = `user:${userId}`;
    socket.join(room);
    log(`[connect] user=${userId} sid=${socket.id} ip=${ip}`);

    socket.on("notify:ack", async ({id}) => {
        try {
            if (!id || mongoose.connection?.readyState !== 1) return;
            await Notification.findByIdAndUpdate(id, {deliveredAt: new Date()}).exec();
        } catch {
        }
    });
    socket.on("notify:read", async ({id}) => {
        try {
            if (!id || mongoose.connection?.readyState !== 1) return;
            await Notification.findByIdAndUpdate(id, {status: "read", readAt: new Date()}).exec();
        } catch {
        }
    });
    socket.on("ping:client", () => socket.emit("pong:server", {ts: Date.now()}));
    socket.on("disconnect", (reason) => log(`[disconnect] user=${userId} sid=${socket.id} reason=${reason}`));
});

// === Utils: enviar notificación ===
async function emitNotification({userId, title = "Aviso", body = "", data = {}, idempotencyKey = ""}) {
    const payload = {title, body, data, status: "unread"};
    let saved = null;

    if (MONGO_URI && mongoose.connection?.readyState === 1) {
        if (idempotencyKey) {
            try {
                const existing = await Idempotency.findOne({key: idempotencyKey}).lean();
                if (existing?.notificationId) {
                    io.to(`user:${userId}`).emit("notify", {
                        ...payload,
                        id: existing.notificationId,
                        createdAt: Date.now()
                    });
                    return existing.notificationId;
                }
            } catch {
            }
        }
        try {
            saved = await Notification.create({userId: String(userId), ...payload});
            if (idempotencyKey) {
                try {
                    await Idempotency.create({key: idempotencyKey, notificationId: saved._id});
                } catch {
                    try {
                        const ex = await Idempotency.findOne({key: idempotencyKey}).lean();
                        if (ex?.notificationId) {
                            io.to(`user:${userId}`).emit("notify", {
                                ...payload,
                                id: ex.notificationId,
                                createdAt: Date.now()
                            });
                            return ex.notificationId;
                        }
                    } catch {
                    }
                }
            }
        } catch (e) {
            warn("notification persist error:", e?.message);
        }
    }

    io.to(`user:${userId}`).emit("notify", {...payload, id: saved?._id, createdAt: saved?.createdAt || Date.now()});
    return saved?._id || null;
}

// === API REST mínima existente ===
function requireInternalAuth(req, res, next) {
    const token = req.headers["x-internal-auth"];
    if (!INTERNAL_TOKEN || token === INTERNAL_TOKEN) return next();
    return res.status(401).json({ok: false, error: "unauthorized_internal"});
}

app.get("/v1/health", (req, res) => res.json({ok: true, ts: Date.now()}));

app.post("/v1/emit", requireInternalAuth, async (req, res) => {
    const { userId, title, body, data } = req.body || {};
    if (!userId) return res.status(400).json({ ok: false, error: "missing_userId" });

    try {
        const id = await emitNotification({
            userId: String(userId),
            title: title || "Aviso",
            body:  body  || "",
            data:  data  || {},
            idempotencyKey: req.headers["idempotency-key"] || ""
        });
        return res.json({ ok: true, delivered: true, id });
    } catch (e) {
        return res.status(500).json({ ok: false, error: e?.message || "emit_failed" });
    }
});
app.get("/v1/online/:userId", (req, res) => {
    const room = io.sockets.adapter.rooms.get(`user:${req.params.userId}`) || new Set();
    res.json({ok: true, sockets: room.size});
});
app.get("/v1/notifications/:userId", async (req, res) => {
    if (!MONGO_URI) return res.status(503).json({ok: false, error: "mongo_disabled"});
    if (mongoose.connection?.readyState !== 1) return res.status(503).json({ok: false, error: "mongo_disconnected"});
    const {userId} = req.params;
    const page = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(100, Math.max(1, Number(req.query.limit || 20)));
    const skip = (page - 1) * limit;
    try {
        const [items, total] = await Promise.all([
            Notification.find({userId: String(userId)}).sort({createdAt: -1}).skip(skip).limit(limit).lean(),
            Notification.countDocuments({userId: String(userId)}),
        ]);
        res.json({ok: true, page, limit, total, items});
    } catch {
        res.status(500).json({ok: false, error: "mongo_query_error"});
    }
});
app.post("/v1/notifications/:id/read", requireInternalAuth, async (req, res) => {
    try {
        await Notification.findByIdAndUpdate(req.params.id, {status: "read", readAt: new Date()}).exec();
        res.json({ok: true});
    } catch {
        res.status(500).json({ok: false});
    }
});
app.post("/v1/notifications/:id/hide", requireInternalAuth, async (req, res) => {
    try {
        await Notification.findByIdAndUpdate(req.params.id, {status: "hidden"}).exec();
        res.json({ok: true});
    } catch {
        res.status(500).json({ok: false});
    }
});

// === HTTP INGEST (Express vía /ingest-raw para aceptar binario) ===
// Si prefieres NO usar el servidor HTTP crudo, puedes mandar tus dispositivos a POST https://notify.tu.com/ingest-raw
app.post("/ingest-raw", express.raw({type: "*/*", limit: MAX_HTTP_BODY}), async (req, res) => {
    try {
        const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
        const ipSan = sanitizeIp(ip);
        const connTs = new Date().toISOString().replace(/[:.]/g, "-");
        const logFile = path.join(LOG_DIR, `http-${ipSan}-${connTs}.log`);

        const header = `${new Date().toISOString()} ${req.method} ${req.url} from ${ip} (${req.body.length} bytes)`;
        const line = logLine(ip, Buffer.from(req.body || []), "HTTP");
        safeAppend(logFile, header + "\n" + line);

        const meta = {
            ip,
            proto: "HTTP",
            headers: {"user-agent": req.headers["user-agent"] || ""},
            path: req.url,
            method: req.method
        };

        // --- EXTRAER SEGMENTOS HEX Y PROCESAR CADA UNO ---
        const segments = extractHexSegments(Buffer.from(req.body || []));
        if (segments.length === 0) {
            await postIngestLogToLaravel({
                proto: "HTTP",
                ip,
                endpoint: req.url || "/ingest-raw",
                attempt: 0,
                ok: false,
                http_status: 422,
                error: "invalid_or_missing_hex",
                action: "drop_invalid_hex",
                has_7e: false,
                hex_len: 0,
            });
            return res.status(422).json({ ok: false, error: "invalid_or_missing_hex" });
        }

        const results = [];
        for (const hex of segments) {
            const frames = splitFramesFromHex(hex); // 7E...7E (una o varias)
            for (const frame of frames) {
                const laravelRes = await forwardHexToLaravel(frame, meta);
                const notifies = collectNotifies(laravelRes);
                for (const n of notifies) {
                    await emitNotification({
                        userId: String(n.userId),
                        title: n.title || "Aviso",
                        body:  n.body  || "",
                        data:  n.data  || {},
                        idempotencyKey: n.idempotencyKey || ""
                    });
                }
                results.push({ ok: !!laravelRes?.ok, laravel: laravelRes });
            }
        }

        res.status(200).json({ ok: true, segments: segments.length, results });
    } catch (e) {
        err("ingest-raw error:", e?.message);
        res.status(500).json({ok: false, error: "ingest_error"});
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
            res.writeHead(413);
            res.end("Payload Too Large");
            req.destroy();
            return;
        }
        chunks.push(c);
    });

    req.on("end", async () => {
        const body = Buffer.concat(chunks);
        const header = `${new Date().toISOString()} ${req.method} ${req.url} from ${ip} (${bytes} bytes)`;
        const line = logLine(ip, body, "HTTP");
        safeAppend(logFile, header + "\n" + line);

        const meta = {ip, proto: "HTTP", path: req.url, method: req.method};

        // --- EXTRAER SEGMENTOS HEX Y PROCESAR CADA UNO ---
        const segments = extractHexSegments(body);
        if (segments.length === 0) {
            await postIngestLogToLaravel({
                proto: "HTTP",
                ip,
                endpoint: "http",
                attempt: 0,
                ok: false,
                http_status: 422,
                error: "invalid_or_missing_hex",
                action: "drop_invalid_hex",
                has_7e: false,
                hex_len: 0,
            });
            res.writeHead(422, { "Content-Type": "application/json" });
            return res.end(JSON.stringify({ ok: false, error: "invalid_or_missing_hex" }));
        }

        const results = [];
        for (const hex of segments) {
            const frames = splitFramesFromHex(hex);
            for (const frame of frames) {
                const laravelRes = await forwardHexToLaravel(frame, meta);
                if (laravelRes?.ok && laravelRes?.notify?.userId) {
                    await emitNotification({
                        userId: String(laravelRes.notify.userId),
                        title: laravelRes.notify.title || "Aviso",
                        body: laravelRes.notify.body || "",
                        data: laravelRes.notify.data || {},
                        idempotencyKey: laravelRes.notify.idempotencyKey || ""
                    });
                }
                results.push({ ok: !!laravelRes?.ok, laravel: laravelRes });
            }
        }

        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, segments: segments.length, results, ts: new Date().toISOString() }));
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

        // --- EXTRAER SEGMENTOS HEX Y PROCESAR CADA UNO ---
        const segments = extractHexSegments(buf);
        if (segments.length === 0) {
            await postIngestLogToLaravel({
                proto: "TCP",
                ip,
                endpoint: "tcp",
                attempt: 0,
                ok: false,
                http_status: 422,
                error: "invalid_or_missing_hex",
                action: "drop_invalid_hex",
                has_7e: false,
                hex_len: 0,
            });
            safeAppend(logFile, `# DROP ${new Date().toISOString()} invalid_or_missing_hex from ${ip}`);
            return;
        }

        const meta = { ip, proto: "TCP" };

        for (const hex of segments) {
            const frames = splitFramesFromHex(hex);
            for (const frame of frames) {
                const laravelRes = await forwardHexToLaravel(frame, meta);
                const notifies = collectNotifies(laravelRes);
                for (const n of notifies) {
                    await emitNotification({
                        userId: String(n.userId),
                        title: n.title || "Aviso",
                        body:  n.body  || "",
                        data:  n.data  || {},
                        idempotencyKey: n.idempotencyKey || ""
                    });
                }
            }
        }
    });

    socket.on("timeout", () => {
        safeAppend(logFile, `# TIMEOUT ${new Date().toISOString()}`);
        warn(`TCP timeout ${ip}`);
        socket.end();
    });
    socket.on("end", () => {
        safeAppend(logFile, `# CLOSE ${new Date().toISOString()}`);
        log(`TCP close ${ip}`);
    });
    socket.on("error", (e) => {
        safeAppend(logFile, `# ERROR ${new Date().toISOString()} ${e.message}`);
        err(`TCP socket error ${ip}: ${e.message}`);
    });
});

httpIngestServer.on("listening", () => log(`HTTP ingest listening on ${HTTP_INGEST_PORT}`));
httpIngestServer.on("error", (e) => err(`HTTP ingest error: ${e.message}`));
tcpServer.on("listening", () => log(`TCP listening on ${TCP_PORT}`));
tcpServer.on("error", (e) => err(`TCP server error: ${e.message}`));

// === Start ===
async function start() {
    if (MONGO_URI) {
        try {
            await mongoose.connect(MONGO_URI, {serverSelectionTimeoutMS: 5000});
            log("[mongo] conectado");
        } catch (e) {
            err("[mongo] no se pudo conectar:", e?.message);
        }
    } else {
        log("[mongo] MONGO_URI no configurado, persistencia deshabilitada");
    }

    httpIngestServer.listen(HTTP_INGEST_PORT);
    tcpServer.listen(TCP_PORT);

    server.listen(PORT, () => log(`Unified server (Express+Socket.IO) :${PORT}`));
}

start();

// Global errors
process.on("uncaughtException", (e) => err("uncaughtException:", e?.stack || e));
process.on("unhandledRejection", (e) => err("unhandledRejection:", e?.stack || e));