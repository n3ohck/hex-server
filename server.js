require("dotenv").config();

const express  = require("express");
const http     = require("http");
const net      = require("net");
const fs       = require("fs");
const path     = require("path");
const { Server } = require("socket.io");
const cors     = require("cors");
const helmet   = require("helmet");
const axios    = require("axios");
const jwt      = require("jsonwebtoken");
const mongoose = require("mongoose");
const https    = require("https");

/* =========================
 *  Config
 * ========================= */
const PORT               = Number(process.env.PORT || 3001);
const HTTP_INGEST_PORT   = parseInt(process.env.HTTP_INGEST_PORT || "9000", 10);
const TCP_PORT           = parseInt(process.env.TCP_PORT || "9100", 10);
const LOG_DIR            = process.env.LOG_DIR || "/var/www/html/hex-server";
const LOG_SENT_DIR       = process.env.LOG_SENT_DIR || path.join(LOG_DIR, "logs_sent");
const MAX_HTTP_BODY      = 5 * 1024 * 1024;

const CORS_ORIGINS = (process.env.CORS_ORIGINS || "")
    .split(",")
    .map(s => s.trim())
    .filter(Boolean);

const SOCKET_TOKEN             = process.env.SOCKET_TOKEN || "";
const JWT_PUBLIC_KEY           = process.env.JWT_PUBLIC_KEY || "";
const INTROSPECT_URL           = process.env.LARAVEL_INTROSPECT_URL || "";
const INTROSPECT_BEARER        = process.env.LARAVEL_INTROSPECT_BEARER || "";
const INTERNAL_TOKEN           = process.env.INTERNAL_TOKEN || "";
const MONGO_URI                = process.env.MONGO_URI || "";

const LARAVEL_INGEST_URL       = process.env.LARAVEL_INGEST_URL || "";
const LARAVEL_INGEST_BEARER    = process.env.LARAVEL_INGEST_BEARER || "";
const LARAVEL_TIMEOUT_MS       = parseInt(process.env.LARAVEL_TIMEOUT_MS || "5000", 10);
const LARAVEL_MAX_RETRIES      = parseInt(process.env.LARAVEL_MAX_RETRIES || "2", 10);

const LARAVEL_INGEST_LOG_URL   = process.env.LARAVEL_INGEST_LOG_URL || "";
const LARAVEL_INGEST_LOG_BEARER= process.env.LARAVEL_INGEST_LOG_BEARER || LARAVEL_INGEST_BEARER;

/* =========================
 *  Helpers básicos
 * ========================= */
const log  = (...a) => console.log("[INFO ]", ...a);
const warn = (...a) => console.warn("[WARN ]", ...a);
const err  = (...a) => console.error("[ERROR]", ...a);

const corsOptions = {
    origin: true,
    credentials: true,
    methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
    allowedHeaders: ["Content-Type","Authorization","X-Internal-Auth","Idempotency-Key"],
    exposedHeaders: ["Idempotency-Key"],
    maxAge: 600
};

const sanitizeIp = (addr = "unknown") =>
    addr.replace(/[:.]/g, "_").replace(/^_+ffff_/, "");

const isPrintable = (b) => b >= 0x20 && b <= 0x7e;

const hexFromBuffer = (buf) => Buffer.from(buf || []).toString("hex").toUpperCase();

const asciiFromBuffer = (buf) =>
    Array.from(buf || []).map(b => (isPrintable(b) ? String.fromCharCode(b) : ".")).join("");

const safePreview = (obj, n = 700) => {
    try {
        if (typeof obj === "string") return obj.slice(0, n);
        return JSON.stringify(obj).slice(0, n);
    } catch { return ""; }
};

const maskBearer = (b) => {
    if (!b) return "";
    const s = String(b);
    if (s.length <= 12) return s[0] + "***" + s.slice(-1);
    return s.slice(0, 6) + "***" + s.slice(-4);
};

/* =========================
 *  FileStore: guarda raw/hex
 * ========================= */
class FileStore {
    static ensureDir(p) {
        try {
            if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
            fs.accessSync(p, fs.constants.W_OK);
        } catch (e) {
            err(`Dir not writable (${p}): ${e.message}`);
        }
    }

    static init() {
        this.ensureDir(LOG_DIR);
        this.ensureDir(LOG_SENT_DIR);
    }

    static baseDirBy(meta = {}) {
        const day = new Date().toISOString().slice(0,10);
        const proto = (meta.proto || "GEN").toUpperCase();
        const ipSan = sanitizeIp(meta.ip || "unknown");
        const base = path.join(LOG_DIR, "ingest_store", day, proto, ipSan);
        this.ensureDir(base);
        return base;
    }

    /** Guarda raw y hex; devuelve rutas { raw_file, hex_file } */
    static saveRawAndHex(buffer, meta = {}) {
        const base = this.baseDirBy(meta);
        const ts = new Date().toISOString().replace(/[:.]/g, "-");
        const raw_file = path.join(base, `raw-${ts}.bin`);
        const hex_file = path.join(base, `hex-${ts}.txt`);

        try { fs.writeFileSync(raw_file, Buffer.from(buffer || [])); } catch(e){ err("write raw:", e.message); }
        try { fs.writeFileSync(hex_file, hexFromBuffer(buffer)); } catch(e){ err("write hex:", e.message); }

        return { raw_file, hex_file };
    }

    /** Genera ruta de log_sent (para request a Laravel) */
    static sentLogFile(meta = {}, tag = "sent") {
        const ipSan = sanitizeIp(meta?.ip || "unknown");
        const ts = new Date().toISOString().replace(/[:.]/g, "-");
        return path.join(LOG_SENT_DIR, `${tag}-${ipSan}-${ts}.log`);
    }

    static append(file, line) {
        try { fs.appendFileSync(file, line + "\n", { flag: "a" }); } catch(e){ err(`append fail (${file}): ${e.message}`); }
    }
}
FileStore.init();

/* =========================
 *  Particionamiento HEX
 * ========================= */
function extractHexSegments(buf) {
    if (!buf || !buf.length) return [];
    const s = buf.toString("utf8");
    const matches = [...s.matchAll(/HEX\s*[:=]\s*([0-9A-Fa-f]+)(?=\s|$|ASCII\s*[:=])/g)];
    let segs = matches.map(m => m[1].toUpperCase());
    if (segs.length === 0) {
        const clean = s.replace(/[^0-9A-Fa-f]/g, "").toUpperCase();
        if (clean) segs = [clean];
    }
    return segs.filter(h => h.length % 2 === 0);
}

function splitFramesFromHex(hex) {
    const clean = String(hex).replace(/[^0-9A-F]/gi, "").toUpperCase();
    if (!clean) return [];
    const m = clean.match(/7E(?:[0-9A-F]{2})+?7E/g);
    return Array.isArray(m) ? m : [];
}

const has7eFlags = (frameHex) => String(frameHex).toUpperCase().startsWith("7E") && String(frameHex).toUpperCase().endsWith("7E");

/* =========================
 *  LaravelClient
 * ========================= */
class LaravelClient {
    static async forwardHex(frameHex, meta) {
        if (!LARAVEL_INGEST_URL) return { ok:false, error:"missing_ingest_url", __httpStatus:0 };

        const headers = { "Content-Type":"application/json" };
        if (LARAVEL_INGEST_BEARER) headers.Authorization = LARAVEL_INGEST_BEARER;

        const sfile = FileStore.sentLogFile(meta, meta?.proto === "TCP" ? "tcp-sent" : "http-sent");
        FileStore.append(sfile, `[${new Date().toISOString()}] POST ${LARAVEL_INGEST_URL} ip=${meta?.ip||"unknown"} proto=${meta?.proto||"?"} hex_len=${frameHex.length} auth=${maskBearer(LARAVEL_INGEST_BEARER)}`);

        let lastErr = null;
        for (let attempt = 0; attempt <= LARAVEL_MAX_RETRIES; attempt++) {
            try {
                const res = await axios.post(LARAVEL_INGEST_URL, { hex: frameHex, received_at: new Date().toISOString() }, {
                    headers,
                    timeout: LARAVEL_TIMEOUT_MS,
                    httpsAgent: new https.Agent({ rejectUnauthorized: process.env.NODE_ENV === "production" }),
                });
                // Guarda respuesta completa
                fs.writeFileSync(sfile.replace(/\.log$/, ".json"), JSON.stringify(res.data, null, 2));
                if (typeof res.data === "object") res.data.__httpStatus = res.status;
                return res.data;
            } catch(e) {
                lastErr = e;
                const status  = e?.response?.status || 0;
                const edata   = e?.response?.data ? e.response.data : { error: e?.message || "error" };
                FileStore.append(sfile, `[${new Date().toISOString()}] ERROR attempt=${attempt+1} status=${status} detail=${safePreview(edata)}`);
                if (attempt < LARAVEL_MAX_RETRIES) await new Promise(r => setTimeout(r, 500 * (attempt + 1)));
            }
        }
        return { ok:false, error:lastErr?.message || "laravel_forward_failed", __httpStatus:0 };
    }

    static async postIngestLog(entry) {
        if (!LARAVEL_INGEST_LOG_URL) return;
        const headers = { "Content-Type":"application/json" };
        if (LARAVEL_INGEST_LOG_BEARER) headers.Authorization = LARAVEL_INGEST_LOG_BEARER;

        try {
            await axios.post(LARAVEL_INGEST_LOG_URL, entry, {
                headers,
                timeout: 5000,
                httpsAgent: new https.Agent({ rejectUnauthorized: process.env.NODE_ENV === "production" }),
            });
        } catch(e) {
            warn("postIngestLog error:", e?.message);
        }
    }
}

/* =========================
 *  IngestLogger (éxito/fallo)
 * ========================= */
class IngestLogger {
    static async logSuccess({ proto, ip, endpoint, hex, hex_file, raw_file, http_status = 200, response }) {
        await LaravelClient.postIngestLog({
            ts: new Date().toISOString(),
            proto, ip, endpoint,
            attempt: 1,
            ok: true,
            http_status,
            hex: hex || "",
            hex_len: (hex||"").length,
            response: response || null,
            meta: { hex_file, raw_file },
        });
    }

    static async logError({ proto, ip, endpoint, hex, hex_file, raw_file, http_status = 422, error, response }) {
        await LaravelClient.postIngestLog({
            ts: new Date().toISOString(),
            proto, ip, endpoint,
            attempt: 1,
            ok: false,
            http_status,
            hex: hex || "",
            hex_len: (hex||"").length,
            error: error || "unknown_error",
            response: response ? safePreview(response) : null,
            meta: { hex_file, raw_file }
        });
    }
}

/* =========================
 *  Notifier (Mongo + Socket)
 * ========================= */
let Notification, Idempotency;
try { Notification = mongoose.model("Notification"); }
catch {
    const NotificationSchema = new mongoose.Schema({
        userId: { type: String, index: true, required: true },
        title:  { type: String, default:"Aviso", enum:["Aviso","Error","Warning","Info"] },
        body:   { type: String, default:"" },
        status: { type: String, default:"unread", enum:["read","unread","hidden"] },
        data:   { type: mongoose.Schema.Types.Mixed, default:{} },
        deliveredAt: { type: Date, default: null },
        readAt: { type: Date, default: null },
    }, { timestamps: { createdAt:"createdAt", updatedAt:false }});
    NotificationSchema.index({ userId:1, createdAt:-1 });
    Notification = mongoose.model("Notification", NotificationSchema);
}
try { Idempotency = mongoose.model("Idempotency"); }
catch {
    const IdempotencySchema = new mongoose.Schema({
        key: { type:String, required:true, unique:true, index:true },
        notificationId: { type: mongoose.Schema.Types.ObjectId, required:true },
    }, { timestamps: { createdAt:"createdAt", updatedAt:false }});
    IdempotencySchema.index({ createdAt:1 }, { expireAfterSeconds: 86400 });
    Idempotency = mongoose.model("Idempotency", IdempotencySchema);
}

class Notifier {
    constructor(io) { this.io = io; }

    async emit({ userId, title="Aviso", body="", data={}, idempotencyKey="" }) {
        const payload = { title, body, data, status:"unread" };
        let saved = null;

        if (MONGO_URI && mongoose.connection?.readyState === 1) {
            if (idempotencyKey) {
                try {
                    const existing = await Idempotency.findOne({ key:idempotencyKey }).lean();
                    if (existing?.notificationId) {
                        this.io.to(`user:${userId}`).emit("notify", { ...payload, id:existing.notificationId, createdAt:Date.now() });
                        return existing.notificationId;
                    }
                } catch {}
            }
            try {
                saved = await Notification.create({ userId:String(userId), ...payload });
                if (idempotencyKey) {
                    try { await Idempotency.create({ key:idempotencyKey, notificationId:saved._id }); }
                    catch {
                        try {
                            const ex = await Idempotency.findOne({ key:idempotencyKey }).lean();
                            if (ex?.notificationId) {
                                this.io.to(`user:${userId}`).emit("notify", { ...payload, id:ex.notificationId, createdAt:Date.now() });
                                return ex.notificationId;
                            }
                        } catch {}
                    }
                }
            } catch(e){ warn("notification persist error:", e?.message); }
        }

        this.io.to(`user:${userId}`).emit("notify", { ...payload, id:saved?._id, createdAt: saved?.createdAt || Date.now() });
        return saved?._id || null;
    }
}

/* =========================
 *  Auth sockets
 * ========================= */
async function authFromLaravel(token) {
    if (!INTROSPECT_URL) return null;
    try {
        const r = await axios.get(INTROSPECT_URL, {
            headers: { Authorization:`Bearer ${token}`, "X-Internal-Auth": INTROSPECT_BEARER },
            timeout: 3000,
        });
        return String(r?.data?.id || r?.data?.user?.id || "") || null;
    } catch { return null; }
}

function authFromJwt(token) {
    if (!JWT_PUBLIC_KEY) return null;
    try {
        const payload = jwt.verify(token, JWT_PUBLIC_KEY, { algorithms:["RS256"] });
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

/* =========================
 *  App + IO
 * ========================= */
const app = express();
app.use(express.json());
app.use(helmet());
app.use(cors(corsOptions));
app.options(/.*/, cors(corsOptions));
app.set("trust proxy", true);

const server = http.createServer(app);
const io = new Server(server, {
    cors: { origin:true, credentials:true, methods:["GET","POST","PUT","PATCH","DELETE","OPTIONS"], allowedHeaders:["Content-Type","Authorization","X-Internal-Auth","Idempotency-Key"] },
    transports:["websocket","polling"],
});

io.use(async (socket, next) => {
    try {
        const userId = await resolveUserIdFromHandshake(socket);
        if (!userId) return next(new Error("unauthorized"));
        socket.data.userId = userId;
        next();
    } catch { next(new Error("auth_error")); }
});

const notifier = new Notifier(io);

io.on("connection", (socket) => {
    const userId = socket.data.userId;
    const ip = socket.handshake.headers["x-forwarded-for"] || socket.handshake.address;
    socket.join(`user:${userId}`);
    log(`[connect] user=${userId} sid=${socket.id} ip=${ip}`);

    socket.on("notify:ack", async ({ id }) => {
        try { if (id && mongoose.connection?.readyState === 1) await Notification.findByIdAndUpdate(id, { deliveredAt:new Date() }).exec(); } catch {}
    });
    socket.on("notify:read", async ({ id }) => {
        try { if (id && mongoose.connection?.readyState === 1) await Notification.findByIdAndUpdate(id, { status:"read", readAt:new Date() }).exec(); } catch {}
    });
    socket.on("ping:client", () => socket.emit("pong:server", { ts: Date.now() }));
    socket.on("disconnect", (reason) => log(`[disconnect] user=${userId} sid=${socket.id} reason=${reason}`));
});

/* =========================
 *  Ingestor
 * ========================= */
class Ingestor {
    static collectNotifies(laravelRes) {
        const list = [];
        if (!laravelRes || typeof laravelRes !== "object") return list;
        if (laravelRes.notify?.userId) list.push(laravelRes.notify);
        if (Array.isArray(laravelRes.results)) {
            for (const it of laravelRes.results) {
                if (it?.notify?.userId) list.push(it.notify);
            }
        }
        return list;
    }

    static async processBuffer({ buffer, ip, proto, endpoint = "" }) {
        // Guardar original para re-proceso
        const { raw_file, hex_file } = FileStore.saveRawAndHex(buffer, { ip, proto });

        const segments = extractHexSegments(buffer);
        if (segments.length === 0) {
            await IngestLogger.logError({
                proto, ip, endpoint,
                hex: "", hex_file, raw_file,
                http_status: 422,
                error: "invalid_or_missing_hex"
            });
            return { ok:false, reason:"invalid_or_missing_hex" };
        }

        const results = [];
        for (const hex of segments) {
            const frames = splitFramesFromHex(hex);
            if (frames.length === 0) {
                await IngestLogger.logError({
                    proto, ip, endpoint,
                    hex, hex_file, raw_file,
                    http_status: 422,
                    error: "missing_frame_flags"
                });
                continue;
            }

            for (const frame of frames) {
                const laravelRes = await LaravelClient.forwardHex(frame, { ip, proto, path:endpoint, method:"INGEST" });

                // Log éxito/fallo (incluye hex y paths)
                if (laravelRes?.ok) {
                    await IngestLogger.logSuccess({
                        proto, ip, endpoint,
                        hex: frame, hex_file, raw_file,
                        http_status: Number(laravelRes.__httpStatus || 200),
                        response: laravelRes
                    });
                } else {
                    await IngestLogger.logError({
                        proto, ip, endpoint,
                        hex: frame, hex_file, raw_file,
                        http_status: Number(laravelRes?.__httpStatus || 422),
                        error: laravelRes?.error || "ingest_failed",
                        response: laravelRes
                    });
                }

                // Notificaciones (si las hubo)
                const notifies = this.collectNotifies(laravelRes);
                for (const n of notifies) {
                    await notifier.emit({
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
        return { ok:true, results, raw_file, hex_file };
    }
}

/* =========================
 *  REST utilitario
 * ========================= */
function requireInternalAuth(req, res, next) {
    const token = req.headers["x-internal-auth"];
    if (!INTERNAL_TOKEN || token === INTERNAL_TOKEN) return next();
    return res.status(401).json({ ok:false, error:"unauthorized_internal" });
}

app.get("/v1/health", (req, res) => res.json({ ok:true, ts:Date.now() }));

app.post("/v1/emit", requireInternalAuth, async (req, res) => {
    const { userId, title, body, data } = req.body || {};
    if (!userId) return res.status(400).json({ ok:false, error:"missing_userId" });
    try {
        const id = await notifier.emit({
            userId:String(userId),
            title:title || "Aviso",
            body: body || "",
            data: data || {},
            idempotencyKey: req.headers["idempotency-key"] || ""
        });
        res.json({ ok:true, delivered:true, id });
    } catch(e) {
        res.status(500).json({ ok:false, error: e?.message || "emit_failed" });
    }
});

app.get("/v1/online/:userId", (req,res) => {
    const room = io.sockets.adapter.rooms.get(`user:${req.params.userId}`) || new Set();
    res.json({ ok:true, sockets: room.size });
});

app.get("/v1/notifications/:userId", async (req,res) => {
    if (!MONGO_URI) return res.status(503).json({ ok:false, error:"mongo_disabled" });
    if (mongoose.connection?.readyState !== 1) return res.status(503).json({ ok:false, error:"mongo_disconnected" });
    const { userId } = req.params;
    const page  = Math.max(1, Number(req.query.page || 1));
    const limit = Math.min(100, Math.max(1, Number(req.query.limit || 20)));
    const skip  = (page - 1) * limit;
    try {
        const [items, total] = await Promise.all([
            Notification.find({ userId:String(userId) }).sort({ createdAt:-1 }).skip(skip).limit(limit).lean(),
            Notification.countDocuments({ userId:String(userId) }),
        ]);
        res.json({ ok:true, page, limit, total, items });
    } catch { res.status(500).json({ ok:false, error:"mongo_query_error" }); }
});

app.post("/v1/notifications/:id/read", requireInternalAuth, async (req,res) => {
    try { await Notification.findByIdAndUpdate(req.params.id, { status:"read", readAt:new Date() }).exec(); res.json({ ok:true }); }
    catch { res.status(500).json({ ok:false }); }
});

app.post("/v1/notifications/:id/hide", requireInternalAuth, async (req,res) => {
    try { await Notification.findByIdAndUpdate(req.params.id, { status:"hidden" }).exec(); res.json({ ok:true }); }
    catch { res.status(500).json({ ok:false }); }
});

/* =========================
 *  HTTP Ingest (/ingest-raw)
 * ========================= */
app.post("/ingest-raw", express.raw({ type:"*/*", limit:MAX_HTTP_BODY }), async (req, res) => {
    try {
        const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
        const result = await Ingestor.processBuffer({
            buffer: Buffer.from(req.body || []),
            ip,
            proto: "HTTP",
            endpoint: "/ingest-raw"
        });
        if (!result.ok) return res.status(422).json({ ok:false, error: result.reason || "invalid" });
        res.status(200).json({ ok:true, segments:(result.results||[]).length, results: result.results });
    } catch(e) {
        err("ingest-raw error:", e?.message);
        await IngestLogger.logError({ proto:"HTTP", ip:"unknown", endpoint:"/ingest-raw", http_status:500, error:e?.message||"ingest_error" });
        res.status(500).json({ ok:false, error:"ingest_error" });
    }
});

/* =========================
 *  HTTP crudo (puerto dedicado)
 * ========================= */
const httpIngestServer = http.createServer(async (req, res) => {
    try {
        const chunks = [];
        let bytes = 0;
        req.on("data", (c) => {
            bytes += c.length;
            if (bytes > MAX_HTTP_BODY) {
                warn(`HTTP body too large (${bytes} bytes)`);
                res.writeHead(413);
                res.end("Payload Too Large");
                req.destroy();
                return;
            }
            chunks.push(c);
        });
        req.on("end", async () => {
            const ip = req.socket.remoteAddress || "unknown";
            const body = Buffer.concat(chunks);
            const result = await Ingestor.processBuffer({ buffer: body, ip, proto:"HTTP", endpoint: req.url });
            if (!result.ok) {
                res.writeHead(422, { "Content-Type":"application/json" });
                return res.end(JSON.stringify({ ok:false, error: result.reason || "invalid" }));
            }
            res.writeHead(200, { "Content-Type":"application/json" });
            res.end(JSON.stringify({ ok:true, segments:(result.results||[]).length, results: result.results, ts:new Date().toISOString() }));
        });
        req.on("error", async (e) => {
            const ip = req.socket.remoteAddress || "unknown";
            await IngestLogger.logError({ proto:"HTTP", ip, endpoint:"http_ingest_server", http_status:500, error:e?.message || "http_req_error" });
        });
    } catch(e) {
        err("httpIngestServer:", e?.message);
    }
});

/* =========================
 *  TCP Server
 * ========================= */
const tcpServer = net.createServer((socket) => {
    const ip = socket.remoteAddress || "unknown";
    socket.setKeepAlive(true, 30_000);
    socket.setNoDelay(true);
    socket.setTimeout(300_000);

    socket.on("data", async (buf) => {
        await Ingestor.processBuffer({ buffer: buf, ip, proto:"TCP", endpoint:"tcp:data" });
    });

    socket.on("timeout", () => { warn(`TCP timeout ${ip}`); socket.end(); });
    socket.on("end", () => log(`TCP close ${ip}`));
    socket.on("error", async (e) => {
        err(`TCP socket error ${ip}: ${e.message}`);
        await IngestLogger.logError({ proto:"TCP", ip, endpoint:"tcp_socket_error", http_status:500, error:e?.message || "tcp_socket_error" });
    });
});

/* =========================
 *  Start
 * ========================= */
async function start() {
    if (MONGO_URI) {
        try {
            await mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
            log("[mongo] conectado");
        } catch (e) { err("[mongo] no se pudo conectar:", e?.message); }
    } else {
        log("[mongo] MONGO_URI no configurado, persistencia deshabilitada");
    }
    httpIngestServer.listen(HTTP_INGEST_PORT, () => log(`HTTP ingest :${HTTP_INGEST_PORT}`));
    tcpServer.listen(TCP_PORT, () => log(`TCP ingest :${TCP_PORT}`));
    server.listen(PORT, () => log(`App (Express+Socket.IO) :${PORT}`));
}
start();

/* =========================
 *  Global errors
 * ========================= */
process.on("uncaughtException", async (e) => {
    err("uncaughtException:", e?.stack || e);
    await LaravelClient.postIngestLog({ ts:new Date().toISOString(), action:"uncaughtException", ok:false, error:e?.message||"uncaughtException", http_status:500 });
});
process.on("unhandledRejection", async (e) => {
    err("unhandledRejection:", e?.stack || e);
    await LaravelClient.postIngestLog({ ts:new Date().toISOString(), action:"unhandledRejection", ok:false, error:(e && e.message) || String(e) || "unhandledRejection", http_status:500 });
});