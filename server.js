// server.js (debug/verbose)
const http = require('http');
const net  = require('net');
const fs   = require('fs');
const path = require('path');

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '9000', 10);
const TCP_PORT  = parseInt(process.env.TCP_PORT  || '9100', 10);
const LOG_DIR   = process.env.LOG_DIR || "/var/www/html/hex-server";
const MAX_HTTP_BODY = 5 * 1024 * 1024; // 5MB, evita OOM por error

const startTs = new Date().toISOString();

// ---- util console wrappers (systemd captura stdout/err) ----
const log = (...args) => console.log('[INFO ]', ...args);
const warn = (...args) => console.warn('[WARN ]', ...args);
const err  = (...args) => console.error('[ERROR]', ...args);

// ---- helpers ----
const sanitizeIp = (addr = 'unknown') =>
    addr.replace(/[:.]/g,'_').replace(/^_+ffff_/, '');
const isPrintable = b => b >= 0x20 && b <= 0x7E;

function logLine(clientIP, buf, tag = '') {
    const now = new Date().toISOString();
    const hex = buf.toString('hex').toUpperCase();
    const ascii = Array.from(buf).map(b => isPrintable(b) ? String.fromCharCode(b) : '.').join('');
    return `[${now}] ${tag} IP=${clientIP} LEN=${buf.length} HEX=${hex} ASCII=${ascii}`;
}

// append con manejo de errores (loggea al journal si falla)
function safeAppend(file, text) {
    try {
        fs.appendFileSync(file, text + '\n', { flag: 'a' });
    } catch (e) {
        err(`append fail (${file}): ${e.message}`);
    }
}

// ---- prepara LOG_DIR y valida permisos ----
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

// ============================================================
// HTTP SERVER (puerto 9000)
// ============================================================
const httpServer = http.createServer((req, res) => {
    const ip = req.socket.remoteAddress || 'unknown';
    const ipSan = sanitizeIp(ip);

    // (Opcional) loggear headers si estás depurando mucho:
    // log('HTTP headers from', ip, req.headers);

    let bytes = 0;
    const chunks = [];

    req.on('data', (c) => {
        bytes += c.length;
        if (bytes > MAX_HTTP_BODY) {
            warn(`HTTP body too large from ${ip} (${bytes} bytes) - aborting`);
            res.writeHead(413);
            res.end('Payload Too Large');
            req.destroy();
            return;
        }
        chunks.push(c);
    });

    req.on('end', () => {
        const body = Buffer.concat(chunks);
        const logFile = path.join(LOG_DIR, `http-${ipSan}.log`);
        const header = `${new Date().toISOString()} ${req.method} ${req.url} from ${ip} (${bytes} bytes)`;
        const line = logLine(ip, body, 'HTTP');

        safeAppend(logFile, header + '\n' + line);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: "ok",
            ip,
            length: body.length,
            receivedPreview: body.toString('utf8').slice(0, 512), // evita logs gigantes
            ts: new Date().toISOString()
        }));
    });

    req.on('error', (e) => {
        err(`HTTP req error from ${ip}: ${e.message}`);
    });
});

httpServer.on('listening', () => log(`HTTP listening on ${HTTP_PORT}`));
httpServer.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        err(`HTTP port ${HTTP_PORT} in use`);
    } else {
        err(`HTTP server error: ${e.message}`);
    }
});
httpServer.listen(HTTP_PORT);

// ============================================================
// TCP SERVER (puerto 9100)
// ============================================================
const tcpServer = net.createServer((socket) => {
    const ip = socket.remoteAddress || 'unknown';
    const ipSan = sanitizeIp(ip);
    const connTs = new Date().toISOString().replace(/[:.]/g, '-');
    const logFile = path.join(LOG_DIR, `tcp-${ipSan}-${connTs}.log`);

    // Ajustes de socket
    socket.setKeepAlive(true, 30_000);
    socket.setNoDelay(true);
    socket.setTimeout(300_000); // 5 min

    // apertura de conexión
    safeAppend(logFile, `# OPEN ${new Date().toISOString()} from ${ip}`);
    log(`TCP conn from ${ip} -> ${path.basename(logFile)}`);

    socket.on('data', (buf) => {
        // log de trama (hex + ascii) siempre
        const line = logLine(ip, buf, 'TCP');
        safeAppend(logFile, line);
    });

    socket.on('timeout', () => {
        safeAppend(logFile, `# TIMEOUT ${new Date().toISOString()}`);
        warn(`TCP timeout ${ip}`);
        socket.end();
    });

    socket.on('end', () => {
        safeAppend(logFile, `# CLOSE ${new Date().toISOString()}`);
        log(`TCP close ${ip}`);
    });

    socket.on('error', (e) => {
        safeAppend(logFile, `# ERROR ${new Date().toISOString()} ${e.message}`);
        err(`TCP socket error ${ip}: ${e.message}`);
    });
});

tcpServer.on('listening', () => log(`TCP listening on ${TCP_PORT}`));
tcpServer.on('error', (e) => {
    if (e.code === 'EADDRINUSE') {
        err(`TCP port ${TCP_PORT} in use`);
    } else {
        err(`TCP server error: ${e.message}`);
    }
});
tcpServer.listen(TCP_PORT);

// ============================================================
// Global: manejo de errores y señales
// ============================================================
process.on('uncaughtException', (e) => {
    err('uncaughtException:', e && e.stack ? e.stack : e);
});
process.on('unhandledRejection', (e) => {
    err('unhandledRejection:', e && e.stack ? e.stack : e);
});

function shutdown(sig) {
    warn(`Received ${sig}, shutting down...`);
    try { httpServer.close(() => log('HTTP server closed')); } catch {}
    try { tcpServer.close(() => log('TCP server closed')); } catch {}
    setTimeout(() => process.exit(0), 1500);
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));

log(`Boot @ ${startTs} | LOG_DIR=${LOG_DIR} | HTTP_PORT=${HTTP_PORT} | TCP_PORT=${TCP_PORT}`);