// server.js
const http = require('http');
const net = require('net');
const fs = require('fs');
const path = require('path');

const HTTP_PORT = parseInt(process.env.HTTP_PORT || '9000', 10);
const TCP_PORT  = parseInt(process.env.TCP_PORT  || '9100', 10);
const LOG_DIR   = process.env.LOG_DIR || "/var/www/html/hex-server";

// Asegura directorio de logs
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// Utils
const sanitizeIp = (addr = 'unknown') => addr.replace(/[:.]/g,'_').replace(/^_+ffff_/, '');
const isPrintable = (c) => c >= 0x20 && c <= 0x7E;

// Formatea línea de log con HEX y ASCII seguro
function logLine(clientIP, buf, tag = '') {
    const now = new Date().toISOString();
    const hex = buf.toString('hex').toUpperCase();
    const ascii = Array.from(buf).map(b => isPrintable(b) ? String.fromCharCode(b) : '.').join('');
    return `[${now}] ${tag} IP=${clientIP} LEN=${buf.length} HEX=${hex} ASCII=${ascii}`;
}

// ---------- HTTP SERVER (puerto 9000) ----------
const httpServer = http.createServer((req, res) => {
    const ip = req.socket.remoteAddress || "unknown";
    const ipSan = sanitizeIp(ip);

    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
        const body = Buffer.concat(chunks);

        const logFile = path.join(LOG_DIR, `http-${ipSan}.log`);
        const header = `${req.method} ${req.url} from ${ip}\n`;
        const line = logLine(ip, body, 'HTTP');

        try {
            fs.appendFileSync(logFile, header + line + '\n');
        } catch (e) {
            // si falla log, al menos respondemos
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: "ok",
            ip,
            length: body.length,
            received: body.toString()
        }));
    });
});

httpServer.listen(HTTP_PORT, () => {
    console.log(`HTTP listening on ${HTTP_PORT}`);
});

// ---------- TCP SERVER (puerto 9100) ----------
const tcpServer = net.createServer((socket) => {
    const ip = socket.remoteAddress || 'unknown';
    const ipSan = sanitizeIp(ip);
    const startTs = new Date().toISOString().replace(/[:.]/g, '-');

    // Un archivo por conexión para dejar trazabilidad
    const logFile = path.join(LOG_DIR, `tcp-${ipSan}-${startTs}.log`);
    const write = (text) => {
        try { fs.appendFileSync(logFile, text + '\n'); } catch (e) {}
    };

    write(`# OPEN ${new Date().toISOString()} from ${ip}`);

    socket.on('data', (buf) => {
        write(logLine(ip, buf, 'TCP'));
    });

    socket.on('end', () => write(`# CLOSE ${new Date().toISOString()}`));
    socket.on('error', (err) => write(`# ERROR ${new Date().toISOString()} ${err.message}`));
});

tcpServer.listen(TCP_PORT, () => {
    console.log(`TCP listening on ${TCP_PORT}`);
});