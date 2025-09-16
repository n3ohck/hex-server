const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 9000;
const LOG_DIR = "/var/www/html/hex-server";

// Asegura que el directorio exista
if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
}

// Función para formatear log
function logLine(clientIP, buf) {
    const now = new Date().toISOString();
    const hex = buf.toString('hex').toUpperCase();
    const ascii = buf.toString('utf8').replace(/[^\x20-\x7E]/g, '.');
    return `[${now}] IP=${clientIP} LEN=${buf.length} HEX=${hex} ASCII=${ascii}\n`;
}

const server = http.createServer((req, res) => {
    const ip = req.socket.remoteAddress || "unknown";
    let chunks = [];

    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
        const body = Buffer.concat(chunks);

        // Nombre del archivo de log
        const logFile = path.join(LOG_DIR, `http-${ip.replace(/[:.]/g,'_')}.log`);

        // Guardar en log
        fs.appendFileSync(logFile, req.method + " " + req.url + "\n" + logLine(ip, body));

        // Responder al cliente
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
            status: "ok",
            ip: ip,
            length: body.length,
            received: body.toString()
        }));
    });
});

server.listen(PORT, () => {
    console.log(`HTTP escuchando en puerto ${PORT}`);
});
