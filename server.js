const http = require('http');
const fs   = require('fs');
const path = require('path');

const PORT    = 9000;                                  // HTTP en 9000
const LOG_DIR = '/var/www/html/hex-server';

// Asegura carpeta
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

function isLikelyHexAscii(buf) {
  // ¿Solo 0-9 a-f A-F y espacios?
  const s = buf.toString('utf8');
  return /^[0-9a-fA-F\s]+$/.test(s);
}

function toHexFromMaybeAscii(buf) {
  if (isLikelyHexAscii(buf)) {
    // Ya venía como string hex -> normalizamos
    return buf.toString('utf8').replace(/\s+/g, '').toUpperCase();
  }
  // Venía en binario -> lo pasamos a hex
  return buf.toString('hex').toUpperCase();
}

const server = http.createServer((req, res) => {
  // Salud / test rápido
  if (req.method === 'GET' && req.url === '/') {
    res.writeHead(200, {'Content-Type':'text/plain'});
    res.end('OK\n');
    return;
  }

  // Solo aceptamos POST /ingest
  if (req.method !== 'POST' || !req.url.startsWith('/ingest')) {
    res.writeHead(404, {'Content-Type':'text/plain'});
    res.end('Not Found\n');
    return;
  }

  // Identidad y archivo por conexión
  const now       = new Date();
  const timestamp = now.toISOString().replace(/[:.]/g, '-');
  const clientIP  = (req.socket.remoteAddress || '').replace(/[:f]+/g, '');
  const logFile   = path.join(LOG_DIR, `hex-${clientIP}-${timestamp}.log`);

  const chunks = [];
  req.on('data', (chunk) => chunks.push(chunk));
  req.on('end', () => {
    try {
      const body  = Buffer.concat(chunks);
      const hex   = toHexFromMaybeAscii(body);
      const ascii = body.toString('ascii').replace(/[^\x20-\x7E]+/g, '.');
      const line  = `${new Date().toISOString()} ${clientIP} len=${body.length} HEX=${hex} ASCII=${ascii}\n`;
      fs.appendFileSync(logFile, line);
      res.writeHead(200, {'Content-Type':'text/plain'});
      res.end('OK\n');
      console.log(`HTTP ${clientIP} -> ${logFile} (${body.length} bytes)`);
    } catch (e) {
      console.error('Error guardando:', e.message);
      res.writeHead(500, {'Content-Type':'text/plain'});
      res.end('ERROR\n');
    }
  });

  req.on('error', (err) => {
    console.error('HTTP error:', err.message);
  });
});

server.listen(PORT, () => console.log(`HTTP listening on ${PORT}`));
