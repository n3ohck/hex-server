const net  = require('net');
const fs   = require('fs');
const path = require('path');

const PORT    = 9000;
const LOG_DIR = '/var/www/html/hex-server';

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

const server = net.createServer((socket) => {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const clientIP = (socket.remoteAddress || '')
    .replace(/^::ffff:/, '')
    .replace(/^\[?::1\]?$/, '127.0.0.1');

  const logFile = path.join(LOG_DIR, `hex-${clientIP}-${ts}.log`);
  console.log(`Nueva conexión: ${clientIP} -> ${logFile}`);

  socket.setKeepAlive(true, 60_000);
  socket.setNoDelay(true);

  socket.on('data', (chunk) => {
    const hex   = chunk.toString('hex').toUpperCase();
    const ascii = chunk.toString('ascii').replace(/[^\x20-\x7E]+/g, '.');
    const line  = `${new Date().toISOString()} ${clientIP} len=${chunk.length} HEX=${hex} ASCII=${ascii}\n`;
    fs.appendFileSync(logFile, line);
    console.log(line.trim());
  });

  socket.on('end',   () => console.log(`Conexión cerrada: ${clientIP}`));
  socket.on('error', (err) => console.error(`Error ${clientIP}:`, err.message));
});

server.listen(PORT, () => console.log(`Listening on ${PORT}`));
