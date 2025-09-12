const net  = require('net');
const fs   = require('fs');
const path = require('path');

const PORT    = 9000;
const LOG_DIR = '/var/www/html/hex-server';

// Asegura carpeta
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const server = net.createServer((socket) => {
  const now       = new Date();
  const timestamp = now.toISOString().replace(/[:.]/g, '-');
  const clientIP  = (socket.remoteAddress || '').replace(/[:f]+/g, '');
  const logFile   = path.join(LOG_DIR, `hex-${clientIP}-${timestamp}.log`);

  console.log(`Nueva conexión: ${clientIP} -> ${logFile}`);

  socket.on('data', (chunk) => {
    // SIEMPRE convertir binario a HEX (y dejar ASCII solo para debug)
    const hex   = chunk.toString('hex').toUpperCase();
    const ascii = chunk.toString('ascii').replace(/[^\x20-\x7E]+/g, '.');
    const line  = `${new Date().toISOString()} ${clientIP} len=${chunk.length} HEX=${hex} ASCII=${ascii}\n`;
    fs.appendFileSync(logFile, line);
  });

  socket.on('end',   () => console.log(`Conexión cerrada: ${clientIP}`));
  socket.on('error', (err) => console.error(`Error ${clientIP}:`, err.message));
});

server.listen(PORT, () => console.log(`Listening on ${PORT}`));
