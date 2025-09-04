const net = require('net');
const fs = require('fs');
const path = require('path');

const PORT = 9000;
const LOG_DIR = '/var/www/html/hex-server';

// Asegúrate que la carpeta exista
if (!fs.existsSync(LOG_DIR)) {
  fs.mkdirSync(LOG_DIR, { recursive: true });
}

const server = net.createServer((socket) => {
  // Creamos un nombre único de archivo por conexión
  const now = new Date();
  const timestamp = now.toISOString().replace(/[:.]/g, '-'); 
  const clientIP = socket.remoteAddress.replace(/[:f]+/g, ''); // limpia IPv6 ::ffff:
  const logFile = path.join(LOG_DIR, `hex-${clientIP}-${timestamp}.log`);

  console.log(`Nueva conexión desde ${clientIP}, guardando en ${logFile}`);

  socket.on('data', (chunk) => {
    const hex = chunk.toString().trim();
    if (!/^[0-9a-fA-F\s]+$/.test(hex)) return;
    fs.appendFileSync(
      logFile,
      `${new Date().toISOString()} ${clientIP} ${hex.replace(/\s+/g, '')}\n`
    );
  });

  socket.on('end', () => {
    console.log(`Conexión cerrada: ${clientIP}`);
  });

  socket.on('error', (err) => {
    console.error(`Error con ${clientIP}:`, err.message);
  });
});

server.listen(PORT, () => console.log(`Listening on ${PORT}`));
