const net = require('net');
const fs = require('fs');
const path = require('path');

const PORT = 9000;
const LOG_DIR = '/var/www/html/hex-server';
if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

// JT808: des-escape 0x7D01->0x7D y 0x7D02->0x7E
function unescapeJT808(buf) {
  const out = [];
  for (let i = 0; i < buf.length; i++) {
    if (buf[i] === 0x7d && i + 1 < buf.length) {
      const nxt = buf[i + 1];
      if (nxt === 0x01) { out.push(0x7d); i++; continue; }
      if (nxt === 0x02) { out.push(0x7e); i++; continue; }
    }
    out.push(buf[i]);
  }
  return Buffer.from(out);
}

// Checksum XOR de todos los bytes (cabecera+cuerpo), excluyendo el último byte (que es el checksum)
function checksumOK(payloadWithCS) {
  if (payloadWithCS.length < 2) return false;
  const expected = payloadWithCS[payloadWithCS.length - 1];
  let x = 0;
  for (let i = 0; i < payloadWithCS.length - 1; i++) x ^= payloadWithCS[i];
  return (x & 0xff) === expected;
}

const server = net.createServer((socket) => {
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  const clientIP = (socket.remoteAddress || '').replace(/^::ffff:/, ''); // limpia solo el prefijo IPv6
  const okLog  = path.join(LOG_DIR, `hex-${clientIP}-${ts}.log`);
  const badLog = path.join(LOG_DIR, `hex-${clientIP}-${ts}.bad.log`);

  console.log(`Nueva conexión desde ${clientIP}. Ok: ${okLog}  Bad: ${badLog}`);

  let buf = Buffer.alloc(0); // acumulador por conexión

  socket.on('data', (chunk) => {
    // 1) acumular binario tal cual (TCP puede trocear o juntar)
    buf = Buffer.concat([buf, chunk]);

    // 2) extraer todos los frames completos 7E ... 7E que haya en el buffer
    while (true) {
      const start = buf.indexOf(0x7e);
      if (start === -1) {                      // no hay inicio
        if (buf.length > 1 << 20) buf = Buffer.alloc(0); // evita crecer infinito
        break;
      }
      const end = buf.indexOf(0x7e, start + 1);
      if (end === -1) {                        // hay inicio pero falta fin -> esperar más datos
        if (start > 0) buf = buf.slice(start); // descarta basura previa
        break;
      }

      // 3) tomamos el frame completo (incluye 7E…7E) y lo retiramos del buffer
      const frame = buf.slice(start, end + 1);
      buf = buf.slice(end + 1);

      // 4) procesamos: quitar 7E extremos, des-escape y validar checksum
      const inner = frame.slice(1, frame.length - 1);
      const unesc = unescapeJT808(inner);
      const isOK  = checksumOK(unesc);

      const hexFull = frame.toString('hex').toUpperCase(); // para auditar el frame tal cual llegó
      const line = `${new Date().toISOString()} ${clientIP} ${hexFull}\n`;
      fs.appendFileSync(isOK ? okLog : badLog, line);
    }
  });

  socket.on('end',   () => console.log(`Conexión cerrada: ${clientIP}`));
  socket.on('error', (e) => console.error(`Error con ${clientIP}:`, e.message));
});

server.listen(PORT, '0.0.0.0', () => console.log(`Listening on ${PORT}`));
