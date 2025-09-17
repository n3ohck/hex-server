import net from 'net';
import { Server as SocketServer } from 'socket.io';
import { LogService } from './log-service';
import { generateId, formatTimestamp, cleanIP, sanitizeAscii } from '../shared/utils';
import { HexLog } from '../shared/types';

export class TCPServer {
  private server: net.Server;
  private port: number;
  private logService: LogService;
  private io: SocketServer;

  constructor(port: number, logService: LogService, io: SocketServer) {
    this.port = port;
    this.logService = logService;
    this.io = io;
    this.server = net.createServer();
    this.setupServer();
  }

  private setupServer(): void {
    this.server.on('connection', (socket) => {
      const now = new Date();
      const timestamp = formatTimestamp(now);
      const clientIP = cleanIP(socket.remoteAddress || '');
      const connectionId = generateId();

      console.log(`📡 Nueva conexión TCP: ${clientIP} (${connectionId})`);

      // Emit connection event via WebSocket
      this.io.emit('tcp:connection', {
        clientIP,
        connectionId,
        timestamp: now.toISOString()
      });

      socket.on('data', async (chunk) => {
        try {
          const hex = chunk.toString('hex').toUpperCase();
          const ascii = sanitizeAscii(chunk);
          
          const logEntry: HexLog = {
            id: generateId(),
            timestamp: new Date().toISOString(),
            clientIP,
            dataLength: chunk.length,
            hexData: hex,
            asciiData: ascii,
            fileName: `hex-${clientIP}-${timestamp}.log`
          };

          // Save to file
          await this.logService.saveLogEntry(logEntry);

          // Emit real-time update via WebSocket
          this.io.emit('tcp:data', logEntry);

          console.log(`📦 Data from ${clientIP}: ${chunk.length} bytes`);
        } catch (error) {
          console.error(`❌ Error processing data from ${clientIP}:`, error);
        }
      });

      socket.on('end', () => {
        console.log(`🔌 Conexión cerrada: ${clientIP}`);
        this.io.emit('tcp:disconnect', {
          clientIP,
          connectionId,
          timestamp: new Date().toISOString()
        });
      });

      socket.on('error', (err) => {
        console.error(`❌ Error TCP ${clientIP}:`, err.message);
        this.io.emit('tcp:error', {
          clientIP,
          connectionId,
          error: err.message,
          timestamp: new Date().toISOString()
        });
      });
    });

    this.server.on('error', (err) => {
      console.error('❌ TCP Server error:', err);
    });
  }

  public start(): void {
    this.server.listen(this.port, () => {
      console.log(`🔌 TCP Server listening on port ${this.port}`);
    });
  }

  public stop(): void {
    this.server.close(() => {
      console.log('🔌 TCP Server stopped');
    });
  }

  public getConnections(): Promise<number> {
    return new Promise((resolve, reject) => {
      this.server.getConnections((err, count) => {
        if (err) reject(err);
        else resolve(count);
      });
    });
  }
}