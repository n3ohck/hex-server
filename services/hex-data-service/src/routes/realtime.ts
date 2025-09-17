import { Router, Request, Response } from 'express';
import { Server as SocketServer } from 'socket.io';
import { ApiResponse } from '../../shared/types';

export const createRealtimeRoutes = (io: SocketServer): Router => {
  const router = Router();

  // GET /api/realtime/status - Get WebSocket connection status
  router.get('/status', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const sockets = await io.fetchSockets();
      const connectionCount = sockets.length;
      
      res.json({
        success: true,
        data: {
          connectionCount,
          connectedSockets: sockets.map(socket => ({
            id: socket.id,
            rooms: Array.from(socket.rooms),
            handshake: {
              address: socket.handshake.address,
              time: socket.handshake.time,
              headers: socket.handshake.headers
            }
          }))
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/realtime/broadcast - Send a test message to all connected clients
  router.post('/broadcast', (req: Request, res: Response<ApiResponse>) => {
    try {
      const { event, data, message } = req.body;
      
      if (!event) {
        return res.status(400).json({
          success: false,
          error: 'Event name is required'
        });
      }

      io.emit(event, {
        ...data,
        message: message || 'Test broadcast message',
        timestamp: new Date().toISOString(),
        source: 'api'
      });
      
      res.json({
        success: true,
        message: `Broadcast sent to all connected clients`,
        data: { event, payload: data }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/realtime/emit - Send message to specific room
  router.post('/emit/:room', (req: Request, res: Response<ApiResponse>) => {
    try {
      const { room } = req.params;
      const { event, data, message } = req.body;
      
      if (!event) {
        return res.status(400).json({
          success: false,
          error: 'Event name is required'
        });
      }

      io.to(room).emit(event, {
        ...data,
        message: message || `Message to room: ${room}`,
        timestamp: new Date().toISOString(),
        source: 'api',
        room
      });
      
      res.json({
        success: true,
        message: `Message sent to room: ${room}`,
        data: { event, room, payload: data }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // Setup WebSocket event handlers
  io.on('connection', (socket) => {
    console.log(`🔌 WebSocket client connected: ${socket.id}`);
    
    socket.emit('welcome', {
      message: 'Connected to Hex Data Service',
      socketId: socket.id,
      timestamp: new Date().toISOString()
    });

    socket.on('join-room', (room: string) => {
      socket.join(room);
      console.log(`👥 Socket ${socket.id} joined room: ${room}`);
      socket.emit('room-joined', { room, socketId: socket.id });
    });

    socket.on('leave-room', (room: string) => {
      socket.leave(room);
      console.log(`👋 Socket ${socket.id} left room: ${room}`);
      socket.emit('room-left', { room, socketId: socket.id });
    });

    socket.on('disconnect', (reason) => {
      console.log(`🔌 WebSocket client disconnected: ${socket.id} (${reason})`);
    });

    socket.on('error', (error) => {
      console.error(`❌ WebSocket error for ${socket.id}:`, error);
    });
  });

  return router;
};