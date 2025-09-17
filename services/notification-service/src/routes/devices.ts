import { Router, Request, Response } from 'express';
import { DeviceService } from '../services/device-service';
import { ApiResponse } from '../../shared/types';
import { validateRequired } from '../../shared/middleware';

export const createDeviceRoutes = (deviceService: DeviceService): Router => {
  const router = Router();

  // POST /api/devices/register - Register a new device
  router.post('/register', 
    validateRequired(['token', 'platform']),
    async (req: Request, res: Response<ApiResponse>) => {
      try {
        const { token, platform, userId } = req.body;
        
        if (!['ios', 'android', 'web'].includes(platform)) {
          return res.status(400).json({
            success: false,
            error: 'platform must be ios, android, or web'
          });
        }

        const device = await deviceService.registerDevice(token, platform, userId);
        
        res.status(201).json({
          success: true,
          data: device,
          message: 'Device registered successfully'
        });
      } catch (error) {
        res.status(500).json({
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }
  );

  // GET /api/devices/:deviceId - Get device by ID
  router.get('/:deviceId', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { deviceId } = req.params;
      const device = await deviceService.getDevice(deviceId);
      
      if (!device) {
        return res.status(404).json({
          success: false,
          error: 'Device not found'
        });
      }

      res.json({
        success: true,
        data: device
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // GET /api/devices/user/:userId - Get devices for a user
  router.get('/user/:userId', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { userId } = req.params;
      const devices = await deviceService.getDevicesByUser(userId);
      
      res.json({
        success: true,
        data: {
          devices,
          count: devices.length
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // GET /api/devices/platform/:platform - Get devices by platform
  router.get('/platform/:platform', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { platform } = req.params;
      
      if (!['ios', 'android', 'web'].includes(platform)) {
        return res.status(400).json({
          success: false,
          error: 'platform must be ios, android, or web'
        });
      }

      const devices = await deviceService.getDevicesByPlatform(platform as 'ios' | 'android' | 'web');
      
      res.json({
        success: true,
        data: {
          devices,
          count: devices.length,
          platform
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // GET /api/devices - Get all active devices
  router.get('/', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const devices = await deviceService.getAllActiveDevices();
      
      res.json({
        success: true,
        data: {
          devices,
          count: devices.length
        }
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // PUT /api/devices/:deviceId - Update device
  router.put('/:deviceId', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { deviceId } = req.params;
      const updates = req.body;
      
      // Don't allow updating the ID or token
      delete updates.id;
      delete updates.token;
      
      const device = await deviceService.updateDevice(deviceId, updates);
      
      if (!device) {
        return res.status(404).json({
          success: false,
          error: 'Device not found'
        });
      }

      res.json({
        success: true,
        data: device,
        message: 'Device updated successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // DELETE /api/devices/:deviceId/deactivate - Deactivate device
  router.delete('/:deviceId/deactivate', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { deviceId } = req.params;
      const success = await deviceService.deactivateDevice(deviceId);
      
      if (!success) {
        return res.status(404).json({
          success: false,
          error: 'Device not found'
        });
      }

      res.json({
        success: true,
        message: 'Device deactivated successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // DELETE /api/devices/:deviceId - Remove device
  router.delete('/:deviceId', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { deviceId } = req.params;
      const success = await deviceService.removeDevice(deviceId);
      
      if (!success) {
        return res.status(404).json({
          success: false,
          error: 'Device not found'
        });
      }

      res.json({
        success: true,
        message: 'Device removed successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // DELETE /api/devices/token/:token - Remove device by token
  router.delete('/token/:token', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { token } = req.params;
      const success = await deviceService.removeDeviceByToken(token);
      
      if (!success) {
        return res.status(404).json({
          success: false,
          error: 'Device not found'
        });
      }

      res.json({
        success: true,
        message: 'Device removed successfully'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // GET /api/devices/stats - Get device statistics
  router.get('/admin/stats', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const stats = await deviceService.getStats();
      
      res.json({
        success: true,
        data: stats
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // POST /api/devices/cleanup - Clean up inactive devices
  router.post('/admin/cleanup', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const daysOld = parseInt(req.body.days) || 30;
      const removedCount = await deviceService.cleanupInactiveDevices(daysOld);
      
      res.json({
        success: true,
        data: { removedCount },
        message: `Cleaned up ${removedCount} inactive devices`
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  return router;
};