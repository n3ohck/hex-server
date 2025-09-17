import { Router, Request, Response } from 'express';
import { LogService } from '../log-service';
import { ApiResponse, HexLogQuery } from '../../shared/types';

export const createLogRoutes = (logService: LogService): Router => {
  const router = Router();

  // GET /api/logs - Get all logs with pagination and filtering
  router.get('/', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const query: HexLogQuery = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 50,
        clientIP: req.query.clientIP as string,
        startDate: req.query.startDate as string,
        endDate: req.query.endDate as string,
        sortOrder: (req.query.sortOrder as 'asc' | 'desc') || 'desc'
      };

      const result = await logService.getLogs(query);
      
      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // GET /api/logs/client/:clientIP - Get logs for specific client
  router.get('/client/:clientIP', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const { clientIP } = req.params;
      const query = {
        page: parseInt(req.query.page as string) || 1,
        limit: parseInt(req.query.limit as string) || 50
      };

      const result = await logService.getLogsByClient(clientIP, query);
      
      res.json({
        success: true,
        data: result
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error'
      });
    }
  });

  // GET /api/logs/stats - Get logging statistics
  router.get('/stats', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const stats = await logService.getStats();
      
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

  // DELETE /api/logs/cleanup - Delete old log files
  router.delete('/cleanup', async (req: Request, res: Response<ApiResponse>) => {
    try {
      const daysOld = parseInt(req.query.days as string) || 30;
      const result = await logService.deleteOldLogs(daysOld);
      
      res.json({
        success: true,
        data: result,
        message: `Deleted ${result.deleted} files (${result.size})`
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