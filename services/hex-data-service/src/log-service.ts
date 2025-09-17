import { promises as fs } from 'fs';
import path from 'path';
import { HexLog, HexLogQuery, PaginationQuery } from '../shared/types';
import { ensureDir, readLogFiles, parseLogLine } from '../shared/utils';

export class LogService {
  private logDir: string;

  constructor(logDir: string) {
    this.logDir = logDir;
    this.init();
  }

  private async init(): Promise<void> {
    await ensureDir(this.logDir);
    console.log(`📁 Log directory initialized: ${this.logDir}`);
  }

  async saveLogEntry(logEntry: HexLog): Promise<void> {
    const logFile = path.join(this.logDir, logEntry.fileName);
    const logLine = `${logEntry.timestamp} ${logEntry.clientIP} len=${logEntry.dataLength} HEX=${logEntry.hexData} ASCII=${logEntry.asciiData}\n`;
    
    try {
      await fs.appendFile(logFile, logLine);
    } catch (error) {
      console.error('❌ Error saving log entry:', error);
      throw error;
    }
  }

  async getLogs(query: HexLogQuery = {}): Promise<{ logs: HexLog[], total: number, page: number, totalPages: number }> {
    const { 
      page = 1, 
      limit = 50, 
      clientIP, 
      startDate, 
      endDate,
      sortOrder = 'desc' 
    } = query;

    try {
      const files = await readLogFiles(this.logDir, clientIP);
      let allLogs: HexLog[] = [];

      for (const file of files) {
        const filePath = path.join(this.logDir, file);
        const content = await fs.readFile(filePath, 'utf-8');
        const lines = content.trim().split('\n').filter(line => line.trim());

        for (const line of lines) {
          const parsed = parseLogLine(line);
          if (parsed) {
            const log: HexLog = {
              id: `${file}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
              ...parsed,
              fileName: file
            };

            // Date filtering
            if (startDate && new Date(log.timestamp) < new Date(startDate)) continue;
            if (endDate && new Date(log.timestamp) > new Date(endDate)) continue;

            allLogs.push(log);
          }
        }
      }

      // Sort logs
      allLogs.sort((a, b) => {
        const dateA = new Date(a.timestamp).getTime();
        const dateB = new Date(b.timestamp).getTime();
        return sortOrder === 'desc' ? dateB - dateA : dateA - dateB;
      });

      // Pagination
      const total = allLogs.length;
      const totalPages = Math.ceil(total / limit);
      const startIndex = (page - 1) * limit;
      const endIndex = startIndex + limit;
      const logs = allLogs.slice(startIndex, endIndex);

      return {
        logs,
        total,
        page,
        totalPages
      };
    } catch (error) {
      console.error('❌ Error reading logs:', error);
      throw error;
    }
  }

  async getLogsByClient(clientIP: string, query: PaginationQuery = {}): Promise<{ logs: HexLog[], total: number }> {
    return this.getLogs({ ...query, clientIP });
  }

  async getStats(): Promise<{
    totalLogs: number;
    totalClients: number;
    totalFiles: number;
    diskUsage: string;
  }> {
    try {
      const files = await readLogFiles(this.logDir);
      const clients = new Set<string>();
      let totalLogs = 0;
      let totalSize = 0;

      for (const file of files) {
        const filePath = path.join(this.logDir, file);
        const stats = await fs.stat(filePath);
        totalSize += stats.size;

        const content = await fs.readFile(filePath, 'utf-8');
        const lines = content.trim().split('\n').filter(line => line.trim());
        totalLogs += lines.length;

        // Extract client IP from filename
        const match = file.match(/hex-(.+?)-/);
        if (match) {
          clients.add(match[1]);
        }
      }

      return {
        totalLogs,
        totalClients: clients.size,
        totalFiles: files.length,
        diskUsage: this.formatBytes(totalSize)
      };
    } catch (error) {
      console.error('❌ Error getting stats:', error);
      throw error;
    }
  }

  private formatBytes(bytes: number): string {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async deleteOldLogs(daysOld: number = 30): Promise<{ deleted: number, size: string }> {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);

    try {
      const files = await readLogFiles(this.logDir);
      let deletedCount = 0;
      let deletedSize = 0;

      for (const file of files) {
        const filePath = path.join(this.logDir, file);
        const stats = await fs.stat(filePath);

        if (stats.mtime < cutoffDate) {
          deletedSize += stats.size;
          await fs.unlink(filePath);
          deletedCount++;
        }
      }

      return {
        deleted: deletedCount,
        size: this.formatBytes(deletedSize)
      };
    } catch (error) {
      console.error('❌ Error deleting old logs:', error);
      throw error;
    }
  }
}