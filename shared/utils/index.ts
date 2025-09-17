import { promises as fs } from 'fs';
import path from 'path';

// Generate unique ID
export const generateId = (): string => {
  return Date.now().toString(36) + Math.random().toString(36).substr(2);
};

// Format timestamp for file naming
export const formatTimestamp = (date: Date): string => {
  return date.toISOString().replace(/[:.]/g, '-');
};

// Clean IP address for file naming
export const cleanIP = (ip: string): string => {
  return (ip || '').replace(/[:f]+/g, '');
};

// Ensure directory exists
export const ensureDir = async (dirPath: string): Promise<void> => {
  try {
    await fs.access(dirPath);
  } catch {
    await fs.mkdir(dirPath, { recursive: true });
  }
};

// Read log files from directory
export const readLogFiles = async (logDir: string, clientIP?: string): Promise<string[]> => {
  try {
    const files = await fs.readdir(logDir);
    
    if (clientIP) {
      return files.filter(file => file.includes(`hex-${clientIP}-`));
    }
    
    return files.filter(file => file.startsWith('hex-') && file.endsWith('.log'));
  } catch (error) {
    console.error('Error reading log files:', error);
    return [];
  }
};

// Parse log line
export const parseLogLine = (line: string): any => {
  try {
    const match = line.match(/^(.+?) (.+?) len=(\d+) HEX=(.+?) ASCII=(.+)$/);
    if (!match) return null;
    
    const [, timestamp, clientIP, length, hex, ascii] = match;
    
    return {
      timestamp,
      clientIP,
      dataLength: parseInt(length),
      hexData: hex,
      asciiData: ascii.trim()
    };
  } catch (error) {
    return null;
  }
};

// Validate hex string
export const isValidHex = (hex: string): boolean => {
  return /^[0-9A-Fa-f]+$/.test(hex) && hex.length % 2 === 0;
};

// Convert hex to buffer
export const hexToBuffer = (hex: string): Buffer => {
  return Buffer.from(hex, 'hex');
};

// Sanitize ASCII for display
export const sanitizeAscii = (buffer: Buffer): string => {
  return buffer.toString('ascii').replace(/[^\x20-\x7E]+/g, '.');
};