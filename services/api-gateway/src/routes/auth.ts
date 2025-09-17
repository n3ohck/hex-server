import { Router, Request, Response } from 'express';
import { generateToken, verifyToken, AuthRequest } from '../middleware/auth';
import { ApiResponse } from '../../shared/types';
import { generateId } from '../../shared/utils';

// Simple in-memory user store for demo purposes
// In production, use a proper database
interface User {
  id: string;
  username: string;
  password: string; // In production, this should be hashed
  role: string;
  createdAt: string;
}

const users: Map<string, User> = new Map();

// Create default admin user
const adminUser: User = {
  id: 'admin-001',
  username: 'admin',
  password: 'admin123', // In production, hash this!
  role: 'admin',
  createdAt: new Date().toISOString()
};
users.set('admin', adminUser);

// Create default user
const defaultUser: User = {
  id: 'user-001',
  username: 'user',
  password: 'user123', // In production, hash this!
  role: 'user',
  createdAt: new Date().toISOString()
};
users.set('user', defaultUser);

export const createAuthRoutes = (): Router => {
  const router = Router();

  // POST /api/auth/login - User login
  router.post('/login', (req: Request, res: Response<ApiResponse>) => {
    try {
      const { username, password } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({
          success: false,
          error: 'Username and password are required'
        });
      }

      const user = users.get(username);
      
      if (!user || user.password !== password) {
        return res.status(401).json({
          success: false,
          error: 'Invalid username or password'
        });
      }

      const token = generateToken(user.id, user.role);
      
      res.json({
        success: true,
        data: {
          token,
          user: {
            id: user.id,
            username: user.username,
            role: user.role
          }
        },
        message: 'Login successful'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Login error'
      });
    }
  });

  // POST /api/auth/register - User registration
  router.post('/register', (req: Request, res: Response<ApiResponse>) => {
    try {
      const { username, password, role = 'user' } = req.body;
      
      if (!username || !password) {
        return res.status(400).json({
          success: false,
          error: 'Username and password are required'
        });
      }

      if (users.has(username)) {
        return res.status(409).json({
          success: false,
          error: 'Username already exists'
        });
      }

      // Validate role
      if (!['user', 'admin'].includes(role)) {
        return res.status(400).json({
          success: false,
          error: 'Invalid role. Must be user or admin'
        });
      }

      const newUser: User = {
        id: generateId(),
        username,
        password, // In production, hash this!
        role,
        createdAt: new Date().toISOString()
      };

      users.set(username, newUser);
      
      const token = generateToken(newUser.id, newUser.role);
      
      res.status(201).json({
        success: true,
        data: {
          token,
          user: {
            id: newUser.id,
            username: newUser.username,
            role: newUser.role
          }
        },
        message: 'Registration successful'
      });
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Registration error'
      });
    }
  });

  // GET /api/auth/verify - Verify token
  router.get('/verify', (req: Request, res: Response<ApiResponse>) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: 'Access token required'
        });
      }

      const token = authHeader.substring(7);
      
      try {
        const decoded = verifyToken(token);
        
        res.json({
          success: true,
          data: {
            userId: decoded.userId,
            role: decoded.role,
            exp: decoded.exp,
            iat: decoded.iat
          },
          message: 'Token is valid'
        });
      } catch (jwtError) {
        return res.status(401).json({
          success: false,
          error: 'Invalid or expired token'
        });
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Token verification error'
      });
    }
  });

  // GET /api/auth/me - Get current user info
  router.get('/me', (req: AuthRequest, res: Response<ApiResponse>) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: 'Access token required'
        });
      }

      const token = authHeader.substring(7);
      
      try {
        const decoded = verifyToken(token);
        
        // Find user by ID
        let userFound: User | undefined;
        for (const user of users.values()) {
          if (user.id === decoded.userId) {
            userFound = user;
            break;
          }
        }

        if (!userFound) {
          return res.status(404).json({
            success: false,
            error: 'User not found'
          });
        }
        
        res.json({
          success: true,
          data: {
            id: userFound.id,
            username: userFound.username,
            role: userFound.role,
            createdAt: userFound.createdAt
          }
        });
      } catch (jwtError) {
        return res.status(401).json({
          success: false,
          error: 'Invalid or expired token'
        });
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'User info error'
      });
    }
  });

  // GET /api/auth/users - List all users (admin only)
  router.get('/users', (req: AuthRequest, res: Response<ApiResponse>) => {
    try {
      const authHeader = req.headers.authorization;
      
      if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
          success: false,
          error: 'Access token required'
        });
      }

      const token = authHeader.substring(7);
      
      try {
        const decoded = verifyToken(token);
        
        if (decoded.role !== 'admin') {
          return res.status(403).json({
            success: false,
            error: 'Admin access required'
          });
        }

        const userList = Array.from(users.values()).map(user => ({
          id: user.id,
          username: user.username,
          role: user.role,
          createdAt: user.createdAt
        }));
        
        res.json({
          success: true,
          data: {
            users: userList,
            count: userList.length
          }
        });
      } catch (jwtError) {
        return res.status(401).json({
          success: false,
          error: 'Invalid or expired token'
        });
      }
    } catch (error) {
      res.status(500).json({
        success: false,
        error: error instanceof Error ? error.message : 'Users list error'
      });
    }
  });

  return router;
};