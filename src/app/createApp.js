import cors from 'cors';
import express from 'express';

import { errorHandler } from '../middleware/errorHandler.js';
import { buildRateLimiters } from '../middleware/rateLimit.js';
import { createAuthRoutes } from '../routes/authRoutes.js';
import { createMailRoutes } from '../routes/mailRoutes.js';
import { createMiscRoutes } from '../routes/miscRoutes.js';
import { createOAuthRoutes } from '../routes/oauthRoutes.js';
import { createPushRoutes } from '../routes/pushRoutes.js';
import { createSendRoutes } from '../routes/sendRoutes.js';

export function createApp({
  env,
  authService,
  authMiddleware,
  accountService,
  googleOAuthService,
  mailService,
  pushService,
  smtpQueueService,
  watcherManager,
}) {
  const app = express();
  app.disable('x-powered-by');

  const { globalLimiter, authLimiter, sendStatusLimiter } = buildRateLimiters(env.rateLimit);

  const corsOptions = {
    origin(origin, callback) {
      if (!origin || env.corsOrigins.includes('*') || env.corsOrigins.includes(origin)) {
        callback(null, true);
        return;
      }
      callback(new Error('Origin not allowed by CORS'));
    },
    credentials: true,
  };

  app.use(cors(corsOptions));
  app.options('*', cors(corsOptions));
  app.use(globalLimiter);
  app.use(express.json({ limit: '8mb' }));

  app.get('/health', (_req, res) => {
    res.json({
      ok: true,
      time: new Date().toISOString(),
      pushEnabled: pushService.enabled,
    });
  });

  const api = express.Router();

  const authRoutes = createAuthRoutes({
    authService,
    authMiddleware,
    accountService,
    watcherManager,
    pushService,
  });

  api.use('/auth', authLimiter, authRoutes);
  // Backward-compatible aliases for existing Flutter login/session flow.
  api.use(authLimiter, authRoutes);
  api.use('/oauth', createOAuthRoutes({
    authMiddleware,
    googleOAuthService,
    accountService,
    watcherManager,
  }));
  api.use('/push', createPushRoutes({ authMiddleware, pushService }));
  api.use(createMailRoutes({ authMiddleware, mailService }));
  api.use(createSendRoutes({ authMiddleware, smtpQueueService, sendStatusLimiter }));
  api.use(createMiscRoutes({ authMiddleware }));

  app.use('/api', api);

  app.use((_req, res) => {
    res.status(404).json({
      success: false,
      error: 'Route not found',
      code: 'NOT_FOUND',
    });
  });

  app.use(errorHandler);

  return app;
}
