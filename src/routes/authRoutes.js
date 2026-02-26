import express from 'express';

import { validateBody } from '../middleware/validate.js';
import { loginSchema } from './schemas.js';

export function createAuthRoutes({ authService, authMiddleware, accountService, watcherManager, pushService }) {
  const router = express.Router();

  router.post('/login', validateBody(loginSchema), async (req, res, next) => {
    try {
      const { email, password } = req.validatedBody;
      const session = await authService.login({ email, password });

      const accounts = await accountService.listAccounts(session.user.id);
      const hasMailAccount = accounts.length > 0;
      await Promise.all(
        accounts.map((account) =>
          watcherManager.startForUserAccount({
            userId: session.user.id,
            accountId: account.id,
          }),
        ),
      );

      res.json({
        success: true,
        token: session.token,
        currentUser: {
          id: session.user.id,
          email: session.user.email,
          userName: session.user.email.split('@')[0],
          imapMode: hasMailAccount,
        },
        linkedAccounts: accounts,
      });
    } catch (error) {
      next(error);
    }
  });

  router.get('/session', authMiddleware, async (req, res, next) => {
    try {
      const accounts = await accountService.listAccounts(req.auth.userId);
      const hasMailAccount = accounts.length > 0;
      res.json({
        success: true,
        currentUser: {
          id: req.auth.userId,
          email: req.auth.email,
          userName: req.auth.email.split('@')[0],
          imapMode: hasMailAccount,
        },
        linkedAccounts: accounts,
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/logout', authMiddleware, async (req, res, next) => {
    try {
      await watcherManager.stopForUser(req.auth.userId);
      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  });

  router.post('/push/unregister', authMiddleware, async (req, res, next) => {
    try {
      const token = String(req.body?.token || '').trim();
      if (!token) {
        res.status(400).json({ success: false, error: 'token is required', code: 'VALIDATION_ERROR' });
        return;
      }
      await pushService.unregisterDevice({ userId: req.auth.userId, token });
      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
