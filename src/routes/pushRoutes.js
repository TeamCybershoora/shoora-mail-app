import express from 'express';

import { validateBody } from '../middleware/validate.js';
import { registerDeviceSchema, unregisterDeviceSchema } from './schemas.js';

export function createPushRoutes({ authMiddleware, pushService }) {
  const router = express.Router();

  router.post('/register-device', authMiddleware, validateBody(registerDeviceSchema), async (req, res, next) => {
    try {
      const registered = await pushService.registerDevice({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId || null,
        token: req.validatedBody.token,
        platform: req.validatedBody.platform,
      });

      res.json({
        success: true,
        device: {
          id: registered?.id || null,
          accountId: registered?.accountId || null,
          platform: registered?.platform || req.validatedBody.platform,
          updatedAt: registered?.updatedAt || null,
        },
      });
    } catch (error) {
      next(error);
    }
  });

  router.post('/unregister-device', authMiddleware, validateBody(unregisterDeviceSchema), async (req, res, next) => {
    try {
      await pushService.unregisterDevice({
        userId: req.auth.userId,
        token: req.validatedBody.token,
      });
      res.json({ success: true });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
