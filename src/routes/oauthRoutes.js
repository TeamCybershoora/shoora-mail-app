import express from 'express';

import { validateBody, validateQuery } from '../middleware/validate.js';
import {
  oauthAuthorizeSchema,
  oauthExchangeSchema,
} from './schemas.js';

export function createOAuthRoutes({ authMiddleware, googleOAuthService, accountService, watcherManager }) {
  const router = express.Router();

  router.get('/google/url', validateQuery(oauthAuthorizeSchema), (req, res) => {
    const { state, codeChallenge, loginHint } = req.validatedQuery;
    const authUrl = googleOAuthService.buildAuthorizationUrl({
      state,
      codeChallenge,
      loginHint,
    });

    res.json({ success: true, authUrl });
  });

  router.post('/google/exchange', authMiddleware, validateBody(oauthExchangeSchema), async (req, res, next) => {
    try {
      const account = await accountService.linkGoogleAccount({
        userId: req.auth.userId,
        code: req.validatedBody.code,
        codeVerifier: req.validatedBody.codeVerifier,
        redirectUri: req.validatedBody.redirectUri,
      });

      await watcherManager.startForUserAccount({
        userId: req.auth.userId,
        accountId: account.id,
      });

      res.json({
        success: true,
        account,
      });
    } catch (error) {
      next(error);
    }
  });

  router.get('/accounts', authMiddleware, async (req, res, next) => {
    try {
      const accounts = await accountService.listAccounts(req.auth.userId);
      res.json({ success: true, accounts });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
