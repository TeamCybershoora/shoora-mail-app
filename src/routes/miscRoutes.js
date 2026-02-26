import express from 'express';

export function createMiscRoutes({ authMiddleware }) {
  const router = express.Router();

  const mockHandler = (endpoint) => (_req, res) => {
    res.json({
      success: true,
      mock: true,
      endpoint,
    });
  };

  router.post('/save-draft', authMiddleware, mockHandler('/api/save-draft'));
  router.post('/settings', authMiddleware, mockHandler('/api/settings'));
  router.post('/toggle-important', authMiddleware, mockHandler('/api/toggle-important'));

  return router;
}
