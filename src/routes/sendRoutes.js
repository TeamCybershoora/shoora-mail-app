import express from 'express';

import { validateBody, validateQuery } from '../middleware/validate.js';
import { enqueueSendSchema, sendStatusQuerySchema } from './schemas.js';

function normalizeRecipients(value) {
  if (Array.isArray(value)) {
    return value;
  }
  if (typeof value === 'string') {
    return [value];
  }
  return [];
}

export function createSendRoutes({ authMiddleware, smtpQueueService, sendStatusLimiter }) {
  const router = express.Router();
  const applySendStatusLimiter = sendStatusLimiter || ((_req, _res, next) => next());

  router.post('/send-mail', authMiddleware, validateBody(enqueueSendSchema), async (req, res, next) => {
    try {
      const payload = {
        accountId: req.validatedBody.accountId,
        from: req.validatedBody.from,
        to: normalizeRecipients(req.validatedBody.to),
        cc: req.validatedBody.cc,
        bcc: req.validatedBody.bcc,
        subject: req.validatedBody.subject,
        text: req.validatedBody.text,
        html: req.validatedBody.html,
        attachments: req.validatedBody.attachments || [],
      };

      const job = await smtpQueueService.enqueue({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId || null,
        payload,
      });

      res.json({
        success: true,
        queued: true,
        jobId: job.id,
        status: job.status,
        messageId: null,
        acceptedRecipients: payload.to,
        appendStatus: 'queued',
        appendedMailbox: null,
        appendError: null,
        rawMessage: '',
      });
    } catch (error) {
      next(error);
    }
  });

  router.get('/send-status', applySendStatusLimiter, authMiddleware, validateQuery(sendStatusQuerySchema), async (req, res, next) => {
    try {
      const job = await smtpQueueService.getStatus({
        userId: req.auth.userId,
        jobId: req.validatedQuery.jobId,
      });

      if (!job) {
        res.status(404).json({
          success: false,
          error: 'Send job not found',
          code: 'NOT_FOUND',
        });
        return;
      }

      res.json({
        success: true,
        job: {
          id: job.id,
          status: job.status,
          attempts: job.attempts,
          nextRunAt: job.nextRunAt,
          lastError: job.lastError,
          messageId: job.messageId || null,
          acceptedRecipients: Array.isArray(job.acceptedRecipients)
            ? job.acceptedRecipients
            : [],
          appendStatus: typeof job.appendStatus === 'string'
            ? job.appendStatus
            : 'queued',
          appendedMailbox: job.appendedMailbox || null,
          appendError: job.appendError || null,
          sentAt: job.sentAt || null,
          failedAt: job.failedAt || null,
        },
      });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
