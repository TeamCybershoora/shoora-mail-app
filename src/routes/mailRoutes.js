import express from 'express';

import { validateBody, validateQuery } from '../middleware/validate.js';
import {
  attachmentQuerySchema,
  deleteMailSchema,
  fetchMailboxSchema,
  fetchMessageSchema,
  markReadSchema,
  moveMailSchema,
  searchSchema,
  toggleStarSchema,
} from './schemas.js';

export function createMailRoutes({ authMiddleware, mailService }) {
  const router = express.Router();

  router.post('/inbox-fetch', authMiddleware, validateBody(fetchMailboxSchema), async (req, res, next) => {
    try {
      const page = await mailService.fetchMailboxHeaders({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId,
        mailbox: 'INBOX',
        limit: req.validatedBody.limit,
        offset: req.validatedBody.offset,
      });
      res.json({ success: true, headersOnly: true, ...page });
    } catch (error) {
      next(error);
    }
  });

  router.post('/folder-fetch', authMiddleware, validateBody(fetchMailboxSchema), async (req, res, next) => {
    try {
      const page = await mailService.fetchMailboxHeaders({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId,
        mailbox: req.validatedBody.mailbox,
        limit: req.validatedBody.limit,
        offset: req.validatedBody.offset,
      });
      res.json({ success: true, headersOnly: true, ...page });
    } catch (error) {
      next(error);
    }
  });

  router.post('/search', authMiddleware, validateBody(searchSchema), async (req, res, next) => {
    try {
      const page = await mailService.searchHeaders({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId,
        mailbox: req.validatedBody.mailbox,
        query: req.validatedBody.query,
        limit: req.validatedBody.limit,
        offset: req.validatedBody.offset,
      });
      res.json({ success: true, ...page });
    } catch (error) {
      next(error);
    }
  });

  router.post('/mail-detail', authMiddleware, validateBody(fetchMessageSchema), async (req, res, next) => {
    try {
      const detail = await mailService.fetchMessageDetail({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId,
        mailbox: req.validatedBody.mailbox,
        uid: req.validatedBody.uid,
      });

      res.json({ success: true, mail: detail });
    } catch (error) {
      next(error);
    }
  });

  router.get('/attachment-download', authMiddleware, validateQuery(attachmentQuerySchema), async (req, res, next) => {
    try {
      const attachment = await mailService.fetchAttachment({
        userId: req.auth.userId,
        accountId: req.validatedQuery.accountId,
        mailbox: req.validatedQuery.mailbox,
        uid: req.validatedQuery.uid,
        partId: req.validatedQuery.part,
        index: req.validatedQuery.index,
        fileName: req.validatedQuery.name || '',
      });

      const disposition = req.validatedQuery.inline ? 'inline' : 'attachment';
      const safeName = String(attachment.filename || 'attachment.bin')
        .replace(/[\r\n]/g, ' ')
        .replace(/["\\]/g, '_')
        .trim();

      res.setHeader('Content-Type', attachment.contentType);
      res.setHeader('Content-Length', String(attachment.buffer.length));
      res.setHeader('X-Shoora-Attachment-Source', 'direct');
      res.setHeader('Content-Disposition', `${disposition}; filename="${safeName || 'attachment.bin'}"`);
      res.status(200).send(attachment.buffer);
    } catch (error) {
      next(error);
    }
  });

  router.get('/mailboxes-list', authMiddleware, async (req, res, next) => {
    try {
      const accountId = req.query.accountId ? String(req.query.accountId) : undefined;
      const mailboxes = await mailService.listMailboxes({
        userId: req.auth.userId,
        accountId,
      });
      res.json({ success: true, mailboxes });
    } catch (error) {
      next(error);
    }
  });

  router.post('/mark-read', authMiddleware, validateBody(markReadSchema), async (req, res, next) => {
    try {
      const result = await mailService.setRead({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId,
        mailbox: req.validatedBody.mailbox,
        uid: req.validatedBody.uid,
        read: req.validatedBody.read,
      });
      res.json({ success: true, ...result });
    } catch (error) {
      next(error);
    }
  });

  router.post('/toggle-star', authMiddleware, validateBody(toggleStarSchema), async (req, res, next) => {
    try {
      const result = await mailService.setStarred({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId,
        mailbox: req.validatedBody.mailbox,
        uid: req.validatedBody.uid,
        starred: req.validatedBody.starred,
      });
      res.json({ success: true, ...result });
    } catch (error) {
      next(error);
    }
  });

  router.post('/move-mail', authMiddleware, validateBody(moveMailSchema), async (req, res, next) => {
    try {
      const result = await mailService.moveMessage({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId,
        fromMailbox: req.validatedBody.fromMailbox,
        toMailbox: req.validatedBody.toMailbox,
        uid: req.validatedBody.uid,
      });
      res.json({ success: true, ...result });
    } catch (error) {
      next(error);
    }
  });

  router.post('/delete-mail', authMiddleware, validateBody(deleteMailSchema), async (req, res, next) => {
    try {
      const result = await mailService.deleteMessage({
        userId: req.auth.userId,
        accountId: req.validatedBody.accountId,
        mailbox: req.validatedBody.mailbox,
        uid: req.validatedBody.uid,
      });
      res.json({ success: true, ...result });
    } catch (error) {
      next(error);
    }
  });

  return router;
}
