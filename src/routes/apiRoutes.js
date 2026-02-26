import express from 'express';

import {
  ApiError,
  TooLargePreviewError,
  UnauthorizedError,
  asApiError,
} from '../utils/errors.js';
import {
  buildSessionPayload,
  toCurrentUser,
} from '../session/sessionManager.js';
import { attachmentPreviewLimitBytes } from '../services/imapService.js';

function deriveUserName(email) {
  const value = String(email || '').trim();
  const at = value.indexOf('@');
  return at > 0 ? value.slice(0, at) : value;
}

function parsePositiveInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function parseNonNegativeInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed < 0) {
    return fallback;
  }
  return parsed;
}

function parseBoolean(value, fallback = false) {
  if (value == null || value === '') {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes';
}

function sanitizeFilename(value, fallback) {
  const file = String(value || fallback || 'attachment.bin')
    .replace(/[\r\n]/g, ' ')
    .replace(/["\\]/g, '_')
    .trim();
  return file || fallback || 'attachment.bin';
}

function supportsInlinePreview(contentType) {
  const mime = String(contentType || '').toLowerCase();
  if (mime.startsWith('image/')) {
    return true;
  }
  if (mime.startsWith('video/')) {
    return true;
  }
  if (mime === 'application/pdf') {
    return true;
  }
  return false;
}

function defaultNoImapMailboxResponse(mailbox, offset) {
  return {
    mailbox,
    total: 0,
    headers: [],
    hasMore: false,
    nextOffset: offset,
  };
}

export function createApiRouter({
  config,
  sessionManager,
  imapService,
  smtpService,
  hasImapRuntime,
}) {
  const router = express.Router();

  const wrap = (handler) => (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };

  const requireSession = (req, _res, next) => {
    const session = sessionManager.readSessionFromRequest(req);
    if (!session) {
      next(new UnauthorizedError('Session is missing or invalid'));
      return;
    }
    req.currentSession = session;
    next();
  };

  router.post(
    '/login',
    wrap(async (req, res) => {
      const email = String(req.body?.email || '').trim().toLowerCase();
      const password = String(req.body?.password || '');

      if (!email || !password) {
        throw new ApiError(400, 'email and password are required');
      }

      const fallbackConfigured =
        Boolean(config.siteAuth.email) && Boolean(config.siteAuth.password);
      const fallbackMatch =
        fallbackConfigured &&
        email === config.siteAuth.email &&
        password === config.siteAuth.password;

      if (fallbackMatch) {
        const sessionPayload = buildSessionPayload({
          email,
          userName: deriveUserName(email),
          imapPassword: null,
          imapMode: false,
        });

        sessionManager.setSessionCookie(res, sessionPayload);
        res.json({
          success: true,
          currentUser: toCurrentUser(sessionPayload),
          inbox: defaultNoImapMailboxResponse('INBOX', 0),
        });
        return;
      }

      const imapAvailable = hasImapRuntime();
      if (imapAvailable) {
        const valid = await imapService.verifyImapCredentials(email, password);
        if (!valid) {
          throw new UnauthorizedError('Invalid IMAP credentials');
        }

        const sessionPayload = buildSessionPayload({
          email,
          userName: deriveUserName(email),
          imapPassword: password,
          imapMode: true,
        });

        sessionManager.setSessionCookie(res, sessionPayload);

        const inbox = await imapService.fetchMailboxMailHeaders(sessionPayload, {
          mailbox: 'INBOX',
          limit: 30,
          offset: 0,
        });

        res.json({
          success: true,
          currentUser: toCurrentUser(sessionPayload),
          inbox,
        });
        return;
      }

      if (!fallbackConfigured) {
        throw new ApiError(
          503,
          'Fallback mode is active but SITE_EMAIL/SITE_PASSWORD are not configured',
        );
      }

      throw new UnauthorizedError('Invalid fallback credentials');
    }),
  );

  router.get(
    '/session',
    wrap(async (req, res) => {
      const session = sessionManager.readSessionFromRequest(req);
      if (!session) {
        throw new UnauthorizedError('Session is missing or invalid');
      }

      res.json({
        success: true,
        currentUser: toCurrentUser(session),
      });
    }),
  );

  router.post(
    '/logout',
    wrap(async (_req, res) => {
      sessionManager.clearSessionCookie(res);
      res.json({ success: true });
    }),
  );

  const handleFolderFetch = async (req, res, mailbox) => {
    const session = req.currentSession;
    const limit = parsePositiveInteger(req.body?.limit, 30);
    const offset = parseNonNegativeInteger(req.body?.offset, 0);
    const headersOnly = parseBoolean(req.body?.headersOnly, true);

    if (!session.imapMode) {
      res.json({
        success: true,
        headersOnly: true,
        ...defaultNoImapMailboxResponse(mailbox, offset),
      });
      return;
    }

    const page = headersOnly
      ? await imapService.fetchMailboxMailHeaders(session, {
          mailbox,
          limit,
          offset,
        })
      : await imapService.fetchMailboxMails(session, {
          mailbox,
          limit,
          offset,
        });

    const totalResult = await imapService.fetchMailboxTotal(session, mailbox);

    res.json({
      success: true,
      headersOnly,
      ...page,
      total: totalResult.total,
    });
  };

  router.post(
    '/inbox-fetch',
    requireSession,
    wrap(async (req, res) => {
      await handleFolderFetch(req, res, 'INBOX');
    }),
  );

  router.post(
    '/folder-fetch',
    requireSession,
    wrap(async (req, res) => {
      const mailbox = String(req.body?.mailbox || 'INBOX').trim() || 'INBOX';
      await handleFolderFetch(req, res, mailbox);
    }),
  );

  router.post(
    '/mail-detail',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      const mailbox = String(req.body?.mailbox || 'INBOX').trim() || 'INBOX';
      const uid = parsePositiveInteger(req.body?.uid, NaN);
      if (!Number.isFinite(uid)) {
        throw new ApiError(400, 'uid is required');
      }

      if (!session.imapMode) {
        throw new ApiError(503, 'mail-detail is unavailable in fallback mode');
      }

      const detail = await imapService.fetchMailboxMailDetailByUid(session, {
        mailbox,
        uid,
      });

      res.json({
        success: true,
        mail: detail,
      });
    }),
  );

  router.post(
    '/mark-read',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      const mailbox = String(req.body?.mailbox || 'INBOX').trim() || 'INBOX';
      const uid = parsePositiveInteger(req.body?.uid, NaN);
      const read = parseBoolean(req.body?.read, true);
      if (!Number.isFinite(uid)) {
        throw new ApiError(400, 'uid is required');
      }

      if (!session.imapMode) {
        res.json({ success: true, mailbox, uid, read });
        return;
      }

      const result = await imapService.setMailboxMailSeenByUid(session, {
        mailbox,
        uid,
        read,
      });

      res.json({ success: true, ...result });
    }),
  );

  router.post(
    '/toggle-star',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      const mailbox = String(req.body?.mailbox || 'INBOX').trim() || 'INBOX';
      const uid = parsePositiveInteger(req.body?.uid, NaN);
      const starred = parseBoolean(req.body?.starred, true);
      if (!Number.isFinite(uid)) {
        throw new ApiError(400, 'uid is required');
      }

      if (!session.imapMode) {
        res.json({ success: true, mailbox, uid, starred });
        return;
      }

      const result = await imapService.setMailboxMailFlaggedByUid(session, {
        mailbox,
        uid,
        flagged: starred,
      });

      res.json({ success: true, ...result });
    }),
  );

  router.post(
    '/move-mail',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      const fromMailbox = String(req.body?.fromMailbox || '').trim();
      const toMailbox = String(req.body?.toMailbox || '').trim();
      const uid = parsePositiveInteger(req.body?.uid, NaN);

      if (!fromMailbox || !toMailbox || !Number.isFinite(uid)) {
        throw new ApiError(400, 'fromMailbox, toMailbox and uid are required');
      }

      if (!session.imapMode) {
        res.json({
          success: true,
          fromMailbox,
          toMailbox,
          uid,
          method: 'NO_IMAP',
        });
        return;
      }

      const result = await imapService.moveMailboxMailByUid(session, {
        fromMailbox,
        toMailbox,
        uid,
      });

      res.json({ success: true, ...result });
    }),
  );

  router.post(
    '/delete-mail',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      const mailbox = String(req.body?.mailbox || 'INBOX').trim() || 'INBOX';
      const uid = parsePositiveInteger(req.body?.uid, NaN);
      if (!Number.isFinite(uid)) {
        throw new ApiError(400, 'uid is required');
      }

      if (!session.imapMode) {
        res.json({ success: true, mailbox, uid, deleted: true });
        return;
      }

      const result = await imapService.deleteMailboxMailByUid(session, {
        mailbox,
        uid,
      });

      res.json({ success: true, ...result });
    }),
  );

  router.get(
    '/mailboxes-list',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      if (!session.imapMode) {
        res.json({
          success: true,
          mailboxes: ['INBOX', 'Sent', 'Drafts', 'Trash'],
        });
        return;
      }

      const result = await imapService.listImapMailboxes(session);
      res.json({ success: true, ...result });
    }),
  );

  router.post(
    '/mailbox-create',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      const name = String(req.body?.name || '').trim();
      if (!name) {
        throw new ApiError(400, 'name is required');
      }

      if (!session.imapMode) {
        res.json({ success: true, mailbox: name, created: true });
        return;
      }

      const result = await imapService.createImapMailbox(session, name);
      res.json({ success: true, ...result });
    }),
  );

  router.post(
    '/send-mail',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      const payload = {
        from: req.body?.from,
        to: req.body?.to,
        subject: req.body?.subject,
        text: req.body?.text,
        html: req.body?.html,
        attachments: req.body?.attachments,
      };

      const result = await smtpService.sendMailAndAppend(session, payload);
      res.json({
        success: true,
        ...result,
      });
    }),
  );

  router.get(
    '/attachment-download',
    requireSession,
    wrap(async (req, res) => {
      const session = req.currentSession;
      if (!session.imapMode) {
        throw new ApiError(503, 'attachment-download is unavailable in fallback mode');
      }

      const mailbox = String(req.query.mailbox || 'INBOX').trim() || 'INBOX';
      const uid = parsePositiveInteger(req.query.uid, NaN);
      if (!Number.isFinite(uid)) {
        throw new ApiError(400, 'uid query parameter is required');
      }

      const index = req.query.index != null
        ? parseNonNegativeInteger(req.query.index, NaN)
        : null;
      const name = req.query.name != null ? String(req.query.name) : '';
      const part = req.query.part != null ? String(req.query.part) : '';
      const inlineRequested = parseBoolean(req.query.inline, false);
      const maxBytes = inlineRequested ? attachmentPreviewLimitBytes : undefined;

      let attachment;
      if (part.trim()) {
        try {
          attachment = await imapService.downloadAttachmentByPart(session, {
            mailbox,
            uid,
            partId: part,
            maxBytes,
          });
        } catch (error) {
          if (error instanceof TooLargePreviewError) {
            throw error;
          }

          attachment = await imapService.downloadAttachmentFromRaw(session, {
            mailbox,
            uid,
            index,
            name,
            partId: part,
            maxBytes,
          });
        }
      } else {
        attachment = await imapService.downloadAttachmentFromRaw(session, {
          mailbox,
          uid,
          index,
          name,
          partId: part,
          maxBytes,
        });
      }

      const filename = sanitizeFilename(name || attachment.filename, 'attachment.bin');
      const inline = inlineRequested && supportsInlinePreview(attachment.contentType);
      const disposition = inline ? 'inline' : 'attachment';

      res.setHeader('Content-Type', attachment.contentType || 'application/octet-stream');
      res.setHeader('Content-Length', String(attachment.size || attachment.buffer.length));
      res.setHeader('X-Shoora-Attachment-Source', attachment.source || 'fallback');
      res.setHeader(
        'Content-Disposition',
        `${disposition}; filename="${filename}"`,
      );

      res.status(200).send(attachment.buffer);
    }),
  );

  const mockSuccess = (endpoint) =>
    wrap(async (_req, res) => {
      res.json({
        success: true,
        mock: true,
        endpoint,
      });
    });

  router.post('/save-draft', requireSession, mockSuccess('/api/save-draft'));
  router.post('/settings', requireSession, mockSuccess('/api/settings'));
  router.post('/toggle-important', requireSession, mockSuccess('/api/toggle-important'));

  router.use((error, _req, res, _next) => {
    const apiError = asApiError(error);
    res.status(apiError.statusCode).json({
      success: false,
      error: apiError.message,
      code: apiError.code,
      details: apiError.details || null,
    });
  });

  return router;
}

