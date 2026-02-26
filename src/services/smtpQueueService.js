import { setTimeout as sleep } from 'node:timers/promises';

import { ImapFlow } from 'imapflow';
import nodemailer from 'nodemailer';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';

import { logger } from '../lib/logger.js';

const DEFAULT_SENT_MAILBOXES = [
  'Sent',
  'Sent Items',
  'Sent Mail',
  'Sent Messages',
  'INBOX.Sent',
  '[Gmail]/Sent Mail',
];

const IMAP_OPERATION_TIMEOUT_MS = 15_000;

function normalizeAttachments(source) {
  if (!Array.isArray(source)) {
    return [];
  }

  return source
    .map((item, index) => {
      if (!item || typeof item !== 'object') {
        return null;
      }

      const filename = String(item.filename || `attachment-${index + 1}`).trim();
      const base64 = String(item.base64 || item.contentBase64 || item.content || '');
      if (!base64) {
        return null;
      }

      return {
        filename,
        content: Buffer.from(base64, 'base64'),
        contentType: String(item.mimeType || item.type || 'application/octet-stream'),
        contentDisposition: item.inline ? 'inline' : 'attachment',
        cid: item.contentId ? String(item.contentId) : undefined,
      };
    })
    .filter(Boolean);
}

export class SmtpQueueService {
  constructor({ userStore, accountService, queueConfig, gmailConfig }) {
    this.userStore = userStore;
    this.accountService = accountService;
    this.queueConfig = queueConfig;
    this.gmailConfig = gmailConfig;

    this._running = false;
    this._worker = null;
  }

  start() {
    if (this._running) {
      return;
    }
    this._running = true;
    this._worker = this._loop();
  }

  async stop() {
    this._running = false;
    if (this._worker) {
      await this._worker;
      this._worker = null;
    }
  }

  async enqueue({ userId, accountId, payload }) {
    return this.userStore.enqueueSendJob({
      userId,
      accountId,
      payload,
    });
  }

  async getStatus({ userId, jobId }) {
    return this.userStore.getSendJob(jobId, userId);
  }

  async _loop() {
    while (this._running) {
      try {
        await this._processDueJobs();
      } catch (error) {
        logger.error('SMTP queue loop failure', { error: error.message });
      }

      await sleep(this.queueConfig.workerIntervalMs);
    }
  }

  async _processDueJobs() {
    const jobs = await this.userStore.listRunnableSendJobs(Date.now());
    for (const job of jobs) {
      if (!this._running) {
        return;
      }
      // eslint-disable-next-line no-await-in-loop
      await this._processJob(job);
    }
  }

  async _processJob(job) {
    const attempts = Number(job.attempts || 0);

    await this.userStore.updateSendJob(job.id, {
      status: 'processing',
      attempts: attempts + 1,
    });

    try {
      const account = await this.accountService.resolveAccountForUser({
        userId: job.userId,
        accountId: job.accountId,
      });

      const authContext = await this.accountService.getAccountAuth(account);
      const payload = job.payload || {};
      const accountFrom = String(authContext.email || '').trim();
      const requestedFrom = String(payload.from || '').trim();
      const fromAddress =
        requestedFrom &&
          accountFrom &&
          requestedFrom.toLowerCase() === accountFrom.toLowerCase()
        ? requestedFrom
        : (accountFrom || requestedFrom);

      const transporter = nodemailer.createTransport({
        host: this.gmailConfig.smtpHost,
        port: this.gmailConfig.smtpPort,
        secure: this.gmailConfig.smtpSecure,
        auth: this._smtpAuth(authContext),
      });

      const mailOptions = {
        from: fromAddress,
        to: payload.to,
        cc: payload.cc,
        bcc: payload.bcc,
        subject: payload.subject,
        text: payload.text,
        html: payload.html,
        attachments: normalizeAttachments(payload.attachments),
      };

      const rawMessage = await this._buildRawMessage(mailOptions);
      const sendInfo = await transporter.sendMail(mailOptions);

      transporter.close();

      const appendOutcome = await this._appendToSentMailbox({
        authContext,
        rawMessage,
      });

      await this.userStore.updateSendJob(job.id, {
        status: 'sent',
        sentAt: new Date().toISOString(),
        messageId: sendInfo.messageId || null,
        acceptedRecipients: Array.isArray(sendInfo.accepted)
          ? sendInfo.accepted.map((item) => String(item))
          : (Array.isArray(payload.to) ? payload.to.map((item) => String(item)) : []),
        response: sendInfo.response || null,
        appendStatus: appendOutcome.appended ? 'appended' : 'failed',
        appendedMailbox: appendOutcome.mailbox || null,
        appendError: appendOutcome.error || null,
        nextRunAt: null,
        lastError: null,
      });
    } catch (error) {
      const failedAttempts = attempts + 1;
      const maxAttempts = this.queueConfig.maxAttempts;
      const exhausted = failedAttempts >= maxAttempts;

      if (exhausted) {
        await this.userStore.updateSendJob(job.id, {
          status: 'failed',
          nextRunAt: null,
          lastError: String(error?.message || error),
          failedAt: new Date().toISOString(),
        });

        logger.warn('SMTP job permanently failed', {
          jobId: job.id,
          error: error.message,
        });
        return;
      }

      const backoffMs = Math.min(60_000, Math.pow(2, failedAttempts) * 1000);
      await this.userStore.updateSendJob(job.id, {
        status: 'queued',
        nextRunAt: Date.now() + backoffMs,
        lastError: String(error?.message || error),
      });

      logger.warn('SMTP job retry scheduled', {
        jobId: job.id,
        backoffMs,
        attempts: failedAttempts,
        error: error.message,
      });
    }
  }

  _smtpAuth(authContext) {
    if (authContext.mode === 'password') {
      return {
        user: authContext.email,
        pass: authContext.password,
      };
    }

    return {
      type: 'OAuth2',
      user: authContext.email,
      accessToken: authContext.accessToken,
    };
  }

  _imapAuth(authContext) {
    if (authContext.mode === 'password') {
      return {
        user: authContext.email,
        pass: authContext.password,
      };
    }

    return {
      user: authContext.email,
      accessToken: authContext.accessToken,
    };
  }

  async _buildRawMessage(mailOptions) {
    const composer = new MailComposer(mailOptions);
    return composer.compile().build();
  }

  async _appendToSentMailbox({ authContext, rawMessage }) {
    const hosts = this._uniqueValues([
      ...(Array.isArray(authContext.imapHostCandidates) ? authContext.imapHostCandidates : []),
      this.gmailConfig.imapHost,
    ]);

    let client = null;
    let lastError = null;

    for (const host of hosts) {
      const candidate = new ImapFlow({
        host,
        port: this.gmailConfig.imapPort,
        secure: this.gmailConfig.imapSecure,
        logger: false,
        auth: this._imapAuth(authContext),
        tls: {
          rejectUnauthorized: this.gmailConfig.imapRejectUnauthorized !== false,
        },
        disableAutoIdle: true,
        socketTimeout: IMAP_OPERATION_TIMEOUT_MS,
        commandTimeout: IMAP_OPERATION_TIMEOUT_MS,
      });

      try {
        await candidate.connect();
        client = candidate;
        break;
      } catch (error) {
        lastError = error;
        await this._closeImapClient(candidate);
      }
    }

    if (!client) {
      return {
        appended: false,
        mailbox: null,
        error: String(lastError?.message || 'Unable to connect to IMAP for Sent append'),
      };
    }

    try {
      const candidates = await this._resolveSentMailboxCandidates(client);
      for (const mailbox of candidates) {
        try {
          await client.append(mailbox, rawMessage);
          return {
            appended: true,
            mailbox,
            error: null,
          };
        } catch (error) {
          lastError = error;
        }
      }

      return {
        appended: false,
        mailbox: null,
        error: String(lastError?.message || 'All sent mailbox append attempts failed'),
      };
    } finally {
      await this._closeImapClient(client);
    }
  }

  async _resolveSentMailboxCandidates(client) {
    const dynamicCandidates = [];

    try {
      const listed = await client.list();
      for (const mailbox of listed || []) {
        const path = String(mailbox?.path || '').trim();
        if (!path) {
          continue;
        }

        const specialUse = String(mailbox?.specialUse || '').toLowerCase();
        const hasSentSpecialUse = specialUse.includes('\\sent');
        const flags = mailbox?.flags instanceof Set
          ? Array.from(mailbox.flags, (value) => String(value).toLowerCase())
          : [];
        const hasSentFlag = flags.some((value) => value.includes('\\sent'));

        if (hasSentSpecialUse || hasSentFlag) {
          dynamicCandidates.push(path);
        }
      }

      for (const mailbox of listed || []) {
        const path = String(mailbox?.path || '').trim();
        if (!path) {
          continue;
        }
        if (path.toLowerCase().includes('sent')) {
          dynamicCandidates.push(path);
        }
      }
    } catch (error) {
      logger.warn('Unable to list IMAP mailboxes for Sent append', {
        error: error.message,
      });
    }

    return this._uniqueValues([
      ...dynamicCandidates,
      ...DEFAULT_SENT_MAILBOXES,
    ]);
  }

  async _closeImapClient(client) {
    if (!client) {
      return;
    }

    try {
      await client.logout();
    } catch {
      try {
        client.close();
      } catch {
        // ignore
      }
    }
  }

  _uniqueValues(values) {
    const seen = new Set();
    const out = [];

    for (const value of values) {
      const normalized = String(value || '').trim();
      if (!normalized) {
        continue;
      }

      const lowered = normalized.toLowerCase();
      if (seen.has(lowered)) {
        continue;
      }

      seen.add(lowered);
      out.push(normalized);
    }

    return out;
  }
}
