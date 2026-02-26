import nodemailer from 'nodemailer';
import MailComposer from 'nodemailer/lib/mail-composer/index.js';

import { ApiError, UnauthorizedError } from '../utils/errors.js';

const DEFAULT_SENT_MAILBOXES = [
  'Sent',
  'Sent Items',
  'Sent Mail',
  'Sent Messages',
  'INBOX.Sent',
  '[Gmail]/Sent Mail',
];

export class SmtpService {
  constructor({ smtpConfig, imapService, sentMailboxCandidates = [] }) {
    this.config = smtpConfig;
    this.imapService = imapService;
    this.sentMailboxCandidates = this._uniqueValues([
      ...sentMailboxCandidates,
      ...DEFAULT_SENT_MAILBOXES,
    ]);
  }

  async sendMailAndAppend(session, payload) {
    const normalized = this._normalizePayload(session, payload);
    const transporter = this._createTransport(session, normalized.from);

    let sendInfo;
    let rawBuffer;
    try {
      rawBuffer = await this._buildRawMessage(normalized.mailOptions);
      sendInfo = await this._withTimeout(
        transporter.sendMail(normalized.mailOptions),
        'SMTP send',
      );
    } catch (error) {
      throw this._normalizeSmtpError(error);
    } finally {
      transporter.close();
    }

    const appendOutcome = await this._appendToSentMailbox(session, rawBuffer);

    return {
      messageId: sendInfo.messageId || null,
      acceptedRecipients: Array.isArray(sendInfo.accepted)
        ? sendInfo.accepted.map((item) => String(item))
        : normalized.to,
      response: sendInfo.response || null,
      rawMessage: rawBuffer.toString('utf8'),
      appendStatus: appendOutcome.appended ? 'appended' : 'failed',
      appendedMailbox: appendOutcome.mailbox || null,
      appendError: appendOutcome.error || null,
    };
  }

  async _appendToSentMailbox(session, rawBuffer) {
    let lastError = null;

    for (const mailbox of this.sentMailboxCandidates) {
      try {
        await this.imapService.appendToMailbox(session, {
          mailbox,
          rawMessage: rawBuffer,
        });
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
      error: lastError?.message || 'All sent mailbox append attempts failed',
    };
  }

  _normalizePayload(session, payload) {
    const fromInput = String(payload?.from || '').trim();
    const from = fromInput || session?.email || '';
    if (!from) {
      throw new ApiError(400, 'from is required');
    }

    const recipients = Array.isArray(payload?.to)
      ? payload.to
      : String(payload?.to || '')
          .split(',')
          .map((item) => item.trim())
          .filter(Boolean);

    if (!recipients.length) {
      throw new ApiError(400, 'At least one recipient is required');
    }

    const subject = String(payload?.subject || '').trim();
    const text = payload?.text != null ? String(payload.text) : '';
    const html = payload?.html != null ? String(payload.html) : '';

    const attachments = this._normalizeAttachments(payload?.attachments);

    return {
      from,
      to: recipients,
      mailOptions: {
        from,
        to: recipients,
        subject,
        text,
        html,
        attachments,
      },
    };
  }

  _normalizeAttachments(source) {
    if (!Array.isArray(source) || !source.length) {
      return [];
    }

    return source
      .map((item, index) => {
        if (!item || typeof item !== 'object') {
          return null;
        }

        const filename = String(item.filename || `attachment-${index + 1}`).trim();
        const contentBase64 =
          item.base64 ||
          item.contentBase64 ||
          item.content ||
          '';

        const content = Buffer.from(String(contentBase64), 'base64');
        const contentType = String(item.type || item.mimeType || 'application/octet-stream');
        const inline = Boolean(item.inline);
        const contentId = item.contentId ? String(item.contentId) : undefined;

        return {
          filename,
          content,
          contentType,
          cid: contentId,
          contentDisposition: inline ? 'inline' : 'attachment',
        };
      })
      .filter(Boolean);
  }

  _createTransport(session, fromAddress) {
    const host = this.config.host || this._deriveSmtpHost(fromAddress || session?.email);
    if (!host) {
      throw new ApiError(503, 'SMTP host is not configured');
    }

    const user = this.config.user || session?.email;
    const pass = this.config.pass || session?.imapPassword;

    if (!user || !pass) {
      throw new UnauthorizedError(
        'SMTP credentials are unavailable. Set SMTP_USER/SMTP_PASS or sign in with IMAP mode.',
      );
    }

    return nodemailer.createTransport({
      host,
      port: this.config.port,
      secure: this.config.secure,
      requireTLS: this.config.startTls,
      auth: {
        user,
        pass,
      },
      connectionTimeout: this.config.operationTimeoutMs,
      greetingTimeout: this.config.operationTimeoutMs,
      socketTimeout: this.config.operationTimeoutMs,
      tls: {
        rejectUnauthorized: this.config.rejectUnauthorized,
      },
    });
  }

  _deriveSmtpHost(email) {
    const value = String(email || '').trim();
    const at = value.lastIndexOf('@');
    if (at <= 0 || at >= value.length - 1) {
      return '';
    }
    return `smtp.${value.slice(at + 1)}`;
  }

  async _buildRawMessage(mailOptions) {
    const composer = new MailComposer(mailOptions);
    return this._withTimeout(
      composer.compile().build(),
      'SMTP raw message build',
    );
  }

  async _withTimeout(promise, label) {
    const timeoutMs = this.config.operationTimeoutMs;
    let timeoutHandle;

    const timeoutPromise = new Promise((_, reject) => {
      timeoutHandle = setTimeout(() => {
        reject(new ApiError(504, `${label} timed out`));
      }, timeoutMs);
    });

    try {
      return await Promise.race([promise, timeoutPromise]);
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  _normalizeSmtpError(error) {
    if (error instanceof ApiError) {
      return error;
    }

    const message = String(error?.message || 'SMTP operation failed');
    if (message.toLowerCase().includes('auth')) {
      return new UnauthorizedError('SMTP authentication failed');
    }

    if (message.toLowerCase().includes('timeout')) {
      return new ApiError(504, 'SMTP request timed out');
    }

    return new ApiError(502, message);
  }

  _uniqueValues(values) {
    const seen = new Set();
    const out = [];
    for (const value of values) {
      const normalized = String(value || '').trim();
      if (!normalized) {
        continue;
      }
      if (seen.has(normalized.toLowerCase())) {
        continue;
      }
      seen.add(normalized.toLowerCase());
      out.push(normalized);
    }
    return out;
  }
}

