import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';

import {
  ApiError,
  NotFoundError,
  TooLargePreviewError,
  UnauthorizedError,
} from '../utils/errors.js';

const PREVIEW_LIMIT_BYTES = 25 * 1024 * 1024;

const RETRYABLE_NETWORK_CODES = new Set([
  'ETIMEDOUT',
  'ECONNRESET',
  'ECONNREFUSED',
  'EPIPE',
  'EHOSTUNREACH',
  'ENOTFOUND',
]);

function isReadableStream(value) {
  return value && typeof value.pipe === 'function' && typeof value.on === 'function';
}

export class ImapService {
  constructor(imapConfig) {
    this.config = imapConfig;
    this.previewLimitBytes = PREVIEW_LIMIT_BYTES;
  }

  async verifyImapCredentials(email, password) {
    this._assertImapConfigured();

    const session = {
      email,
      imapPassword: password,
      imapMode: true,
    };

    try {
      await this._withImapConnection(session, {
        mailbox: 'INBOX',
        operation: async () => true,
        authPasswordOverride: password,
      });
      return true;
    } catch (error) {
      if (error?.authenticationFailed) {
        return false;
      }
      const message = String(error?.message || '').toLowerCase();
      if (message.includes('auth') || message.includes('login')) {
        return false;
      }
      throw this._normalizeImapError(error);
    }
  }

  async fetchMailboxTotal(session, mailbox = 'INBOX') {
    const result = await this._withImapConnection(session, {
      mailbox,
      operation: async (client) => ({
        mailbox,
        total: Number(client.mailbox?.exists || 0),
      }),
    });
    return result;
  }

  async fetchMailboxMailHeaders(session, options = {}) {
    const mailbox = options.mailbox || 'INBOX';
    const limit = this._normalizeLimit(options.limit);
    const offset = this._normalizeOffset(options.offset);

    return this._withImapConnection(session, {
      mailbox,
      operation: async (client) => {
        const total = Number(client.mailbox?.exists || 0);
        if (total <= 0 || offset >= total) {
          return {
            mailbox,
            total,
            headers: [],
            hasMore: false,
            nextOffset: offset,
          };
        }

        const seqEnd = total - offset;
        const seqStart = Math.max(1, seqEnd - limit + 1);

        const headers = [];
        const query = {
          uid: true,
          envelope: true,
          flags: true,
          bodyStructure: true,
          size: true,
          internalDate: true,
        };

        for await (const message of client.fetch(`${seqStart}:${seqEnd}`, query)) {
          headers.push(this._serializeHeader(mailbox, message));
        }

        headers.sort((left, right) => right.uid - left.uid);
        const nextOffset = Math.min(total, offset + headers.length);

        return {
          mailbox,
          total,
          headers,
          hasMore: nextOffset < total,
          nextOffset,
        };
      },
    });
  }

  async fetchMailboxMails(session, options = {}) {
    return this.fetchMailboxMailHeaders(session, options);
  }

  async fetchMailboxMailDetailByUid(session, { mailbox = 'INBOX', uid }) {
    const normalizedUid = this._normalizeUid(uid);

    return this._withImapConnection(session, {
      mailbox,
      operation: async (client) => {
        const message = await this._withTimeout(
          client.fetchOne(
            normalizedUid,
            {
              uid: true,
              envelope: true,
              flags: true,
              bodyStructure: true,
              source: true,
              size: true,
              internalDate: true,
            },
            { uid: true },
          ),
          'IMAP fetch detail',
        );

        if (!message) {
          throw new NotFoundError(`Message uid ${normalizedUid} was not found in ${mailbox}`);
        }

        const sourceBuffer = this._toBuffer(message.source);
        const parsed = await this._withTimeout(
          simpleParser(sourceBuffer),
          'MIME parse',
        );

        const from =
          parsed.from?.value?.[0]?.address ||
          parsed.from?.text ||
          this._firstEnvelopeAddress(message.envelope?.from);

        const to =
          parsed.to?.value?.[0]?.address ||
          parsed.to?.text ||
          this._firstEnvelopeAddress(message.envelope?.to);

        const attachments = this._mergeAttachmentMetadata(
          this._extractAttachmentsFromBodyStructure(message.bodyStructure),
          parsed.attachments || [],
        );

        const textBody = (parsed.text || '').trim();
        const htmlBodyRaw = parsed.html;
        const htmlBody = typeof htmlBodyRaw === 'string'
          ? htmlBodyRaw
          : '';

        return {
          uid: Number(message.uid || normalizedUid),
          mailbox,
          subject: parsed.subject || message.envelope?.subject || '(no subject)',
          from: from || 'Unknown sender',
          to: to || 'Unknown recipient',
          date: this._toIsoString(parsed.date || message.internalDate || message.envelope?.date),
          messageId: parsed.messageId || message.envelope?.messageId || null,
          flags: this._normalizeFlags(message.flags),
          snippet: this._snippet(textBody || htmlBody),
          textBody,
          htmlBody,
          attachments,
          rawSize: sourceBuffer.length,
        };
      },
    });
  }

  async setMailboxMailSeenByUid(session, { mailbox = 'INBOX', uid, read }) {
    const normalizedUid = this._normalizeUid(uid);
    const shouldRead = Boolean(read);

    await this._withImapConnection(session, {
      mailbox,
      operation: async (client) => {
        if (shouldRead) {
          await this._withTimeout(
            client.messageFlagsAdd(normalizedUid, ['\\Seen'], { uid: true }),
            'IMAP mark seen',
          );
        } else {
          await this._withTimeout(
            client.messageFlagsRemove(normalizedUid, ['\\Seen'], { uid: true }),
            'IMAP mark unseen',
          );
        }
      },
    });

    return {
      mailbox,
      uid: normalizedUid,
      read: shouldRead,
    };
  }

  async setMailboxMailFlaggedByUid(session, { mailbox = 'INBOX', uid, flagged }) {
    const normalizedUid = this._normalizeUid(uid);
    const shouldFlag = Boolean(flagged);

    await this._withImapConnection(session, {
      mailbox,
      operation: async (client) => {
        if (shouldFlag) {
          await this._withTimeout(
            client.messageFlagsAdd(normalizedUid, ['\\Flagged'], { uid: true }),
            'IMAP mark flagged',
          );
        } else {
          await this._withTimeout(
            client.messageFlagsRemove(normalizedUid, ['\\Flagged'], { uid: true }),
            'IMAP clear flagged',
          );
        }
      },
    });

    return {
      mailbox,
      uid: normalizedUid,
      flagged: shouldFlag,
    };
  }

  async moveMailboxMailByUid(session, { fromMailbox, toMailbox, uid }) {
    const normalizedUid = this._normalizeUid(uid);
    if (!fromMailbox || !toMailbox) {
      throw new ApiError(400, 'fromMailbox and toMailbox are required');
    }

    return this._withImapConnection(session, {
      mailbox: fromMailbox,
      operation: async (client) => {
        const supportsMove = this._supportsMoveCapability(client);

        if (supportsMove) {
          try {
            await this._withTimeout(
              client.messageMove(normalizedUid, toMailbox, { uid: true }),
              'IMAP move',
            );
            return {
              fromMailbox,
              toMailbox,
              uid: normalizedUid,
              method: 'MOVE',
            };
          } catch {
            // Fall through to COPY + DELETE.
          }
        }

        await this._withTimeout(
          client.messageCopy(normalizedUid, toMailbox, { uid: true }),
          'IMAP copy fallback',
        );
        await this._withTimeout(
          client.messageDelete(normalizedUid, { uid: true }),
          'IMAP delete fallback',
        );

        return {
          fromMailbox,
          toMailbox,
          uid: normalizedUid,
          method: 'COPY_DELETE',
        };
      },
    });
  }

  async deleteMailboxMailByUid(session, { mailbox = 'INBOX', uid }) {
    const normalizedUid = this._normalizeUid(uid);

    await this._withImapConnection(session, {
      mailbox,
      operation: async (client) => {
        await this._withTimeout(
          client.messageDelete(normalizedUid, { uid: true }),
          'IMAP delete',
        );
      },
    });

    return {
      mailbox,
      uid: normalizedUid,
      deleted: true,
    };
  }

  async listImapMailboxes(session) {
    const names = await this._withImapConnection(session, {
      operation: async (client) => {
        const listed = await this._withTimeout(client.list(), 'IMAP list mailboxes');
        return (listed || [])
          .map((entry) => entry?.path)
          .filter((name) => typeof name === 'string' && name.trim());
      },
    });

    return {
      mailboxes: names,
    };
  }

  async createImapMailbox(session, name) {
    const normalizedName = String(name || '').trim();
    if (!normalizedName) {
      throw new ApiError(400, 'Mailbox name is required');
    }

    await this._withImapConnection(session, {
      operation: async (client) => {
        await this._withTimeout(
          client.mailboxCreate(normalizedName),
          'IMAP create mailbox',
        );
      },
    });

    return {
      mailbox: normalizedName,
      created: true,
    };
  }

  async appendToMailbox(session, { mailbox, rawMessage }) {
    const normalizedMailbox = String(mailbox || '').trim();
    if (!normalizedMailbox) {
      throw new ApiError(400, 'Mailbox is required for APPEND');
    }

    const payload = Buffer.isBuffer(rawMessage)
      ? rawMessage
      : Buffer.from(String(rawMessage || ''), 'utf8');

    await this._withImapConnection(session, {
      mailbox: normalizedMailbox,
      operation: async (client) => {
        await this._withTimeout(
          client.append(normalizedMailbox, payload),
          'IMAP append',
        );
      },
    });

    return {
      mailbox: normalizedMailbox,
      size: payload.length,
      appended: true,
    };
  }

  async downloadAttachmentByPart(
    session,
    {
      mailbox = 'INBOX',
      uid,
      partId,
      maxBytes,
    },
  ) {
    const normalizedUid = this._normalizeUid(uid);
    const normalizedPart = String(partId || '').trim();
    if (!normalizedPart) {
      throw new ApiError(400, 'part is required for direct attachment download');
    }

    return this._withImapConnection(session, {
      mailbox,
      operation: async (client) => {
        const head = await this._withTimeout(
          client.fetchOne(
            normalizedUid,
            {
              uid: true,
              bodyStructure: true,
            },
            { uid: true },
          ),
          'IMAP attachment head fetch',
        );

        if (!head) {
          throw new NotFoundError(`Message uid ${normalizedUid} was not found in ${mailbox}`);
        }

        const attachmentMeta = this
          ._extractAttachmentsFromBodyStructure(head.bodyStructure)
          .find((item) => item.partId === normalizedPart);

        if (attachmentMeta?.size && Number.isFinite(maxBytes) && attachmentMeta.size > maxBytes) {
          throw new TooLargePreviewError(attachmentMeta.size, maxBytes);
        }

        const downloaded = await this._withTimeout(
          client.download(normalizedUid, normalizedPart, { uid: true }),
          'IMAP part download',
        );

        if (!downloaded || !downloaded.content) {
          throw new NotFoundError(`Attachment part ${normalizedPart} was not found`);
        }

        const buffer = await this._streamToBuffer(downloaded.content, maxBytes);

        const contentType =
          attachmentMeta?.type ||
          downloaded?.meta?.contentType ||
          'application/octet-stream';

        const filename =
          attachmentMeta?.filename ||
          downloaded?.meta?.filename ||
          `part-${normalizedPart}`;

        return {
          source: 'direct',
          partId: normalizedPart,
          filename,
          contentType,
          size: buffer.length,
          buffer,
        };
      },
    });
  }

  async downloadAttachmentFromRaw(
    session,
    {
      mailbox = 'INBOX',
      uid,
      index,
      name,
      partId,
      maxBytes,
    },
  ) {
    const normalizedUid = this._normalizeUid(uid);

    return this._withImapConnection(session, {
      mailbox,
      operation: async (client) => {
        const message = await this._withTimeout(
          client.fetchOne(
            normalizedUid,
            {
              uid: true,
              bodyStructure: true,
              source: true,
            },
            { uid: true },
          ),
          'IMAP full source fetch',
        );

        if (!message) {
          throw new NotFoundError(`Message uid ${normalizedUid} was not found in ${mailbox}`);
        }

        const structureAttachments = this._extractAttachmentsFromBodyStructure(
          message.bodyStructure,
        );

        const sourceBuffer = this._toBuffer(message.source);
        const parsed = await this._withTimeout(
          simpleParser(sourceBuffer),
          'MIME parse for attachment fallback',
        );

        const parsedAttachments = parsed.attachments || [];
        if (!parsedAttachments.length) {
          throw new NotFoundError('No attachments were found in this message');
        }

        const selected = this._pickParsedAttachment({
          parsedAttachments,
          structureAttachments,
          index,
          name,
          partId,
        });

        if (!selected) {
          throw new NotFoundError('Requested attachment could not be found');
        }

        const buffer = Buffer.from(selected.attachment.content || Buffer.alloc(0));
        if (Number.isFinite(maxBytes) && buffer.length > maxBytes) {
          throw new TooLargePreviewError(buffer.length, maxBytes);
        }

        return {
          source: 'fallback',
          partId: selected.partId || String(partId || ''),
          filename:
            selected.attachment.filename ||
            selected.meta?.filename ||
            String(name || 'attachment.bin'),
          contentType:
            selected.attachment.contentType ||
            selected.meta?.type ||
            'application/octet-stream',
          size: buffer.length,
          buffer,
        };
      },
    });
  }

  _pickParsedAttachment({
    parsedAttachments,
    structureAttachments,
    index,
    name,
    partId,
  }) {
    const normalizedName = String(name || '').trim().toLowerCase();
    const normalizedPart = String(partId || '').trim();
    const asIndex = Number.isFinite(Number(index)) ? Number(index) : null;

    if (asIndex != null && asIndex >= 0 && asIndex < parsedAttachments.length) {
      return {
        attachment: parsedAttachments[asIndex],
        meta: structureAttachments[asIndex] || null,
        partId: structureAttachments[asIndex]?.partId || null,
      };
    }

    if (normalizedPart) {
      const matchedMeta = structureAttachments.find((item) => item.partId === normalizedPart);
      if (matchedMeta) {
        const byName = parsedAttachments.find((item) => {
          const file = String(item.filename || '').trim().toLowerCase();
          return file && file === String(matchedMeta.filename || '').trim().toLowerCase();
        });

        if (byName) {
          return {
            attachment: byName,
            meta: matchedMeta,
            partId: matchedMeta.partId,
          };
        }
      }
    }

    if (normalizedName) {
      const byName = parsedAttachments.find((item) => {
        const file = String(item.filename || '').trim().toLowerCase();
        return file && file === normalizedName;
      });

      if (byName) {
        const meta = structureAttachments.find(
          (item) => String(item.filename || '').trim().toLowerCase() === normalizedName,
        );
        return {
          attachment: byName,
          meta: meta || null,
          partId: meta?.partId || null,
        };
      }
    }

    const first = parsedAttachments[0];
    if (!first) {
      return null;
    }

    return {
      attachment: first,
      meta: structureAttachments[0] || null,
      partId: structureAttachments[0]?.partId || null,
    };
  }

  _serializeHeader(mailbox, message) {
    const attachments = this._extractAttachmentsFromBodyStructure(message.bodyStructure);

    return {
      uid: Number(message.uid),
      mailbox,
      subject: message.envelope?.subject || '(no subject)',
      from: this._firstEnvelopeAddress(message.envelope?.from) || 'Unknown sender',
      to: this._firstEnvelopeAddress(message.envelope?.to) || 'Unknown recipient',
      date: this._toIsoString(message.internalDate || message.envelope?.date),
      messageId: message.envelope?.messageId || null,
      flags: this._normalizeFlags(message.flags),
      snippet: '',
      size: Number(message.size || 0),
      attachments,
    };
  }

  _mergeAttachmentMetadata(structureAttachments, parsedAttachments) {
    if (!parsedAttachments.length) {
      return structureAttachments;
    }

    const merged = [...structureAttachments];
    for (const attachment of parsedAttachments) {
      const filename = String(attachment.filename || '').trim();
      const loweredFilename = filename.toLowerCase();
      const size = Number(attachment.size || attachment.content?.length || 0);

      const index = merged.findIndex((candidate) => {
        const sameName = String(candidate.filename || '').trim().toLowerCase() === loweredFilename;
        const sameSize = Number(candidate.size || 0) === size;
        return sameName || (sameSize && loweredFilename);
      });

      if (index >= 0) {
        const current = merged[index];
        merged[index] = {
          ...current,
          filename: current.filename || filename || `part-${current.partId || index + 1}`,
          type: current.type || attachment.contentType || 'application/octet-stream',
          size: current.size || size,
          contentId: attachment.cid || null,
        };
        continue;
      }

      merged.push({
        index: merged.length,
        partId: '',
        filename: filename || `attachment-${merged.length + 1}`,
        type: attachment.contentType || 'application/octet-stream',
        size,
        contentId: attachment.cid || null,
      });
    }

    return merged.map((item, index) => ({
      ...item,
      index,
    }));
  }

  _extractAttachmentsFromBodyStructure(bodyStructure) {
    const attachments = [];

    const walk = (node) => {
      if (!node || typeof node !== 'object') {
        return;
      }

      if (Array.isArray(node)) {
        for (const child of node) {
          walk(child);
        }
        return;
      }

      const children = Array.isArray(node.childNodes) ? node.childNodes : [];
      if (children.length > 0) {
        for (const child of children) {
          walk(child);
        }
        return;
      }

      const params = this._normalizeKeyMap(node.parameters);
      const dispParams = this._normalizeKeyMap(node.dispositionParameters);
      const filename =
        params.name ||
        params.filename ||
        dispParams.filename ||
        dispParams.name ||
        null;

      const disposition = String(node.disposition || '').toLowerCase();
      const markAsAttachment =
        Boolean(filename) || disposition === 'attachment' || disposition === 'inline';

      if (!markAsAttachment) {
        return;
      }

      const partId = String(node.part || node.partId || node.id || attachments.length + 1);
      const type = this._contentTypeFromBodyNode(node);
      const size = Number(node.size || 0);

      attachments.push({
        index: attachments.length,
        partId,
        filename: filename || `part-${partId}`,
        type,
        size: Number.isFinite(size) ? Math.max(size, 0) : 0,
      });
    };

    walk(bodyStructure);
    return attachments;
  }

  _contentTypeFromBodyNode(node) {
    const rawType = String(node.type || '').toLowerCase();
    if (rawType.includes('/')) {
      return rawType;
    }

    const type = String(node.type || node.mainType || 'application').toLowerCase();
    const subtype = String(node.subtype || node.subType || 'octet-stream').toLowerCase();
    return `${type}/${subtype}`;
  }

  _normalizeKeyMap(value) {
    if (!value || typeof value !== 'object') {
      return {};
    }

    const out = {};
    for (const [key, mapValue] of Object.entries(value)) {
      out[String(key || '').trim().toLowerCase()] = String(mapValue || '').trim();
    }
    return out;
  }

  _firstEnvelopeAddress(envelopeValue) {
    if (!Array.isArray(envelopeValue) || !envelopeValue.length) {
      return null;
    }

    const first = envelopeValue[0];
    if (!first || typeof first !== 'object') {
      return null;
    }

    if (typeof first.address === 'string' && first.address.trim()) {
      return first.address;
    }

    if (typeof first.mailbox === 'string' && typeof first.host === 'string') {
      if (first.mailbox && first.host) {
        return `${first.mailbox}@${first.host}`;
      }
    }

    return null;
  }

  _snippet(value) {
    const normalized = String(value || '').replace(/\s+/g, ' ').trim();
    if (!normalized) {
      return '';
    }
    return normalized.length > 180 ? `${normalized.slice(0, 177)}...` : normalized;
  }

  _normalizeFlags(flags) {
    if (!flags) {
      return [];
    }
    if (Array.isArray(flags)) {
      return flags.map((item) => String(item));
    }
    if (flags instanceof Set) {
      return Array.from(flags, (item) => String(item));
    }
    return [];
  }

  _toIsoString(value) {
    if (!value) {
      return null;
    }

    if (value instanceof Date) {
      return value.toISOString();
    }

    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return null;
    }
    return parsed.toISOString();
  }

  _normalizeUid(uid) {
    const parsed = Number.parseInt(String(uid || ''), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      throw new ApiError(400, 'uid must be a positive integer');
    }
    return parsed;
  }

  _normalizeLimit(limit) {
    const parsed = Number.parseInt(String(limit || ''), 10);
    if (!Number.isFinite(parsed) || parsed <= 0) {
      return 30;
    }
    return Math.min(parsed, 100);
  }

  _normalizeOffset(offset) {
    const parsed = Number.parseInt(String(offset || ''), 10);
    if (!Number.isFinite(parsed) || parsed < 0) {
      return 0;
    }
    return parsed;
  }

  _assertImapConfigured() {
    if (!this.config.host || !this.config.port) {
      throw new ApiError(503, 'IMAP is not configured on this server');
    }
  }

  _assertSessionHasImapCredentials(session, authPasswordOverride = null) {
    if (!session || !session.email) {
      throw new UnauthorizedError('Session is missing user email');
    }

    const password = authPasswordOverride || session.imapPassword;
    if (!password) {
      throw new UnauthorizedError('Session does not contain IMAP credentials');
    }
  }

  _imapClientOptions(session, authPasswordOverride = null) {
    return {
      host: this.config.host,
      port: this.config.port,
      secure: this.config.secure,
      auth: {
        user: session.email,
        pass: authPasswordOverride || session.imapPassword,
      },
      tls: {
        rejectUnauthorized: this.config.rejectUnauthorized,
      },
      // We create short-lived request/response connections, so disable automatic
      // idle handling to avoid late queued commands after the socket is gone.
      disableAutoIdle: true,
      logger: false,
    };
  }

  async _withImapConnection(
    session,
    {
      mailbox,
      operation,
      authPasswordOverride = null,
      maxAttempts = 2,
    },
  ) {
    this._assertImapConfigured();
    this._assertSessionHasImapCredentials(session, authPasswordOverride);

    let attempt = 0;
    let lastError;

    while (attempt < maxAttempts) {
      attempt += 1;
      const client = new ImapFlow(this._imapClientOptions(session, authPasswordOverride));
      let lock = null;
      let emittedError = null;
      const absorbLateClientErrors = () => {};
      const onClientError = (error) => {
        emittedError = emittedError || error || new Error('IMAP connection emitted an unknown error');
      };
      // Keep a passive error listener attached for the lifetime of the client
      // to prevent uncaught 'error' crashes from late internal events.
      client.on('error', absorbLateClientErrors);
      client.on('error', onClientError);

      try {
        await this._withTimeout(client.connect(), 'IMAP connect');

        if (mailbox) {
          lock = await this._withTimeout(
            client.getMailboxLock(mailbox),
            'IMAP mailbox lock',
          );
        }

        const result = await this._withTimeout(
          operation(client),
          'IMAP operation',
        );

        if (lock) {
          lock.release();
          lock = null;
        }

        await this._safeLogout(client);
        return result;
      } catch (error) {
        if (lock) {
          try {
            lock.release();
          } catch {
            // ignore lock release errors
          }
        }

        await this._safeLogout(client);
        const effectiveError = error || emittedError;
        lastError = effectiveError;

        if (attempt >= maxAttempts || !this._isRetryableImapError(effectiveError)) {
          throw this._normalizeImapError(effectiveError);
        }
      } finally {
        client.removeListener('error', onClientError);
      }
    }

    throw this._normalizeImapError(lastError);
  }

  async _safeLogout(client) {
    if (!client) {
      return;
    }

    try {
      await client.logout();
    } catch {
      try {
        client.close();
      } catch {
        // ignore connection close errors
      }
    }
  }

  _supportsMoveCapability(client) {
    const capabilities = client?.capabilities;
    if (!capabilities) {
      return false;
    }

    if (capabilities instanceof Set) {
      return capabilities.has('MOVE');
    }

    return String(capabilities).toUpperCase().includes('MOVE');
  }

  _isRetryableImapError(error) {
    if (!error) {
      return false;
    }

    if (error.authenticationFailed) {
      return false;
    }

    if (error instanceof ApiError && error.statusCode < 500) {
      return false;
    }

    const code = String(error.code || '').toUpperCase();
    if (RETRYABLE_NETWORK_CODES.has(code) || code === 'NOCONNECTION') {
      return true;
    }

    const message = String(error.message || '').toLowerCase();
    return (
      message.includes('timeout') ||
      message.includes('connection closed') ||
      message.includes('connection not available') ||
      message.includes('socket')
    );
  }

  _normalizeImapError(error) {
    if (error instanceof ApiError) {
      return error;
    }

    if (error?.authenticationFailed) {
      return new UnauthorizedError('Invalid IMAP credentials');
    }

    const message = String(error?.message || 'IMAP operation failed');
    const lowered = message.toLowerCase();

    if (lowered.includes('auth') || lowered.includes('login')) {
      return new UnauthorizedError('Invalid IMAP credentials');
    }

    if (lowered.includes('timeout')) {
      return new ApiError(504, 'IMAP request timed out');
    }

    return new ApiError(502, message || 'IMAP backend error');
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
      const result = await Promise.race([promise, timeoutPromise]);
      return result;
    } finally {
      clearTimeout(timeoutHandle);
    }
  }

  _toBuffer(source) {
    if (!source) {
      return Buffer.alloc(0);
    }
    if (Buffer.isBuffer(source)) {
      return source;
    }
    if (source instanceof Uint8Array) {
      return Buffer.from(source);
    }
    if (typeof source === 'string') {
      return Buffer.from(source, 'utf8');
    }
    return Buffer.from(String(source));
  }

  async _streamToBuffer(stream, maxBytes) {
    if (!isReadableStream(stream)) {
      return this._toBuffer(stream);
    }

    const chunks = [];
    let size = 0;

    return new Promise((resolve, reject) => {
      let settled = false;

      const onData = (chunk) => {
        if (settled) {
          return;
        }
        const buffer = Buffer.from(chunk);
        size += buffer.length;
        if (Number.isFinite(maxBytes) && size > maxBytes) {
          settled = true;
          cleanup();
          reject(new TooLargePreviewError(size, maxBytes));
          try {
            stream.destroy();
          } catch {
            // ignore stream destroy errors
          }
          return;
        }
        chunks.push(buffer);
      };

      const onError = (error) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(this._normalizeImapError(error));
      };

      const onEnd = () => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        resolve(Buffer.concat(chunks));
      };

      const cleanup = () => {
        stream.removeListener('data', onData);
        stream.removeListener('error', onError);
        stream.removeListener('end', onEnd);
      };

      // Keep one no-op error handler attached so any late error events from
      // imapflow internals do not terminate the process.
      stream.on('error', () => {});

      stream.on('data', onData);
      stream.on('error', onError);
      stream.on('end', onEnd);
    });
  }
}

export const attachmentPreviewLimitBytes = PREVIEW_LIMIT_BYTES;

