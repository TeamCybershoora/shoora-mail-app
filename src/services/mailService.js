import { ImapFlow } from 'imapflow';
import { simpleParser } from 'mailparser';

import { ApiError, NotFoundError } from '../utils/errors.js';

function firstAddress(addresses) {
  if (!Array.isArray(addresses) || !addresses.length) {
    return null;
  }
  const first = addresses[0];
  if (!first) {
    return null;
  }
  if (typeof first.address === 'string' && first.address.trim()) {
    return first.address.trim();
  }
  if (first.mailbox && first.host) {
    return `${first.mailbox}@${first.host}`;
  }
  return null;
}

function normalizeFlags(flags) {
  if (flags instanceof Set) {
    return Array.from(flags, (item) => String(item));
  }
  if (Array.isArray(flags)) {
    return flags.map((item) => String(item));
  }
  return [];
}

function normalizePartHeaders(headers) {
  if (!headers) {
    return {};
  }
  const out = {};
  for (const [key, value] of Object.entries(headers)) {
    out[String(key).toLowerCase()] = value;
  }
  return out;
}

export class MailService {
  constructor({ accountService, gmailConfig, commandTimeoutMs }) {
    this.accountService = accountService;
    this.gmailConfig = gmailConfig;
    this.commandTimeoutMs = commandTimeoutMs;
  }

  async listMailboxes({ userId, accountId }) {
    const account = await this.accountService.resolveAccountForUser({ userId, accountId });
    const authContext = await this.accountService.getAccountAuth(account);

    return this._withClient(authContext, async (client) => {
      const listed = await client.list();
      return listed
        .map((item) => item.path)
        .filter((item) => typeof item === 'string' && item.trim());
    });
  }

  async fetchMailboxHeaders({ userId, accountId, mailbox = 'INBOX', limit = 30, offset = 0 }) {
    const account = await this.accountService.resolveAccountForUser({ userId, accountId });
    const authContext = await this.accountService.getAccountAuth(account);

    return this._withClient(authContext, async (client) => {
      const lock = await client.getMailboxLock(mailbox);
      try {
        const total = Number(client.mailbox?.exists || 0);
        if (total <= 0 || offset >= total) {
          return {
            mailbox,
            total,
            hasMore: false,
            nextOffset: offset,
            headers: [],
          };
        }

        const safeLimit = Math.max(1, Math.min(100, Number(limit || 30)));
        const safeOffset = Math.max(0, Number(offset || 0));
        const seqEnd = total - safeOffset;
        const seqStart = Math.max(1, seqEnd - safeLimit + 1);

        const headers = [];
        for await (const message of client.fetch(`${seqStart}:${seqEnd}`, {
          uid: true,
          envelope: true,
          flags: true,
          bodyStructure: true,
          internalDate: true,
          size: true,
        })) {
          headers.push({
            uid: Number(message.uid),
            mailbox,
            subject: message.envelope?.subject || '(no subject)',
            from: firstAddress(message.envelope?.from) || 'Unknown sender',
            to: firstAddress(message.envelope?.to) || 'Unknown recipient',
            date: (message.internalDate || message.envelope?.date || null)
              ? new Date(message.internalDate || message.envelope?.date).toISOString()
              : null,
            messageId: message.envelope?.messageId || null,
            flags: normalizeFlags(message.flags),
            snippet: '',
            size: Number(message.size || 0),
            threadId: this._deriveThreadId({
              messageId: message.envelope?.messageId,
              references: null,
              inReplyTo: null,
              subject: message.envelope?.subject || '',
            }),
            attachments: this._extractAttachmentsFromBodyStructure(message.bodyStructure),
          });
        }

        headers.sort((left, right) => right.uid - left.uid);
        const nextOffset = Math.min(total, safeOffset + headers.length);

        return {
          mailbox,
          total,
          hasMore: nextOffset < total,
          nextOffset,
          headers,
        };
      } finally {
        lock.release();
      }
    });
  }

  async fetchMessageDetail({ userId, accountId, mailbox = 'INBOX', uid }) {
    const account = await this.accountService.resolveAccountForUser({ userId, accountId });
    const authContext = await this.accountService.getAccountAuth(account);

    return this._withClient(authContext, async (client) => {
      const lock = await client.getMailboxLock(mailbox);
      try {
        const message = await client.fetchOne(
          Number(uid),
          {
            uid: true,
            envelope: true,
            flags: true,
            bodyStructure: true,
            source: true,
            internalDate: true,
            size: true,
          },
          { uid: true },
        );

        if (!message) {
          throw new NotFoundError(`Message ${uid} was not found in ${mailbox}`);
        }

        const source = Buffer.isBuffer(message.source)
          ? message.source
          : Buffer.from(message.source || '');
        const parsed = await simpleParser(source);

        const messageId = parsed.messageId || message.envelope?.messageId || null;
        const references = Array.isArray(parsed.references) ? parsed.references.join(' ') : null;
        const inReplyTo = parsed.inReplyTo || null;

        return {
          uid: Number(message.uid),
          mailbox,
          subject: parsed.subject || message.envelope?.subject || '(no subject)',
          from:
            parsed.from?.value?.[0]?.address ||
            parsed.from?.text ||
            firstAddress(message.envelope?.from) ||
            'Unknown sender',
          to:
            parsed.to?.value?.[0]?.address ||
            parsed.to?.text ||
            firstAddress(message.envelope?.to) ||
            'Unknown recipient',
          date: (parsed.date || message.internalDate || message.envelope?.date || null)
            ? new Date(parsed.date || message.internalDate || message.envelope?.date).toISOString()
            : null,
          messageId,
          flags: normalizeFlags(message.flags),
          snippet: this._snippet(parsed.text || parsed.html || ''),
          textBody: parsed.text || '',
          htmlBody: typeof parsed.html === 'string' ? parsed.html : '',
          rawSize: source.length,
          threadId: this._deriveThreadId({
            messageId,
            references,
            inReplyTo,
            subject: parsed.subject || message.envelope?.subject || '',
          }),
          attachments: this._mergeAttachments(
            this._extractAttachmentsFromBodyStructure(message.bodyStructure),
            parsed.attachments || [],
          ),
        };
      } finally {
        lock.release();
      }
    });
  }

  async fetchAttachment({
    userId,
    accountId,
    mailbox = 'INBOX',
    uid,
    partId,
    index = null,
    fileName = '',
  }) {
    const account = await this.accountService.resolveAccountForUser({ userId, accountId });
    const authContext = await this.accountService.getAccountAuth(account);

    return this._withClient(authContext, async (client) => {
      const lock = await client.getMailboxLock(mailbox);
      try {
        if (partId) {
          const downloaded = await client.download(Number(uid), String(partId), { uid: true });
          if (!downloaded?.content) {
            throw new NotFoundError('Attachment not found');
          }
          const buffer = await this._streamToBuffer(downloaded.content);
          const headers = normalizePartHeaders(downloaded.meta || {});
          return {
            buffer,
            contentType: headers['content-type'] || 'application/octet-stream',
            filename: fileName || headers.filename || `part-${partId}`,
          };
        }

        const sourceMessage = await client.fetchOne(
          Number(uid),
          { uid: true, source: true, bodyStructure: true },
          { uid: true },
        );
        if (!sourceMessage) {
          throw new NotFoundError('Message not found');
        }

        const parsed = await simpleParser(Buffer.from(sourceMessage.source || ''));
        const attachments = parsed.attachments || [];
        let selected = null;

        if (Number.isInteger(index) && Number(index) >= 0 && Number(index) < attachments.length) {
          selected = attachments[Number(index)];
        }

        if (!selected && fileName) {
          selected = attachments.find((item) => String(item.filename || '').trim() === String(fileName).trim()) || null;
        }

        if (!selected) {
          selected = attachments[0] || null;
        }

        if (!selected) {
          throw new NotFoundError('Attachment not found');
        }

        return {
          buffer: Buffer.from(selected.content || Buffer.alloc(0)),
          contentType: selected.contentType || 'application/octet-stream',
          filename: selected.filename || fileName || 'attachment.bin',
        };
      } finally {
        lock.release();
      }
    });
  }

  async setRead({ userId, accountId, mailbox = 'INBOX', uid, read }) {
    return this._setFlag({
      userId,
      accountId,
      mailbox,
      uid,
      flag: '\\Seen',
      value: Boolean(read),
    });
  }

  async setStarred({ userId, accountId, mailbox = 'INBOX', uid, starred }) {
    return this._setFlag({
      userId,
      accountId,
      mailbox,
      uid,
      flag: '\\Flagged',
      value: Boolean(starred),
    });
  }

  async moveMessage({ userId, accountId, fromMailbox, toMailbox, uid }) {
    const account = await this.accountService.resolveAccountForUser({ userId, accountId });
    const authContext = await this.accountService.getAccountAuth(account);

    return this._withClient(authContext, async (client) => {
      const lock = await client.getMailboxLock(fromMailbox);
      try {
        const capabilities = client.capabilities instanceof Set
          ? client.capabilities
          : new Set(String(client.capabilities || '').split(' ').filter(Boolean));

        if (capabilities.has('MOVE')) {
          await client.messageMove(Number(uid), toMailbox, { uid: true });
          return { fromMailbox, toMailbox, uid: Number(uid), method: 'MOVE' };
        }

        await client.messageCopy(Number(uid), toMailbox, { uid: true });
        await client.messageDelete(Number(uid), { uid: true });
        return { fromMailbox, toMailbox, uid: Number(uid), method: 'COPY_DELETE' };
      } finally {
        lock.release();
      }
    });
  }

  async deleteMessage({ userId, accountId, mailbox = 'INBOX', uid }) {
    const account = await this.accountService.resolveAccountForUser({ userId, accountId });
    const authContext = await this.accountService.getAccountAuth(account);

    return this._withClient(authContext, async (client) => {
      const lock = await client.getMailboxLock(mailbox);
      try {
        await client.messageDelete(Number(uid), { uid: true });
        return { mailbox, uid: Number(uid), deleted: true };
      } finally {
        lock.release();
      }
    });
  }

  async searchHeaders({ userId, accountId, mailbox = 'INBOX', query, limit = 50, offset = 0 }) {
    const page = await this.fetchMailboxHeaders({
      userId,
      accountId,
      mailbox,
      limit: 100,
      offset: 0,
    });

    const normalized = String(query || '').trim().toLowerCase();
    if (!normalized) {
      return page;
    }

    const filtered = page.headers.filter((item) => {
      const haystack = [
        item.subject,
        item.from,
        item.to,
        item.messageId,
      ]
        .join(' ')
        .toLowerCase();
      return haystack.includes(normalized);
    });

    const safeOffset = Math.max(0, Number(offset || 0));
    const safeLimit = Math.max(1, Math.min(100, Number(limit || 50)));
    const sliced = filtered.slice(safeOffset, safeOffset + safeLimit);

    return {
      mailbox,
      total: filtered.length,
      hasMore: safeOffset + sliced.length < filtered.length,
      nextOffset: safeOffset + sliced.length,
      headers: sliced,
    };
  }

  async fetchLatestMessageMeta({ accountId }) {
    const account = await this.accountService.resolveAccountForUser({ userId: null, accountId });
    const authContext = await this.accountService.getAccountAuth(account);

    return this._withClient(authContext, async (client) => {
      const lock = await client.getMailboxLock('INBOX');
      try {
        const total = Number(client.mailbox?.exists || 0);
        if (total <= 0) {
          return null;
        }

        let latest = null;
        for await (const message of client.fetch(`${total}:${total}`, {
          uid: true,
          envelope: true,
          flags: true,
          internalDate: true,
        })) {
          latest = message;
        }

        if (!latest) {
          return null;
        }

        const messageId = latest.envelope?.messageId || null;
        return {
          mailbox: 'INBOX',
          uid: Number(latest.uid),
          messageId,
          threadId: this._deriveThreadId({
            messageId,
            references: null,
            inReplyTo: null,
            subject: latest.envelope?.subject || '',
          }),
          date: (latest.internalDate || latest.envelope?.date || null)
            ? new Date(latest.internalDate || latest.envelope?.date).toISOString()
            : null,
        };
      } finally {
        lock.release();
      }
    });
  }

  async _withClient(authContext, operation) {
    const account = authContext?.account;
    if (!account) {
      throw new ApiError(404, 'Mail account not found', { code: 'ACCOUNT_NOT_FOUND' });
    }

    const auth = this._imapAuth(authContext);
    const hostCandidates = this._hostCandidates(authContext);
    let lastError = null;

    for (const host of hostCandidates) {
      const client = new ImapFlow({
        host,
        port: this.gmailConfig.imapPort,
        secure: this.gmailConfig.imapSecure,
        logger: false,
        auth,
        tls: {
          rejectUnauthorized: this.gmailConfig.imapRejectUnauthorized !== false,
        },
        disableAutoIdle: true,
        socketTimeout: this.commandTimeoutMs,
        commandTimeout: this.commandTimeoutMs,
      });

      try {
        await client.connect();
        return await operation(client);
      } catch (error) {
        lastError = error;
      } finally {
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
    }

    const message = String(lastError?.message || '').toLowerCase();
    if (message.includes('auth') || message.includes('invalid credentials') || message.includes('login')) {
      throw new ApiError(401, 'Mail authorization failed', { code: 'MAIL_AUTH_FAILED' });
    }
    throw new ApiError(502, lastError?.message || 'IMAP request failed', {
      code: 'IMAP_FAILED',
    });
  }

  async _setFlag({ userId, accountId, mailbox, uid, flag, value }) {
    const account = await this.accountService.resolveAccountForUser({ userId, accountId });
    const authContext = await this.accountService.getAccountAuth(account);

    return this._withClient(authContext, async (client) => {
      const lock = await client.getMailboxLock(mailbox);
      try {
        if (value) {
          await client.messageFlagsAdd(Number(uid), [flag], { uid: true });
        } else {
          await client.messageFlagsRemove(Number(uid), [flag], { uid: true });
        }
        return { mailbox, uid: Number(uid), [flag === '\\Seen' ? 'read' : 'starred']: value };
      } finally {
        lock.release();
      }
    });
  }

  _snippet(value) {
    const normalized = String(value || '').replace(/\s+/g, ' ').trim();
    if (!normalized) {
      return '';
    }
    return normalized.length > 180 ? `${normalized.slice(0, 177)}...` : normalized;
  }

  _deriveThreadId({ messageId, references, inReplyTo, subject }) {
    const candidate = String(inReplyTo || '').trim() || String(references || '').split(' ').filter(Boolean).pop() || String(messageId || '').trim();
    if (candidate) {
      return candidate.replace(/[<>]/g, '');
    }
    const normalizedSubject = String(subject || '').trim().toLowerCase().replace(/^re:\s*/i, '');
    return `subject:${normalizedSubject || 'no-subject'}`;
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
      if (children.length) {
        for (const child of children) {
          walk(child);
        }
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
      const asAttachment = Boolean(filename) || disposition === 'attachment' || disposition === 'inline';

      if (!asAttachment) {
        return;
      }

      const partId = String(node.part || node.partId || node.id || attachments.length + 1);
      const type = this._contentTypeFromNode(node);

      attachments.push({
        index: attachments.length,
        partId,
        filename: filename || `part-${partId}`,
        type,
        size: Number(node.size || 0),
      });
    };

    walk(bodyStructure);
    return attachments;
  }

  _mergeAttachments(structureAttachments, parsedAttachments) {
    if (!Array.isArray(parsedAttachments) || !parsedAttachments.length) {
      return structureAttachments;
    }

    const merged = [...structureAttachments];
    for (const attachment of parsedAttachments) {
      const filename = String(attachment.filename || '').trim();
      const lowerName = filename.toLowerCase();
      const size = Number(attachment.size || attachment.content?.length || 0);

      const index = merged.findIndex((candidate) => {
        const sameName = String(candidate.filename || '').trim().toLowerCase() === lowerName;
        const sameSize = Number(candidate.size || 0) === size;
        return sameName || (sameSize && lowerName);
      });

      if (index >= 0) {
        merged[index] = {
          ...merged[index],
          filename: merged[index].filename || filename,
          type: merged[index].type || attachment.contentType || 'application/octet-stream',
          size: merged[index].size || size,
        };
        continue;
      }

      merged.push({
        index: merged.length,
        partId: '',
        filename: filename || `attachment-${merged.length + 1}`,
        type: attachment.contentType || 'application/octet-stream',
        size,
      });
    }

    return merged;
  }

  _normalizeKeyMap(value) {
    if (!value || typeof value !== 'object') {
      return {};
    }

    const out = {};
    for (const [key, mapValue] of Object.entries(value)) {
      out[String(key).trim().toLowerCase()] = String(mapValue || '').trim();
    }
    return out;
  }

  _contentTypeFromNode(node) {
    const raw = String(node.type || '').toLowerCase();
    if (raw.includes('/')) {
      return raw;
    }

    const type = String(node.type || node.mainType || 'application').toLowerCase();
    const subtype = String(node.subtype || node.subType || 'octet-stream').toLowerCase();
    return `${type}/${subtype}`;
  }

  async _streamToBuffer(stream) {
    const chunks = [];
    for await (const chunk of stream) {
      chunks.push(Buffer.from(chunk));
    }
    return Buffer.concat(chunks);
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

  _hostCandidates(authContext) {
    const configured = Array.isArray(authContext?.imapHostCandidates)
      ? authContext.imapHostCandidates
      : [];

    const out = [];
    const push = (value) => {
      const normalized = String(value || '').trim();
      if (!normalized || out.includes(normalized)) {
        return;
      }
      out.push(normalized);
    };

    configured.forEach(push);
    push(this.gmailConfig.imapHost);
    return out;
  }
}
