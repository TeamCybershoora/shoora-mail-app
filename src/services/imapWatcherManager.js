import { setTimeout as sleep } from 'node:timers/promises';

import { ImapFlow } from 'imapflow';

import { logger } from '../lib/logger.js';

export class ImapWatcherManager {
  constructor({ accountService, pushService, gmailConfig, watchConfig }) {
    this.accountService = accountService;
    this.pushService = pushService;
    this.gmailConfig = gmailConfig;
    this.watchConfig = watchConfig;
    this.watchers = new Map();
  }

  async startForUserAccount({ userId, accountId }) {
    if (!accountId) {
      return;
    }

    const existing = this.watchers.get(accountId);
    if (existing?.running) {
      return;
    }

    const state = existing || {
      accountId,
      userId,
      running: false,
      stopRequested: false,
      backoffMs: this.watchConfig.baseReconnectDelayMs,
      lastNotifiedUid: null,
      client: null,
      runner: null,
      processingExists: false,
    };

    state.userId = userId;
    state.stopRequested = false;
    state.running = true;
    state.runner = this._runWatcherLoop(state);
    this.watchers.set(accountId, state);
  }

  async stopForAccount(accountId) {
    const state = this.watchers.get(accountId);
    if (!state) {
      return;
    }

    state.stopRequested = true;
    state.running = false;

    if (state.client) {
      try {
        await state.client.logout();
      } catch {
        try {
          state.client.close();
        } catch {
          // ignore
        }
      }
    }

    if (state.runner) {
      try {
        await state.runner;
      } catch {
        // ignore
      }
    }

    this.watchers.delete(accountId);
  }

  async stopForUser(userId) {
    const stops = [];
    for (const [accountId, state] of this.watchers.entries()) {
      if (state.userId === userId) {
        stops.push(this.stopForAccount(accountId));
      }
    }
    await Promise.all(stops);
  }

  async _runWatcherLoop(state) {
    while (!state.stopRequested) {
      try {
        await this._connectAndWatch(state);
      } catch (error) {
        if (this._isFatalAccountAuthError(error)) {
          logger.error('IMAP watcher disabled for account due to non-recoverable auth state', {
            accountId: state.accountId,
            error: error.message,
          });
          state.stopRequested = true;
          break;
        }

        logger.warn('IMAP watcher loop error', {
          accountId: state.accountId,
          error: error.message,
        });
      }

      if (state.stopRequested) {
        break;
      }

      const delay = Math.min(state.backoffMs, this.watchConfig.maxReconnectDelayMs);
      await sleep(delay);
      state.backoffMs = Math.min(delay * 2, this.watchConfig.maxReconnectDelayMs);
    }

    state.running = false;
  }

  async _connectAndWatch(state) {
    const account = await this.accountService.resolveAccountForUser({
      userId: state.userId,
      accountId: state.accountId,
    });

    const authContext = await this.accountService.getAccountAuth(account);
    const auth = this._imapAuth(authContext);
    const client = await this._connectWithFallback(authContext, auth);

    state.client = client;
    state.processingExists = false;

    client.on('error', (error) => {
      logger.warn('IMAP watcher client error', {
        accountId: state.accountId,
        error: error.message,
      });
    });

    await client.mailboxOpen('INBOX');
    state.backoffMs = this.watchConfig.baseReconnectDelayMs;

    let knownCount = Number(client.mailbox?.exists || 0);

    client.on('exists', async (event) => {
      if (state.stopRequested || state.processingExists) {
        return;
      }

      const count = Number(event?.count || 0);
      if (!Number.isFinite(count) || count <= knownCount) {
        knownCount = Math.max(knownCount, count);
        return;
      }

      state.processingExists = true;
      try {
        const latest = await this._fetchLatestMessage(client, count);
        knownCount = count;
        if (!latest) {
          return;
        }

        if (state.lastNotifiedUid === latest.uid) {
          return;
        }

        state.lastNotifiedUid = latest.uid;

        const pushResult = await this.pushService.sendNewMailNotification({
          userId: state.userId,
          accountId: state.accountId,
          mailbox: 'INBOX',
          uid: latest.uid,
          threadId: latest.threadId,
          sender: latest.sender,
          subject: latest.subject,
        });

        if (pushResult.disabled) {
          logger.warn('New mail detected, but push delivery is disabled', {
            accountId: state.accountId,
            uid: latest.uid,
          });
          return;
        }

        logger.info('New mail push attempted', {
          accountId: state.accountId,
          uid: latest.uid,
          delivered: Number(pushResult.delivered || 0),
          failed: Number(pushResult.failed || 0),
          invalidTokensRemoved: Number(pushResult.invalidTokensRemoved || 0),
          failureCodes: pushResult.failureCodes || {},
        });
      } catch (error) {
        logger.warn('Failed handling IMAP exists event', {
          accountId: state.accountId,
          error: error.message,
        });
      } finally {
        state.processingExists = false;
      }
    });

    try {
      while (!state.stopRequested) {
        await client.idle();
      }
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
      state.client = null;
    }
  }

  async _fetchLatestMessage(client, count) {
    let latest = null;
    for await (const message of client.fetch(`${count}:${count}`, {
      uid: true,
      envelope: true,
    })) {
      latest = message;
    }

    if (!latest) {
      return null;
    }

    const messageId = latest.envelope?.messageId || '';
    return {
      uid: Number(latest.uid),
      threadId: this._deriveThreadId(messageId, latest.envelope?.subject || ''),
      sender: this._senderFromEnvelope(latest.envelope?.from),
      subject: String(latest.envelope?.subject || '').trim(),
    };
  }

  _deriveThreadId(messageId, subject) {
    const cleanMessageId = String(messageId || '').replace(/[<>]/g, '').trim();
    if (cleanMessageId) {
      return cleanMessageId;
    }

    const normalizedSubject = String(subject || '').trim().toLowerCase().replace(/^re:\s*/i, '');
    return `subject:${normalizedSubject || 'no-subject'}`;
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

  _senderFromEnvelope(fromList) {
    if (!Array.isArray(fromList) || fromList.length === 0) {
      return '';
    }
    const first = fromList[0];
    if (!first || typeof first !== 'object') {
      return '';
    }

    const name = String(first.name || '').trim();
    if (name) {
      return name;
    }

    const address = String(first.address || '').trim();
    if (address) {
      return address;
    }

    const mailbox = String(first.mailbox || '').trim();
    const host = String(first.host || '').trim();
    if (mailbox && host) {
      return `${mailbox}@${host}`;
    }
    return '';
  }

  async _connectWithFallback(authContext, auth) {
    const hosts = this._hostCandidates(authContext);
    let lastError = null;

    for (const host of hosts) {
      const client = new ImapFlow({
        host,
        port: this.gmailConfig.imapPort,
        secure: this.gmailConfig.imapSecure,
        logger: false,
        auth,
        tls: {
          rejectUnauthorized: this.gmailConfig.imapRejectUnauthorized !== false,
        },
        disableAutoIdle: false,
        socketTimeout: this.watchConfig.commandTimeoutMs,
        commandTimeout: this.watchConfig.commandTimeoutMs,
      });

      try {
        await client.connect();
        return client;
      } catch (error) {
        lastError = error;
        try {
          client.close();
        } catch {
          // ignore
        }
      }
    }

    throw lastError || new Error('IMAP watcher failed to connect');
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

  _isFatalAccountAuthError(error) {
    const message = String(error?.message || '').toLowerCase();
    if (!message) {
      return false;
    }

    return (
      message.includes('could not be decrypted') ||
      message.includes('relink account') ||
      message.includes('sign in again')
    );
  }
}
