import { randomUUID } from 'node:crypto';

import bcrypt from 'bcryptjs';

import { hashValue } from '../lib/crypto.js';

export class UserStore {
  constructor(jsonStore) {
    this.store = jsonStore;
  }

  async ensureDefaultUser({ email, password, passwordHash }) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail) {
      return;
    }

    await this.store.withState(async (state) => {
      const existing = state.users.find((user) => user.email === normalizedEmail);
      if (existing) {
        return state;
      }

      let effectiveHash = String(passwordHash || '').trim();
      if (!effectiveHash) {
        effectiveHash = await bcrypt.hash(String(password || ''), 12);
      }

      state.users.push({
        id: randomUUID(),
        email: normalizedEmail,
        passwordHash: effectiveHash,
        createdAt: new Date().toISOString(),
      });
      return state;
    });
  }

  async findUserByEmail(email) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const state = await this.store.getState();
    return state.users.find((user) => user.email === normalizedEmail) || null;
  }

  async verifyAppUser(email, password) {
    const user = await this.findUserByEmail(email);
    if (!user) {
      return null;
    }

    const valid = await bcrypt.compare(String(password || ''), String(user.passwordHash || ''));
    return valid ? user : null;
  }

  async upsertAppUserCredentials({ email, password }) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail) {
      return null;
    }

    const nextHash = await bcrypt.hash(String(password || ''), 12);
    let upserted = null;

    await this.store.withState((state) => {
      const existing = state.users.find((item) => item.email === normalizedEmail);
      if (existing) {
        existing.passwordHash = nextHash;
        existing.updatedAt = new Date().toISOString();
        upserted = { ...existing };
        return state;
      }

      const created = {
        id: randomUUID(),
        email: normalizedEmail,
        passwordHash: nextHash,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      state.users.push(created);
      upserted = { ...created };
      return state;
    });

    return upserted;
  }

  async upsertGoogleAccount({
    userId,
    providerEmail,
    displayName,
    scopes,
    tokenCipher,
    refreshCipher,
    expiresAt,
    profile,
  }) {
    const normalized = String(providerEmail || '').trim().toLowerCase();

    let upserted = null;
    await this.store.withState((state) => {
      const existing = state.accounts.find(
        (item) => item.userId === userId && item.provider === 'google' && item.providerEmail === normalized,
      );

      if (existing) {
        existing.displayName = displayName || existing.displayName || normalized;
        existing.scopes = Array.isArray(scopes) ? scopes : [];
        existing.tokenCipher = tokenCipher;
        existing.refreshCipher = refreshCipher;
        existing.expiresAt = expiresAt;
        existing.profile = profile || null;
        existing.updatedAt = new Date().toISOString();
        upserted = { ...existing };
        return state;
      }

      const created = {
        id: randomUUID(),
        userId,
        provider: 'google',
        providerEmail: normalized,
        displayName: displayName || normalized,
        scopes: Array.isArray(scopes) ? scopes : [],
        tokenCipher,
        refreshCipher,
        expiresAt,
        profile: profile || null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      state.accounts.push(created);
      upserted = { ...created };
      return state;
    });

    return upserted;
  }

  async upsertStackmailAccount({
    userId,
    providerEmail,
    displayName,
    secretCipher,
  }) {
    const normalized = String(providerEmail || '').trim().toLowerCase();
    let upserted = null;

    await this.store.withState((state) => {
      const existing = state.accounts.find(
        (item) =>
          item.userId === userId &&
          item.provider === 'stackmail' &&
          item.providerEmail === normalized,
      );

      if (existing) {
        existing.displayName = displayName || existing.displayName || normalized;
        existing.secretCipher = secretCipher;
        existing.scopes = [];
        existing.tokenCipher = null;
        existing.refreshCipher = null;
        existing.expiresAt = 0;
        existing.profile = null;
        existing.updatedAt = new Date().toISOString();
        upserted = { ...existing };
        return state;
      }

      const created = {
        id: randomUUID(),
        userId,
        provider: 'stackmail',
        providerEmail: normalized,
        displayName: displayName || normalized,
        scopes: [],
        tokenCipher: null,
        refreshCipher: null,
        secretCipher,
        expiresAt: 0,
        profile: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      state.accounts.push(created);
      upserted = { ...created };
      return state;
    });

    return upserted;
  }

  async listAccountsForUser(userId) {
    const state = await this.store.getState();
    return state.accounts.filter((account) => account.userId === userId);
  }

  async getAccount(userId, accountId) {
    const state = await this.store.getState();
    return (
      state.accounts.find((item) => item.id === accountId && item.userId === userId) || null
    );
  }

  async getAccountById(accountId) {
    const state = await this.store.getState();
    return state.accounts.find((item) => item.id === accountId) || null;
  }

  async updateAccountTokens(accountId, { tokenCipher, refreshCipher, expiresAt }) {
    let updated = null;
    await this.store.withState((state) => {
      const account = state.accounts.find((item) => item.id === accountId);
      if (!account) {
        return state;
      }

      account.tokenCipher = tokenCipher;
      account.refreshCipher = refreshCipher;
      account.expiresAt = expiresAt;
      account.updatedAt = new Date().toISOString();
      updated = { ...account };
      return state;
    });

    return updated;
  }

  async registerDeviceToken({ userId, accountId, token, platform = 'android' }) {
    const normalizedToken = String(token || '').trim();
    const tokenHash = hashValue(normalizedToken);
    if (!normalizedToken) {
      return null;
    }

    let output = null;
    await this.store.withState((state) => {
      const existing = state.devices.find(
        (device) => device.userId === userId && device.accountId === accountId && device.tokenHash === tokenHash,
      );

      if (existing) {
        existing.token = normalizedToken;
        existing.platform = platform;
        existing.updatedAt = new Date().toISOString();
        output = { ...existing };
        return state;
      }

      const created = {
        id: randomUUID(),
        userId,
        accountId,
        token: normalizedToken,
        tokenHash,
        platform,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      state.devices.push(created);
      output = { ...created };
      return state;
    });

    return output;
  }

  async unregisterDeviceToken({ userId, token }) {
    const normalizedToken = String(token || '').trim();
    const tokenHash = hashValue(normalizedToken);

    await this.store.withState((state) => {
      state.devices = state.devices.filter(
        (device) => !(device.userId === userId && device.tokenHash === tokenHash),
      );
      return state;
    });
  }

  async getDeviceTokens({ userId, accountId = null }) {
    const state = await this.store.getState();
    return state.devices
      .filter((device) => {
        if (device.userId !== userId) {
          return false;
        }
        if (
          accountId &&
          device.accountId != null &&
          device.accountId !== accountId
        ) {
          return false;
        }
        return Boolean(device.token);
      })
      .map((device) => device.token);
  }

  async enqueueSendJob(job) {
    let queued = null;
    await this.store.withState((state) => {
      const next = {
        id: randomUUID(),
        status: 'queued',
        attempts: 0,
        nextRunAt: Date.now(),
        lastError: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        ...job,
      };
      state.smtpQueue.push(next);
      queued = { ...next };
      return state;
    });

    return queued;
  }

  async listRunnableSendJobs(nowMs = Date.now()) {
    const state = await this.store.getState();
    return state.smtpQueue.filter(
      (job) => job.status !== 'sent' && job.status !== 'failed' && Number(job.nextRunAt || 0) <= nowMs,
    );
  }

  async updateSendJob(jobId, patch) {
    let updated = null;
    await this.store.withState((state) => {
      const job = state.smtpQueue.find((item) => item.id === jobId);
      if (!job) {
        return state;
      }
      Object.assign(job, patch, { updatedAt: new Date().toISOString() });
      updated = { ...job };
      return state;
    });
    return updated;
  }

  async getSendJob(jobId, userId) {
    const state = await this.store.getState();
    return state.smtpQueue.find((job) => job.id === jobId && job.userId === userId) || null;
  }
}
