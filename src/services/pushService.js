import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import admin from 'firebase-admin';

import { logger } from '../lib/logger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const backendRoot = path.resolve(__dirname, '..', '..');
const TOKEN_ERROR_CODE_PARTS = [
  'registration-token-not-registered',
  'invalid-registration-token',
  'mismatch-sender-id',
  'invalid-package-name',
];
const ANDROID_NOTIFICATION_CHANNEL_ID = 'shoora_mail_new_mail';
const MAX_FCM_TTL_SECONDS = 2_419_200; // 28 days (FCM maximum).

function loadServiceAccount({ path: serviceAccountPath, json }) {
  if (json) {
    try {
      return JSON.parse(json);
    } catch (error) {
      throw new Error(`Invalid FCM_SERVICE_ACCOUNT_JSON: ${error.message}`);
    }
  }

  const configuredPath = String(serviceAccountPath || '').trim();
  if (configuredPath) {
    const candidates = [];
    if (path.isAbsolute(configuredPath)) {
      candidates.push(configuredPath);
    } else {
      candidates.push(configuredPath);
      candidates.push(path.resolve(process.cwd(), configuredPath));
      candidates.push(path.resolve(backendRoot, configuredPath));
      candidates.push(path.resolve(process.cwd(), 'backend', configuredPath));
    }

    const uniqueCandidates = Array.from(new Set(candidates));
    for (const candidate of uniqueCandidates) {
      if (!fs.existsSync(candidate)) {
        continue;
      }
      const raw = fs.readFileSync(candidate, 'utf8');
      return JSON.parse(raw);
    }

    throw new Error(
      `FCM service account file not found. Checked: ${uniqueCandidates.join(', ')}`,
    );
  }

  return null;
}

function normalizeErrorCode(code) {
  return String(code || '').trim().toLowerCase();
}

function isPermanentlyInvalidTokenCode(code, { hasAnySuccess = false } = {}) {
  const normalized = normalizeErrorCode(code);
  if (!normalized) {
    return false;
  }
  if (hasAnySuccess && normalized.includes('invalid-argument')) {
    return true;
  }
  return TOKEN_ERROR_CODE_PARTS.some((part) => normalized.includes(part));
}

function summarizeFailureCodes(failures) {
  return failures.reduce((out, item) => {
    const code = normalizeErrorCode(item.code) || 'unknown';
    out[code] = Number(out[code] || 0) + 1;
    return out;
  }, {});
}

function tokenSuffix(token) {
  const text = String(token || '');
  if (!text) {
    return '';
  }
  return text.slice(-10);
}

function normalizeTtlMs(seconds) {
  const safeSeconds = Number.isFinite(seconds) ? Number(seconds) : 0;
  const boundedSeconds = Math.max(60, Math.min(safeSeconds, MAX_FCM_TTL_SECONDS));
  return Math.trunc(boundedSeconds * 1000);
}

export class PushService {
  constructor({ userStore, fcmConfig }) {
    this.userStore = userStore;
    this.fcmConfig = fcmConfig;
    this.messaging = null;
    this._enabled = false;
  }

  init() {
    try {
      const serviceAccount = loadServiceAccount({
        path: this.fcmConfig.serviceAccountPath,
        json: this.fcmConfig.serviceAccountJson,
      });

      if (!serviceAccount) {
        logger.warn('FCM disabled: service account not configured');
        this._enabled = false;
        return;
      }

      if (!admin.apps.length) {
        admin.initializeApp({
          credential: admin.credential.cert(serviceAccount),
        });
      }

      this.messaging = admin.messaging();
      this._enabled = true;
      logger.info('FCM push service initialized');
    } catch (error) {
      this._enabled = false;
      logger.error('FCM init failed', { error: error.message });
    }
  }

  get enabled() {
    return this._enabled;
  }

  async registerDevice({ userId, accountId, token, platform }) {
    return this.userStore.registerDeviceToken({
      userId,
      accountId,
      token,
      platform,
    });
  }

  async unregisterDevice({ userId, token }) {
    await this.userStore.unregisterDeviceToken({ userId, token });
  }

  async sendNewMailNotification({
    userId,
    accountId,
    mailbox,
    uid,
    threadId,
    sender = '',
    subject = '',
  }) {
    if (!this._enabled || !this.messaging) {
      return { delivered: 0, failed: 0, disabled: true };
    }

    const tokens = await this.userStore.getDeviceTokens({ userId, accountId });
    if (!tokens.length) {
      return { delivered: 0, failed: 0, disabled: false };
    }

    const senderText = String(sender || '').trim();
    const subjectText = String(subject || '').trim();
    const title = senderText ? `New mail from ${senderText}` : 'New mail';
    const body = subjectText || 'You received a new email.';

    const ttlMs = normalizeTtlMs(this.fcmConfig.ttlSeconds);
    const androidPriority =
      String(this.fcmConfig.androidPriority || '').trim().toLowerCase() === 'normal'
        ? 'normal'
        : 'high';
    const collapseKey = `new_mail_${String(accountId || '').trim() || 'default'}`;

    const message = {
      tokens,
      notification: {
        title,
        body,
      },
      data: {
        type: 'new_mail',
        accountId: String(accountId || ''),
        mailbox: String(mailbox || 'INBOX'),
        uid: String(uid || ''),
        threadId: String(threadId || ''),
        sender: senderText,
        subject: subjectText,
      },
      android: {
        priority: androidPriority,
        ttl: ttlMs,
        collapseKey,
        directBootOk: true,
        notification: {
          channelId: ANDROID_NOTIFICATION_CHANNEL_ID,
          priority: 'high',
          defaultSound: true,
          visibility: 'public',
          tag: `mail-${String(accountId || '').trim() || 'default'}`,
          clickAction: 'FLUTTER_NOTIFICATION_CLICK',
        },
      },
      apns: {
        headers: {
          'apns-push-type': 'alert',
          'apns-priority': '10',
        },
        payload: {
          aps: {
            sound: 'default',
            contentAvailable: true,
          },
        },
      },
    };

    const response = await this.messaging.sendEachForMulticast(message);
    const failures = [];
    const invalidTokens = [];

    if (response.failureCount > 0) {
      response.responses.forEach((result, index) => {
        if (result.success) {
          return;
        }

        const code = result.error?.code || '';
        const errorMessage = result.error?.message || '';
        const token = tokens[index];

        failures.push({
          code,
          message: errorMessage,
          token,
        });

        if (
          isPermanentlyInvalidTokenCode(code, {
            hasAnySuccess: response.successCount > 0,
          }) &&
          token
        ) {
          invalidTokens.push(token);
        }
      });
    }

    const uniqueInvalidTokens = Array.from(new Set(invalidTokens));

    if (uniqueInvalidTokens.length) {
      await Promise.all(
        uniqueInvalidTokens.map((token) => this.userStore.unregisterDeviceToken({ userId, token })),
      );
    }

    if (failures.length) {
      logger.warn('FCM delivery failures', {
        userId,
        accountId,
        totalTokens: tokens.length,
        failed: failures.length,
        invalidTokensRemoved: uniqueInvalidTokens.length,
        codes: summarizeFailureCodes(failures),
        samples: failures.slice(0, 3).map((failure) => ({
          code: failure.code || '',
          message: String(failure.message || '').slice(0, 200),
          tokenSuffix: tokenSuffix(failure.token),
        })),
      });
    }

    return {
      delivered: response.successCount,
      failed: response.failureCount,
      invalidTokensRemoved: uniqueInvalidTokens.length,
      failureCodes: summarizeFailureCodes(failures),
      disabled: false,
    };
  }
}
