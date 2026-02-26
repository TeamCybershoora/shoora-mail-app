import { ImapFlow } from 'imapflow';

import { logger } from '../lib/logger.js';
import { TokenVault } from './tokenVault.js';

import {
  ApiError,
  ConflictError,
  NotFoundError,
  UnauthorizedError,
} from '../utils/errors.js';

const FALLBACK_KEYS_ENV = 'ENCRYPTION_KEY_FALLBACKS';

export class AccountService {
  constructor({
    userStore,
    tokenVault,
    googleOAuthService,
    stackmailConfig,
    commandTimeoutMs,
    directLoginEnabled = true,
    fallbackTokenVaults = null,
    fallbackEncryptionKeys = null,
  }) {
    this.userStore = userStore;
    this.tokenVault = tokenVault;
    this.googleOAuthService = googleOAuthService;
    this.stackmailConfig = stackmailConfig;
    this.commandTimeoutMs = commandTimeoutMs;
    this.directLoginEnabled = directLoginEnabled;
    this.fallbackTokenVaults = this._resolveFallbackTokenVaults({
      fallbackTokenVaults,
      fallbackEncryptionKeys,
    });
  }

  async listAccounts(userId) {
    const accounts = await this.userStore.listAccountsForUser(userId);
    return accounts.map((account) => this._publicAccount(account));
  }

  async linkGoogleAccount({ userId, code, codeVerifier, redirectUri }) {
    this._assertGoogleOAuthConfigured();

    const exchange = await this.googleOAuthService.exchangeCode({
      code,
      codeVerifier,
      redirectUri,
    });

    if (!exchange.refreshToken) {
      throw new ConflictError(
        'Google did not provide refresh token. Re-consent with prompt=consent.',
      );
    }

    const profile = await this.googleOAuthService.fetchUserProfile(exchange.accessToken);
    if (!profile.email || !profile.emailVerified) {
      throw new UnauthorizedError('Google email is missing or not verified');
    }

    const expiresAt = Date.now() + (exchange.expiresInSec * 1000);
    const sealed = this.tokenVault.sealOAuthTokens({
      accessToken: exchange.accessToken,
      refreshToken: exchange.refreshToken,
      expiresAt,
    });

    const scopes = exchange.scope
      ? exchange.scope.split(' ').map((item) => item.trim()).filter(Boolean)
      : [];

    const account = await this.userStore.upsertGoogleAccount({
      userId,
      providerEmail: profile.email,
      displayName: profile.name || profile.email,
      scopes,
      tokenCipher: sealed.accessTokenCipher,
      refreshCipher: sealed.refreshTokenCipher,
      expiresAt: sealed.expiresAt,
      profile,
    });

    return this._publicAccount(account);
  }

  async authenticateStackmailLogin({ email, password }) {
    if (!this.directLoginEnabled) {
      throw new UnauthorizedError('Invalid credentials');
    }

    await this._verifyStackmailCredentials({ email, password });

    const user = await this.userStore.upsertAppUserCredentials({ email, password });
    if (!user) {
      throw new UnauthorizedError('Invalid credentials');
    }

    const sealedPassword = this.tokenVault.seal(password);
    const account = await this.userStore.upsertStackmailAccount({
      userId: user.id,
      providerEmail: email,
      displayName: email,
      secretCipher: sealedPassword,
    });

    return {
      user,
      account,
    };
  }

  async resolveAccountForUser({ userId, accountId = null }) {
    if (accountId) {
      const account = userId
        ? await this.userStore.getAccount(userId, accountId)
        : await this.userStore.getAccountById(accountId);
      if (!account) {
        throw new NotFoundError('Mail account not found');
      }
      if (userId && account.userId !== userId) {
        throw new NotFoundError('Mail account not found');
      }
      return account;
    }

    if (!userId) {
      throw new NotFoundError('Mail account not found');
    }

    const accounts = await this.userStore.listAccountsForUser(userId);
    if (!accounts.length) {
      throw new NotFoundError('No linked mail account. Sign in with your StackMail account.');
    }

    const stackmailAccount = accounts.find((item) => item.provider === 'stackmail');
    return stackmailAccount || accounts[0];
  }

  async getAccountAuth(account) {
    if (!account) {
      throw new NotFoundError('Mail account not found');
    }

    if (account.provider === 'stackmail') {
      const opened = this._openEncryptedValue(account.secretCipher);
      const password = opened.value;
      if (!password) {
        throw new UnauthorizedError('StackMail credentials missing. Please sign in again.');
      }

      let effectiveAccount = account;
      if (opened.usedFallback) {
        effectiveAccount = await this._migrateStackmailSecret(account, password);
      }

      return {
        account: effectiveAccount,
        mode: 'password',
        email: effectiveAccount.providerEmail,
        password,
        imapHostCandidates: this._imapHostCandidates(effectiveAccount.providerEmail),
      };
    }

    const { account: updatedAccount, accessToken } = await this.getValidAccessToken(account);
    return {
      account: updatedAccount,
      mode: 'oauth',
      email: updatedAccount.providerEmail,
      accessToken,
      imapHostCandidates: this._imapHostCandidates(updatedAccount.providerEmail),
    };
  }

  async getValidAccessToken(account) {
    this._assertGoogleOAuthConfigured();

    const openedResult = this._openOAuthTokens(account);
    const opened = openedResult.value;
    let effectiveAccount = account;
    if (openedResult.usedFallback) {
      effectiveAccount = await this._migrateOAuthTokens(account, opened);
    }

    const threshold = Date.now() + 60_000;
    if (opened.accessToken && Number(opened.expiresAt || 0) > threshold) {
      return {
        account: effectiveAccount,
        accessToken: opened.accessToken,
      };
    }

    if (!opened.refreshToken) {
      throw new UnauthorizedError('Refresh token missing. Re-link Google account.');
    }

    const refreshed = await this.googleOAuthService.refreshAccessToken({
      refreshToken: opened.refreshToken,
    });

    const expiresAt = Date.now() + (refreshed.expiresInSec * 1000);
    const sealed = this.tokenVault.sealOAuthTokens({
      accessToken: refreshed.accessToken,
      refreshToken: refreshed.refreshToken,
      expiresAt,
    });

    const updated = await this.userStore.updateAccountTokens(effectiveAccount.id, {
      tokenCipher: sealed.accessTokenCipher,
      refreshCipher: sealed.refreshTokenCipher,
      expiresAt: sealed.expiresAt,
    });

    if (!updated) {
      throw new NotFoundError('Mail account not found while refreshing token');
    }

    return {
      account: updated,
      accessToken: refreshed.accessToken,
    };
  }

  _publicAccount(account) {
    if (!account) {
      return null;
    }
    return {
      id: account.id,
      provider: account.provider,
      email: account.providerEmail,
      displayName: account.displayName,
      scopes: Array.isArray(account.scopes) ? account.scopes : [],
      createdAt: account.createdAt,
      updatedAt: account.updatedAt,
    };
  }

  _assertGoogleOAuthConfigured() {
    if (!this.googleOAuthService || !this.googleOAuthService.isConfigured()) {
      throw new ApiError(503, 'Google OAuth is not configured on this server', {
        code: 'GOOGLE_OAUTH_NOT_CONFIGURED',
      });
    }
  }

  async _verifyStackmailCredentials({ email, password }) {
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const normalizedPassword = String(password || '');
    if (!normalizedEmail || !normalizedPassword) {
      throw new UnauthorizedError('Invalid credentials');
    }

    const hosts = this._imapHostCandidates(normalizedEmail);
    let lastError = null;

    for (const host of hosts) {
      const client = new ImapFlow({
        host,
        port: this.stackmailConfig.imapPort,
        secure: this.stackmailConfig.imapSecure,
        logger: false,
        auth: {
          user: normalizedEmail,
          pass: normalizedPassword,
        },
        tls: {
          rejectUnauthorized: this.stackmailConfig.imapRejectUnauthorized !== false,
        },
        disableAutoIdle: true,
        socketTimeout: this.commandTimeoutMs,
        commandTimeout: this.commandTimeoutMs,
      });

      try {
        await client.connect();
        return;
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
    if (message.includes('auth') || message.includes('login') || message.includes('invalid credentials')) {
      throw new UnauthorizedError('Invalid credentials');
    }
    throw new ApiError(502, lastError?.message || 'StackMail authentication failed', {
      code: 'STACKMAIL_AUTH_FAILED',
    });
  }

  _imapHostCandidates(email) {
    const out = [];
    const push = (value) => {
      const normalized = String(value || '').trim().toLowerCase();
      if (!normalized || out.includes(normalized)) {
        return;
      }
      out.push(normalized);
    };

    push(this.stackmailConfig.imapHost);

    const normalizedEmail = String(email || '').trim().toLowerCase();
    const at = normalizedEmail.lastIndexOf('@');
    if (at > 0 && at < normalizedEmail.length - 1) {
      const domain = normalizedEmail.slice(at + 1);
      push(`imap.${domain}`);
      push(`mail.${domain}`);
    }

    return out;
  }

  _openEncryptedValue(cipherText) {
    return this._openWithAnyVault(
      (vault) => vault.open(cipherText),
      'Stored account credentials could not be decrypted. Check ENCRYPTION_KEY and sign in again.',
    );
  }

  _openOAuthTokens(account) {
    return this._openWithAnyVault(
      (vault) => vault.openOAuthTokens(account),
      'Stored OAuth tokens could not be decrypted. Check ENCRYPTION_KEY and relink account.',
    );
  }

  _openWithAnyVault(openFn, unauthorizedMessage) {
    const vaults = [this.tokenVault, ...this.fallbackTokenVaults];
    for (let index = 0; index < vaults.length; index += 1) {
      const vault = vaults[index];
      try {
        return {
          value: openFn(vault),
          usedFallback: index > 0,
        };
      } catch {
        // Try next vault.
      }
    }

    throw new UnauthorizedError(unauthorizedMessage);
  }

  _resolveFallbackTokenVaults({ fallbackTokenVaults, fallbackEncryptionKeys }) {
    if (Array.isArray(fallbackTokenVaults) && fallbackTokenVaults.length > 0) {
      return fallbackTokenVaults;
    }

    const keys = Array.isArray(fallbackEncryptionKeys)
      ? fallbackEncryptionKeys
      : this._loadFallbackEncryptionKeysFromEnv();
    if (!keys.length) {
      return [];
    }

    const vaults = this._buildFallbackTokenVaultsFromKeys(keys);
    if (vaults.length > 0) {
      logger.warn('AccountService fallback encryption keys are enabled', {
        count: vaults.length,
      });
    }
    return vaults;
  }

  _loadFallbackEncryptionKeysFromEnv() {
    const raw = String(process.env[FALLBACK_KEYS_ENV] || '').trim();
    if (!raw) {
      return [];
    }
    return this._parseFallbackKeys(raw);
  }

  _parseFallbackKeys(raw) {
    return String(raw)
      .split(/[\n,]+/)
      .map((value) => value.trim())
      .filter(Boolean);
  }

  _buildFallbackTokenVaultsFromKeys(keys) {
    const primarySecret = String(this.tokenVault?.secret || '').trim();

    const unique = [];
    const seen = new Set();
    for (const key of keys) {
      if (key === primarySecret || seen.has(key)) {
        continue;
      }
      seen.add(key);
      unique.push(new TokenVault({ encryptionSecret: key }));
    }
    return unique;
  }

  async _migrateStackmailSecret(account, password) {
    const sealedPassword = this.tokenVault.seal(password);
    if (sealedPassword === account.secretCipher) {
      return account;
    }

    const updated = await this.userStore.upsertStackmailAccount({
      userId: account.userId,
      providerEmail: account.providerEmail,
      displayName: account.displayName || account.providerEmail,
      secretCipher: sealedPassword,
    });

    if (updated) {
      logger.info('Migrated stackmail secret to primary ENCRYPTION_KEY', {
        accountId: account.id,
      });
      return updated;
    }

    return account;
  }

  async _migrateOAuthTokens(account, tokens) {
    const sealed = this.tokenVault.sealOAuthTokens(tokens);
    const updated = await this.userStore.updateAccountTokens(account.id, {
      tokenCipher: sealed.accessTokenCipher,
      refreshCipher: sealed.refreshTokenCipher,
      expiresAt: sealed.expiresAt,
    });

    if (updated) {
      logger.info('Migrated oauth tokens to primary ENCRYPTION_KEY', {
        accountId: account.id,
      });
      return updated;
    }

    return account;
  }
}
