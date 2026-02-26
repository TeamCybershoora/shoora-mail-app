import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';

export class SessionManager {
  constructor({ cookieName, secret, maxAgeMs, secureCookie }) {
    this.cookieName = cookieName;
    this.maxAgeMs = maxAgeMs;
    this.secureCookie = secureCookie;
    this._key = createHash('sha256').update(secret, 'utf8').digest();
  }

  createToken(payload) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this._key, iv);
    const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return `${iv.toString('base64url')}.${encrypted.toString('base64url')}.${tag.toString('base64url')}`;
  }

  parseToken(token) {
    if (!token || typeof token !== 'string') {
      return null;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      return null;
    }

    try {
      const iv = Buffer.from(parts[0], 'base64url');
      const encrypted = Buffer.from(parts[1], 'base64url');
      const tag = Buffer.from(parts[2], 'base64url');
      const decipher = createDecipheriv('aes-256-gcm', this._key, iv);
      decipher.setAuthTag(tag);
      const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
      const parsed = JSON.parse(decrypted.toString('utf8'));
      if (!parsed || typeof parsed !== 'object') {
        return null;
      }
      return parsed;
    } catch {
      return null;
    }
  }

  setSessionCookie(response, payload) {
    const token = this.createToken(payload);
    response.cookie(this.cookieName, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: this.secureCookie,
      path: '/',
      maxAge: this.maxAgeMs,
    });
  }

  clearSessionCookie(response) {
    response.clearCookie(this.cookieName, {
      httpOnly: true,
      sameSite: 'lax',
      secure: this.secureCookie,
      path: '/',
    });
  }

  readSessionFromRequest(request) {
    const token = request.cookies?.[this.cookieName];
    return this.parseToken(token);
  }
}

export function buildSessionPayload({ email, userName, imapPassword, imapMode }) {
  return {
    email,
    userName,
    imapPassword: imapPassword || null,
    imapMode,
    issuedAt: new Date().toISOString(),
  };
}

export function toCurrentUser(sessionPayload) {
  return {
    email: sessionPayload.email,
    userName: sessionPayload.userName,
    imapMode: Boolean(sessionPayload.imapMode),
  };
}

