import { decryptString, encryptString } from '../lib/crypto.js';

export class TokenVault {
  constructor({ encryptionSecret }) {
    this.secret = encryptionSecret;
  }

  seal(value) {
    return encryptString(String(value || ''), this.secret);
  }

  open(cipherText) {
    if (!cipherText) {
      return '';
    }
    return decryptString(cipherText, this.secret);
  }

  sealOAuthTokens(tokens) {
    return {
      accessTokenCipher: this.seal(tokens.accessToken),
      refreshTokenCipher: this.seal(tokens.refreshToken),
      expiresAt: Number(tokens.expiresAt || 0),
    };
  }

  openOAuthTokens(account) {
    return {
      accessToken: this.open(account.tokenCipher),
      refreshToken: this.open(account.refreshCipher),
      expiresAt: Number(account.expiresAt || 0),
    };
  }
}
