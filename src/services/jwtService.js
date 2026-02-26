import jwt from 'jsonwebtoken';

import { UnauthorizedError } from '../utils/errors.js';

export class JwtService {
  constructor({ secret, issuer, audience, expiresIn }) {
    this.secret = secret;
    this.issuer = issuer;
    this.audience = audience;
    this.expiresIn = expiresIn;
  }

  sign(payload) {
    return jwt.sign(payload, this.secret, {
      issuer: this.issuer,
      audience: this.audience,
      expiresIn: this.expiresIn,
    });
  }

  verify(token) {
    try {
      return jwt.verify(token, this.secret, {
        issuer: this.issuer,
        audience: this.audience,
      });
    } catch {
      throw new UnauthorizedError('Invalid or expired access token');
    }
  }
}
