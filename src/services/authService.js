import { UnauthorizedError } from '../utils/errors.js';

export class AuthService {
  constructor({ userStore, jwtService, accountService = null }) {
    this.userStore = userStore;
    this.jwtService = jwtService;
    this.accountService = accountService;
  }

  async login({ email, password }) {
    let user = null;
    if (this.accountService?.directLoginEnabled) {
      const linked = await this.accountService.authenticateStackmailLogin({
        email,
        password,
      });
      user = linked?.user || null;
    } else {
      user = await this.userStore.verifyAppUser(email, password);
    }

    if (!user) {
      throw new UnauthorizedError('Invalid credentials');
    }

    const token = this.jwtService.sign({
      sub: user.id,
      email: user.email,
      typ: 'access',
    });

    return {
      token,
      user: {
        id: user.id,
        email: user.email,
      },
    };
  }

  authenticateBearer(authorizationHeader) {
    const value = String(authorizationHeader || '').trim();
    if (!value.toLowerCase().startsWith('bearer ')) {
      throw new UnauthorizedError('Missing Bearer token');
    }
    const token = value.slice(7).trim();
    if (!token) {
      throw new UnauthorizedError('Missing Bearer token');
    }

    return this.jwtService.verify(token);
  }
}
