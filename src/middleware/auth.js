import { UnauthorizedError } from '../utils/errors.js';

export function buildAuthMiddleware({ authService }) {
  return (req, _res, next) => {
    try {
      const claims = authService.authenticateBearer(req.headers.authorization);
      req.auth = {
        userId: String(claims.sub || ''),
        email: String(claims.email || ''),
      };
      if (!req.auth.userId) {
        throw new UnauthorizedError('Invalid token subject');
      }
      next();
    } catch (error) {
      next(error);
    }
  };
}
