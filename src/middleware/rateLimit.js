import rateLimit from 'express-rate-limit';

function isSendStatusRequest(req) {
  const path = String(req.path || req.originalUrl || '').toLowerCase();
  return path === '/api/send-status' || path.startsWith('/api/send-status?');
}

function toRateLimitBody({ windowMs, retryAfterSeconds }) {
  return {
    success: false,
    error: 'Too many requests. Please retry shortly.',
    code: 'RATE_LIMITED',
    details: {
      retryAfterSeconds,
      windowMs,
    },
  };
}

function resolveRetryAfterSeconds(res, fallbackMs) {
  const header = Number.parseInt(String(res.getHeader('Retry-After') ?? ''), 10);
  if (Number.isFinite(header) && header > 0) {
    return header;
  }
  return Math.max(1, Math.ceil(fallbackMs / 1000));
}

function createLimiter({ windowMs, max, skip }) {
  return rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    skip,
    handler(req, res) {
      const retryAfterSeconds = resolveRetryAfterSeconds(res, windowMs);
      res.status(429).json(toRateLimitBody({ windowMs, retryAfterSeconds }));
    },
  });
}

export function buildRateLimiters(rateLimitConfig) {
  const globalLimiter = createLimiter({
    windowMs: rateLimitConfig.windowMs,
    max: rateLimitConfig.max,
    skip: (req) => isSendStatusRequest(req),
  });

  const authLimiter = createLimiter({
    windowMs: rateLimitConfig.windowMs,
    max: rateLimitConfig.authMax,
  });

  const sendStatusLimiter = createLimiter({
    windowMs: rateLimitConfig.windowMs,
    max: Math.max(rateLimitConfig.max * 4, 300),
  });

  return { globalLimiter, authLimiter, sendStatusLimiter };
}
