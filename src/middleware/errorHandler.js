import { logger } from '../lib/logger.js';
import { toApiError } from '../utils/errors.js';

export function errorHandler(error, _req, res, _next) {
  const apiError = toApiError(error);

  if (apiError.statusCode >= 500) {
    logger.error('Unhandled API error', {
      code: apiError.code,
      message: apiError.message,
      details: apiError.details,
      stack: error?.stack,
    });
  }

  res.status(apiError.statusCode).json({
    success: false,
    error: apiError.message,
    code: apiError.code,
    details: apiError.details,
  });
}
