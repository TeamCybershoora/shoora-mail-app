export class ApiError extends Error {
  constructor(statusCode, message, options = {}) {
    super(message);
    this.name = 'ApiError';
    this.statusCode = statusCode;
    this.code = options.code || 'API_ERROR';
    this.details = options.details || null;
  }
}

export class ValidationError extends ApiError {
  constructor(message, details = null) {
    super(400, message, { code: 'VALIDATION_ERROR', details });
  }
}

export class UnauthorizedError extends ApiError {
  constructor(message = 'Unauthorized') {
    super(401, message, { code: 'UNAUTHORIZED' });
  }
}

export class ForbiddenError extends ApiError {
  constructor(message = 'Forbidden') {
    super(403, message, { code: 'FORBIDDEN' });
  }
}

export class NotFoundError extends ApiError {
  constructor(message = 'Not found') {
    super(404, message, { code: 'NOT_FOUND' });
  }
}

export class ConflictError extends ApiError {
  constructor(message = 'Conflict', details = null) {
    super(409, message, { code: 'CONFLICT', details });
  }
}

export function toApiError(error) {
  if (error instanceof ApiError) {
    return error;
  }

  return new ApiError(500, error?.message || 'Internal server error', {
    code: 'INTERNAL_ERROR',
  });
}
