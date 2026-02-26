import { ZodError } from 'zod';

import { ValidationError } from '../utils/errors.js';

function parseWithSchema(schema, value) {
  const result = schema.safeParse(value);
  if (result.success) {
    return result.data;
  }

  const details = result.error.issues.map((issue) => ({
    path: issue.path.join('.'),
    message: issue.message,
    code: issue.code,
  }));

  throw new ValidationError('Request validation failed', details);
}

export function validateBody(schema) {
  return (req, _res, next) => {
    try {
      req.validatedBody = parseWithSchema(schema, req.body || {});
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function validateQuery(schema) {
  return (req, _res, next) => {
    try {
      req.validatedQuery = parseWithSchema(schema, req.query || {});
      next();
    } catch (error) {
      next(error);
    }
  };
}

export function parseZodError(error) {
  if (!(error instanceof ZodError)) {
    return null;
  }
  return new ValidationError('Request validation failed', error.issues);
}
