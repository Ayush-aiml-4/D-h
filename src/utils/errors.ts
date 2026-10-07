export type ErrorCode =
  | 'VALIDATION_ERROR'
  | 'BAD_REQUEST'
  | 'UNAUTHORIZED'
  | 'FORBIDDEN'
  | 'NOT_FOUND'
  | 'CONFLICT'
  | 'UNPROCESSABLE_ENTITY'
  | 'TOO_MANY_REQUESTS'
  | 'PAYLOAD_TOO_LARGE'
  | 'DATABASE_ERROR'
  | 'SERVICE_UNAVAILABLE'
  | 'INTERNAL_ERROR';

export class AppError extends Error {
  public readonly code: ErrorCode;
  public readonly statusCode: number;
  public readonly details?: any;

  constructor(code: ErrorCode, message: string, statusCode: number, details?: any) {
    super(message);
    this.name = 'AppError';
    this.code = code;
    this.statusCode = statusCode;
    this.details = details;
    Object.setPrototypeOf(this, AppError.prototype);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: any) {
    super('VALIDATION_ERROR', message, 400, details);
  }
}

export class BadRequestError extends AppError {
  constructor(message: string, details?: any) {
    super('BAD_REQUEST', message, 400, details);
  }
}

export class UnauthorizedError extends AppError {
  constructor(message: string = 'Authentication required or token expired') {
    super('UNAUTHORIZED', message, 401);
  }
}

export class ForbiddenError extends AppError {
  constructor(message: string = 'You do not have permission to access or modify this resource') {
    super('FORBIDDEN', message, 403);
  }
}

export class NotFoundError extends AppError {
  constructor(message: string = 'Requested resource not found') {
    super('NOT_FOUND', message, 404);
  }
}

export class ConflictError extends AppError {
  constructor(message: string = 'State transition conflict or duplicate mutation attempt') {
    super('CONFLICT', message, 409);
  }
}

export class UnprocessableEntityError extends AppError {
  constructor(message: string = 'Unprocessable entity semantic validation failure') {
    super('UNPROCESSABLE_ENTITY', message, 422);
  }
}

export class RateLimitedError extends AppError {
  constructor(message: string = 'Rate limit exceeded: Too many requests') {
    super('TOO_MANY_REQUESTS', message, 429);
  }
}

export class PayloadTooLargeError extends AppError {
  constructor(message: string = 'Request payload exceeds maximum allowed size') {
    super('PAYLOAD_TOO_LARGE', message, 413);
  }
}

export class ServiceUnavailableError extends AppError {
  constructor(message: string = 'Database or dependent service is temporarily unavailable') {
    super('SERVICE_UNAVAILABLE', message, 503);
  }
}

export class InternalServerError extends AppError {
  constructor(message: string = 'An unexpected internal server error occurred') {
    super('INTERNAL_ERROR', message, 500);
  }
}

export function isDatabaseError(err: any): boolean {
  if (!err) return false;
  const msg = (err.message || String(err)).toLowerCase();
  const code = String(err.code || '');
  return (
    msg.includes('econrefused') ||
    msg.includes('etimedout') ||
    msg.includes('connection refused') ||
    msg.includes('pool destroyed') ||
    msg.includes('connection terminated') ||
    code === 'ECONNREFUSED' ||
    code === 'ETIMEDOUT' ||
    code === '57P01' || // admin_shutdown
    code === '57P02' || // crash_shutdown
    code === '57P03' // cannot_connect_now
  );
}
