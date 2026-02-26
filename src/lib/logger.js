import { env } from '../config/env.js';

const LEVELS = ['error', 'warn', 'info', 'debug'];
const minLevelIndex = LEVELS.indexOf(env.logLevel);

function shouldLog(level) {
  const index = LEVELS.indexOf(level);
  if (index < 0) {
    return true;
  }
  if (minLevelIndex < 0) {
    return true;
  }
  return index <= minLevelIndex;
}

function write(level, message, meta) {
  if (!shouldLog(level)) {
    return;
  }

  const payload = {
    ts: new Date().toISOString(),
    level,
    msg: message,
    ...(meta ? { meta } : {}),
  };
  const output = JSON.stringify(payload);
  if (level === 'error') {
    // eslint-disable-next-line no-console
    console.error(output);
  } else {
    // eslint-disable-next-line no-console
    console.log(output);
  }
}

export const logger = {
  error(message, meta) {
    write('error', message, meta);
  },
  warn(message, meta) {
    write('warn', message, meta);
  },
  info(message, meta) {
    write('info', message, meta);
  },
  debug(message, meta) {
    write('debug', message, meta);
  },
};
