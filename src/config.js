import process from 'node:process';

function parseBoolean(value, fallback = false) {
  if (value == null || value === '') {
    return fallback;
  }
  const normalized = String(value).trim().toLowerCase();
  return normalized === 'true' || normalized === '1' || normalized === 'yes';
}

function parseInteger(value, fallback) {
  const parsed = Number.parseInt(String(value ?? ''), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    return fallback;
  }
  return parsed;
}

function parseList(value, fallback = []) {
  if (!value || !String(value).trim()) {
    return fallback;
  }
  return String(value)
    .split(',')
    .map((item) => item.trim())
    .filter(Boolean);
}

const DEFAULT_SENT_MAILBOXES = [
  'Sent',
  'Sent Items',
  'Sent Mail',
  'Sent Messages',
  'INBOX.Sent',
  '[Gmail]/Sent Mail',
];

export const config = {
  port: parseInteger(process.env.PORT, 3000),
  session: {
    cookieName: 'shooramail_session',
    secret: process.env.SESSION_SECRET || '',
    maxAgeMs: parseInteger(process.env.SESSION_MAX_AGE_MS, 7 * 24 * 60 * 60 * 1000),
    secureCookie: parseBoolean(process.env.SESSION_COOKIE_SECURE, false),
  },
  siteAuth: {
    email: (process.env.SITE_EMAIL || '').trim().toLowerCase(),
    password: process.env.SITE_PASSWORD || '',
  },
  imap: {
    host: (process.env.IMAP_HOST || '').trim(),
    port: parseInteger(process.env.IMAP_PORT, 993),
    secure: parseBoolean(process.env.IMAP_SECURE, true),
    rejectUnauthorized: parseBoolean(process.env.IMAP_REJECT_UNAUTHORIZED, true),
    operationTimeoutMs: parseInteger(process.env.IMAP_OPERATION_TIMEOUT_MS, 12000),
  },
  smtp: {
    host: (process.env.SMTP_HOST || '').trim(),
    port: parseInteger(process.env.SMTP_PORT, 465),
    secure: parseBoolean(process.env.SMTP_SECURE, true),
    startTls: parseBoolean(process.env.SMTP_STARTTLS, false),
    rejectUnauthorized: parseBoolean(process.env.SMTP_REJECT_UNAUTHORIZED, true),
    user: (process.env.SMTP_USER || '').trim(),
    pass: process.env.SMTP_PASS || '',
    operationTimeoutMs: parseInteger(process.env.SMTP_OPERATION_TIMEOUT_MS, 12000),
  },
  sentMailboxCandidates: parseList(
    process.env.SENT_MAILBOX_CANDIDATES,
    DEFAULT_SENT_MAILBOXES,
  ),
};

export function assertConfig() {
  if (!config.session.secret || config.session.secret.length < 16) {
    throw new Error('SESSION_SECRET must be set and at least 16 characters long');
  }
}

export function hasImapRuntime() {
  return Boolean(config.imap.host && config.imap.port > 0);
}

