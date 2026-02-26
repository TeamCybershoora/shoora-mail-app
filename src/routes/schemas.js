import { z } from 'zod';

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

export const oauthAuthorizeSchema = z.object({
  state: z.string().optional(),
  codeChallenge: z.string().optional(),
  loginHint: z.string().email().optional(),
});

export const oauthExchangeSchema = z.object({
  code: z.string().min(1),
  codeVerifier: z.string().optional(),
  redirectUri: z.string().url().optional(),
});

export const accountQuerySchema = z.object({
  accountId: z.string().uuid().optional(),
});

export const registerDeviceSchema = z.object({
  token: z.string().min(10),
  accountId: z.string().uuid().optional(),
  platform: z.enum(['android', 'ios', 'web']).default('android'),
});

export const unregisterDeviceSchema = z.object({
  token: z.string().min(10),
});

export const fetchMailboxSchema = z.object({
  accountId: z.string().uuid().optional(),
  mailbox: z.string().default('INBOX'),
  limit: z.number().int().positive().max(100).default(30),
  offset: z.number().int().nonnegative().default(0),
});

export const fetchMessageSchema = z.object({
  accountId: z.string().uuid().optional(),
  mailbox: z.string().default('INBOX'),
  uid: z.number().int().positive(),
});

export const attachmentQuerySchema = z.object({
  accountId: z.string().uuid().optional(),
  mailbox: z.string().default('INBOX'),
  uid: z.coerce.number().int().positive(),
  part: z.string().optional(),
  index: z.coerce.number().int().nonnegative().optional(),
  name: z.string().optional(),
  inline: z.coerce.boolean().default(false),
});

export const enqueueSendSchema = z.object({
  accountId: z.string().uuid().optional(),
  from: z.string().email().optional(),
  to: z.union([z.array(z.string().email()).min(1), z.string().email()]),
  cc: z.array(z.string().email()).optional(),
  bcc: z.array(z.string().email()).optional(),
  subject: z.string().default(''),
  text: z.string().optional(),
  html: z.string().optional(),
  attachments: z
    .array(
      z.object({
        filename: z.string().min(1),
        mimeType: z.string().optional(),
        type: z.string().optional(),
        base64: z.string().optional(),
        contentBase64: z.string().optional(),
        content: z.string().optional(),
        inline: z.boolean().optional(),
        contentId: z.string().optional(),
      }),
    )
    .optional(),
});

export const sendStatusQuerySchema = z.object({
  jobId: z.string().uuid(),
});

export const markReadSchema = z.object({
  accountId: z.string().uuid().optional(),
  mailbox: z.string().default('INBOX'),
  uid: z.number().int().positive(),
  read: z.boolean(),
});

export const toggleStarSchema = z.object({
  accountId: z.string().uuid().optional(),
  mailbox: z.string().default('INBOX'),
  uid: z.number().int().positive(),
  starred: z.boolean(),
});

export const moveMailSchema = z.object({
  accountId: z.string().uuid().optional(),
  fromMailbox: z.string().min(1),
  toMailbox: z.string().min(1),
  uid: z.number().int().positive(),
});

export const deleteMailSchema = z.object({
  accountId: z.string().uuid().optional(),
  mailbox: z.string().default('INBOX'),
  uid: z.number().int().positive(),
});

export const searchSchema = z.object({
  accountId: z.string().uuid().optional(),
  mailbox: z.string().default('INBOX'),
  query: z.string().default(''),
  limit: z.number().int().positive().max(100).default(50),
  offset: z.number().int().nonnegative().default(0),
});
