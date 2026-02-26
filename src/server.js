import { createApp } from './app/createApp.js';
import { env, assertEnv } from './config/env.js';
import { logger } from './lib/logger.js';
import { buildAuthMiddleware } from './middleware/auth.js';
import { AccountService } from './services/accountService.js';
import { AuthService } from './services/authService.js';
import { GoogleOAuthService } from './services/googleOAuthService.js';
import { ImapWatcherManager } from './services/imapWatcherManager.js';
import { JwtService } from './services/jwtService.js';
import { MailService } from './services/mailService.js';
import { PushService } from './services/pushService.js';
import { SmtpQueueService } from './services/smtpQueueService.js';
import { TokenVault } from './services/tokenVault.js';
import { JsonStore } from './store/jsonStore.js';
import { UserStore } from './store/userStore.js';

async function bootstrap() {
  assertEnv();

  const jsonStore = new JsonStore(env.storage.filePath);
  await jsonStore.init();

  const userStore = new UserStore(jsonStore);
  await userStore.ensureDefaultUser({
    email: env.appAuth.email,
    password: env.appAuth.password,
    passwordHash: env.appAuth.passwordHash,
  });

  const jwtService = new JwtService(env.jwt);
  const tokenVault = new TokenVault({ encryptionSecret: env.encryption.key });
  const googleOAuthService = new GoogleOAuthService({ config: env.google });
  const accountService = new AccountService({
    userStore,
    tokenVault,
    googleOAuthService,
    stackmailConfig: env.gmail,
    commandTimeoutMs: env.imapWatch.commandTimeoutMs,
    directLoginEnabled: env.stackmail.directLoginEnabled,
  });
  const authService = new AuthService({
    userStore,
    jwtService,
    accountService,
  });

  const mailService = new MailService({
    accountService,
    gmailConfig: env.gmail,
    commandTimeoutMs: env.imapWatch.commandTimeoutMs,
  });

  const pushService = new PushService({ userStore, fcmConfig: env.fcm });
  pushService.init();

  const smtpQueueService = new SmtpQueueService({
    userStore,
    accountService,
    queueConfig: env.smtpQueue,
    gmailConfig: env.gmail,
  });
  smtpQueueService.start();

  const watcherManager = new ImapWatcherManager({
    accountService,
    pushService,
    gmailConfig: env.gmail,
    watchConfig: env.imapWatch,
  });

  const existing = await jsonStore.getState();
  await Promise.all(
    existing.accounts.map((account) =>
      watcherManager.startForUserAccount({
        userId: account.userId,
        accountId: account.id,
      }),
    ),
  );

  const authMiddleware = buildAuthMiddleware({ authService });

  const app = createApp({
    env,
    authService,
    authMiddleware,
    accountService,
    googleOAuthService,
    mailService,
    pushService,
    smtpQueueService,
    watcherManager,
  });

  const server = app.listen(env.port, () => {
    logger.info(`ShooraMail backend listening`, { port: env.port });
  });

  const shutdown = async (signal) => {
    logger.info('Shutting down server', { signal });
    await smtpQueueService.stop();
    await Promise.all(
      Array.from(watcherManager.watchers.keys()).map((accountId) => watcherManager.stopForAccount(accountId)),
    );
    server.close(() => {
      process.exit(0);
    });
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

bootstrap().catch((error) => {
  logger.error('Backend bootstrap failed', { error: error.message, stack: error.stack });
  process.exit(1);
});
