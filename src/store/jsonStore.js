import fs from 'node:fs/promises';
import path from 'node:path';

const DEFAULT_STATE = {
  users: [],
  accounts: [],
  devices: [],
  smtpQueue: [],
  metadata: {},
};

export class JsonStore {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this._writeQueue = Promise.resolve();
  }

  async init() {
    await fs.mkdir(path.dirname(this.filePath), { recursive: true });
    try {
      await fs.access(this.filePath);
    } catch {
      await this._writeState(DEFAULT_STATE);
    }
  }

  async getState() {
    const raw = await fs.readFile(this.filePath, 'utf8');
    const parsed = JSON.parse(raw);
    return {
      users: Array.isArray(parsed.users) ? parsed.users : [],
      accounts: Array.isArray(parsed.accounts) ? parsed.accounts : [],
      devices: Array.isArray(parsed.devices) ? parsed.devices : [],
      smtpQueue: Array.isArray(parsed.smtpQueue) ? parsed.smtpQueue : [],
      metadata: parsed.metadata && typeof parsed.metadata === 'object' ? parsed.metadata : {},
    };
  }

  async saveState(nextState) {
    this._writeQueue = this._writeQueue.then(() => this._writeState(nextState));
    await this._writeQueue;
  }

  async withState(mutator) {
    const state = await this.getState();
    const next = await mutator(structuredClone(state));
    if (!next || typeof next !== 'object') {
      throw new Error('State mutator must return next state object');
    }
    await this.saveState(next);
    return next;
  }

  async _writeState(state) {
    const payload = JSON.stringify(state, null, 2);
    const tempPath = `${this.filePath}.tmp`;
    await fs.writeFile(tempPath, payload, 'utf8');
    await fs.rename(tempPath, this.filePath);
  }
}
