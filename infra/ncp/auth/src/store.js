import { promises as fs } from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const FILE_MODE = 0o600;
const DIR_MODE = 0o700;
const NUMERIC_INVITE_RE = /^\d{8}$/;

function hashInvite(code) {
  return crypto.createHash('sha256').update(code).digest();
}

function numericInviteKey(code) {
  return `n_${hashInvite(code).toString('hex')}`;
}

function randomNumericInvite() {
  return crypto.randomInt(0, 100_000_000).toString().padStart(8, '0');
}

export class Store {
  constructor(filePath) {
    this.filePath = filePath;
    this._queue = Promise.resolve();
    this._cache = null;
  }

  _withLock(fn) {
    const run = this._queue.then(fn);
    this._queue = run.then(() => {}, () => {});
    return run;
  }

  async _load() {
    if (this._cache) return this._cache;
    try {
      const parsed = JSON.parse(await fs.readFile(this.filePath, 'utf8'));
      this._cache = { version: 1, devices: parsed.devices || {}, invites: parsed.invites || {} };
    } catch (error) {
      if (error.code !== 'ENOENT') throw error;
      this._cache = { version: 1, devices: {}, invites: {} };
    }
    return this._cache;
  }

  async _persist() {
    const dir = path.dirname(this.filePath);
    await fs.mkdir(dir, { recursive: true, mode: DIR_MODE });
    await fs.chmod(dir, DIR_MODE).catch(() => {});
    const tmp = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
    const handle = await fs.open(tmp, 'w', FILE_MODE);
    try {
      await handle.writeFile(JSON.stringify(this._cache, null, 2), 'utf8');
      await handle.sync();
    } finally {
      await handle.close();
    }
    await fs.chmod(tmp, FILE_MODE).catch(() => {});
    await fs.rename(tmp, this.filePath);
    await fs.chmod(this.filePath, FILE_MODE).catch(() => {});
  }

  async createInvite(ttlMs, { numeric = false } = {}) {
    return this._withLock(async () => {
      const data = await this._load();
      let inviteId;
      let secret;
      let inviteCode;
      if (numeric) {
        do {
          inviteCode = randomNumericInvite();
          inviteId = numericInviteKey(inviteCode);
        } while (data.invites[inviteId]);
        secret = inviteCode;
      } else {
        inviteId = crypto.randomUUID();
        secret = crypto.randomBytes(24).toString('base64url');
        inviteCode = `${inviteId}.${secret}`;
      }
      const now = Date.now();
      const expiresAt = now + ttlMs;
      data.invites[inviteId] = {
        hash: hashInvite(secret).toString('hex'),
        createdAt: now,
        expiresAt,
        usedAt: null,
        deviceId: null,
      };
      await this._persist();
      return { inviteCode, inviteId, expiresAt };
    });
  }

  async registerDevice(inviteCode, peerId, record) {
    return this._withLock(async () => {
      const data = await this._load();
      if (typeof inviteCode !== 'string') return { ok: false, reason: 'invite_invalid' };
      let inviteId;
      let secret;
      if (NUMERIC_INVITE_RE.test(inviteCode)) {
        inviteId = numericInviteKey(inviteCode);
        secret = inviteCode;
      } else {
        const separator = inviteCode.indexOf('.');
        if (separator < 1) return { ok: false, reason: 'invite_invalid' };
        inviteId = inviteCode.slice(0, separator);
        secret = inviteCode.slice(separator + 1);
      }
      const invite = data.invites[inviteId];
      if (!invite || invite.usedAt || Date.now() > invite.expiresAt) {
        return { ok: false, reason: 'invite_invalid' };
      }
      const candidate = hashInvite(secret);
      const stored = Buffer.from(invite.hash, 'hex');
      if (candidate.length !== stored.length || !crypto.timingSafeEqual(candidate, stored)) {
        return { ok: false, reason: 'invite_invalid' };
      }
      if (Object.values(data.devices).some((device) => device.peerId === peerId)) {
        return { ok: false, reason: 'peer_already_registered' };
      }
      data.devices[record.deviceId] = record;
      invite.usedAt = Date.now();
      invite.deviceId = record.deviceId;
      await this._persist();
      return { ok: true, device: record };
    });
  }

  async getDevice(deviceId) {
    return this._withLock(async () => {
      const data = await this._load();
      return data.devices[deviceId] || null;
    });
  }

  async listDevices() {
    return this._withLock(async () => {
      const data = await this._load();
      return Object.values(data.devices).map(({ publicKeySpkiB64, ...safe }) => safe);
    });
  }

  async revokeDevice(deviceId) {
    return this._withLock(async () => {
      const data = await this._load();
      if (!data.devices[deviceId]) return false;
      delete data.devices[deviceId];
      await this._persist();
      return true;
    });
  }

  async listInvites() {
    return this._withLock(async () => {
      const data = await this._load();
      return Object.entries(data.invites).map(([inviteId, invite]) => ({
        inviteId,
        createdAt: invite.createdAt,
        expiresAt: invite.expiresAt,
        usedAt: invite.usedAt,
        deviceId: invite.deviceId,
      }));
    });
  }
}
