'use strict';

const crypto = require('node:crypto');

function hashSecret(secret, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(String(secret), salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}

function verifySecret(secret, encoded) {
  try {
    const [kind, salt, expectedHex] = String(encoded).split(':');
    if (kind !== 'scrypt' || !salt || !expectedHex) return false;
    const actual = crypto.scryptSync(String(secret), salt, 64);
    const expected = Buffer.from(expectedHex, 'hex');
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  } catch {
    return false;
  }
}

function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/**
 * Generates a cryptographically strong alphanumeric string guaranteed to contain
 * uppercase letters, lowercase letters, and digits when len >= 6.
 */
function generateStrongCredential(len = 18, options = {}) {
  const targetLen = Math.max(4, Number(len) || 18);
  const exclude = String(options.exclude || '').trim();
  const prefix = String(options.prefix || '');
  const bodyLen = Math.max(4, targetLen - prefix.length);

  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.slice(0, 24);
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '2345678901'.slice(0, 10);
  const all = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const chars = [];
    const bytes = crypto.randomBytes(bodyLen * 2);
    if (bodyLen >= 6) {
      chars.push(upper[bytes[0] % upper.length]);
      chars.push(upper[bytes[1] % upper.length]);
      chars.push(lower[bytes[2] % lower.length]);
      chars.push(lower[bytes[3] % lower.length]);
      chars.push(digits[bytes[4] % digits.length]);
      chars.push(digits[bytes[5] % digits.length]);
      for (let i = 6; i < bodyLen; i += 1) {
        chars.push(all[bytes[i] % all.length]);
      }
      // Cryptographic Fisher-Yates shuffle
      for (let i = chars.length - 1; i > 0; i -= 1) {
        const j = bytes[bodyLen + i] % (i + 1);
        const tmp = chars[i];
        chars[i] = chars[j];
        chars[j] = tmp;
      }
    } else {
      for (let i = 0; i < bodyLen; i += 1) {
        chars.push(all[bytes[i] % all.length]);
      }
    }
    const candidate = `${prefix}${chars.join('')}`;
    if (!exclude || (candidate !== exclude && !candidate.includes(exclude) && !exclude.includes(candidate))) {
      return candidate;
    }
  }
  return `${prefix}${crypto.randomBytes(bodyLen).toString('base64url').replace(/[^a-zA-Z0-9]/g, '').slice(0, bodyLen)}`;
}

function randomString(len = 12, exclude = '') {
  return generateStrongCredential(len, { exclude });
}

function parseCookies(header = '') {
  return Object.fromEntries(
    String(header || '')
      .split(';')
      .map((part) => {
        const at = part.indexOf('=');
        if (at < 0) return ['', ''];
        try {
          return [
            decodeURIComponent(part.slice(0, at).trim()),
            decodeURIComponent(part.slice(at + 1).trim())
          ];
        } catch {
          return ['', ''];
        }
      })
      .filter(([key]) => key)
  );
}

const fs = require("node:fs");
const path = require("node:path");

class SessionManager {
  constructor(hours = 168, persistPath = "") {
    this.ttlMs = hours * 60 * 60 * 1000;
    this.sessions = new Map();
    this.persistPath = persistPath || "";
    this._lastSaveAt = 0;
    if (this.persistPath) this._loadFromDisk();
  }

  setPersistPath(filePath) {
    this.persistPath = String(filePath || "");
    if (this.persistPath) this._loadFromDisk();
  }

  _loadFromDisk() {
    try {
      if (!this.persistPath || !fs.existsSync(this.persistPath)) return;
      const raw = JSON.parse(fs.readFileSync(this.persistPath, "utf8") || "[]");
      const now = Date.now();
      if (Array.isArray(raw)) {
        for (const s of raw) {
          if (s && s.id && s.csrf && Number(s.expiresAt) > now) {
            this.sessions.set(s.id, s);
          }
        }
      }
    } catch { /* ignore */ }
  }

  _saveToDisk() {
    if (!this.persistPath) return;
    try {
      fs.mkdirSync(path.dirname(this.persistPath), { recursive: true });
      const tmp = `${this.persistPath}.tmp.${process.pid}`;
      fs.writeFileSync(tmp, JSON.stringify([...this.sessions.values()]), { mode: 0o600 });
      fs.renameSync(tmp, this.persistPath);
      this._lastSaveAt = Date.now();
    } catch { /* ignore */ }
  }

  setMaxAgeMinutes(minutes) {
    const num = Number(minutes);
    if (Number.isFinite(num) && num >= 5) {
      this.ttlMs = num * 60 * 1000;
    }
  }

  create(userId, username) {
    this.prune();
    if (this.sessions.size >= 100) {
      const oldestKey = this.sessions.keys().next().value;
      if (oldestKey) this.sessions.delete(oldestKey);
    }
    const id = randomToken(32);
    const session = {
      id,
      userId,
      username,
      csrf: randomToken(24),
      expiresAt: Date.now() + this.ttlMs
    };
    this.sessions.set(id, session);
    this._saveToDisk();
    return session;
  }

  get(request) {
    const id = parseCookies(request.headers.cookie).ng_session;
    if (!id) return null;
    const session = this.sessions.get(id);
    const now = Date.now();
    if (!session || session.expiresAt <= now) {
      if (session) {
        this.sessions.delete(id);
        this._saveToDisk();
      }
      return null;
    }
    // Sliding session renewal: extend expiry on active usage (throttled disk write every 5 min)
    if (session.expiresAt - now < this.ttlMs * 0.8) {
      session.expiresAt = now + this.ttlMs;
      if (now - this._lastSaveAt > 300000) this._saveToDisk();
    }
    return session;
  }

  delete(request) {
    const id = parseCookies(request.headers.cookie).ng_session;
    if (id && this.sessions.delete(id)) {
      this._saveToDisk();
    }
  }

  clearAll() {
    this.sessions.clear();
    this._saveToDisk();
  }

  prune() {
    const now = Date.now();
    let changed = false;
    for (const [id, session] of this.sessions) {
      if (session.expiresAt <= now) {
        this.sessions.delete(id);
        changed = true;
      }
    }
    if (changed) this._saveToDisk();
  }
}

module.exports = {
  hashSecret,
  verifySecret,
  randomToken,
  randomString,
  generateStrongCredential,
  parseCookies,
  SessionManager
};
