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

class SessionManager {
  constructor(hours = 24) {
    this.ttlMs = hours * 60 * 60 * 1000;
    this.sessions = new Map();
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
    return session;
  }

  get(request) {
    const id = parseCookies(request.headers.cookie).ng_session;
    if (!id) return null;
    const session = this.sessions.get(id);
    if (!session || session.expiresAt <= Date.now()) {
      if (session) this.sessions.delete(id);
      return null;
    }
    return session;
  }

  delete(request) {
    const id = parseCookies(request.headers.cookie).ng_session;
    if (id) this.sessions.delete(id);
  }

  clearAll() {
    this.sessions.clear();
  }

  prune() {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (session.expiresAt <= now) this.sessions.delete(id);
    }
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
