'use strict';

const fs = require('node:fs');
const path = require('node:path');

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
  '.png': 'image/png'
};

function sendJson(res, status, data, headers = {}) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    ...headers
  });
  res.end(body);
}

function sendError(res, status, message, code = 'request_error') {
  sendJson(res, status, { error: code, message });
}

async function readBuffer(req, maxBytes = 64 * 1024 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > maxBytes) {
      const error = new Error('上传数据超出大小限制 (最大 64MB)');
      error.statusCode = 413;
      throw error;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function readJson(req, maxBytes = 16 * 1024 * 1024) {
  const buf = await readBuffer(req, maxBytes);
  if (!buf.length) return {};
  try {
    return JSON.parse(buf.toString('utf8'));
  } catch {
    const error = new Error('请求 JSON 格式无效');
    error.statusCode = 400;
    throw error;
  }
}

/**
 * Sanitizes webBasePath: removes any accidental newlines/control chars from shell pipes,
 * keeps only clean URL path characters, and normalizes leading/trailing slashes.
 */
function normalizeBasePath(raw = '/') {
  const firstLine = String(raw || '/').split(/[\r\n]+/)[0].trim();
  const safeChars = firstLine.replace(/[^a-zA-Z0-9/_-]/g, '');
  let clean = safeChars.startsWith('/') ? safeChars : `/${safeChars}`;
  clean = clean.replace(/\/+/g, '/');
  if (clean.length > 1 && clean.endsWith('/')) {
    clean = clean.slice(0, -1);
  }
  return clean || '/';
}

function stripBasePath(pathname, basePath) {
  const norm = normalizeBasePath(basePath);
  if (norm === '/') return pathname;
  if (pathname === norm || pathname === `${norm}/`) return '/';
  if (pathname.startsWith(`${norm}/`)) return pathname.slice(norm.length);
  return null;
}

function route(pattern, pathname) {
  const names = [];
  const regex = new RegExp(
    `^${pattern.replace(/:[A-Za-z0-9_]+/g, (part) => {
      names.push(part.slice(1));
      return '([^/]+)';
    })}/?$`
  );
  const match = pathname.match(regex);
  if (!match) return null;
  const safeDec = (v) => { try { return decodeURIComponent(v); } catch { return v; } };
  return Object.fromEntries(names.map((name, index) => [name, safeDec(match[index + 1])]));
}

async function serveStatic(publicDir, pathname, res, basePath = '/') {
  const relative = pathname === '/' ? 'index.html' : pathname.replace(/^\/+/, '');
  const target = path.resolve(publicDir, relative);
  if (!target.startsWith(path.resolve(publicDir) + path.sep) && target !== path.resolve(publicDir, 'index.html')) {
    return false;
  }
  try {
    const stat = await fs.promises.stat(target);
    if (!stat.isFile()) return false;
    let body = await fs.promises.readFile(target);
    if (path.basename(target) === 'index.html') {
      const norm = normalizeBasePath(basePath);
      const prefix = norm === '/' ? '' : norm;
      const html = body
        .toString('utf8')
        .replace(/href="\/styles\.css/g, `href="${prefix}/styles.css`)
        .replace(/src="\/vendor\/qrcode\.js/g, `src="${prefix}/vendor/qrcode.js`)
        .replace(/src="\/app\.js/g, `src="${prefix}/app.js`)
        .replace('window.__NG_BASE_PATH__ = "/"', `window.__NG_BASE_PATH__ = ${JSON.stringify(norm)}`);
      body = Buffer.from(html, 'utf8');
    }
    res.writeHead(200, {
      'content-type': MIME[path.extname(target)] || 'application/octet-stream',
      'content-length': body.length,
      'cache-control': 'no-store',
      'x-content-type-options': 'nosniff'
    });
    res.end(body);
    return true;
  } catch (error) {
    if (error.code === 'ENOENT') return false;
    throw error;
  }
}

module.exports = {
  sendJson,
  sendError,
  readBuffer,
  readJson,
  normalizeBasePath,
  stripBasePath,
  route,
  serveStatic
};
