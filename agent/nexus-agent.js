#!/usr/bin/env node
'use strict';

/**
 * NexusGate Plus · Ultra-Lightweight Cluster Agent (v1.0.3)
 * Zero external npm dependencies · < 15 MB RAM footprint
 * Supports Relay Node, Exit Node (SS/SS2022/VMess), and Hot-Standby Failover Node.
 * Features:
 * - Hash-based On-Change Sing-box Reload (0 restarts when configHash is unchanged)
 * - Autonomous Data Plane (continues serving 100% traffic even if Master is offline/rebooting)
 * - Local Clash API Traffic Delta Buffering & Online IP/Device Reporting
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

function parseArgs(argv) {
  const out = {
    master: process.env.NG_MASTER_URL || '',
    nodeId: process.env.NG_NODE_ID || 'node_remote',
    token: process.env.NG_AGENT_TOKEN || '',
    port: Number(process.env.NG_AGENT_PORT || 19090),
    clashPort: Number(process.env.NG_CLASH_PORT || 10086),
    configPath: process.env.NG_SINGBOX_CONFIG || '/etc/nexusgate/sing-box/config.json',
    singboxBin: process.env.NG_SINGBOX_BIN || '/usr/local/bin/sing-box'
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--master' && argv[i + 1]) out.master = argv[++i];
    else if (arg === '--node-id' && argv[i + 1]) out.nodeId = argv[++i];
    else if (arg === '--token' && argv[i + 1]) out.token = argv[++i];
    else if (arg === '--port' && argv[i + 1]) out.port = Number(argv[++i]);
    else if (arg === '--config' && argv[i + 1]) out.configPath = argv[++i];
    else if (arg === '--singbox-bin' && argv[i + 1]) out.singboxBin = argv[++i];
  }
  return out;
}

const cfg = parseArgs(process.argv);
let currentConfigHash = '';
let sbChild = null;
const connTrafficSeen = new Map();
const pendingInboundDeltas = {};
const pendingClientDeltas = {};
const pendingOutboundDeltas = {};
let latestInboundOnline = {};

function addDelta(storeMap, key, up, down) {
  if (!key || (up <= 0 && down <= 0)) return;
  if (!storeMap[key]) storeMap[key] = { up: 0, down: 0 };
  storeMap[key].up += up;
  storeMap[key].down += down;
}

function pollLocalClashTraffic() {
  return new Promise((resolve) => {
    const req = http.get(`http://127.0.0.1:${cfg.clashPort}/connections`, { timeout: 1500 }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        try {
          const data = JSON.parse(raw || '{}');
          const conns = Array.isArray(data.connections) ? data.connections : [];
          const activeIds = new Set();
          const onlineMap = {};

          for (const conn of conns) {
            if (!conn || !conn.id) continue;
            activeIds.add(conn.id);
            const prev = connTrafficSeen.get(conn.id) || { up: 0, down: 0 };
            const curUp = Math.max(0, Number(conn.upload || 0));
            const curDown = Math.max(0, Number(conn.download || 0));
            const dUp = Math.max(0, curUp - prev.up);
            const dDown = Math.max(0, curDown - prev.down);
            connTrafficSeen.set(conn.id, { up: curUp, down: curDown });

            const meta = conn.metadata || {};
            const rawType = String(meta.type || '');
            const inbTag = rawType.includes('/') ? rawType.split('/').pop() : (meta.inboundTag || '');
            const userEmail = String(meta.user || '').trim();
            const srcIp = String(meta.sourceIP || '').trim();
            const outTag = Array.isArray(conn.chains) && conn.chains.length ? conn.chains[0] : '';

            if (inbTag) {
              addDelta(pendingInboundDeltas, inbTag, dUp, dDown);
              if (!onlineMap[inbTag]) onlineMap[inbTag] = new Set();
              if (srcIp) onlineMap[inbTag].add(srcIp);
            }
            if (userEmail) addDelta(pendingClientDeltas, userEmail, dUp, dDown);
            if (outTag) addDelta(pendingOutboundDeltas, outTag, dUp, dDown);
          }

          for (const oldId of connTrafficSeen.keys()) {
            if (!activeIds.has(oldId)) connTrafficSeen.delete(oldId);
          }

          const formattedOnline = {};
          for (const [tag, ipSet] of Object.entries(onlineMap)) {
            const ips = [...ipSet];
            formattedOnline[tag] = { ips, devices: ips.length };
          }
          latestInboundOnline = formattedOnline;
        } catch { /* ignore */ }
        resolve();
      });
    });
    req.on('error', () => resolve());
    req.on('timeout', () => { req.destroy(); resolve(); });
  });
}

function verifySignature(token, ts, bodyStr, sig) {
  if (!token) return false;
  const expected = crypto
    .createHmac('sha256', String(token))
    .update(`${ts}.${bodyStr}`)
    .digest('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(sig || '')));
  } catch {
    return false;
  }
}

function collectNodeMetrics() {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = Math.max(0, totalMem - freeMem);
  const load = os.loadavg()[0] || 0;
  const cpuCount = Math.max(1, os.cpus().length);
  const cpuPct = Math.min(100, Math.round((load / cpuCount) * 1000) / 10);

  let sbVersion = '1.12.23';
  if (fs.existsSync(cfg.singboxBin)) {
    const v = spawnSync(cfg.singboxBin, ['version'], { encoding: 'utf8', timeout: 2000 });
    const m = String(v.stdout || '').match(/[0-9]+\.[0-9]+\.[0-9]+/);
    if (m) sbVersion = m[0];
  }

  let sbRunning = false;
  const sysCheck = spawnSync('systemctl', ['is-active', '--quiet', 'nexusgate-singbox.service']);
  if (sysCheck.status === 0 || (sbChild && !sbChild.killed)) {
    sbRunning = true;
  }

  return {
    cpuPct,
    memPct: Math.round((usedMem / totalMem) * 1000) / 10,
    memUsedMB: Math.round(usedMem / (1024 * 1024)),
    memTotalMB: Math.round(totalMem / (1024 * 1024)),
    sbRunning,
    sbVersion
  };
}

function applySyncedPayload(payload = {}) {
  if (Array.isArray(payload.certificates)) {
    for (const cert of payload.certificates) {
      if (cert.certPath && cert.certPem) {
        try {
          fs.mkdirSync(path.dirname(cert.certPath), { recursive: true });
          fs.writeFileSync(cert.certPath, cert.certPem, { mode: 0o644 });
        } catch { /* ignore */ }
      }
      if (cert.keyPath && cert.keyPem) {
        try {
          fs.mkdirSync(path.dirname(cert.keyPath), { recursive: true });
          fs.writeFileSync(cert.keyPath, cert.keyPem, { mode: 0o600 });
        } catch { /* ignore */ }
      }
    }
  }

  const nextHash = payload.configHash || '';
  const metrics = collectNodeMetrics();
  const needRestart = !nextHash || nextHash !== currentConfigHash || !metrics.sbRunning;

  if (payload.singboxConfig && typeof payload.singboxConfig === 'object' && needRestart) {
    fs.mkdirSync(path.dirname(cfg.configPath), { recursive: true });
    const tmpPath = `${cfg.configPath}.tmp.${process.pid}`;
    fs.writeFileSync(tmpPath, JSON.stringify(payload.singboxConfig, null, 2), { mode: 0o600 });
    fs.renameSync(tmpPath, cfg.configPath);

    const sysRestart = spawnSync('systemctl', ['restart', 'nexusgate-singbox.service'], { timeout: 6000 });
    if (sysRestart.status !== 0 && fs.existsSync(cfg.singboxBin)) {
      if (sbChild && !sbChild.killed) {
        try { sbChild.kill('SIGTERM'); } catch { /* ignore */ }
      }
      sbChild = spawn(cfg.singboxBin, ['run', '-c', cfg.configPath], {
        stdio: 'ignore',
        detached: false
      });
      sbChild.on('error', () => {});
    }
  }

  if (payload.configHash) {
    currentConfigHash = payload.configHash;
  }
  return { ok: true, configHash: currentConfigHash, reloaded: needRestart };
}

async function sendHeartbeat() {
  if (!cfg.master || !cfg.token) return;
  await pollLocalClashTraffic();
  try {
    const parsedUrl = new URL(`${cfg.master.replace(/\/+$/, '')}/api/cluster/heartbeat`);
    const snapshotInb = { ...pendingInboundDeltas };
    const snapshotCli = { ...pendingClientDeltas };
    const snapshotOut = { ...pendingOutboundDeltas };
    const bodyStr = JSON.stringify({
      nodeId: cfg.nodeId,
      configHash: currentConfigHash,
      metrics: collectNodeMetrics(),
      inboundDeltas: snapshotInb,
      clientDeltas: snapshotCli,
      outboundDeltas: snapshotOut,
      inboundOnline: latestInboundOnline
    });
    const client = parsedUrl.protocol === 'https:' ? https : http;
    const req = client.request(
      {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname,
        method: 'POST',
        rejectUnauthorized: false,
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyStr),
          Authorization: `Bearer ${cfg.token}`,
          'X-Nexus-Node': cfg.nodeId
        },
        timeout: 6000
      },
      (res) => {
        let raw = '';
        res.on('data', (c) => { raw += c; });
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            // Clear buffered traffic deltas only after Master confirms receipt
            for (const k of Object.keys(snapshotInb)) delete pendingInboundDeltas[k];
            for (const k of Object.keys(snapshotCli)) delete pendingClientDeltas[k];
            for (const k of Object.keys(snapshotOut)) delete pendingOutboundDeltas[k];
          }
          try {
            const data = JSON.parse(raw || '{}');
            if (data.needsUpdate && data.singboxConfig) {
              applySyncedPayload(data);
            }
          } catch { /* ignore */ }
        });
      }
    );
    req.on('error', () => {});
    req.on('timeout', () => req.destroy());
    req.write(bodyStr);
    req.end();
  } catch { /* ignore */ }
}

const server = http.createServer((req, res) => {
  const sendJson = (code, obj) => {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
    res.end(body);
  };

  if (req.url === '/healthz' && req.method === 'GET') {
    return sendJson(200, { ok: true, nodeId: cfg.nodeId, configHash: currentConfigHash, metrics: collectNodeMetrics() });
  }

  let rawBody = '';
  req.on('data', (chunk) => {
    rawBody += chunk;
    if (rawBody.length > 16 * 1024 * 1024) req.destroy();
  });
  req.on('end', () => {
    const authHeader = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
    const sig = req.headers['x-nexus-signature'];
    const ts = req.headers['x-nexus-timestamp'];
    const authed = (cfg.token && authHeader === cfg.token) || verifySignature(cfg.token, ts, rawBody, sig);
    if (!authed) {
      return sendJson(401, { error: 'Unauthorized Agent Request' });
    }

    if (req.url === '/agent/v1/sync' && req.method === 'POST') {
      try {
        const payload = JSON.parse(rawBody || '{}');
        const result = applySyncedPayload(payload);
        return sendJson(200, result);
      } catch (err) {
        return sendJson(400, { error: err.message });
      }
    }

    if (req.url === '/agent/v1/status' && req.method === 'GET') {
      return sendJson(200, { ok: true, nodeId: cfg.nodeId, configHash: currentConfigHash, metrics: collectNodeMetrics() });
    }

    return sendJson(404, { error: 'Not Found' });
  });
});

if (require.main === module) {
  server.listen(cfg.port, '0.0.0.0', () => {
    console.log(`[NexusGate-Agent v1.0.3] Listening on 0.0.0.0:${cfg.port} (Node: ${cfg.nodeId})`);
    sendHeartbeat();
    setInterval(sendHeartbeat, 10000).unref();
    setInterval(() => {
      if (connTrafficSeen.size > 2000) connTrafficSeen.clear();
      if (typeof global.gc === 'function') {
        try { global.gc(); } catch { /* ignore */ }
      }
    }, 60000).unref();
  });
}

module.exports = { applySyncedPayload, collectNodeMetrics, pollLocalClashTraffic };
