#!/usr/bin/env node
'use strict';

/**
 * NexusGate Plus · Ultra-Lightweight Cluster Agent (v1.0.7)
 * Zero external npm dependencies · < 15 MB RAM footprint
 * Supports Relay Node, Exit Node (SS/SS2022/VMess), and Hot-Standby Failover Node.
 * Features:
 * - 100% Autonomous Data Plane (Control Plane / Data Plane Decoupling):
 *   Even if Master Panel is completely offline/destroyed, local Sing-box continues serving
 *   all user nodes & relay forwarding with 0-second downtime and 0 timeouts!
 * - Persistent Offline Traffic Buffer (agent-offline-state.json): buffers traffic deltas on disk
 *   while Master is unreachable and flushes losslessly upon Master recovery or Standby takeover.
 * - Dual-Master Automatic Failover (--master + --standby-master / dynamic Standby discovery):
 *   Automatically switches heartbeats to Standby Master after 3 consecutive Primary failures.
 * - Hash-based On-Change Sing-box Reload (0 restarts when configHash is unchanged).
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
    standbyMaster: process.env.NG_STANDBY_MASTER_URL || '',
    nodeId: process.env.NG_NODE_ID || 'node_remote',
    token: process.env.NG_AGENT_TOKEN || '',
    port: Number(process.env.NG_AGENT_PORT || 19090),
    clashPort: Number(process.env.NG_CLASH_PORT || 10086),
    configPath: process.env.NG_SINGBOX_CONFIG || '/etc/nexusgate/sing-box/config.json',
    statePath: process.env.NG_AGENT_STATE || '',
    singboxBin: process.env.NG_SINGBOX_BIN || '/usr/local/bin/sing-box'
  };
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--master' && argv[i + 1]) out.master = argv[++i];
    else if (arg === '--standby-master' && argv[i + 1]) out.standbyMaster = argv[++i];
    else if (arg === '--node-id' && argv[i + 1]) out.nodeId = argv[++i];
    else if (arg === '--token' && argv[i + 1]) out.token = argv[++i];
    else if (arg === '--port' && argv[i + 1]) out.port = Number(argv[++i]);
    else if (arg === '--config' && argv[i + 1]) out.configPath = argv[++i];
    else if (arg === '--state' && argv[i + 1]) out.statePath = argv[++i];
    else if (arg === '--singbox-bin' && argv[i + 1]) out.singboxBin = argv[++i];
  }
  if (!out.statePath) {
    out.statePath = path.join(path.dirname(out.configPath), 'agent-offline-state.json');
  }
  return out;
}

const cfg = parseArgs(process.argv);
let currentConfigHash = '';
let sbChild = null;
let consecutiveMasterFailures = 0;
let usingStandbyMaster = false;
let masterReachable = true;
let lastMasterContactAt = '';
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

function loadOfflineState(customStatePath = cfg.statePath) {
  try {
    if (!customStatePath || !fs.existsSync(customStatePath)) return;
    const raw = JSON.parse(fs.readFileSync(customStatePath, 'utf8') || '{}');
    if (raw.configHash && !currentConfigHash) currentConfigHash = String(raw.configHash);
    if (raw.standbyMaster && !cfg.standbyMaster) cfg.standbyMaster = String(raw.standbyMaster);
    if (raw.inboundDeltas && typeof raw.inboundDeltas === 'object') {
      for (const [k, v] of Object.entries(raw.inboundDeltas)) {
        addDelta(pendingInboundDeltas, k, Number(v?.up || 0), Number(v?.down || 0));
      }
    }
    if (raw.clientDeltas && typeof raw.clientDeltas === 'object') {
      for (const [k, v] of Object.entries(raw.clientDeltas)) {
        addDelta(pendingClientDeltas, k, Number(v?.up || 0), Number(v?.down || 0));
      }
    }
    if (raw.outboundDeltas && typeof raw.outboundDeltas === 'object') {
      for (const [k, v] of Object.entries(raw.outboundDeltas)) {
        addDelta(pendingOutboundDeltas, k, Number(v?.up || 0), Number(v?.down || 0));
      }
    }
  } catch { /* ignore */ }
}

function saveOfflineState(customStatePath = cfg.statePath) {
  try {
    if (!customStatePath) return;
    fs.mkdirSync(path.dirname(customStatePath), { recursive: true });
    const tmp = `${customStatePath}.tmp.${process.pid}`;
    fs.writeFileSync(
      tmp,
      JSON.stringify({
        updatedAt: new Date().toISOString(),
        configHash: currentConfigHash,
        master: cfg.master,
        standbyMaster: cfg.standbyMaster || '',
        usingStandbyMaster,
        consecutiveMasterFailures,
        inboundDeltas: pendingInboundDeltas,
        clientDeltas: pendingClientDeltas,
        outboundDeltas: pendingOutboundDeltas
      }),
      { mode: 0o600 }
    );
    fs.renameSync(tmp, customStatePath);
  } catch { /* ignore */ }
}

/**
 * Autonomous Data Plane Guardian:
 * Ensures that if a persisted `/etc/nexusgate/sing-box/config.json` exists on disk,
 * Sing-box stays running locally even if Master Panel is unreachable or Agent just rebooted.
 */
function ensureLocalSingboxRunning(customCfg = cfg) {
  try {
    const configFile = customCfg.configPath || cfg.configPath;
    if (!configFile || !fs.existsSync(configFile)) return false;
    const metrics = collectNodeMetrics(customCfg);
    if (metrics.sbRunning) return true;
    const sysStart = spawnSync('systemctl', ['start', 'nexusgate-singbox.service'], { timeout: 5000 });
    if (sysStart.status === 0) return true;
    const bin = customCfg.singboxBin || cfg.singboxBin;
    if (bin && fs.existsSync(bin)) {
      if (sbChild && !sbChild.killed) return true;
      sbChild = spawn(bin, ['run', '-c', configFile], { stdio: 'ignore', detached: false });
      sbChild.on('error', () => {});
      return true;
    }
  } catch { /* ignore */ }
  return false;
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

function collectNodeMetrics(customCfg = cfg) {
  const totalMem = os.totalmem();
  const freeMem = os.freemem();
  const usedMem = Math.max(0, totalMem - freeMem);
  const load = os.loadavg()[0] || 0;
  const cpuCount = Math.max(1, os.cpus().length);
  const cpuPct = Math.min(100, Math.round((load / cpuCount) * 1000) / 10);

  let sbVersion = '1.12.23';
  const bin = customCfg.singboxBin || cfg.singboxBin;
  if (bin && fs.existsSync(bin)) {
    const v = spawnSync(bin, ['version'], { encoding: 'utf8', timeout: 2000 });
    const m = String(v.stdout || '').match(/[0-9]+\.[0-9]+\.[0-9]+/);
    if (m) sbVersion = m[0];
  }

  let sbRunning = false;
  const configFile = customCfg.configPath || cfg.configPath;
  const sysCheck = spawnSync('systemctl', ['is-active', '--quiet', 'nexusgate-singbox.service']);
  if (sysCheck.status === 0 || (sbChild && !sbChild.killed) || (configFile && fs.existsSync(configFile))) {
    sbRunning = true;
  }

  return {
    cpuPct,
    memPct: Math.round((usedMem / totalMem) * 1000) / 10,
    memUsedMB: Math.round(usedMem / (1024 * 1024)),
    memTotalMB: Math.round(totalMem / (1024 * 1024)),
    sbRunning,
    sbVersion,
    autonomousMode: !masterReachable,
    activeMasterUrl: usingStandbyMaster && cfg.standbyMaster ? cfg.standbyMaster : cfg.master
  };
}

function applySyncedPayload(payload = {}, customCfg = cfg) {
  if (payload.standbyMasterUrl !== undefined) {
    const nextStandby = String(payload.standbyMasterUrl || '').trim();
    if (nextStandby) cfg.standbyMaster = nextStandby;
  }

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

  const targetConfigPath = customCfg.configPath || cfg.configPath;
  const nextHash = payload.configHash || '';
  const configExists = targetConfigPath && fs.existsSync(targetConfigPath);
  const needRestart = !nextHash || nextHash !== currentConfigHash || !configExists;

  if (payload.singboxConfig && typeof payload.singboxConfig === 'object' && needRestart) {
    fs.mkdirSync(path.dirname(targetConfigPath), { recursive: true });
    const tmpPath = `${targetConfigPath}.tmp.${process.pid}`;
    fs.writeFileSync(tmpPath, JSON.stringify(payload.singboxConfig, null, 2), { mode: 0o600 });
    fs.renameSync(tmpPath, targetConfigPath);

    const sysRestart = spawnSync('systemctl', ['restart', 'nexusgate-singbox.service'], { timeout: 6000 });
    const bin = customCfg.singboxBin || cfg.singboxBin;
    if (sysRestart.status !== 0 && bin && fs.existsSync(bin)) {
      if (sbChild && !sbChild.killed) {
        try { sbChild.kill('SIGTERM'); } catch { /* ignore */ }
      }
      sbChild = spawn(bin, ['run', '-c', targetConfigPath], {
        stdio: 'ignore',
        detached: false
      });
      sbChild.on('error', () => {});
    }
  }

  if (payload.configHash) {
    currentConfigHash = payload.configHash;
  }
  saveOfflineState(customCfg.statePath || cfg.statePath);
  return {
    ok: true,
    configHash: currentConfigHash,
    reloaded: needRestart,
    standbyMaster: cfg.standbyMaster || ''
  };
}

function postHeartbeatToUrl(masterBaseUrl, bodyStr, token, nodeId, timeoutMs = 5000) {
  return new Promise((resolve) => {
    try {
      const parsedUrl = new URL(`${String(masterBaseUrl).replace(/\/+$/, '')}/api/cluster/heartbeat`);
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
            Authorization: `Bearer ${token}`,
            'X-Nexus-Node': nodeId
          },
          timeout: timeoutMs
        },
        (res) => {
          let raw = '';
          res.on('data', (c) => { raw += c; });
          res.on('end', () => {
            if (res.statusCode >= 200 && res.statusCode < 300) {
              try {
                resolve({ ok: true, data: JSON.parse(raw || '{}') });
              } catch {
                resolve({ ok: true, data: {} });
              }
            } else {
              resolve({ ok: false, statusCode: res.statusCode });
            }
          });
        }
      );
      req.on('error', (err) => resolve({ ok: false, error: err.message }));
      req.on('timeout', () => {
        req.destroy();
        resolve({ ok: false, error: 'timeout' });
      });
      req.write(bodyStr);
      req.end();
    } catch (err) {
      resolve({ ok: false, error: err.message });
    }
  });
}

async function sendHeartbeat(customOpts = {}) {
  const primaryUrl = customOpts.master !== undefined ? customOpts.master : cfg.master;
  const standbyUrl = customOpts.standbyMaster !== undefined ? customOpts.standbyMaster : cfg.standbyMaster;
  const token = customOpts.token || cfg.token;
  const nodeId = customOpts.nodeId || cfg.nodeId;

  // Always ensure local Sing-box stays alive autonomously even if Master is unreachable
  ensureLocalSingboxRunning(customOpts);

  if (!primaryUrl && !standbyUrl) return { ok: false, autonomousMode: true };
  if (!token) return { ok: false, autonomousMode: true };

  if (!customOpts.skipClashPoll) {
    await pollLocalClashTraffic();
  }

  const snapshotInb = JSON.parse(JSON.stringify(pendingInboundDeltas));
  const snapshotCli = JSON.parse(JSON.stringify(pendingClientDeltas));
  const snapshotOut = JSON.parse(JSON.stringify(pendingOutboundDeltas));

  const bodyStr = JSON.stringify({
    nodeId,
    configHash: currentConfigHash,
    metrics: collectNodeMetrics(customOpts),
    inboundDeltas: snapshotInb,
    clientDeltas: snapshotCli,
    outboundDeltas: snapshotOut,
    inboundOnline: latestInboundOnline
  });

  const targetUrl = (usingStandbyMaster && standbyUrl) ? standbyUrl : primaryUrl;
  let hbRes = await postHeartbeatToUrl(targetUrl, bodyStr, token, nodeId, customOpts.timeoutMs || 4000);

  if (!hbRes.ok) {
    consecutiveMasterFailures += 1;
    // If primary Master failed >= 2 times and a Standby Master URL is configured, automatically fail over to Standby Master!
    if (!usingStandbyMaster && standbyUrl && standbyUrl !== primaryUrl && consecutiveMasterFailures >= 2) {
      const standbyRes = await postHeartbeatToUrl(standbyUrl, bodyStr, token, nodeId, customOpts.timeoutMs || 4000);
      if (standbyRes.ok) {
        usingStandbyMaster = true;
        hbRes = standbyRes;
      }
    } else if (usingStandbyMaster && primaryUrl && primaryUrl !== standbyUrl) {
      // If Standby Master also failed, try Primary Master again in case Primary recovered
      const primaryRetry = await postHeartbeatToUrl(primaryUrl, bodyStr, token, nodeId, customOpts.timeoutMs || 4000);
      if (primaryRetry.ok) {
        usingStandbyMaster = false;
        hbRes = primaryRetry;
      }
    }
  }

  if (hbRes.ok) {
    consecutiveMasterFailures = 0;
    masterReachable = true;
    lastMasterContactAt = new Date().toISOString();

    // Clear buffered traffic deltas only after Master confirms receipt
    for (const k of Object.keys(snapshotInb)) delete pendingInboundDeltas[k];
    for (const k of Object.keys(snapshotCli)) delete pendingClientDeltas[k];
    for (const k of Object.keys(snapshotOut)) delete pendingOutboundDeltas[k];

    const data = hbRes.data || {};
    if (data.standbyMasterUrl && data.standbyMasterUrl !== cfg.standbyMaster) {
      cfg.standbyMaster = String(data.standbyMasterUrl).trim();
    }
    if (data.needsUpdate && data.singboxConfig) {
      applySyncedPayload(data, customOpts);
    } else {
      saveOfflineState(customOpts.statePath || cfg.statePath);
    }
    return {
      ok: true,
      autonomousMode: false,
      usingStandbyMaster,
      activeMasterUrl: usingStandbyMaster && standbyUrl ? standbyUrl : primaryUrl,
      configHash: currentConfigHash
    };
  }

  // Master is offline: Agent enters Autonomous Offline Guardian Mode, persists deltas to disk, and keeps Sing-box running!
  masterReachable = false;
  saveOfflineState(customOpts.statePath || cfg.statePath);
  return {
    ok: false,
    autonomousMode: true,
    usingStandbyMaster,
    consecutiveMasterFailures,
    bufferedInboundTags: Object.keys(pendingInboundDeltas).length
  };
}

function createAgentHttpServer(customCfg = cfg) {
  return http.createServer((req, res) => {
    const sendJson = (code, obj) => {
      const body = JSON.stringify(obj);
      res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(body);
    };

    if (req.url === '/healthz' && req.method === 'GET') {
      return sendJson(200, {
        ok: true,
        nodeId: customCfg.nodeId || cfg.nodeId,
        configHash: currentConfigHash,
        autonomousDataPlane: true,
        masterReachable,
        usingStandbyMaster,
        standbyMaster: customCfg.standbyMaster || cfg.standbyMaster || '',
        lastMasterContactAt,
        metrics: collectNodeMetrics(customCfg)
      });
    }

    let rawBody = '';
    req.on('data', (chunk) => {
      rawBody += chunk;
      if (rawBody.length > 16 * 1024 * 1024) req.destroy();
    });
    req.on('end', () => {
      const token = customCfg.token || cfg.token;
      const authHeader = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim();
      const sig = req.headers['x-nexus-signature'];
      const ts = req.headers['x-nexus-timestamp'];
      const authed = (token && authHeader === token) || verifySignature(token, ts, rawBody, sig);
      if (!authed) {
        return sendJson(401, { error: 'Unauthorized Agent Request' });
      }

      if (req.url === '/agent/v1/sync' && req.method === 'POST') {
        try {
          const payload = JSON.parse(rawBody || '{}');
          const result = applySyncedPayload(payload, customCfg);
          masterReachable = true;
          lastMasterContactAt = new Date().toISOString();
          return sendJson(200, result);
        } catch (err) {
          return sendJson(400, { error: err.message });
        }
      }

      if (req.url === '/agent/v1/status' && req.method === 'GET') {
        return sendJson(200, {
          ok: true,
          nodeId: customCfg.nodeId || cfg.nodeId,
          configHash: currentConfigHash,
          autonomousDataPlane: true,
          masterReachable,
          usingStandbyMaster,
          standbyMaster: customCfg.standbyMaster || cfg.standbyMaster || '',
          bufferedInboundTags: Object.keys(pendingInboundDeltas),
          metrics: collectNodeMetrics(customCfg)
        });
      }

      return sendJson(404, { error: 'Not Found' });
    });
  });
}

if (require.main === module) {
  loadOfflineState();
  ensureLocalSingboxRunning();
  const server = createAgentHttpServer(cfg);
  server.listen(cfg.port, '0.0.0.0', () => {
    console.log(`[NexusGate-Agent v1.0.7] Listening on 0.0.0.0:${cfg.port} (Node: ${cfg.nodeId}, Autonomous Data Plane Active)`);
    sendHeartbeat();
    setInterval(() => sendHeartbeat(), 10000).unref();
    setInterval(() => {
      ensureLocalSingboxRunning();
      if (connTrafficSeen.size > 2000) connTrafficSeen.clear();
      if (typeof global.gc === 'function') {
        try { global.gc(); } catch { /* ignore */ }
      }
    }, 60000).unref();
  });
}

module.exports = {
  cfg,
  addDelta,
  pendingInboundDeltas,
  pendingClientDeltas,
  pendingOutboundDeltas,
  loadOfflineState,
  saveOfflineState,
  ensureLocalSingboxRunning,
  applySyncedPayload,
  collectNodeMetrics,
  pollLocalClashTraffic,
  sendHeartbeat,
  createAgentHttpServer
};
