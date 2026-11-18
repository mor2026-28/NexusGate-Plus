#!/usr/bin/env node
'use strict';

/**
 * NexusGate Plus · Ultra-Lightweight Cluster Agent (v1.0.15)
 * Zero external npm dependencies · < 15 MB RAM footprint
 * Supports Relay Node, Exit Node (SS/SS2022/VMess), and Hot-Standby Failover Node.
 * Features:
 * - 100% Autonomous Data Plane (Control Plane / Data Plane Decoupling):
 *   Even if Master Panel is completely offline/destroyed, local Sing-box continues serving
 *   all user nodes & relay forwarding with 0-second downtime and 0 timeouts!
 * - High-Frequency 1s Clash API + Kernel Socket (`ss -tnH`) Poller with 60s Rolling Session Lease:
 *   Captures even sub-second latency tests (e.g. v2rayN 300ms Ctrl+R ping) and maintains
 *   accurate per-inbound & per-client online IP/device counts and `lastOnline` timestamps.
 * - Real-Time Per-Inbound & Per-Client `limitIp` / `limitDevice` Enforcement on Relay Nodes:
 *   Keeps the first N allowed devices/IPs 100% online while immediately terminating the (N+1)th
 *   excess connection via Clash API DELETE + `ss -K` + temporary 60s per-port iptables block.
 * - Event-Driven Instant Heartbeat Push & OTA Self-Upgrade (`targetAgentVersion`).
 */

const fs = require('node:fs');
const os = require('node:os');
const net = require('node:net');
const path = require('node:path');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { spawn, spawnSync } = require('node:child_process');

const AGENT_VERSION = '1.0.15';
const ACTIVE_LEASE_TTL_MS = 60000;
const EXCESS_IP_BLOCK_TTL_MS = 60000;

function parseArgs(argv) {
  const out = {
    master: process.env.NG_MASTER_URL || '',
    standbyMaster: process.env.NG_STANDBY_MASTER_URL || '',
    nodeId: process.env.NG_NODE_ID || 'node_remote',
    token: process.env.NG_AGENT_TOKEN || '',
    port: Number(process.env.NG_AGENT_PORT || 19090),
    clashPort: Number(process.env.NG_CLASH_PORT || 10086),
    clashSecret: process.env.NG_CLASH_SECRET || '',
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
let currentSbOnlyHash = '';
let sbChild = null;
let consecutiveMasterFailures = 0;
let usingStandbyMaster = false;
let masterReachable = true;
let lastMasterContactAt = '';
let lastHeartbeatSentAt = 0;
let heartbeatInFlight = false;

const connTrafficSeen = new Map();
const pendingInboundDeltas = {};
const pendingClientDeltas = {};
const pendingOutboundDeltas = {};
let latestInboundOnline = {};
let lastOnlineSignature = '';

// Map<inboundTag, Map<deviceFp, { ip, deviceFp, user, firstSeenAt, lastSeenAt }>>
const activeSessionLeases = new Map();
// Map<`${ip}:${port}`, { ip, port, inboundTag, isV6, expiresAt }>
const tempBlockedExcessIps = new Map();
const recentSocketKillAt = new Map();
let inboundByTag = new Map();
let inboundByPort = new Map();
let lastKernelScanAt = 0;
let cachedKernelPortPeers = new Map();
let cachedPeerToLocalPort = new Map();

function normalizeClientIp(rawIp) {
  const s = String(rawIp || '').trim().replace(/^\[|\]$/g, '').replace(/^::ffff:/i, '');
  if (!s || s === '127.0.0.1' || s === '::1' || s === '0.0.0.0' || s === '::') return '';
  return s;
}

function addDelta(storeMap, key, up, down) {
  if (!key || (up <= 0 && down <= 0)) return;
  if (!storeMap[key]) storeMap[key] = { up: 0, down: 0 };
  storeMap[key].up += up;
  storeMap[key].down += down;
}

/**
 * Rebuilds `inboundByTag` and `inboundByPort` from synced `inboundPolicies` and/or `singboxConfig`.
 */
function rebuildInboundPolicyIndex(singboxConfig = null, inboundPolicies = null, customCfg = cfg) {
  let sbCfg = singboxConfig;
  if (!sbCfg) {
    const configFile = customCfg.configPath || cfg.configPath;
    if (configFile && fs.existsSync(configFile)) {
      try { sbCfg = JSON.parse(fs.readFileSync(configFile, 'utf8')); } catch { sbCfg = null; }
    }
  }
  if (sbCfg?.experimental?.clash_api) {
    const extCtrl = String(sbCfg.experimental.clash_api.external_controller || '');
    const mPort = extCtrl.match(/:(\d+)$/);
    if (mPort) cfg.clashPort = Number(mPort[1]);
    if (sbCfg.experimental.clash_api.secret !== undefined) {
      cfg.clashSecret = String(sbCfg.experimental.clash_api.secret || '');
    }
  }

  const nextByTag = new Map();
  const nextByPort = new Map();

  if (Array.isArray(inboundPolicies)) {
    for (const p of inboundPolicies) {
      if (!p || !p.tag) continue;
      const item = {
        tag: p.tag,
        port: Number(p.port || 0),
        remark: p.remark || p.tag,
        limitIp: Math.max(0, Number(p.limitIp || 0)),
        limitDevice: Math.max(0, Number(p.limitDevice || 0)),
        clients: Array.isArray(p.clients) ? p.clients : []
      };
      nextByTag.set(item.tag, item);
      if (item.port > 0) nextByPort.set(item.port, item);
    }
  }

  if (sbCfg && Array.isArray(sbCfg.inbounds)) {
    for (const sbInb of sbCfg.inbounds) {
      if (!sbInb || !sbInb.tag) continue;
      const port = Number(sbInb.listen_port || 0);
      const existing = nextByTag.get(sbInb.tag);
      if (existing) {
        if (!existing.port && port > 0) {
          existing.port = port;
          nextByPort.set(port, existing);
        }
        if ((!existing.clients || existing.clients.length === 0) && Array.isArray(sbInb.users)) {
          existing.clients = sbInb.users.map((u) => ({
            email: u.name || u.username || 'default',
            enable: true,
            limitIp: 0,
            limitDevice: 0
          }));
        }
      } else {
        const fallbackItem = {
          tag: sbInb.tag,
          port,
          remark: sbInb.tag,
          limitIp: 0,
          limitDevice: 0,
          clients: Array.isArray(sbInb.users)
            ? sbInb.users.map((u) => ({
                email: u.name || u.username || 'default',
                enable: true,
                limitIp: 0,
                limitDevice: 0
              }))
            : []
        };
        nextByTag.set(fallbackItem.tag, fallbackItem);
        if (port > 0) nextByPort.set(port, fallbackItem);
      }
    }
  }

  if (nextByTag.size > 0) {
    inboundByTag = nextByTag;
    inboundByPort = nextByPort;
  }
}

function loadOfflineState(customStatePath = cfg.statePath) {
  try {
    if (!customStatePath || !fs.existsSync(customStatePath)) return;
    const raw = JSON.parse(fs.readFileSync(customStatePath, 'utf8') || '{}');
    if (raw.configHash && !currentConfigHash) currentConfigHash = String(raw.configHash);
    if (raw.sbOnlyHash && !currentSbOnlyHash) currentSbOnlyHash = String(raw.sbOnlyHash);
    if (raw.standbyMaster && !cfg.standbyMaster) cfg.standbyMaster = String(raw.standbyMaster);
    if (Array.isArray(raw.inboundPolicies)) {
      rebuildInboundPolicyIndex(null, raw.inboundPolicies);
    }
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
        sbOnlyHash: currentSbOnlyHash,
        master: cfg.master,
        standbyMaster: cfg.standbyMaster || '',
        usingStandbyMaster,
        consecutiveMasterFailures,
        inboundPolicies: [...inboundByTag.values()],
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
 * Stops any legacy x-ui / xray service that might be holding the migrated inbound ports on this Relay server.
 */
function stopConflictingLegacyXui() {
  if (process.env.NG_TEST_MODE) return false;
  try {
    const xuiCheck = spawnSync('pgrep', ['-f', '/usr/local/x-ui'], { timeout: 1500 });
    const xrayCheck = spawnSync('pgrep', ['-x', 'xray'], { timeout: 1500 });
    if (xuiCheck.status === 0 || xrayCheck.status === 0) {
      spawnSync('systemctl', ['stop', 'x-ui', 'xray'], { timeout: 3000 });
      spawnSync('systemctl', ['disable', 'x-ui', 'xray'], { timeout: 3000 });
      spawnSync('pkill', ['-9', '-f', '/usr/local/x-ui'], { timeout: 2000 });
      spawnSync('pkill', ['-9', '-x', 'xray'], { timeout: 2000 });
      return true;
    }
  } catch { /* ignore */ }
  return false;
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
    const freedPorts = stopConflictingLegacyXui();
    const metrics = collectNodeMetrics(customCfg);
    if (metrics.sbRunning && !freedPorts) return true;
    const sysStart = spawnSync('systemctl', ['restart', 'nexusgate-singbox.service'], { timeout: 5000 });
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

function scanKernelEstablishedSockets() {
  if (process.env.NG_TEST_MODE || inboundByPort.size === 0) {
    return { portPeers: new Map(), peerToLocalPort: new Map() };
  }
  const now = Date.now();
  if (now - lastKernelScanAt < 2000 && cachedKernelPortPeers.size > 0) {
    return { portPeers: cachedKernelPortPeers, peerToLocalPort: cachedPeerToLocalPort };
  }
  lastKernelScanAt = now;
  const portPeers = new Map();
  const peerToLocalPort = new Map();
  try {
    const res = spawnSync('ss', ['-tnH', 'state', 'established'], { encoding: 'utf8', timeout: 1000 });
    if (res.status === 0 && res.stdout) {
      for (const line of res.stdout.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const parts = trimmed.split(/\s+/);
        if (parts.length < 4) continue;
        const localAddr = parts[2] || '';
        const peerAddr = parts[3] || '';
        const lColon = localAddr.lastIndexOf(':');
        const pColon = peerAddr.lastIndexOf(':');
        if (lColon <= 0 || pColon <= 0) continue;
        const localPort = Number(localAddr.slice(lColon + 1));
        if (!inboundByPort.has(localPort)) continue;
        const peerIp = normalizeClientIp(peerAddr.slice(0, pColon));
        const peerPort = Number(peerAddr.slice(pColon + 1) || 0);
        if (!peerIp) continue;
        if (!portPeers.has(localPort)) portPeers.set(localPort, new Set());
        portPeers.get(localPort).add(peerIp);
        if (peerPort > 0) peerToLocalPort.set(`${peerIp}:${peerPort}`, localPort);
        if (!peerToLocalPort.has(peerIp)) peerToLocalPort.set(peerIp, localPort);
      }
    }
  } catch { /* ignore */ }
  cachedKernelPortPeers = portPeers;
  cachedPeerToLocalPort = peerToLocalPort;
  return { portPeers, peerToLocalPort };
}

function closeClashConnection(connId, customCfg = cfg) {
  if (!connId) return;
  const port = Number(customCfg.clashPort || cfg.clashPort || 10086);
  const secret = customCfg.clashSecret !== undefined ? customCfg.clashSecret : cfg.clashSecret;
  const req = http.request({
    hostname: '127.0.0.1',
    port,
    path: `/connections/${encodeURIComponent(connId)}`,
    method: 'DELETE',
    headers: secret ? { Authorization: `Bearer ${secret}` } : {},
    timeout: 1500
  });
  req.on('error', () => {});
  req.end();
}

function applyTempIpPortBlock(srcIp, inboundPort, inboundTag, nowMs = Date.now()) {
  if (!srcIp || !inboundPort || process.env.NG_TEST_MODE) return;
  const key = `${srcIp}:${inboundPort}`;
  if (tempBlockedExcessIps.has(key)) {
    tempBlockedExcessIps.get(key).expiresAt = nowMs + EXCESS_IP_BLOCK_TTL_MS;
    return;
  }
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const isV6 = net.isIP(srcIp) === 6;
  const bin = isV6 ? 'ip6tables' : 'iptables';
  if (isRoot) {
    try {
      for (const proto of ['tcp', 'udp']) {
        const check = spawnSync(bin, ['-C', 'INPUT', '-s', srcIp, '-p', proto, '--dport', String(inboundPort), '-j', 'REJECT'], { timeout: 1000 });
        if (check.status !== 0) {
          spawnSync(bin, ['-I', 'INPUT', '1', '-s', srcIp, '-p', proto, '--dport', String(inboundPort), '-j', 'REJECT'], { timeout: 1000 });
        }
      }
    } catch { /* ignore */ }
  }
  tempBlockedExcessIps.set(key, {
    ip: srcIp,
    port: Number(inboundPort),
    inboundTag,
    isV6,
    expiresAt: nowMs + EXCESS_IP_BLOCK_TTL_MS
  });
}

function removeTempIpPortBlock(key) {
  const item = tempBlockedExcessIps.get(key);
  if (!item) return;
  tempBlockedExcessIps.delete(key);
  if (process.env.NG_TEST_MODE) return;
  const bin = item.isV6 ? 'ip6tables' : 'iptables';
  try {
    for (const proto of ['tcp', 'udp']) {
      spawnSync(bin, ['-D', 'INPUT', '-s', item.ip, '-p', proto, '--dport', String(item.port), '-j', 'REJECT'], { timeout: 1000 });
    }
  } catch { /* ignore */ }
}

function pruneExpiredTempIpBlocks(nowMs = Date.now()) {
  for (const [key, item] of tempBlockedExcessIps.entries()) {
    const inb = inboundByTag.get(item.inboundTag);
    const leaseMap = activeSessionLeases.get(item.inboundTag);
    const limitIp = Number(inb?.limitIp || 0);
    const limitDevice = Number(inb?.limitDevice || 0);
    const curCount = leaseMap ? leaseMap.size : 0;
    const slotsAvailable = !inb ||
      (limitIp === 0 && limitDevice === 0) ||
      (limitDevice > 0 && curCount < limitDevice) ||
      (limitIp > 0 && limitDevice === 0 && curCount < limitIp);
    if (nowMs >= item.expiresAt || slotsAvailable) {
      removeTempIpPortBlock(key);
    }
  }
}

function terminateExcessClient(connId, srcIp, srcPort, inboundPort, inboundTag, isIpAllowed = false, nowMs = Date.now(), customCfg = cfg) {
  if (connId) {
    closeClashConnection(connId, customCfg);
  }
  if (!srcIp || !inboundPort || process.env.NG_TEST_MODE) return;
  const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
  const killKey = isIpAllowed ? `${srcIp}:${inboundPort}:${srcPort}` : `${srcIp}:${inboundPort}:all`;
  const lastKill = recentSocketKillAt.get(killKey) || 0;
  if (recentSocketKillAt.size > 2000) recentSocketKillAt.clear();

  if (!isIpAllowed) {
    if (isRoot && nowMs - lastKill > 3000) {
      recentSocketKillAt.set(killKey, nowMs);
      try {
        spawnSync('ss', ['-K', 'dst', srcIp, 'sport', '=', `:${inboundPort}`], { encoding: 'utf8', timeout: 1000 });
      } catch { /* ignore */ }
    }
    applyTempIpPortBlock(srcIp, inboundPort, inboundTag, nowMs);
  } else if (srcPort > 0 && isRoot && nowMs - lastKill > 3000) {
    recentSocketKillAt.set(killKey, nowMs);
    try {
      spawnSync('ss', ['-K', 'dst', srcIp, 'sport', '=', `:${inboundPort}`, 'dport', '=', `:${srcPort}`], { encoding: 'utf8', timeout: 1000 });
    } catch { /* ignore */ }
  }
}

function resolveInboundTagAndPolicy(conn, peerToLocalPort) {
  const meta = conn?.metadata || {};
  const candidates = [];
  if (meta.inbound) candidates.push(String(meta.inbound).trim());
  if (meta.inboundTag) candidates.push(String(meta.inboundTag).trim());
  if (meta.type) {
    const typeStr = String(meta.type).trim();
    const slashIdx = typeStr.indexOf('/');
    if (slashIdx >= 0) {
      candidates.push(typeStr.slice(slashIdx + 1).trim());
    }
    candidates.push(typeStr);
  }
  if (conn?.rule) {
    const m = String(conn.rule).match(/inbound=\[?([^\],=\s]+)\]?/i);
    if (m && m[1]) candidates.push(m[1].trim());
  }
  for (const cand of candidates) {
    if (cand && inboundByTag.has(cand)) {
      return inboundByTag.get(cand);
    }
  }
  const inbPort = Number(meta.inboundPort || 0);
  if (inbPort > 0 && inboundByPort.has(inbPort)) {
    return inboundByPort.get(inbPort);
  }
  const srcIp = normalizeClientIp(meta.sourceIP);
  const srcPort = Number(meta.sourcePort || 0);
  if (srcIp && peerToLocalPort) {
    const matchedPort = (srcPort > 0 && peerToLocalPort.get(`${srcIp}:${srcPort}`)) || peerToLocalPort.get(srcIp);
    if (matchedPort && inboundByPort.has(matchedPort)) {
      return inboundByPort.get(matchedPort);
    }
  }
  if (candidates[0]) {
    return { tag: candidates[0], port: inbPort, limitIp: 0, limitDevice: 0, clients: [] };
  }
  return null;
}

function registerOrEnforceClient(inb, srcIp, authUser = 'default', srcPort = 0, connId = '', nowMs = Date.now(), customCfg = cfg) {
  if (!inb || !inb.tag || !srcIp) return true;
  if (!activeSessionLeases.has(inb.tag)) {
    activeSessionLeases.set(inb.tag, new Map());
  }
  const leaseMap = activeSessionLeases.get(inb.tag);
  const isSingleClient = (inb.clients?.length || 0) <= 1;
  const effectiveUser = (authUser && authUser !== 'default')
    ? authUser
    : (isSingleClient && inb.clients?.[0]?.email ? inb.clients[0].email : 'default');

  if (authUser === 'default' && !connId) {
    for (const existingEntry of leaseMap.values()) {
      if (existingEntry.ip === srcIp) {
        existingEntry.lastSeenAt = nowMs;
        return true;
      }
    }
  } else if (effectiveUser !== 'default') {
    const defaultKey = `${srcIp}#default`;
    if (leaseMap.has(defaultKey)) leaseMap.delete(defaultKey);
  }

  const allowedIps = new Set();
  for (const entry of leaseMap.values()) {
    allowedIps.add(entry.ip);
  }

  const limitIp = isSingleClient ? Number(inb.limitIp || inb.clients?.[0]?.limitIp || 0) : 0;
  const limitDevice = isSingleClient ? Number(inb.limitDevice || inb.clients?.[0]?.limitDevice || 0) : 0;

  const matchedClient = !isSingleClient && effectiveUser !== 'default'
    ? (inb.clients || []).find((cl) => cl.email === effectiveUser || cl.name === effectiveUser || cl.username === effectiveUser)
    : (isSingleClient ? inb.clients?.[0] : null);
  const canonicalUser = matchedClient ? (matchedClient.email || matchedClient.name || matchedClient.username || effectiveUser) : effectiveUser;
  const deviceFp = `${srcIp}#${canonicalUser}`;

  if (matchedClient && matchedClient.enable === false) {
    terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, allowedIps.has(srcIp), nowMs, customCfg);
    return false;
  }

  if (leaseMap.has(deviceFp)) {
    leaseMap.get(deviceFp).lastSeenAt = nowMs;
    return true;
  }

  const isIpAlreadyAllowed = allowedIps.has(srcIp);

  if (!isSingleClient && matchedClient) {
    const cLimIp = Number(matchedClient.limitIp || inb.limitIp || 0);
    const cLimDev = Number(matchedClient.limitDevice || inb.limitDevice || 0);
    if (cLimIp > 0 || cLimDev > 0) {
      const clientIps = new Set();
      let clientDevCount = 0;
      for (const entry of leaseMap.values()) {
        if (entry.user === canonicalUser) {
          clientIps.add(entry.ip);
          clientDevCount += 1;
        }
      }
      if (cLimIp > 0 && !clientIps.has(srcIp) && clientIps.size >= cLimIp) {
        terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, isIpAlreadyAllowed, nowMs, customCfg);
        return false;
      }
      if (cLimDev > 0 && clientDevCount >= cLimDev) {
        terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, isIpAlreadyAllowed, nowMs, customCfg);
        return false;
      }
    }
  } else {
    if (limitIp > 0 && !isIpAlreadyAllowed && allowedIps.size >= limitIp) {
      terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, false, nowMs, customCfg);
      return false;
    }
    if (limitDevice > 0 && leaseMap.size >= limitDevice) {
      terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, isIpAlreadyAllowed, nowMs, customCfg);
      return false;
    }
  }

  leaseMap.set(deviceFp, {
    ip: srcIp,
    deviceFp,
    user: canonicalUser,
    firstSeenAt: nowMs,
    lastSeenAt: nowMs
  });
  return true;
}

function pollLocalClashTraffic(customCfg = cfg) {
  return new Promise((resolve) => {
    if (inboundByTag.size === 0) {
      rebuildInboundPolicyIndex(null, null, customCfg);
    }
    const nowMs = Date.now();

    // 1. Prune expired 60s session leases
    for (const [tag, leaseMap] of activeSessionLeases.entries()) {
      for (const [devKey, entry] of leaseMap.entries()) {
        if (nowMs - entry.lastSeenAt > ACTIVE_LEASE_TTL_MS) {
          leaseMap.delete(devKey);
        }
      }
      if (leaseMap.size === 0) activeSessionLeases.delete(tag);
    }
    pruneExpiredTempIpBlocks(nowMs);

    const { portPeers, peerToLocalPort } = scanKernelEstablishedSockets();

    const clashPort = Number(customCfg.clashPort || cfg.clashPort || 10086);
    const clashSecret = customCfg.clashSecret !== undefined ? customCfg.clashSecret : cfg.clashSecret;

    const finalizeOnlineSnapshot = () => {
      const formattedOnline = {};
      for (const [tag, leaseMap] of activeSessionLeases.entries()) {
        if (leaseMap.size === 0) continue;
        const ipSet = new Set();
        const devSet = new Set();
        const clientsMap = {};
        let maxLastSeen = 0;
        for (const [devKey, entry] of leaseMap.entries()) {
          ipSet.add(entry.ip);
          devSet.add(devKey);
          if (entry.lastSeenAt > maxLastSeen) maxLastSeen = entry.lastSeenAt;
          const u = entry.user || 'default';
          if (!clientsMap[u]) {
            clientsMap[u] = { ipsSet: new Set(), devsSet: new Set(), lastOnline: 0 };
          }
          clientsMap[u].ipsSet.add(entry.ip);
          clientsMap[u].devsSet.add(devKey);
          if (entry.lastSeenAt > clientsMap[u].lastOnline) clientsMap[u].lastOnline = entry.lastSeenAt;
        }
        const serializedClients = {};
        for (const [u, cObj] of Object.entries(clientsMap)) {
          const cIps = [...cObj.ipsSet];
          serializedClients[u] = {
            ips: cIps,
            devices: Math.max(cObj.devsSet.size, cIps.length),
            lastOnline: cObj.lastOnline
          };
        }
        const ips = [...ipSet];
        formattedOnline[tag] = {
          ips,
          devices: Math.max(devSet.size, ips.length),
          lastOnline: maxLastSeen,
          clients: serializedClients
        };
      }
      latestInboundOnline = formattedOnline;

      const sig = JSON.stringify(
        Object.entries(formattedOnline).map(([t, v]) => [t, v.ips, v.devices])
      );
      if (sig !== lastOnlineSignature) {
        lastOnlineSignature = sig;
        if (!customCfg.skipAutoHeartbeat && !heartbeatInFlight && Date.now() - lastHeartbeatSentAt > 1200) {
          setImmediate(() => { sendHeartbeat({ skipClashPoll: true }).catch(() => {}); });
        }
      }
    };

    const req = http.request({
      hostname: '127.0.0.1',
      port: clashPort,
      path: '/connections',
      method: 'GET',
      headers: clashSecret ? { Authorization: `Bearer ${clashSecret}` } : {},
      timeout: 1500
    }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        try {
          const data = JSON.parse(raw || '{}');
          const conns = Array.isArray(data.connections) ? data.connections : [];
          const activeIds = new Set();

          for (const conn of conns) {
            if (!conn || !conn.id) continue;
            activeIds.add(conn.id);
            const curUp = Math.max(0, Number(conn.upload || 0));
            const curDown = Math.max(0, Number(conn.download || 0));
            const prev = connTrafficSeen.get(conn.id);
            let dUp = 0;
            let dDown = 0;
            if (prev) {
              dUp = Math.max(0, curUp - prev.up);
              dDown = Math.max(0, curDown - prev.down);
            } else {
              const connStartMs = conn.start ? Date.parse(conn.start) : 0;
              const isPreExisting = connStartMs > 0 && (nowMs - connStartMs) > 15000;
              if (!isPreExisting) {
                dUp = curUp;
                dDown = curDown;
              }
            }
            connTrafficSeen.set(conn.id, { up: curUp, down: curDown });

            const meta = conn.metadata || {};
            const srcIp = normalizeClientIp(meta.sourceIP);
            const srcPort = Number(meta.sourcePort || 0);
            const rawUser = String(meta.user || meta.authUser || '').trim();
            const chains = Array.isArray(conn.chains) ? conn.chains : [];

            const inb = resolveInboundTagAndPolicy(conn, peerToLocalPort);
            if (inb && inb.tag) {
              const allowed = srcIp
                ? registerOrEnforceClient(inb, srcIp, rawUser || 'default', srcPort, conn.id, nowMs, customCfg)
                : true;
              if (allowed) {
                addDelta(pendingInboundDeltas, inb.tag, dUp, dDown);
                const effClientEmail = rawUser || ((inb.clients?.length === 1 && inb.clients[0]?.email) ? inb.clients[0].email : '');
                if (effClientEmail) {
                  addDelta(pendingClientDeltas, effClientEmail, dUp, dDown);
                }
                for (const outTag of chains) {
                  if (outTag) addDelta(pendingOutboundDeltas, outTag, dUp, dDown);
                }
              }
            } else {
              for (const outTag of chains) {
                if (outTag) addDelta(pendingOutboundDeltas, outTag, dUp, dDown);
              }
            }
          }

          // Also merge any established kernel sockets on inbound ports (catches raw TCP / direct forwards / early handshakes)
          for (const [localPort, peerIpSet] of portPeers.entries()) {
            const inb = inboundByPort.get(localPort);
            if (!inb) continue;
            for (const peerIp of peerIpSet) {
              registerOrEnforceClient(inb, peerIp, 'default', 0, '', nowMs, customCfg);
            }
          }

          for (const oldId of connTrafficSeen.keys()) {
            if (!activeIds.has(oldId)) connTrafficSeen.delete(oldId);
          }
        } catch { /* ignore */ }
        finalizeOnlineSnapshot();
        resolve();
      });
    });

    req.on('error', () => {
      for (const [localPort, peerIpSet] of portPeers.entries()) {
        const inb = inboundByPort.get(localPort);
        if (!inb) continue;
        for (const peerIp of peerIpSet) {
          registerOrEnforceClient(inb, peerIp, 'default', 0, '', nowMs, customCfg);
        }
      }
      finalizeOnlineSnapshot();
      resolve();
    });
    req.on('timeout', () => {
      req.destroy();
      finalizeOnlineSnapshot();
      resolve();
    });
    req.end();
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
  if (sysCheck.status === 0 || (sbChild && !sbChild.killed)) {
    sbRunning = true;
  } else if (process.env.NG_TEST_MODE && configFile && fs.existsSync(configFile)) {
    sbRunning = true;
  } else {
    const pgCheck = spawnSync('pgrep', ['-x', 'sing-box']);
    if (pgCheck.status === 0) sbRunning = true;
  }

  return {
    cpuPct,
    memPct: Math.round((usedMem / totalMem) * 1000) / 10,
    memUsedMB: Math.round(usedMem / (1024 * 1024)),
    memTotalMB: Math.round(totalMem / (1024 * 1024)),
    sbRunning,
    sbVersion,
    agentVersion: AGENT_VERSION,
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
      const cleanDom = String(cert.domain || '').replace(/^\*\./, '').replace(/[^a-zA-Z0-9._-]/g, '');
      const certTargets = [cert.certPath];
      const keyTargets = [cert.keyPath];
      if (!process.env.NG_TEST_MODE && cleanDom) {
        certTargets.push(`/root/cert/${cleanDom}/fullchain.pem`, `/etc/nexusgate/certs/${cleanDom}/fullchain.pem`);
        keyTargets.push(`/root/cert/${cleanDom}/privkey.pem`, `/etc/nexusgate/certs/${cleanDom}/privkey.pem`);
      }
      if (cert.certPem) {
        for (const cp of [...new Set(certTargets.filter(Boolean))]) {
          try {
            fs.mkdirSync(path.dirname(cp), { recursive: true });
            fs.writeFileSync(cp, cert.certPem, { mode: 0o644 });
          } catch { /* ignore */ }
        }
      }
      if (cert.keyPem) {
        for (const kp of [...new Set(keyTargets.filter(Boolean))]) {
          try {
            fs.mkdirSync(path.dirname(kp), { recursive: true });
            fs.writeFileSync(kp, cert.keyPem, { mode: 0o600 });
          } catch { /* ignore */ }
        }
      }
    }
  }

  if (payload.singboxConfig || payload.inboundPolicies) {
    rebuildInboundPolicyIndex(payload.singboxConfig || null, payload.inboundPolicies || null, customCfg);
  }

  const targetConfigPath = customCfg.configPath || cfg.configPath;
  const nextHash = payload.configHash || '';
  const sbOnlyHash = payload.singboxConfig
    ? crypto.createHash('sha256').update(JSON.stringify({ s: payload.singboxConfig, c: (payload.certificates || []).map((x) => x.certPath) })).digest('hex').slice(0, 16)
    : '';
  const configExists = targetConfigPath && fs.existsSync(targetConfigPath);
  const needRestart = Boolean(
    payload.singboxConfig &&
    typeof payload.singboxConfig === 'object' &&
    (!configExists || !currentSbOnlyHash || sbOnlyHash !== currentSbOnlyHash || !nextHash)
  );

  if (needRestart) {
    fs.mkdirSync(path.dirname(targetConfigPath), { recursive: true });
    const tmpPath = `${targetConfigPath}.tmp.${process.pid}`;
    fs.writeFileSync(tmpPath, JSON.stringify(payload.singboxConfig, null, 2), { mode: 0o600 });
    fs.renameSync(tmpPath, targetConfigPath);
    if (sbOnlyHash) currentSbOnlyHash = sbOnlyHash;

    if (!process.env.NG_TEST_MODE) {
      stopConflictingLegacyXui();
      const inbPorts = (payload.singboxConfig.inbounds || []).map((i) => Number(i.listen_port)).filter((p) => p > 0 && p <= 65535);
      inbPorts.push(Number(customCfg.port || cfg.port || 19090));
      setImmediate(() => {
        for (const p of [...new Set(inbPorts)]) {
          try {
            spawnSync('ufw', ['allow', `${p}/tcp`], { timeout: 1500 });
            spawnSync('ufw', ['allow', `${p}/udp`], { timeout: 1500 });
          } catch { /* ignore */ }
        }
      });
    }

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

function tryOtaSelfUpgrade(masterBaseUrl, targetVersion) {
  if (process.env.NG_TEST_MODE || !masterBaseUrl || !targetVersion || targetVersion === AGENT_VERSION) return;
  try {
    const parsedUrl = new URL(`${String(masterBaseUrl).replace(/\/+$/, '')}/api/cluster/nexus-agent.js`);
    const client = parsedUrl.protocol === 'https:' ? https : http;
    const req = client.request({
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
      path: parsedUrl.pathname,
      method: 'GET',
      rejectUnauthorized: false,
      timeout: 8000
    }, (res) => {
      if (res.statusCode !== 200) return;
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        if (raw.includes('createAgentHttpServer') && raw.includes(targetVersion)) {
          try {
            const selfPath = '/opt/nexusgate-agent/nexus-agent.js';
            if (fs.existsSync(path.dirname(selfPath))) {
              const tmp = `${selfPath}.ota.${process.pid}`;
              fs.writeFileSync(tmp, raw, { mode: 0o755 });
              fs.renameSync(tmp, selfPath);
              saveOfflineState();
              setTimeout(() => process.exit(0), 200);
            }
          } catch { /* ignore */ }
        }
      });
    });
    req.on('error', () => {});
    req.end();
  } catch { /* ignore */ }
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

  ensureLocalSingboxRunning(customOpts);

  if (!primaryUrl && !standbyUrl) return { ok: false, autonomousMode: true };
  if (!token) return { ok: false, autonomousMode: true };

  heartbeatInFlight = true;
  lastHeartbeatSentAt = Date.now();
  try {
    if (!customOpts.skipClashPoll) {
      await pollLocalClashTraffic({ ...customOpts, skipAutoHeartbeat: true });
    }

    const snapshotInb = JSON.parse(JSON.stringify(pendingInboundDeltas));
    const snapshotCli = JSON.parse(JSON.stringify(pendingClientDeltas));
    const snapshotOut = JSON.parse(JSON.stringify(pendingOutboundDeltas));

    const bodyStr = JSON.stringify({
      nodeId,
      agentVersion: AGENT_VERSION,
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
      if (!usingStandbyMaster && standbyUrl && standbyUrl !== primaryUrl && consecutiveMasterFailures >= 2) {
        const standbyRes = await postHeartbeatToUrl(standbyUrl, bodyStr, token, nodeId, customOpts.timeoutMs || 4000);
        if (standbyRes.ok) {
          usingStandbyMaster = true;
          hbRes = standbyRes;
        }
      } else if (usingStandbyMaster && primaryUrl && primaryUrl !== standbyUrl) {
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

      for (const [k, snap] of Object.entries(snapshotInb)) {
        if (pendingInboundDeltas[k]) {
          pendingInboundDeltas[k].up = Math.max(0, pendingInboundDeltas[k].up - snap.up);
          pendingInboundDeltas[k].down = Math.max(0, pendingInboundDeltas[k].down - snap.down);
          if (pendingInboundDeltas[k].up === 0 && pendingInboundDeltas[k].down === 0) delete pendingInboundDeltas[k];
        }
      }
      for (const [k, snap] of Object.entries(snapshotCli)) {
        if (pendingClientDeltas[k]) {
          pendingClientDeltas[k].up = Math.max(0, pendingClientDeltas[k].up - snap.up);
          pendingClientDeltas[k].down = Math.max(0, pendingClientDeltas[k].down - snap.down);
          if (pendingClientDeltas[k].up === 0 && pendingClientDeltas[k].down === 0) delete pendingClientDeltas[k];
        }
      }
      for (const [k, snap] of Object.entries(snapshotOut)) {
        if (pendingOutboundDeltas[k]) {
          pendingOutboundDeltas[k].up = Math.max(0, pendingOutboundDeltas[k].up - snap.up);
          pendingOutboundDeltas[k].down = Math.max(0, pendingOutboundDeltas[k].down - snap.down);
          if (pendingOutboundDeltas[k].up === 0 && pendingOutboundDeltas[k].down === 0) delete pendingOutboundDeltas[k];
        }
      }

      const data = hbRes.data || {};
      if (data.standbyMasterUrl && data.standbyMasterUrl !== cfg.standbyMaster) {
        cfg.standbyMaster = String(data.standbyMasterUrl).trim();
      }
      if ((data.needsUpdate && data.singboxConfig) || data.inboundPolicies) {
        applySyncedPayload(data, customOpts);
      } else {
        saveOfflineState(customOpts.statePath || cfg.statePath);
      }
      const activeMasterUrl = usingStandbyMaster && standbyUrl ? standbyUrl : primaryUrl;
      if (data.targetAgentVersion && data.targetAgentVersion !== AGENT_VERSION) {
        tryOtaSelfUpgrade(activeMasterUrl, data.targetAgentVersion);
      }
      return {
        ok: true,
        autonomousMode: false,
        usingStandbyMaster,
        activeMasterUrl,
        configHash: currentConfigHash
      };
    }

    masterReachable = false;
    saveOfflineState(customOpts.statePath || cfg.statePath);
    return {
      ok: false,
      autonomousMode: true,
      usingStandbyMaster,
      consecutiveMasterFailures,
      bufferedInboundTags: Object.keys(pendingInboundDeltas).length
    };
  } finally {
    heartbeatInFlight = false;
  }
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
        version: AGENT_VERSION,
        nodeId: customCfg.nodeId || cfg.nodeId,
        configHash: currentConfigHash,
        autonomousDataPlane: true,
        masterReachable,
        usingStandbyMaster,
        standbyMaster: customCfg.standbyMaster || cfg.standbyMaster || '',
        lastMasterContactAt,
        inboundOnline: latestInboundOnline,
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
          version: AGENT_VERSION,
          nodeId: customCfg.nodeId || cfg.nodeId,
          configHash: currentConfigHash,
          autonomousDataPlane: true,
          masterReachable,
          usingStandbyMaster,
          standbyMaster: customCfg.standbyMaster || cfg.standbyMaster || '',
          bufferedInboundTags: Object.keys(pendingInboundDeltas),
          inboundOnline: latestInboundOnline,
          metrics: collectNodeMetrics(customCfg)
        });
      }

      return sendJson(404, { error: 'Not Found' });
    });
  });
}

if (require.main === module) {
  loadOfflineState();
  rebuildInboundPolicyIndex();
  ensureLocalSingboxRunning();
  const server = createAgentHttpServer(cfg);
  server.listen(cfg.port, '0.0.0.0', () => {
    console.log(`[NexusGate-Agent v${AGENT_VERSION}] Listening on 0.0.0.0:${cfg.port} (Node: ${cfg.nodeId}, 1s Real-Time Poller & Limit Enforcer Active)`);
    sendHeartbeat();
    // Poll local Sing-box Clash API & kernel sockets every 1s for sub-second connection capture & real-time IP/device limit enforcement
    setInterval(() => { pollLocalClashTraffic().catch(() => {}); }, 1000).unref();
    // Periodic heartbeat every 5s (plus instant event-driven heartbeat on online state change)
    setInterval(() => { sendHeartbeat({ skipClashPoll: false }).catch(() => {}); }, 5000).unref();
    setInterval(() => {
      ensureLocalSingboxRunning();
      if (connTrafficSeen.size > 4000) connTrafficSeen.clear();
      if (typeof global.gc === 'function') {
        try { global.gc(); } catch { /* ignore */ }
      }
    }, 60000).unref();
  });
}

module.exports = {
  AGENT_VERSION,
  cfg,
  addDelta,
  pendingInboundDeltas,
  pendingClientDeltas,
  pendingOutboundDeltas,
  activeSessionLeases,
  loadOfflineState,
  saveOfflineState,
  rebuildInboundPolicyIndex,
  ensureLocalSingboxRunning,
  applySyncedPayload,
  collectNodeMetrics,
  pollLocalClashTraffic,
  sendHeartbeat,
  createAgentHttpServer
};
