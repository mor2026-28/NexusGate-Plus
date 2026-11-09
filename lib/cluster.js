'use strict';

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const { toSingboxInbound, toSingboxOutbound, generateSsKey, normalizeSsMethod } = require('./protocols');
const { compileRouteRule } = require('./singbox');
const { randomToken } = require('./auth');

/**
 * Creates the default local master node record.
 */
function createDefaultLocalNode(settings = {}) {
  return {
    id: 'node_local',
    name: '主控本机 (Local Master)',
    role: 'relay', // 'relay' | 'exit' | 'standby' | 'hybrid'
    isLocal: true,
    enabled: true,
    host: settings.publicIPv4 || '127.0.0.1',
    agentPort: 19090,
    domain: settings.webDomain || settings.defaultTlsDomain || '',
    token: `ag_local_${randomToken(16)}`,
    region: 'Local',
    isp: 'Master Node',
    standbyNodeId: '',
    mirrorStandby: true,
    activeFailoverTo: '',
    failoverAt: '',
    cfZoneId: '',
    cfRecordId: '',
    cfRecordName: '',
    cfProxied: false,
    exitConfig: {
      enabled: false,
      protocol: 'shadowsocks',
      port: 28388,
      method: '2022-blake3-aes-128-gcm',
      password: generateSsKey('2022-blake3-aes-128-gcm'),
      uot: true
    },
    status: 'online',
    lastSeenAt: new Date().toISOString(),
    configHash: '',
    metrics: {
      cpuPct: 2.1,
      memPct: 14.5,
      memUsedMB: 28,
      memTotalMB: 1024,
      diskPct: 18.0,
      sbRunning: true,
      sbVersion: '1.12.23',
      activeConnections: 0,
      upSpeed: 0,
      downSpeed: 0
    },
    createdAt: new Date().toISOString()
  };
}

/**
 * Ensures state.nodes exists and contains at least `node_local`.
 * Also synchronizes shared exit outbounds generated from Exit/Hybrid nodes.
 */
function ensureClusterNodes(state) {
  if (!Array.isArray(state.nodes) || state.nodes.length === 0) {
    state.nodes = [createDefaultLocalNode(state.settings || {})];
  }
  let localNode = state.nodes.find((n) => n.id === 'node_local' || n.isLocal);
  if (!localNode) {
    localNode = createDefaultLocalNode(state.settings || {});
    state.nodes.unshift(localNode);
  }
  if (state.settings?.webDomain && !localNode.domain) {
    localNode.domain = state.settings.webDomain;
  }
  if (state.settings?.publicIPv4 && (!localNode.host || localNode.host === '127.0.0.1')) {
    localNode.host = state.settings.publicIPv4;
  }
  syncExitNodeOutbounds(state);
  return state.nodes;
}

/**
 * When a node has role === 'exit' or role === 'hybrid' (or exitConfig.enabled === true),
 * automatically registers/updates a corresponding shared Shadowsocks outbound in `state.outbounds`
 * so any Relay inbound across any Relay machine can route traffic to this Exit machine with 1 click.
 */
function syncExitNodeOutbounds(state) {
  if (!Array.isArray(state.nodes) || !Array.isArray(state.outbounds)) return;
  for (const node of state.nodes) {
    const isExitRole = node.role === 'exit' || node.role === 'hybrid' || Boolean(node.exitConfig?.enabled);
    const outTag = `exit-${node.id.replace(/^node_/, '')}`;
    const existingIdx = state.outbounds.findIndex((o) => o.exitNodeId === node.id || o.tag === outTag);

    if (!isExitRole || node.enabled === false) {
      continue;
    }

    if (!node.exitConfig) {
      node.exitConfig = {
        enabled: true,
        protocol: 'shadowsocks',
        port: 28388,
        method: '2022-blake3-aes-128-gcm',
        password: generateSsKey('2022-blake3-aes-128-gcm'),
        uot: true
      };
    }
    const method = normalizeSsMethod(node.exitConfig.method || '2022-blake3-aes-128-gcm');
    if (!node.exitConfig.password) {
      node.exitConfig.password = generateSsKey(method);
    }

    const outObj = {
      id: existingIdx >= 0 ? state.outbounds[existingIdx].id : `out_exit_${node.id}`,
      tag: existingIdx >= 0 ? state.outbounds[existingIdx].tag : outTag,
      type: 'shadowsocks',
      remark: `${node.name} [共享落地 SS]`,
      server: node.host || '127.0.0.1',
      port: Number(node.exitConfig.port || 28388),
      method,
      password: node.exitConfig.password,
      uot: node.exitConfig.uot !== false,
      enabled: true,
      sharedExit: true,
      exitNodeId: node.id,
      region: node.region || '',
      up: existingIdx >= 0 ? Number(state.outbounds[existingIdx].up || 0) : 0,
      down: existingIdx >= 0 ? Number(state.outbounds[existingIdx].down || 0) : 0
    };

    if (existingIdx >= 0) {
      state.outbounds[existingIdx] = {
        ...state.outbounds[existingIdx],
        ...outObj
      };
    } else {
      state.outbounds.push(outObj);
    }
  }
}

/**
 * Resolves the effective public domain or IP for an inbound based on its assigned Relay Node.
 */
function resolveInboundNodeHost(state, inbound, fallbackHost = '127.0.0.1') {
  if (inbound.publicHost) return inbound.publicHost;
  const nodeId = inbound.nodeId || 'node_local';
  const node = (state.nodes || []).find((n) => n.id === nodeId);
  if (node) {
    if (node.domain) return node.domain;
    if (node.host && node.host !== '127.0.0.1') return node.host;
  }
  return state.settings?.webDomain || state.settings?.publicIPv4 || fallbackHost || '127.0.0.1';
}

/**
 * Compiles the tailored Sing-box configuration and required SSL certificate bundle
 * for a specific cluster node (`nodeId`).
 *
 * - If `node` is a Standby node (`role === 'standby'`) that is currently taking over
 *   or mirroring a primary Relay node (`primaryNode.activeFailoverTo === node.id` or `primaryNode.mirrorStandby`),
 *   it compiles the exact inbounds, outbounds, routing rules, and SSL certs of those primary Relay node(s)!
 * - If `node` is an Exit node (`role === 'exit'`), it compiles the Shadowsocks / SS2022 exit inbound
 *   plus any direct inbounds explicitly assigned to `node.id`.
 * - If `node` is a Relay or Hybrid node, it compiles all inbounds assigned to `node.id`,
 *   all required outbounds (including Shared Exit outbounds), and all matching route rules.
 */
function compileNodeSingboxConfig(state, nodeId = 'node_local') {
  ensureClusterNodes(state);
  const settings = state.settings || {};
  const targetNode = (state.nodes || []).find((n) => n.id === nodeId) || state.nodes[0];
  if (!targetNode) {
    throw new Error(`未找到集群节点: ${nodeId}`);
  }

  // Determine which logical Relay node IDs this physical machine should serve:
  // 1. Its own nodeId
  // 2. Any primary Relay node that has failed over to this node (`activeFailoverTo === targetNode.id`)
  // 3. Any primary Relay node that has `standbyNodeId === targetNode.id` and `mirrorStandby === true`
  const servedNodeIds = new Set([targetNode.id]);
  const mirroredPrimaryNodes = [];
  for (const n of state.nodes || []) {
    if (n.id === targetNode.id) continue;
    if (n.activeFailoverTo === targetNode.id || (n.standbyNodeId === targetNode.id && n.mirrorStandby)) {
      servedNodeIds.add(n.id);
      mirroredPrimaryNodes.push(n);
    }
  }

  const activeInbounds = (state.inbounds || []).filter((inb) => {
    if (inb.enable === false) return false;
    const assignedNode = inb.nodeId || 'node_local';
    return servedNodeIds.has(assignedNode);
  });

  const sbInbounds = activeInbounds.map((item) => {
    const ownerNode = (state.nodes || []).find((n) => n.id === (item.nodeId || 'node_local')) || targetNode;
    const nodeSettings = {
      ...settings,
      webDomain: ownerNode.domain || settings.webDomain || '',
      defaultTlsDomain: ownerNode.domain || settings.defaultTlsDomain || ''
    };
    return toSingboxInbound(item, state.certificates || [], nodeSettings);
  });

  // If this node is an Exit or Hybrid node, inject its dedicated Shared Exit SS inbound
  if ((targetNode.role === 'exit' || targetNode.role === 'hybrid' || targetNode.exitConfig?.enabled) && targetNode.exitConfig) {
    const ec = targetNode.exitConfig;
    const exitPort = Number(ec.port || 28388);
    const alreadyHasPort = sbInbounds.some((i) => Number(i.listen_port) === exitPort);
    if (!alreadyHasPort) {
      sbInbounds.push({
        type: 'shadowsocks',
        tag: `exit-in-${targetNode.id}`,
        listen: '::',
        listen_port: exitPort,
        method: normalizeSsMethod(ec.method || '2022-blake3-aes-128-gcm'),
        password: ec.password || generateSsKey(ec.method),
        network: ['tcp', 'udp']
      });
    }
  }

  const activeOutbounds = (state.outbounds || []).filter((o) => o.enabled !== false);
  const sbOutbounds = activeOutbounds.map((item) => toSingboxOutbound(item));

  if (!sbOutbounds.some((o) => o.tag === 'direct')) {
    sbOutbounds.unshift({ type: 'direct', tag: 'direct' });
  }
  if (!sbOutbounds.some((o) => o.tag === 'block')) {
    sbOutbounds.push({ type: 'block', tag: 'block' });
  }

  const validInboundTags = new Set(sbInbounds.map((i) => i.tag));
  const validOutboundTags = new Set(sbOutbounds.map((o) => o.tag));
  const neededRuleSets = new Map();
  const routeRules = [{ action: 'sniff' }];

  const existingRuleInbounds = new Set();
  for (const r of (state.routing?.rules || [])) {
    if (
      r.enabled !== false &&
      Array.isArray(r.inbound) &&
      r.inbound.length > 0 &&
      !r.domain?.length &&
      !r.domain_suffix?.length &&
      !r.domain_keyword?.length &&
      !r.ip_cidr?.length &&
      !r.port?.length &&
      !r.protocol?.length &&
      !r.ip_is_private
    ) {
      for (const t of r.inbound) {
        if (validInboundTags.has(t)) existingRuleInbounds.add(t);
      }
    }
  }

  for (const inb of activeInbounds) {
    const tag = inb.tag || `in-${inb.protocol}-${inb.port}`;
    if (inb.outboundTag && inb.outboundTag !== 'default' && validOutboundTags.has(inb.outboundTag) && !existingRuleInbounds.has(tag)) {
      routeRules.push({
        inbound: [tag],
        outbound: inb.outboundTag
      });
    }
  }

  for (const rule of (state.routing?.rules || [])) {
    if (rule.enabled === false || rule.action === 'sniff') continue;
    const compiled = compileRouteRule(rule, neededRuleSets);
    if (Array.isArray(compiled.inbound)) {
      compiled.inbound = compiled.inbound.filter((t) => validInboundTags.has(t));
      if (compiled.inbound.length === 0) continue;
    }
    if (compiled.outbound && !validOutboundTags.has(compiled.outbound)) {
      compiled.outbound = 'direct';
    }
    const hasCondition = Object.keys(compiled).some((k) => !['action', 'outbound'].includes(k));
    if (hasCondition) {
      routeRules.push(compiled);
    }
  }

  const finalRuleSets = [];
  for (const [tag, localPath] of neededRuleSets.entries()) {
    finalRuleSets.push({
      tag,
      type: 'local',
      format: 'binary',
      path: localPath
    });
  }

  const finalOutbound = validOutboundTags.has(state.routing?.final) ? state.routing.final : 'direct';

  const singboxConfig = {
    log: {
      level: settings.singboxLogLevel || 'warn',
      timestamp: true
    },
    inbounds: sbInbounds,
    outbounds: sbOutbounds,
    route: {
      rules: routeRules,
      ...(finalRuleSets.length ? { rule_set: finalRuleSets } : {}),
      final: finalOutbound,
      auto_detect_interface: true
    },
    experimental: {
      clash_api: {
        external_controller: `127.0.0.1:${settings.clashApiPort || 10086}`,
        secret: settings.clashApiSecret || ''
      }
    }
  };

  // Collect SSL certificates referenced by this node's TLS/HY2/AnyTLS/TUIC inbounds
  const requiredCerts = [];
  const seenCertPaths = new Set();
  for (const sbInb of sbInbounds) {
    const cPath = sbInb.tls?.certificate_path;
    const kPath = sbInb.tls?.key_path;
    if (cPath && kPath && !seenCertPaths.has(cPath)) {
      seenCertPaths.add(cPath);
      const certRecord = (state.certificates || []).find((c) => c.certPath === cPath || c.keyPath === kPath);
      let certPem = certRecord?.certPem || '';
      let keyPem = certRecord?.keyPem || '';
      if (!certPem && fs.existsSync(cPath)) {
        try { certPem = fs.readFileSync(cPath, 'utf8'); } catch { /* ignore */ }
      }
      if (!keyPem && fs.existsSync(kPath)) {
        try { keyPem = fs.readFileSync(kPath, 'utf8'); } catch { /* ignore */ }
      }
      requiredCerts.push({
        domain: certRecord?.domain || targetNode.domain || 'default',
        certPath: cPath,
        keyPath: kPath,
        certPem,
        keyPem
      });
    }
  }

  const payloadStr = JSON.stringify({ singboxConfig, certs: requiredCerts.map((c) => ({ p: c.certPath, l: c.certPem.length })) });
  const configHash = crypto.createHash('sha256').update(payloadStr).digest('hex').slice(0, 16);

  return {
    nodeId: targetNode.id,
    nodeName: targetNode.name,
    role: targetNode.role,
    servedNodeIds: [...servedNodeIds],
    mirroredPrimaryNodes: mirroredPrimaryNodes.map((n) => ({ id: n.id, name: n.name, domain: n.domain })),
    configHash,
    singboxConfig,
    certificates: requiredCerts
  };
}

/**
 * Generates an HMAC-SHA256 signature for Master <-> Agent communication.
 */
function signAgentPayload(token, timestamp, bodyStr = '') {
  return crypto
    .createHmac('sha256', String(token || ''))
    .update(`${timestamp}.${bodyStr}`)
    .digest('hex');
}

/**
 * Pushes compiled Sing-box config and SSL certificates to a remote Agent node via HTTP/HTTPS.
 * If the node is only reachable via reverse-heartbeat Pull mode, marks `pendingSync = true`
 * so the Agent pulls it on its next 10s heartbeat.
 */
function pushConfigToAgentNode(state, nodeId, timeoutMs = 4500) {
  return new Promise((resolve) => {
    const compiled = compileNodeSingboxConfig(state, nodeId);
    const node = (state.nodes || []).find((n) => n.id === nodeId);
    if (!node) {
      return resolve({ ok: false, error: 'Node not found' });
    }
    node.configHash = compiled.configHash;

    if (node.isLocal || node.host === '127.0.0.1' || node.host === 'localhost') {
      node.lastSyncAt = new Date().toISOString();
      node.status = 'online';
      return resolve({
        ok: true,
        mode: 'local',
        configHash: compiled.configHash,
        inboundsCount: compiled.singboxConfig.inbounds.length
      });
    }

    const bodyStr = JSON.stringify({
      nodeId: node.id,
      configHash: compiled.configHash,
      singboxConfig: compiled.singboxConfig,
      certificates: compiled.certificates
    });
    const ts = String(Date.now());
    const sig = signAgentPayload(node.token, ts, bodyStr);

    const reqOpts = {
      hostname: node.host,
      port: Number(node.agentPort || 19090),
      path: '/agent/v1/sync',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(bodyStr),
        'X-Nexus-Node': node.id,
        'X-Nexus-Timestamp': ts,
        'X-Nexus-Signature': sig,
        Authorization: `Bearer ${node.token}`
      },
      timeout: timeoutMs
    };

    const client = node.agentTls ? https : http;
    const req = client.request(reqOpts, (res) => {
      let respData = '';
      res.on('data', (chunk) => { respData += chunk; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          node.status = 'online';
          node.lastSeenAt = new Date().toISOString();
          node.lastSyncAt = new Date().toISOString();
          node.pendingSync = false;
          resolve({
            ok: true,
            mode: 'push',
            configHash: compiled.configHash,
            inboundsCount: compiled.singboxConfig.inbounds.length
          });
        } else {
          node.pendingSync = true;
          resolve({
            ok: true,
            mode: 'queued-for-heartbeat',
            configHash: compiled.configHash,
            inboundsCount: compiled.singboxConfig.inbounds.length,
            note: `Agent 返回 HTTP ${res.statusCode}，已排队等待下次心跳自动拉取`
          });
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      node.pendingSync = true;
      resolve({
        ok: true,
        mode: 'queued-for-heartbeat',
        configHash: compiled.configHash,
        inboundsCount: compiled.singboxConfig.inbounds.length,
        note: '配置已生成并入队，Agent 将在下一次心跳 (≤10s) 自动拉取并热重载'
      });
    });

    req.on('error', () => {
      node.pendingSync = true;
      resolve({
        ok: true,
        mode: 'queued-for-heartbeat',
        configHash: compiled.configHash,
        inboundsCount: compiled.singboxConfig.inbounds.length,
        note: '配置已生成并入队，Agent 将在下一次心跳 (≤10s) 自动拉取并热重载'
      });
    });

    req.write(bodyStr);
    req.end();
  });
}

/**
 * Processes a heartbeat report from a remote Relay/Exit/Standby Agent.
 * Accumulates traffic deltas onto the Master store and returns whether the Agent needs to pull a new config.
 */
function handleAgentHeartbeat(store, nodeId, token, payload = {}) {
  return store.transact((state) => {
    ensureClusterNodes(state);
    const node = (state.nodes || []).find((n) => n.id === nodeId);
    if (!node) {
      throw new Error('未知的集群节点 ID');
    }
    if (node.token && token !== node.token) {
      throw new Error('Agent 密钥校验失败');
    }

    node.status = 'online';
    node.lastSeenAt = new Date().toISOString();
    if (payload.metrics && typeof payload.metrics === 'object') {
      node.metrics = {
        ...node.metrics,
        ...payload.metrics
      };
    }

    // Apply traffic deltas reported by the Agent
    if (payload.inboundDeltas && typeof payload.inboundDeltas === 'object') {
      for (const [tag, delta] of Object.entries(payload.inboundDeltas)) {
        const inb = (state.inbounds || []).find((i) => i.tag === tag);
        if (inb) {
          inb.up = Number(inb.up || 0) + Math.max(0, Number(delta.up || 0));
          inb.down = Number(inb.down || 0) + Math.max(0, Number(delta.down || 0));
          inb.lastOnline = Date.now();
        }
      }
    }

    if (payload.clientDeltas && typeof payload.clientDeltas === 'object') {
      for (const [email, delta] of Object.entries(payload.clientDeltas)) {
        for (const inb of state.inbounds || []) {
          const client = (inb.clients || []).find((c) => c.email === email);
          if (client) {
            client.up = Number(client.up || 0) + Math.max(0, Number(delta.up || 0));
            client.down = Number(client.down || 0) + Math.max(0, Number(delta.down || 0));
            client.lastOnline = Date.now();
          }
        }
      }
    }

    if (payload.outboundDeltas && typeof payload.outboundDeltas === 'object') {
      for (const [tag, delta] of Object.entries(payload.outboundDeltas)) {
        const out = (state.outbounds || []).find((o) => o.tag === tag);
        if (out) {
          out.up = Number(out.up || 0) + Math.max(0, Number(delta.up || 0));
          out.down = Number(out.down || 0) + Math.max(0, Number(delta.down || 0));
        }
      }
    }

    const compiled = compileNodeSingboxConfig(state, node.id);
    node.configHash = compiled.configHash;
    const needsUpdate = payload.configHash !== compiled.configHash || Boolean(node.pendingSync);
    if (needsUpdate) {
      node.pendingSync = false;
      node.lastSyncAt = new Date().toISOString();
    }

    return {
      ok: true,
      nodeId: node.id,
      configHash: compiled.configHash,
      needsUpdate,
      ...(needsUpdate
        ? {
            singboxConfig: compiled.singboxConfig,
            certificates: compiled.certificates
          }
        : {})
    };
  });
}

/**
 * Generates the 1-line shell command to install and register `nexus-agent` on a remote Relay/Exit/Standby server.
 */
function buildAgentInstallCommand(state, node, reqHost = '') {
  const cleanHost = String(reqHost || '').split(':')[0] || state.settings?.webDomain || state.settings?.publicIPv4 || 'MASTER_IP';
  const port = state.settings?.webPort || 2053;
  const proto = state.settings?.webCertFile ? 'https' : 'http';
  const basePath = (state.settings?.webBasePath || '/').replace(/\/+$/, '');
  const masterUrl = `${proto}://${cleanHost}:${port}${basePath}`;
  const repo = process.env.NG_REPO || 'mor2026-28/NexusGate-Plus';
  return `curl -fsSL https://raw.githubusercontent.com/${repo}/main/scripts/install-agent.sh | bash -s -- --master "${masterUrl}" --node-id "${node.id}" --token "${node.token}" --port "${node.agentPort || 19090}"`;
}

module.exports = {
  createDefaultLocalNode,
  ensureClusterNodes,
  syncExitNodeOutbounds,
  resolveInboundNodeHost,
  compileNodeSingboxConfig,
  signAgentPayload,
  pushConfigToAgentNode,
  handleAgentHeartbeat,
  buildAgentInstallCommand
};
