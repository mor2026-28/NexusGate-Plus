'use strict';

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const crypto = require('node:crypto');
const {
  certMatchesDomain,
  toSingboxInbound,
  toSingboxOutbound,
  generateSsKey,
  normalizeSsMethod,
  deriveRealityPublicKey,
  ensureUuid
} = require('./protocols');
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
    standbySyncMode: 'on_change', // 'on_change' | 'daily' | 'on_failover'
    autoFailover: true,
    autoFailoverMinutes: 3,
    autoFailback: false,
    fallbackExitNodeId: '',
    activeFailoverTo: '',
    failoverAt: '',
    cfZoneId: '',
    cfRecordId: '',
    cfRecordName: '',
    cfProxied: false,
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
 * Converts an Inbound created on an Exit Server (or marked exposeAsOutbound)
 * into a synchronized Outbound object in `state.outbounds` so any Relay server
 * can select it as a forwarding target (`Inbound ➔ Outbound`).
 */
function buildOutboundFromExitInbound(inbound, exitNode) {
  const proto = String(inbound.protocol || 'shadowsocks').toLowerCase();
  if (proto === 'direct' || proto === 'http' || proto === 'mixed') return null;

  const firstClient = (inbound.clients && inbound.clients[0]) || {};
  const serverHost = inbound.publicHost || exitNode.domain || exitNode.host || '127.0.0.1';
  const port = Number(inbound.port || 443);
  const outTag = `exit-${inbound.tag}`;
  const remark = `[落地:${exitNode.name}] ${inbound.remark || inbound.tag} (${proto.toUpperCase()}:${port})`;

  const out = {
    id: `out_inb_${inbound.id}`,
    tag: outTag,
    type: proto,
    remark,
    server: serverHost,
    port,
    enabled: inbound.enable !== false,
    security: inbound.security || 'none',
    transport: inbound.transport || 'tcp',
    sharedExit: true,
    exitNodeId: exitNode.id,
    linkedInboundId: inbound.id,
    up: Number(inbound.up || 0),
    down: Number(inbound.down || 0)
  };

  if (proto === 'shadowsocks') {
    out.method = normalizeSsMethod(inbound.method || '2022-blake3-aes-128-gcm');
    out.password = inbound.password || firstClient.password || '';
    out.uot = Boolean(inbound.uot);
  } else if (proto === 'vless' || proto === 'vmess') {
    out.uuid = ensureUuid(firstClient.id || inbound.uuid || '');
    out.flow = firstClient.flow || inbound.flow || '';
  } else if (proto === 'trojan' || proto === 'hysteria2' || proto === 'anytls') {
    out.password = firstClient.password || inbound.password || '';
  } else if (proto === 'socks') {
    out.username = firstClient.username || inbound.socksUser || '';
    out.password = firstClient.password || inbound.socksPassword || '';
  } else if (proto === 'tuic') {
    out.uuid = ensureUuid(firstClient.id || inbound.uuid || '');
    out.password = firstClient.password || inbound.password || '';
  }

  if (inbound.security === 'reality' && inbound.reality) {
    out.sni = inbound.reality.serverName || 'tesla.com';
    out.publicKey = inbound.reality.publicKey || deriveRealityPublicKey(inbound.reality.privateKey || '');
    out.shortId = Array.isArray(inbound.reality.shortIds) ? (inbound.reality.shortIds[0] || '') : '';
    out.fingerprint = inbound.reality.fingerprint || 'chrome';
  } else if (inbound.security === 'tls') {
    out.sni = inbound.tlsDomain || exitNode.domain || serverHost;
    out.insecure = Boolean(inbound.allowInsecure);
  }

  if (inbound.transport === 'ws' || inbound.transport === 'httpupgrade') {
    out.wsPath = inbound.wsPath || '/';
    out.wsHost = inbound.wsHost || '';
  } else if (inbound.transport === 'grpc') {
    out.grpcServiceName = inbound.grpcServiceName || 'grpc';
  }

  return out;
}

/**
 * Synchronizes `state.outbounds` with:
 * 1) Any Inbound nodes created on Exit servers (`node.role === 'exit'` or `inbound.exposeAsOutbound === true`)
 * 2) Optional explicit `node.exitConfig.enabled === true` (when user explicitly requests a quick exit SS port)
 * Also cleans up stale auto-generated outbounds whose source inbound or exit node was deleted.
 */
function syncExitNodeOutbounds(state) {
  if (!Array.isArray(state.nodes) || !Array.isArray(state.outbounds)) return;
  const nodesById = new Map(state.nodes.map((n) => [n.id, n]));
  const inboundsById = new Map((state.inbounds || []).map((i) => [i.id, i]));

  // 1. Remove auto-linked outbounds whose source inbound or exit node no longer exists
  state.outbounds = state.outbounds.filter((o) => {
    if (o.linkedInboundId && !inboundsById.has(o.linkedInboundId)) {
      return false;
    }
    if (o.exitNodeId && !o.linkedInboundId) {
      const n = nodesById.get(o.exitNodeId);
      const isExitActive = n && n.enabled !== false && (n.role === 'exit' || n.role === 'hybrid') && n.exitConfig?.enabled === true;
      if (!isExitActive) return false;
    }
    return true;
  });

  // 2. For every inbound created on an Exit server (`role === 'exit'`) or with `exposeAsOutbound`,
  //    automatically create/update its matching Outbound in `state.outbounds`!
  for (const inb of state.inbounds || []) {
    const ownerNode = nodesById.get(inb.nodeId || 'node_local');
    const shouldExpose = Boolean(inb.exposeAsOutbound);
    const existingIdx = state.outbounds.findIndex((o) => o.linkedInboundId === inb.id);

    if (!shouldExpose) {
      if (existingIdx >= 0) {
        state.outbounds.splice(existingIdx, 1);
      }
      continue;
    }

    const builtOut = buildOutboundFromExitInbound(inb, ownerNode || state.nodes[0]);
    if (!builtOut) continue;

    if (existingIdx >= 0) {
      const oldTag = state.outbounds[existingIdx].tag;
      state.outbounds[existingIdx] = {
        ...state.outbounds[existingIdx],
        ...builtOut,
        id: state.outbounds[existingIdx].id
      };
      if (oldTag !== builtOut.tag) {
        for (const rInb of state.inbounds || []) {
          if (rInb.outboundTag === oldTag) rInb.outboundTag = builtOut.tag;
        }
        for (const rule of state.routing?.rules || []) {
          if (rule.outbound === oldTag) rule.outbound = builtOut.tag;
        }
      }
    } else {
      state.outbounds.push(builtOut);
    }
  }

  // 3. Automatically provision & register Shared Exit SS outbound for every Exit / Hybrid server
  //    Supports Exit-to-Exit Fault Tolerance (if an Exit node is offline/failed over and has fallbackExitNodeId, seamlessly uses fallback Exit credentials)
  const sharedExitTags = [];
  for (const node of state.nodes) {
    const isExitRole = node.role === 'exit' || node.role === 'hybrid';
    if (!isExitRole) { if (node.exitConfig) node.exitConfig.enabled = false; continue; }
    if (node.enabled === false || node.exitConfig?.enabled !== true) continue;
    const outTag = `exit-${node.id.replace(/^node_/, '')}`;
    const existingIdx = state.outbounds.findIndex((o) => o.exitNodeId === node.id && !o.linkedInboundId);
    const method = normalizeSsMethod(node.exitConfig.method || '2022-blake3-aes-128-gcm');
    if (!node.exitConfig.password) {
      node.exitConfig.password = generateSsKey(method);
    }

    // Check if this Exit server has failed over to a backup Exit server
    const fbTargetId = node.activeFailoverTo || (node.status === 'offline' && node.fallbackExitNodeId ? node.fallbackExitNodeId : '');
    const fbExitNode = fbTargetId ? nodesById.get(fbTargetId) : null;
    const effectiveExitNode = (fbExitNode && fbExitNode.enabled !== false && fbExitNode.exitConfig) ? fbExitNode : node;
    const effMethod = normalizeSsMethod(effectiveExitNode.exitConfig?.method || method);
    const effPass = effectiveExitNode.exitConfig?.password || node.exitConfig.password;
    const effPort = Number(effectiveExitNode.exitConfig?.port || node.exitConfig.port || 28388);
    const effHost = effectiveExitNode.host || node.host || '127.0.0.1';
    const fbSuffix = effectiveExitNode.id !== node.id ? ` [⚡容错接管: ${effectiveExitNode.name}]` : '';

    const finalTag = existingIdx >= 0 ? state.outbounds[existingIdx].tag : outTag;
    sharedExitTags.push(finalTag);

    const outObj = {
      id: existingIdx >= 0 ? state.outbounds[existingIdx].id : `out_exit_${node.id}`,
      tag: finalTag,
      type: 'shadowsocks',
      remark: `${node.name} [共享落地 SS]${fbSuffix}`,
      server: effHost,
      port: effPort,
      method: effMethod,
      password: effPass,
      uot: node.exitConfig.uot !== false,
      enabled: true,
      sharedExit: true,
      exitNodeId: node.id,
      activeExitNodeId: effectiveExitNode.id,
      fallbackExitNodeId: node.fallbackExitNodeId || '',
      region: node.region || '',
      up: existingIdx >= 0 ? Number(state.outbounds[existingIdx].up || 0) : 0,
      down: existingIdx >= 0 ? Number(state.outbounds[existingIdx].down || 0) : 0
    };
    if (existingIdx >= 0) {
      state.outbounds[existingIdx] = { ...state.outbounds[existingIdx], ...outObj };
    } else {
      state.outbounds.push(outObj);
    }
  }

  // 4. Maintain automatic High-Availability Shared Exit Pool (`exit-ha-pool` urltest group) when >= 2 shared exits exist
  const haIdx = state.outbounds.findIndex((o) => o.id === 'out_exit_ha_pool' || o.tag === 'exit-ha-pool');
  if (sharedExitTags.length >= 2) {
    const haObj = {
      id: 'out_exit_ha_pool',
      tag: 'exit-ha-pool',
      type: 'urltest',
      remark: `⚡ 共享落地高可用自动容错池 (${sharedExitTags.length} 台落地自动测速切换)`,
      server: 'urltest-auto-failover',
      port: 0,
      outbounds: sharedExitTags,
      enabled: true,
      sharedExitHaPool: true,
      up: haIdx >= 0 ? Number(state.outbounds[haIdx].up || 0) : 0,
      down: haIdx >= 0 ? Number(state.outbounds[haIdx].down || 0) : 0
    };
    if (haIdx >= 0) state.outbounds[haIdx] = haObj;
    else state.outbounds.push(haObj);
  } else if (haIdx >= 0) {
    state.outbounds.splice(haIdx, 1);
  }
}

/**
 * Ensures state.nodes exists and contains at least `node_local`.
 * Also synchronizes shared exit outbounds generated from Exit nodes.
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
 * Resolves the effective public domain or IP for an inbound based on its assigned Server Node.
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
 * Returns the set of logical node IDs that a physical machine (`nodeId`) should serve:
 * - Its own `nodeId`
 * - Any primary Relay node that has failed over to `nodeId` (`activeFailoverTo === nodeId`)
 * - Any primary Relay node that has `standbyNodeId === nodeId` and `mirrorStandby === true`
 */
function getServedNodeIds(state, nodeId = 'node_local') {
  const served = new Set([nodeId]);
  const mirroredPrimaryNodes = [];
  const allNodes = state.nodes || [];
  const activeFailoverPrimaries = allNodes.filter((n) => n.id !== nodeId && n.activeFailoverTo === nodeId);
  const boundPrimaries = allNodes.filter((n) => n.id !== nodeId && n.standbyNodeId === nodeId);
  const isSharedStandby = boundPrimaries.length > 1;

  // If this Standby node is actively taking over for one or more failed Primary nodes,
  // ONLY load its own inbounds + the actively failed-over Primary nodes (never mix pre-warmed ports from other healthy Primaries!)
  if (activeFailoverPrimaries.length > 0) {
    for (const n of activeFailoverPrimaries) {
      served.add(n.id);
      mirroredPrimaryNodes.push(n);
    }
    return { servedNodeIds: served, mirroredPrimaryNodes, isSharedStandby, activeFailoverCount: activeFailoverPrimaries.length };
  }

  for (const n of allNodes) {
    if (n.id === nodeId) continue;
    const syncMode = n.standbySyncMode || (n.mirrorStandby === false ? 'on_failover' : 'on_change');
    // When a single Standby machine is shared by multiple Primary machines (1-to-N shared standby),
    // keep it idle (0 ports occupied) while all Primaries are healthy so A/B/C never collide on ports!
    const shouldPrewarm = n.standbyNodeId === nodeId && n.mirrorStandby !== false && syncMode !== 'on_failover' && !isSharedStandby;
    if (shouldPrewarm) {
      served.add(n.id);
      mirroredPrimaryNodes.push(n);
    }
  }
  return { servedNodeIds: served, mirroredPrimaryNodes, isSharedStandby, activeFailoverCount: 0 };
}

/**
 * Compiles the tailored Sing-box configuration and required SSL certificate bundle
 * for a specific cluster node (`nodeId`).
 */
const _compiledNodeCache = new Map();

function compileNodeSingboxConfig(state, nodeId = 'node_local') {
  const cfgVer = state._configVersion || 0;
  const cacheKey = `${nodeId}::${cfgVer}`;
  if (cfgVer > 0 && _compiledNodeCache.has(cacheKey)) {
    return _compiledNodeCache.get(cacheKey);
  }
  ensureClusterNodes(state);
  const settings = state.settings || {};
  const targetNode = (state.nodes || []).find((n) => n.id === nodeId) || state.nodes[0];
  if (!targetNode) {
    throw new Error(`未找到集群节点: ${nodeId}`);
  }

  const { servedNodeIds, mirroredPrimaryNodes } = getServedNodeIds(state, targetNode.id);

  const nodesMap = new Map((state.nodes || []).map((n) => [n.id, n]));
  const rawActiveInbounds = (state.inbounds || []).filter((inb) => {
    if (inb.enable === false) return false;
    const assignedNode = inb.nodeId || 'node_local';
    return servedNodeIds.has(assignedNode);
  });

  // Sort by priority (0 = targetNode own inbounds, 1 = actively failed-over primary inbounds, 2 = pre-warmed mirrorStandby inbounds)
  // and deduplicate by listen port so a Standby node mirroring multiple Relays never binds the same port twice!
  rawActiveInbounds.sort((a, b) => {
    const na = a.nodeId || 'node_local';
    const nb = b.nodeId || 'node_local';
    const pa = na === targetNode.id ? 0 : (nodesMap.get(na)?.activeFailoverTo === targetNode.id ? 1 : 2);
    const pb = nb === targetNode.id ? 0 : (nodesMap.get(nb)?.activeFailoverTo === targetNode.id ? 1 : 2);
    return pa - pb;
  });

  const usedListenPorts = new Set();
  const activeInbounds = [];
  for (const inb of rawActiveInbounds) {
    const p = Number(inb.port);
    if (p > 0 && usedListenPorts.has(p)) continue;
    if (p > 0) usedListenPorts.add(p);
    activeInbounds.push(inb);
  }

  const sbInbounds = activeInbounds.map((item) => {
    const ownerNode = nodesMap.get(item.nodeId || 'node_local') || targetNode;
    const ownerCert = ownerNode.domain
      ? (state.certificates || []).find((c) => c.domain === ownerNode.domain && c.valid !== false)
      : null;
    const nodeSettings = {
      ...settings,
      webDomain: ownerNode.domain || settings.webDomain || '',
      defaultTlsDomain: ownerNode.domain || settings.defaultTlsDomain || '',
      defaultCertFile: ownerCert ? ownerCert.certPath : (ownerNode.isLocal ? settings.defaultCertFile : ''),
      defaultKeyFile: ownerCert ? ownerCert.keyPath : (ownerNode.isLocal ? settings.defaultKeyFile : '')
    };
    return toSingboxInbound(item, state.certificates || [], nodeSettings);
  });

  // If explicit exitConfig.enabled is set on this node, ensure its SS inbound is present
  if ((targetNode.role === 'exit' || targetNode.role === 'hybrid') && targetNode.exitConfig?.enabled === true) {
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

  // Exclude self-referential outbounds (outbounds created from this very node's own inbounds)
  const selfOutTags = new Set(
    (state.outbounds || []).filter((o) => o.exitNodeId === targetNode.id).map((o) => o.tag)
  );
  const activeOutbounds = (state.outbounds || [])
    .filter((o) => o.enabled !== false && o.exitNodeId !== targetNode.id)
    .map((o) => {
      if (o.type === 'urltest' && Array.isArray(o.outbounds)) {
        const filteredMembers = o.outbounds.filter((t) => !selfOutTags.has(t));
        if (!filteredMembers.length) return null;
        return { ...o, outbounds: filteredMembers };
      }
      return o;
    })
    .filter(Boolean);
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

  const blockRules = [];
  const otherCompiledRules = [];
  for (const rule of (state.routing?.rules || [])) {
    if (rule.enabled === false || rule.action === 'sniff') continue;
    if (rule.nodeId && rule.nodeId !== 'all' && !servedNodeIds.has(rule.nodeId)) continue;
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
      if (compiled.outbound === 'block' || compiled.action === 'reject') {
        blockRules.push(compiled);
      } else {
        otherCompiledRules.push(compiled);
      }
    }
  }

  // Evaluate block rules (e.g. ping0.cc, bittorrent, ip_is_private) BEFORE inbound->outbound relay rules!
  routeRules.push(...blockRules);

  for (const inb of activeInbounds) {
    const tag = inb.tag || `in-${inb.protocol}-${inb.port}`;
    if (inb.outboundTag && inb.outboundTag !== 'default' && validOutboundTags.has(inb.outboundTag) && !existingRuleInbounds.has(tag)) {
      routeRules.push({
        inbound: [tag],
        outbound: inb.outboundTag
      });
    }
  }

  routeRules.push(...otherCompiledRules);

  const finalOutbound = validOutboundTags.has(state.routing?.final) ? state.routing.final : 'direct';

  // For inbounds using default routing, append an explicit inbound->finalOutbound rule at the end so Sing-box Clash API always includes inbound=[tag] in conn.rule!
  for (const inb of activeInbounds) {
    const tag = inb.tag || `in-${inb.protocol}-${inb.port}`;
    if ((!inb.outboundTag || inb.outboundTag === 'default') && !existingRuleInbounds.has(tag)) {
      routeRules.push({
        inbound: [tag],
        outbound: finalOutbound
      });
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
        secret: targetNode.isLocal ? (settings.clashApiSecret || '') : ''
      }
    }
  };

  const requiredCerts = [];
  const seenCertPaths = new Set();
  for (const sbInb of sbInbounds) {
    const cPath = sbInb.tls?.certificate_path;
    const kPath = sbInb.tls?.key_path;
    if (cPath && kPath && !seenCertPaths.has(cPath)) {
      seenCertPaths.add(cPath);
      const certRecord = (state.certificates || []).find(
        (c) => c.certPath === cPath || c.keyPath === kPath || (sbInb.tls?.server_name && certMatchesDomain(c.domain, sbInb.tls.server_name))
      );
      let certPem = certRecord?.certPem || '';
      let keyPem = certRecord?.keyPem || '';
      if (!certPem && fs.existsSync(cPath)) {
        try { certPem = fs.readFileSync(cPath, 'utf8'); } catch { /* ignore */ }
      }
      if (!certPem && certRecord?.certPath && fs.existsSync(certRecord.certPath)) {
        try { certPem = fs.readFileSync(certRecord.certPath, 'utf8'); } catch { /* ignore */ }
      }
      if (!keyPem && fs.existsSync(kPath)) {
        try { keyPem = fs.readFileSync(kPath, 'utf8'); } catch { /* ignore */ }
      }
      if (!keyPem && certRecord?.keyPath && fs.existsSync(certRecord.keyPath)) {
        try { keyPem = fs.readFileSync(certRecord.keyPath, 'utf8'); } catch { /* ignore */ }
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

  const inboundPolicies = activeInbounds.map((inb) => ({
    tag: inb.tag || `in-${inb.protocol}-${inb.port}`,
    port: Number(inb.port || 0),
    remark: inb.remark || inb.tag,
    limitIp: Math.max(0, Number(inb.limitIp || 0)),
    limitDevice: Math.max(0, Number(inb.limitDevice || 0)),
    clients: (inb.clients || []).map((c) => ({
      email: c.email || c.name || c.username || 'default',
      enable: c.enable !== false,
      limitIp: Math.max(0, Number(c.limitIp || 0)),
      limitDevice: Math.max(0, Number(c.limitDevice || 0))
    }))
  }));

  const payloadStr = JSON.stringify({
    singboxConfig,
    certs: requiredCerts.map((c) => ({ p: c.certPath, l: c.certPem.length })),
    policies: inboundPolicies
  });
  const configHash = crypto.createHash('sha256').update(payloadStr).digest('hex').slice(0, 16);

  const result = {
    nodeId: targetNode.id,
    nodeName: targetNode.name,
    role: targetNode.role,
    servedNodeIds: [...servedNodeIds],
    mirroredPrimaryNodes: mirroredPrimaryNodes.map((n) => ({ id: n.id, name: n.name, domain: n.domain })),
    configHash,
    singboxConfig,
    inboundPolicies,
    certificates: requiredCerts
  };
  if (cfgVer > 0) {
    if (_compiledNodeCache.size > 200) _compiledNodeCache.clear();
    _compiledNodeCache.set(cacheKey, result);
  }
  return result;
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
 */
function pushConfigToAgentNode(state, nodeId, timeoutMs = 4500) {
  return new Promise((resolve) => {
    const compiled = compileNodeSingboxConfig(state, nodeId);
    const node = (state.nodes || []).find((n) => n.id === nodeId);
    if (!node) {
      return resolve({ ok: false, error: 'Node not found' });
    }
    node.configHash = compiled.configHash;

    if (process.env.NG_TEST_MODE === '1' && !node.isLocal && node.host !== '127.0.0.1' && node.host !== 'localhost') {
      node.pendingSync = true;
      return resolve({ ok: true, mode: 'queued-for-heartbeat', configHash: compiled.configHash, inboundsCount: compiled.singboxConfig.inbounds.length });
    }
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
      inboundPolicies: compiled.inboundPolicies,
      certificates: compiled.certificates,
      standbyMasterUrl: state.settings?.standbyMasterUrl || ""
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
 */
function handleAgentHeartbeat(store, nodeId, token, payload = {}) {
  const state = store.state;
  const runHeartbeat = () => {
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

    const nowMs = Date.now();
    const { servedNodeIds } = getServedNodeIds(state, node.id);
    const findNodeInbound = (tag) =>
      (state.inbounds || []).find((i) => servedNodeIds.has(i.nodeId || 'node_local') && (i.tag === tag || `in-${i.protocol}-${i.port}` === tag)) ||
      (state.inbounds || []).find((i) => i.tag === tag || `in-${i.protocol}-${i.port}` === tag);

    const updatedClientEmails = new Set();
    if (payload.clientDeltas && typeof payload.clientDeltas === 'object') {
      for (const [email, delta] of Object.entries(payload.clientDeltas)) {
        const dUp = Math.max(0, Number(delta?.up || 0));
        const dDown = Math.max(0, Number(delta?.down || 0));
        if (dUp <= 0 && dDown <= 0) continue;
        const candidateInbounds = [
          ...(state.inbounds || []).filter((i) => servedNodeIds.has(i.nodeId || 'node_local')),
          ...(state.inbounds || []).filter((i) => !servedNodeIds.has(i.nodeId || 'node_local'))
        ];
        for (const inb of candidateInbounds) {
          const client = (inb.clients || []).find((c) => c.email === email || c.name === email || c.username === email);
          if (client) {
            client.up = Number(client.up || 0) + dUp;
            client.down = Number(client.down || 0) + dDown;
            client.lastOnline = nowMs;
            inb.lastOnline = nowMs;
            updatedClientEmails.add(client.email);
            break;
          }
        }
      }
    }

    if (payload.inboundDeltas && typeof payload.inboundDeltas === 'object') {
      for (const [tag, delta] of Object.entries(payload.inboundDeltas)) {
        const dUp = Math.max(0, Number(delta?.up || 0));
        const dDown = Math.max(0, Number(delta?.down || 0));
        if (dUp <= 0 && dDown <= 0) continue;
        const inb = findNodeInbound(tag);
        if (inb) {
          inb.up = Number(inb.up || 0) + dUp;
          inb.down = Number(inb.down || 0) + dDown;
          inb.lastOnline = nowMs;
          if (Array.isArray(inb.clients) && inb.clients.length === 1) {
            const c0 = inb.clients[0];
            c0.lastOnline = nowMs;
            if (!updatedClientEmails.has(c0.email)) {
              c0.up = Number(c0.up || 0) + dUp;
              c0.down = Number(c0.down || 0) + dDown;
            }
          }
        }
      }
    }

    if (payload.outboundDeltas && typeof payload.outboundDeltas === 'object') {
      for (const [tag, delta] of Object.entries(payload.outboundDeltas)) {
        const out = (state.outbounds || []).find((o) => o.tag === tag);
        if (out) {
          out.up = Number(out.up || 0) + Math.max(0, Number(delta?.up || 0));
          out.down = Number(out.down || 0) + Math.max(0, Number(delta?.down || 0));
        }
      }
    }

    if (payload.inboundOnline && typeof payload.inboundOnline === 'object') {
      // Clear stale online status for inbounds served primarily by this node that are no longer in payload.inboundOnline
      for (const inb of state.inbounds || []) {
        if ((inb.nodeId || 'node_local') === node.id && !Object.prototype.hasOwnProperty.call(payload.inboundOnline, inb.tag)) {
          inb.remoteActiveIps = [];
          inb.remoteActiveDevices = 0;
          inb.remoteClientOnline = {};
        }
      }
      for (const [tag, onlineInfo] of Object.entries(payload.inboundOnline)) {
        const inb = findNodeInbound(tag);
        if (inb && onlineInfo && typeof onlineInfo === 'object') {
          inb.remoteActiveIps = Array.isArray(onlineInfo.ips) ? onlineInfo.ips : [];
          inb.remoteActiveDevices = Number(onlineInfo.devices || inb.remoteActiveIps.length || 0);
          inb.remoteClientOnline = (onlineInfo.clients && typeof onlineInfo.clients === 'object') ? onlineInfo.clients : {};
          if (inb.remoteActiveDevices > 0) {
            const seenTs = Number(onlineInfo.lastOnline || nowMs);
            inb.lastOnline = seenTs;
            if (Array.isArray(inb.clients) && inb.clients.length === 1) {
              inb.clients[0].lastOnline = seenTs;
            } else if (Array.isArray(inb.clients) && inb.clients.length > 1) {
              for (const [cKey, cInfo] of Object.entries(inb.remoteClientOnline)) {
                const cl = inb.clients.find((c) => c.email === cKey || c.name === cKey || c.username === cKey);
                if (cl && Number(cInfo?.devices || cInfo?.ips?.length || 0) > 0) {
                  cl.lastOnline = Number(cInfo.lastOnline || seenTs);
                }
              }
            }
          }
        }
      }
    }

    // Check traffic quota & expiry on remote node inbounds and clients so exhausted/expired nodes are automatically disabled
    for (const inb of state.inbounds || []) {
      if (!servedNodeIds.has(inb.nodeId || 'node_local') || inb.enable === false) continue;
      if (Array.isArray(inb.clients) && inb.clients.length > 1) {
        for (const cl of inb.clients) {
          if (cl.enable === false) continue;
          const cQuota = Number(cl.totalBytes || (cl.totalGB > 0 ? (cl.totalGB > 1048576 ? cl.totalGB : Math.round(cl.totalGB * (1024 ** 3))) : 0));
          if (cl.expiryTime && cl.expiryTime > 0 && nowMs > cl.expiryTime) {
            cl.enable = false;
            cl.disabledReason = 'expired';
            node.pendingSync = true;
          } else if (cQuota > 0 && (Number(cl.up || 0) + Number(cl.down || 0)) >= cQuota) {
            cl.enable = false;
            cl.disabledReason = 'quota';
            node.pendingSync = true;
          }
        }
      }
      if (inb.expiryTime && inb.expiryTime > 0 && nowMs > inb.expiryTime) {
        inb.enable = false;
        inb.disabledReason = 'expired';
        node.pendingSync = true;
      } else if (inb.total && inb.total > 0 && (Number(inb.up || 0) + Number(inb.down || 0)) >= inb.total) {
        inb.enable = false;
        inb.disabledReason = 'quota';
        node.pendingSync = true;
      }
    }

    const compiled = compileNodeSingboxConfig(state, node.id);
    node.configHash = compiled.configHash;
    const needsUpdate = payload.configHash !== compiled.configHash || Boolean(node.pendingSync);
    if (needsUpdate) {
      node.pendingSync = false;
      node.lastSyncAt = new Date().toISOString();
    }

    if (needsUpdate) {
      store.save();
    } else if (typeof store.markTrafficDirty === 'function') {
      store.markTrafficDirty();
    }
    return {
      ok: true,
      nodeId: node.id,
      targetAgentVersion: '1.0.19',
      configHash: compiled.configHash,
      standbyMasterUrl: state.settings?.standbyMasterUrl || "",
      needsUpdate,
      inboundPolicies: compiled.inboundPolicies,
      ...(needsUpdate
        ? {
            singboxConfig: compiled.singboxConfig,
            certificates: compiled.certificates
          }
        : {})
    };
  };
  return runHeartbeat();
}

/**
 * Generates the 1-line shell command to install and register `nexus-agent` on a remote Relay/Exit/Standby server.
 */
function buildAgentInstallCommand(state, node, reqHost = '') {
  const remoteDomains = new Set(
    (state.nodes || []).filter((n) => !n.isLocal && n.domain).map((n) => String(n.domain).trim().toLowerCase())
  );
  const rawReqHost = String(reqHost || '').split(':')[0].trim();
  const safeReqHost = rawReqHost && !remoteDomains.has(rawReqHost.toLowerCase()) ? rawReqHost : '';
  const safeWebDomain = state.settings?.webDomain && !remoteDomains.has(String(state.settings.webDomain).trim().toLowerCase())
    ? state.settings.webDomain
    : '';
  const cleanHost = safeReqHost || safeWebDomain || state.settings?.publicIPv4 || rawReqHost || 'MASTER_IP';
  const port = state.settings?.webPort || 2053;
  const proto = state.settings?.webCertFile ? 'https' : 'http';
  const basePath = (state.settings?.webBasePath || '/').replace(/\/+$/, '');
  const masterUrl = `${proto}://${cleanHost}:${port}${basePath}`;
  const repo = process.env.NG_REPO || 'mor2026-28/NexusGate-Plus';
  const standbyArg = state.settings?.standbyMasterUrl ? ` --standby-master "${state.settings.standbyMasterUrl}"` : "";
  return `(curl -fsSLk "${masterUrl}/api/cluster/install-agent.sh" || curl -fsSL "https://raw.githubusercontent.com/${repo}/main/scripts/install-agent.sh") | bash -s -- --master "${masterUrl}"${standbyArg} --node-id "${node.id}" --token "${node.token}" --port "${node.agentPort || 19090}" --takeover-3xui`;
}

/**
 * Event-driven smart sync: compares compiled configHash for each remote node against its lastPushedHash,
 * and ONLY pushes to nodes whose configuration actually changed (zero wasted bandwidth when idle!).
 * Respects `standbySyncMode` ('on_change' | 'daily' | 'on_failover').
 */
async function syncChangedClusterNodes(state, options = {}) {
  const { forceAll = false, isDailyTick = false } = options;
  ensureClusterNodes(state);
  const results = [];
  for (const node of state.nodes || []) {
    if (node.isLocal || node.enabled === false) continue;
    // Check if this is a Standby node whose primaries all use 'daily' or 'on_failover'
    if (!forceAll && node.role === 'standby') {
      const boundPrimaries = (state.nodes || []).filter((p) => p.standbyNodeId === node.id || p.activeFailoverTo === node.id);
      const anyActiveFailover = boundPrimaries.some((p) => p.activeFailoverTo === node.id);
      if (!anyActiveFailover && boundPrimaries.length > 0) {
        const allOnFailoverOnly = boundPrimaries.every((p) => p.standbySyncMode === 'on_failover' || p.mirrorStandby === false);
        if (allOnFailoverOnly) continue;
        const allDailyOnly = boundPrimaries.every((p) => p.standbySyncMode === 'daily');
        if (allDailyOnly && !isDailyTick) continue;
      }
    }
    const compiled = compileNodeSingboxConfig(state, node.id);
    if (!forceAll && node.lastPushedHash === compiled.configHash) {
      continue; // Zero config change -> 0 bytes pushed!
    }
    const res = await pushConfigToAgentNode(state, node.id);
    if (res.ok) {
      node.lastPushedHash = compiled.configHash;
    }
    results.push({ nodeId: node.id, ...res });
  }
  return results;
}

module.exports = {
  createDefaultLocalNode,
  buildOutboundFromExitInbound,
  ensureClusterNodes,
  syncExitNodeOutbounds,
  resolveInboundNodeHost,
  getServedNodeIds,
  compileNodeSingboxConfig,
  signAgentPayload,
  pushConfigToAgentNode,
  syncChangedClusterNodes,
  handleAgentHeartbeat,
  buildAgentInstallCommand
};
