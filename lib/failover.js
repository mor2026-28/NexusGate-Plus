'use strict';

const https = require('node:https');
const crypto = require('node:crypto');
const http = require('node:http');
const { ensureClusterNodes, syncExitNodeOutbounds, pushConfigToAgentNode, syncChangedClusterNodes, compileNodeSingboxConfig } = require('./cluster');

/**
 * Helper to execute an HTTPS request to Cloudflare API v4.
 */
function cfRequest(method, apiPath, apiToken, bodyObj = null, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const bodyStr = bodyObj ? JSON.stringify(bodyObj) : '';
    const req = https.request(
      {
        hostname: 'api.cloudflare.com',
        port: 443,
        path: `/client/v4${apiPath}`,
        method,
        headers: {
          Authorization: `Bearer ${apiToken}`,
          'Content-Type': 'application/json',
          ...(bodyStr ? { 'Content-Length': Buffer.byteLength(bodyStr) } : {})
        },
        timeout: timeoutMs
      },
      (res) => {
        let raw = '';
        res.on('data', (chunk) => { raw += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(raw || '{}');
            resolve({ statusCode: res.statusCode, data: parsed });
          } catch (err) {
            reject(new Error(`Cloudflare API 响应解析失败: ${err.message}`));
          }
        });
      }
    );
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Cloudflare API 请求超时'));
    });
    req.on('error', (err) => reject(err));
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

/**
 * Extracts candidate root zone domains from a FQDN (e.g. "hk1.relay.example.co.uk" -> ["relay.example.co.uk", "example.co.uk"]).
 */
function inferRootZoneCandidates(domain = '') {
  const parts = String(domain || '').trim().replace(/\.$/, '').split('.').filter(Boolean);
  if (parts.length <= 2) return [parts.join('.')];
  const out = [parts.slice(-2).join('.')];
  if (parts.length >= 3) {
    out.push(parts.slice(-3).join('.'));
  }
  return [...new Set(out)];
}

/**
 * Splits a raw token string that may contain 1 or multiple Cloudflare API Tokens
 * (separated by newline, comma, or semicolon for users with multiple Cloudflare accounts).
 */
function parseTokenList(...inputs) {
  const out = [];
  for (const rawInput of inputs) {
    if (!rawInput) continue;
    const parts = Array.isArray(rawInput)
      ? rawInput.map((x) => String(x || '').trim()).filter(Boolean)
      : String(rawInput).split(/[\r\n,;\s]+/).map((s) => s.trim()).filter(Boolean);
    for (const p of parts) {
      if (p && !out.includes(p)) out.push(p);
    }
  }
  return out;
}

/**
 * Automatically resolves the matching `{ token, zoneId, zoneName, existingRecord }` across one or multiple
 * Cloudflare API tokens (supporting multiple CF accounts and multiple domains automatically without needing manual Zone ID).
 */
async function resolveCloudflareZoneAndRecord({ tokens = [], explicitZoneId = '', domain = '', recordType = 'A' }) {
  const cleanDomain = String(domain || '').trim();
  const candidates = inferRootZoneCandidates(cleanDomain);
  let lastErr = '';

  for (const token of tokens) {
    // 1. If an explicitZoneId was given, check if it belongs to this token and matches the domain
    if (explicitZoneId) {
      try {
        const zCheck = await cfRequest('GET', `/zones/${explicitZoneId}`, token);
        if (zCheck.data?.success && zCheck.data.result?.id) {
          const zName = String(zCheck.data.result.name || '').toLowerCase();
          if (!zName || cleanDomain.toLowerCase().endsWith(zName)) {
            const rRes = await cfRequest(
              'GET',
              `/zones/${explicitZoneId}/dns_records?type=${recordType}&name=${encodeURIComponent(cleanDomain)}`,
              token
            );
            const rec = (rRes.data?.success && Array.isArray(rRes.data.result) && rRes.data.result[0]) || null;
            return { token, zoneId: explicitZoneId, zoneName: zName || candidates[0], existingRecord: rec };
          }
        }
      } catch (e) {
        lastErr = e.message;
      }
    }

    // 2. Otherwise (or if explicitZoneId belonged to a different domain), auto-query zone by root domain name!
    for (const rootZone of candidates) {
      try {
        const zRes = await cfRequest('GET', `/zones?name=${encodeURIComponent(rootZone)}`, token);
        if (zRes.data?.success && Array.isArray(zRes.data.result) && zRes.data.result[0]?.id) {
          const matchedZone = zRes.data.result[0];
          const rRes = await cfRequest(
            'GET',
            `/zones/${matchedZone.id}/dns_records?type=${recordType}&name=${encodeURIComponent(cleanDomain)}`,
            token
          );
          const rec = (rRes.data?.success && Array.isArray(rRes.data.result) && rRes.data.result[0]) || null;
          return {
            token,
            zoneId: matchedZone.id,
            zoneName: matchedZone.name || rootZone,
            existingRecord: rec
          };
        } else if (zRes.data?.errors?.[0]?.message) {
          lastErr = zRes.data.errors[0].message;
        }
      } catch (e) {
        lastErr = e.message;
      }
    }
  }

  throw new Error(
    lastErr || `在所提供的 Cloudflare API Token 账号下未找到域名 ${cleanDomain} (请确认 Token 具备 Zone.DNS 编辑权限且包含该域名)`
  );
}

/**
 * Tests Cloudflare API connectivity and auto-discovery for a specific Relay node / domain.
 */
async function verifyCloudflareDomainAccess({ apiToken = '', zoneId = '', domain = '' }) {
  const cleanDomain = String(domain || '').trim();
  const tokens = parseTokenList(apiToken);
  if (!cleanDomain) {
    return {
      ok: false,
      mode: 'no-domain',
      domain: '',
      message: '该中转机尚未绑定专属域名，请先在编辑中填写中转机域名（如 hk1.yourdomain.com）'
    };
  }
  if (!tokens.length) {
    const cands = inferRootZoneCandidates(cleanDomain);
    return {
      ok: false,
      mode: 'no-token',
      domain: cleanDomain,
      rootCandidates: cands,
      message: `已识别中转机域名 [${cleanDomain}] (根域名: ${cands[0] || cleanDomain})，但尚未填写 Cloudflare API Token，请先在《中转与落地集群》底部或节点编辑中粘贴 CF API Token`
    };
  }

  const resolved = await resolveCloudflareZoneAndRecord({
    tokens,
    explicitZoneId: zoneId,
    domain: cleanDomain,
    recordType: 'A'
  });

  return {
    ok: true,
    domain: cleanDomain,
    zoneId: resolved.zoneId,
    zoneName: resolved.zoneName,
    recordId: resolved.existingRecord?.id || '',
    currentIp: resolved.existingRecord?.content || '尚未创建 A 记录 (容灾切换时将自动创建)',
    proxied: Boolean(resolved.existingRecord?.proxied),
    message: `✅ CF API 验证成功！已自动匹配根域名 [${resolved.zoneName}] (Zone ID: ${resolved.zoneId.slice(0, 8)}...)，当前解析 IP: ${resolved.existingRecord?.content || '待自动创建'}`
  };
}

/**
 * Updates a Cloudflare DNS A/AAAA record for `domain` to point to `newIp`.
 * Supports multiple CF accounts (multiple tokens) and automatic Zone ID discovery across multiple domains.
 */
async function updateCloudflareDnsIp({
  apiToken = '',
  zoneId = '',
  recordId = '',
  domain = '',
  newIp = '',
  proxied = false
}) {
  const cleanDomain = String(domain || '').trim();
  const cleanIp = String(newIp || '').trim();
  const tokens = parseTokenList(apiToken);

  if (!cleanDomain || !cleanIp) {
    return {
      ok: false,
      mode: 'skipped',
      message: '未配置中转机域名或目标备用机 IP，跳过 DNS 自动解析切换'
    };
  }

  const recordType = cleanIp.includes(':') ? 'AAAA' : 'A';

  if (!tokens.length) {
    return {
      ok: true,
      mode: 'manual-cf',
      domain: cleanDomain,
      recordType,
      targetIp: cleanIp,
      message: `备用机节点与证书已秒级就绪！请前往 Cloudflare 将 ${cleanDomain} 的 ${recordType} 记录修改为 ${cleanIp}（配置 CF API Token 后可全自动完成）`
    };
  }

  try {
    const resolved = await resolveCloudflareZoneAndRecord({
      tokens,
      explicitZoneId: zoneId,
      domain: cleanDomain,
      recordType
    });

    const targetRecordId = resolved.existingRecord?.id || recordId || '';
    const payload = {
      type: recordType,
      name: cleanDomain,
      content: cleanIp,
      ttl: 60,
      proxied: Boolean(proxied)
    };

    const updateRes = targetRecordId
      ? await cfRequest('PUT', `/zones/${resolved.zoneId}/dns_records/${targetRecordId}`, resolved.token, payload)
      : await cfRequest('POST', `/zones/${resolved.zoneId}/dns_records`, resolved.token, payload);

    if (!updateRes.data?.success) {
      throw new Error(updateRes.data?.errors?.[0]?.message || 'Cloudflare DNS 更新失败');
    }

    return {
      ok: true,
      mode: 'cloudflare-api',
      zoneId: resolved.zoneId,
      recordId: updateRes.data.result?.id || targetRecordId,
      domain: cleanDomain,
      recordType,
      targetIp: cleanIp,
      message: `Cloudflare DNS 已自动将 ${cleanDomain} (${recordType}) 切换至 ${cleanIp} (TTL 60s)`
    };
  } catch (err) {
    return {
      ok: false,
      mode: 'cf-error',
      domain: cleanDomain,
      recordType,
      targetIp: cleanIp,
      error: err.message,
      message: `备用机已接管全部节点配置，但 Cloudflare API 自动改绑返回提示 (${err.message})，请手动在 CF 将 ${cleanDomain} 指向 ${cleanIp}`
    };
  }
}

/**
 * Triggers a 1-click or automatic failover from `primaryNodeId` to `standbyNodeId`.
 */
async function triggerNodeFailover(store, primaryNodeId, standbyNodeId = '', options = {}) {
  const { reason = '手动触发一键容灾切换' } = options;

  let primaryNode;
  let standbyNode;
  let cfParams;

  store.transact((state) => {
    ensureClusterNodes(state);
    primaryNode = state.nodes.find((n) => n.id === primaryNodeId);
    if (!primaryNode) {
      throw new Error(`未找到主力中转机: ${primaryNodeId}`);
    }
    const targetStandbyId = standbyNodeId || primaryNode.standbyNodeId;
    if (!targetStandbyId) {
      throw new Error(`请先为 [${primaryNode.name}] 指定一台备用容灾机 (Standby Node)`);
    }
    standbyNode = state.nodes.find((n) => n.id === targetStandbyId);
    if (!standbyNode) {
      throw new Error(`未找到备用容灾机: ${targetStandbyId}`);
    }
    if (standbyNode.id === primaryNode.id) {
      throw new Error('主力中转机与备用容灾机不能是同一台机器');
    }

    primaryNode.standbyNodeId = standbyNode.id;
    primaryNode.activeFailoverTo = standbyNode.id;
    primaryNode.failoverAt = new Date().toISOString();
    primaryNode.status = primaryNode.status === 'online' ? 'failover-standby' : 'offline-failover';

    // Combine node-specific CF token (if set) + global CF token(s) so multi-CF-account setups work seamlessly
    const combinedTokens = [primaryNode.cfApiToken, state.settings?.cfApiToken].filter(Boolean).join('\n');
    cfParams = {
      apiToken: combinedTokens,
      zoneId: primaryNode.cfZoneId || '',
      recordId: primaryNode.cfRecordId || '',
      domain: primaryNode.cfRecordName || primaryNode.domain || '',
      newIp: standbyNode.host,
      proxied: Boolean(primaryNode.cfProxied)
    };
  });

  const syncRes = await pushConfigToAgentNode(store.state, standbyNode.id);
  const compiled = compileNodeSingboxConfig(store.state, standbyNode.id);
  const dnsRes = await updateCloudflareDnsIp(cfParams);

  const eventRecord = store.transact((state) => {
    if (!Array.isArray(state.failoverLogs)) state.failoverLogs = [];
    const pNode = state.nodes.find((n) => n.id === primaryNodeId);
    if (pNode && dnsRes.zoneId) pNode.cfZoneId = dnsRes.zoneId;
    if (pNode && dnsRes.recordId) pNode.cfRecordId = dnsRes.recordId;

    const logItem = {
      id: `fo_${crypto.randomBytes(4).toString('hex')}`,
      at: new Date().toISOString(),
      action: 'failover',
      primaryNodeId: primaryNode.id,
      primaryNodeName: primaryNode.name,
      standbyNodeId: standbyNode.id,
      standbyNodeName: standbyNode.name,
      domain: cfParams.domain || primaryNode.host,
      oldIp: primaryNode.host,
      newIp: standbyNode.host,
      inboundsTakenOver: compiled.singboxConfig.inbounds.length,
      certsSynced: compiled.certificates.length,
      syncMode: syncRes.mode,
      dnsMode: dnsRes.mode,
      dnsMessage: dnsRes.message,
      reason
    };
    state.failoverLogs.unshift(logItem);
    if (state.failoverLogs.length > 50) state.failoverLogs.length = 50;
    return logItem;
  });

  return {
    ok: true,
    event: eventRecord,
    sync: syncRes,
    dns: dnsRes
  };
}

/**
 * Fails back from the Standby node to the recovered Primary Relay node.
 */
async function triggerNodeFailback(store, primaryNodeId, options = {}) {
  const { reason = '主力机恢复，一键回切流量与 DNS' } = options;

  let primaryNode;
  let prevStandbyId = '';
  let prevStandbyName = '';
  let prevStandbyIp = '';
  let cfParams;

  store.transact((state) => {
    ensureClusterNodes(state);
    primaryNode = state.nodes.find((n) => n.id === primaryNodeId);
    if (!primaryNode) {
      throw new Error(`未找到主力中转机: ${primaryNodeId}`);
    }
    prevStandbyId = primaryNode.activeFailoverTo || primaryNode.standbyNodeId || '';
    const stNode = state.nodes.find((n) => n.id === prevStandbyId);
    prevStandbyName = stNode?.name || prevStandbyId;
    prevStandbyIp = stNode?.host || '';

    primaryNode.activeFailoverTo = '';
    primaryNode.failoverAt = '';
    primaryNode.status = 'online';

    const combinedTokens = [primaryNode.cfApiToken, state.settings?.cfApiToken].filter(Boolean).join('\n');
    cfParams = {
      apiToken: combinedTokens,
      zoneId: primaryNode.cfZoneId || '',
      recordId: primaryNode.cfRecordId || '',
      domain: primaryNode.cfRecordName || primaryNode.domain || '',
      newIp: primaryNode.host,
      proxied: Boolean(primaryNode.cfProxied)
    };
  });

  const primarySync = await pushConfigToAgentNode(store.state, primaryNode.id);
  if (prevStandbyId) {
    await pushConfigToAgentNode(store.state, prevStandbyId);
  }
  const dnsRes = await updateCloudflareDnsIp(cfParams);

  const eventRecord = store.transact((state) => {
    if (!Array.isArray(state.failoverLogs)) state.failoverLogs = [];
    const logItem = {
      id: `fb_${crypto.randomBytes(4).toString('hex')}`,
      at: new Date().toISOString(),
      action: 'failback',
      primaryNodeId: primaryNode.id,
      primaryNodeName: primaryNode.name,
      standbyNodeId: prevStandbyId,
      standbyNodeName: prevStandbyName,
      domain: cfParams.domain || primaryNode.host,
      oldIp: prevStandbyIp,
      newIp: primaryNode.host,
      syncMode: primarySync.mode,
      dnsMode: dnsRes.mode,
      dnsMessage: dnsRes.message,
      reason
    };
    state.failoverLogs.unshift(logItem);
    if (state.failoverLogs.length > 50) state.failoverLogs.length = 50;
    return logItem;
  });

  return {
    ok: true,
    event: eventRecord,
    sync: primarySync,
    dns: dnsRes
  };
}

/**
 * Actively probes a remote Agent node's /healthz endpoint to double-check reachability
 * before triggering an automatic failover (prevents false-positive failovers).
 */
function probeNodeReachability(node, timeoutMs = 2000) {
  return new Promise((resolve) => {
    if (!node || !node.host || node.isLocal || node.host === '127.0.0.1') {
      return resolve(true);
    }
    const client = node.agentTls ? https : http;
    const req = client.request(
      {
        hostname: node.host,
        port: Number(node.agentPort || 19090),
        path: '/healthz',
        method: 'GET',
        timeout: timeoutMs,
        rejectUnauthorized: false
      },
      (res) => {
        res.resume();
        resolve(res.statusCode >= 200 && res.statusCode < 400);
      }
    );
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
    req.on('error', () => resolve(false));
    req.end();
  });
}

/**
 * Automatic Failover & Exit Fault-Tolerance Watchdog:
 * 1) Checks Relay nodes with `autoFailover !== false` and `standbyNodeId`: if offline >= `autoFailoverMinutes`
 *    and double-check probe fails, automatically triggers Standby takeover + Cloudflare DNS switch.
 * 2) Checks Relay nodes with `activeFailoverTo` and `autoFailback === true`: if primary recovered online,
 *    automatically fails back.
 * 3) Checks Exit nodes with `fallbackExitNodeId`: if primary Exit node is offline >= `autoFailoverMinutes`
 *    and probe fails, automatically redirects its Shared Exit SS outbound to the healthy `fallbackExitNodeId`
 *    and syncs all Relay servers!
 */
async function checkClusterHealthAndAutoFailover(store, options = {}) {
  const { nowMs = Date.now(), skipActiveProbe = false } = options;
  ensureClusterNodes(store.state);
  const actionsTaken = [];

  for (const node of [...(store.state.nodes || [])]) {
    if (node.isLocal || node.enabled === false || node.role === 'standby') continue;

    const lastSeenMs = Date.parse(node.lastSeenAt || node.createdAt || '') || 0;
    const offlineElapsedMs = lastSeenMs > 0 ? Math.max(0, nowMs - lastSeenMs) : 0;
    const thresholdMinutes = Math.max(1, Number(node.autoFailoverMinutes || 3));
    const thresholdMs = thresholdMinutes * 60 * 1000;
    const isTimedOut = node.status === 'offline' || (lastSeenMs > 0 && offlineElapsedMs >= thresholdMs);

    // Case 1: Relay or Hybrid node automatic failover to Standby
    if (node.role === 'relay' || node.role === 'hybrid') {
      if (!node.activeFailoverTo && node.autoFailover !== false && node.standbyNodeId && isTimedOut) {
        const alive = skipActiveProbe ? false : await probeNodeReachability(node);
        if (alive) {
          store.transact((st) => {
            const n = st.nodes.find((x) => x.id === node.id);
            if (n) {
              n.status = 'online';
              n.lastSeenAt = new Date(nowMs).toISOString();
            }
          });
          continue;
        }
        const foRes = await triggerNodeFailover(store, node.id, node.standbyNodeId, {
          reason: `自动容灾守护：主力中转机连续断线满 ${thresholdMinutes} 分钟，已自动切换备用机并更新 Cloudflare DNS`
        });
        actionsTaken.push({ type: 'relay_auto_failover', nodeId: node.id, standbyNodeId: node.standbyNodeId, event: foRes.event });
      } else if (node.activeFailoverTo && node.autoFailback === true) {
        const recentlySeen = node.status === 'online' && lastSeenMs > 0 && (nowMs - lastSeenMs) < 60000;
        if (recentlySeen) {
          const fbRes = await triggerNodeFailback(store, node.id, {
            reason: '自动容灾守护：检测到主力中转机已恢复在线，自动回切流量与 Cloudflare DNS'
          });
          actionsTaken.push({ type: 'relay_auto_failback', nodeId: node.id, event: fbRes.event });
        }
      }
    }

    // Case 2: Exit node automatic fault-tolerance switchover to fallbackExitNodeId
    if (node.role === 'exit' || node.role === 'hybrid') {
      if (!node.activeFailoverTo && node.fallbackExitNodeId && isTimedOut) {
        const alive = skipActiveProbe ? false : await probeNodeReachability(node);
        if (alive) {
          store.transact((st) => {
            const n = st.nodes.find((x) => x.id === node.id);
            if (n) {
              n.status = 'online';
              n.lastSeenAt = new Date(nowMs).toISOString();
            }
          });
          continue;
        }
        let logItem = null;
        store.transact((st) => {
          const exitNode = st.nodes.find((x) => x.id === node.id);
          const fbExit = st.nodes.find((x) => x.id === node.fallbackExitNodeId);
          if (!exitNode || !fbExit) return;
          exitNode.status = 'offline';
          exitNode.activeFailoverTo = fbExit.id;
          exitNode.failoverAt = new Date(nowMs).toISOString();
          syncExitNodeOutbounds(st);
          if (!Array.isArray(st.failoverLogs)) st.failoverLogs = [];
          logItem = {
            id: `fo_exit_${crypto.randomBytes(4).toString('hex')}`,
            at: new Date(nowMs).toISOString(),
            action: 'exit_failover',
            primaryNodeId: exitNode.id,
            primaryNodeName: exitNode.name,
            standbyNodeId: fbExit.id,
            standbyNodeName: fbExit.name,
            domain: `共享落地池 (${exitNode.host})`,
            oldIp: exitNode.host,
            newIp: fbExit.host,
            syncMode: 'cluster-push',
            dnsMode: 'exit-reroute',
            dnsMessage: `落地容错守护：主落地机 [${exitNode.name}] 离线超时，已自动将所有关联中转流量无缝切往备用落地机 [${fbExit.name} (${fbExit.host})]`,
            reason: `落地机断线满 ${thresholdMinutes} 分钟自动容错切换`
          };
          st.failoverLogs.unshift(logItem);
          if (st.failoverLogs.length > 50) st.failoverLogs.length = 50;
        });
        if (logItem) {
          await syncChangedClusterNodes(store.state, { forceAll: true });
          actionsTaken.push({ type: 'exit_auto_failover', nodeId: node.id, fallbackExitNodeId: node.fallbackExitNodeId, event: logItem });
        }
      } else if (node.activeFailoverTo && node.role === 'exit') {
        const recentlySeen = node.status === 'online' && lastSeenMs > 0 && (nowMs - lastSeenMs) < 60000;
        if (recentlySeen) {
          let logItem = null;
          store.transact((st) => {
            const exitNode = st.nodes.find((x) => x.id === node.id);
            if (!exitNode) return;
            const prevFbId = exitNode.activeFailoverTo;
            const fbExit = st.nodes.find((x) => x.id === prevFbId);
            exitNode.activeFailoverTo = '';
            exitNode.failoverAt = '';
            syncExitNodeOutbounds(st);
            if (!Array.isArray(st.failoverLogs)) st.failoverLogs = [];
            logItem = {
              id: `fb_exit_${crypto.randomBytes(4).toString('hex')}`,
              at: new Date(nowMs).toISOString(),
              action: 'exit_failback',
              primaryNodeId: exitNode.id,
              primaryNodeName: exitNode.name,
              standbyNodeId: prevFbId,
              standbyNodeName: fbExit?.name || prevFbId,
              domain: `共享落地池 (${exitNode.host})`,
              oldIp: fbExit?.host || '',
              newIp: exitNode.host,
              syncMode: 'cluster-push',
              dnsMode: 'exit-reroute',
              dnsMessage: `主落地机 [${exitNode.name} (${exitNode.host})] 已恢复在线，中转流量已自动切回主落地机`,
              reason: '主落地机恢复在线自动回切'
            };
            st.failoverLogs.unshift(logItem);
          });
          if (logItem) {
            await syncChangedClusterNodes(store.state, { forceAll: true });
            actionsTaken.push({ type: 'exit_auto_failback', nodeId: node.id, event: logItem });
          }
        }
      }
    }
  }

  return { ok: true, actionsCount: actionsTaken.length, actions: actionsTaken };
}

module.exports = {
  inferRootZoneCandidates,
  parseTokenList,
  resolveCloudflareZoneAndRecord,
  verifyCloudflareDomainAccess,
  updateCloudflareDnsIp,
  triggerNodeFailover,
  triggerNodeFailback,
  probeNodeReachability,
  checkClusterHealthAndAutoFailover
};
