'use strict';

const https = require('node:https');
const crypto = require('node:crypto');
const { ensureClusterNodes, pushConfigToAgentNode, compileNodeSingboxConfig } = require('./cluster');

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
 * Extracts root zone domain from a FQDN (e.g. "hk1.relay.example.com" -> "example.com").
 */
function inferRootZone(domain = '') {
  const parts = String(domain || '').trim().split('.').filter(Boolean);
  if (parts.length <= 2) return parts.join('.');
  return parts.slice(-2).join('.');
}

/**
 * Updates a Cloudflare DNS A/AAAA record for `domain` to point to `newIp`.
 * If `apiToken` is omitted, returns `{ mode: 'manual', ... }` so the panel can still complete
 * standby node takeover and display the exact IP for manual CF update.
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
  const cleanToken = String(apiToken || '').trim();

  if (!cleanDomain || !cleanIp) {
    return {
      ok: false,
      mode: 'skipped',
      message: '未配置中转机域名或目标备用机 IP，跳过 DNS 自动解析切换'
    };
  }

  const recordType = cleanIp.includes(':') ? 'AAAA' : 'A';

  if (!cleanToken) {
    return {
      ok: true,
      mode: 'manual-cf',
      domain: cleanDomain,
      recordType,
      targetIp: cleanIp,
      message: `备用机节点与证书已秒级就绪！请前往 Cloudflare 将 ${cleanDomain} 的 ${recordType} 记录修改为 ${cleanIp}（若配置 CF API Token 可全自动完成）`
    };
  }

  try {
    let resolvedZoneId = String(zoneId || '').trim();
    if (!resolvedZoneId) {
      const rootZone = inferRootZone(cleanDomain);
      const zRes = await cfRequest('GET', `/zones?name=${encodeURIComponent(rootZone)}`, cleanToken);
      if (zRes.data?.success && Array.isArray(zRes.data.result) && zRes.data.result[0]?.id) {
        resolvedZoneId = zRes.data.result[0].id;
      } else {
        throw new Error(zRes.data?.errors?.[0]?.message || `未能自动查找到域名 ${rootZone} 的 Cloudflare Zone ID`);
      }
    }

    let resolvedRecordId = String(recordId || '').trim();
    if (!resolvedRecordId) {
      const rRes = await cfRequest(
        'GET',
        `/zones/${resolvedZoneId}/dns_records?type=${recordType}&name=${encodeURIComponent(cleanDomain)}`,
        cleanToken
      );
      if (rRes.data?.success && Array.isArray(rRes.data.result) && rRes.data.result[0]?.id) {
        resolvedRecordId = rRes.data.result[0].id;
      }
    }

    const payload = {
      type: recordType,
      name: cleanDomain,
      content: cleanIp,
      ttl: 60,
      proxied: Boolean(proxied)
    };

    const updateRes = resolvedRecordId
      ? await cfRequest('PUT', `/zones/${resolvedZoneId}/dns_records/${resolvedRecordId}`, cleanToken, payload)
      : await cfRequest('POST', `/zones/${resolvedZoneId}/dns_records`, cleanToken, payload);

    if (!updateRes.data?.success) {
      throw new Error(updateRes.data?.errors?.[0]?.message || 'Cloudflare DNS 更新失败');
    }

    return {
      ok: true,
      mode: 'cloudflare-api',
      zoneId: resolvedZoneId,
      recordId: updateRes.data.result?.id || resolvedRecordId,
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
 * 1. Binds `primaryNode.activeFailoverTo = standbyNode.id`
 * 2. Compiles all inbounds, outbounds, routing rules, and SSL certificates of `primaryNode`
 *    into `standbyNode` and pushes them to the Standby Agent
 * 3. Automatically updates Cloudflare DNS A/AAAA record of `primaryNode.domain` to `standbyNode.host`
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

    cfParams = {
      apiToken: primaryNode.cfApiToken || state.settings?.cfApiToken || '',
      zoneId: primaryNode.cfZoneId || state.settings?.cfDefaultZoneId || '',
      recordId: primaryNode.cfRecordId || '',
      domain: primaryNode.cfRecordName || primaryNode.domain || '',
      newIp: standbyNode.host,
      proxied: Boolean(primaryNode.cfProxied)
    };
  });

  // Push combined configuration & SSL certificates to the Standby Agent immediately
  const syncRes = await pushConfigToAgentNode(store.state, standbyNode.id);
  const compiled = compileNodeSingboxConfig(store.state, standbyNode.id);

  // Switch Cloudflare DNS IP if domain is configured
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
 * Fails back from the Standby node to the recovered Primary Relay node:
 * 1. Clears `primaryNode.activeFailoverTo`
 * 2. Pushes latest config to `primaryNode` (and updates `standbyNode`)
 * 3. Switches Cloudflare DNS A/AAAA record back to `primaryNode.host`
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

    cfParams = {
      apiToken: primaryNode.cfApiToken || state.settings?.cfApiToken || '',
      zoneId: primaryNode.cfZoneId || state.settings?.cfDefaultZoneId || '',
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

module.exports = {
  inferRootZone,
  updateCloudflareDnsIp,
  triggerNodeFailover,
  triggerNodeFailback
};
