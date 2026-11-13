'use strict';

const crypto = require('node:crypto');
const { buildClientLinks, parseShareUriToOutbound, toSingboxOutbound } = require('./protocols');

function hashKey(val) {
  return crypto.createHash('sha256').update(String(val || '')).digest('hex').slice(0, 24);
}

/**
 * Converts a standalone share URI (vless://, vmess://, hy2://, trojan://, ss://, anytls://, tuic://, socks5://)
 * into a unified subscription link object with Base64 URI, Clash YAML, Sing-box JSON, and Surge policy line.
 */
function buildLinkFromExternalUri(rawUri, customName = '') {
  const cleanUri = String(rawUri || '').trim();
  if (!cleanUri || !cleanUri.includes('://')) return null;
  try {
    const out = parseShareUriToOutbound(cleanUri, '', customName);
    const name = customName || out.remark || out.tag || 'External-Node';
    const sbOut = toSingboxOutbound({ ...out, tag: name });

    let finalUri = cleanUri;
    if (customName) {
      if (cleanUri.startsWith('vmess://')) {
        try {
          const obj = JSON.parse(Buffer.from(cleanUri.slice(8), 'base64').toString('utf8'));
          obj.ps = name;
          finalUri = `vmess://${Buffer.from(JSON.stringify(obj)).toString('base64')}`;
        } catch { /* keep original */ }
      } else {
        const hashIdx = cleanUri.indexOf('#');
        finalUri = `${hashIdx >= 0 ? cleanUri.slice(0, hashIdx) : cleanUri}#${encodeURIComponent(name)}`;
      }
    }

    const clashObj = {
      name,
      type: out.type === 'shadowsocks' ? 'ss' : (out.type === 'socks' ? 'socks5' : out.type),
      server: out.server,
      port: Number(out.port || 443),
      udp: true
    };

    if (out.type === 'vless' || out.type === 'vmess') {
      clashObj.uuid = out.uuid;
      if (out.type === 'vmess') clashObj.alterId = 0;
      if (out.type === 'vmess') clashObj.cipher = 'auto';
      if (out.flow) clashObj.flow = out.flow;
      if (out.security === 'tls' || out.security === 'reality') {
        clashObj.tls = true;
        if (out.sni) clashObj.servername = out.sni;
        if (out.insecure) clashObj['skip-cert-verify'] = true;
        if (out.security === 'reality') {
          clashObj['client-fingerprint'] = out.fingerprint || 'chrome';
          clashObj['reality-opts'] = {
            'public-key': out.publicKey || '',
            'short-id': out.shortId || ''
          };
        }
      }
      if (out.transport && out.transport !== 'tcp') {
        clashObj.network = out.transport === 'httpupgrade' ? 'ws' : out.transport;
        if (out.transport === 'ws' || out.transport === 'httpupgrade') {
          clashObj['ws-opts'] = {
            path: out.wsPath || '/',
            ...(out.wsHost ? { headers: { Host: out.wsHost } } : {})
          };
        } else if (out.transport === 'grpc') {
          clashObj['grpc-opts'] = { 'grpc-service-name': out.grpcServiceName || 'grpc' };
        }
      }
    } else if (out.type === 'shadowsocks') {
      clashObj.cipher = out.method || '2022-blake3-aes-128-gcm';
      clashObj.password = out.password || '';
    } else if (out.type === 'hysteria2' || out.type === 'anytls' || out.type === 'trojan') {
      clashObj.password = out.password || '';
      if (out.sni) clashObj.sni = out.sni;
      if (out.insecure) clashObj['skip-cert-verify'] = true;
      if (out.type === 'hysteria2') clashObj.alpn = ['h3'];
    } else if (out.type === 'tuic') {
      clashObj.uuid = out.uuid || '';
      clashObj.password = out.password || '';
      if (out.sni) clashObj.sni = out.sni;
      clashObj.alpn = ['h3'];
    } else if (out.type === 'socks') {
      if (out.username) clashObj.username = out.username;
      if (out.password) clashObj.password = out.password;
    }

    let surgeLine = '';
    const safeName = String(name).replace(/[\r\n,=]/g, '_');
    if (out.type === 'shadowsocks') {
      surgeLine = `${safeName} = ss, ${out.server}, ${out.port}, encrypt-method=${out.method || 'aes-128-gcm'}, password=${out.password || ''}, udp-relay=true`;
    } else if (out.type === 'trojan') {
      surgeLine = `${safeName} = trojan, ${out.server}, ${out.port}, password=${out.password || ''}${out.sni ? `, sni=${out.sni}` : ''}${out.insecure ? ', skip-cert-verify=true' : ''}`;
    } else if (out.type === 'vmess') {
      surgeLine = `${safeName} = vmess, ${out.server}, ${out.port}, username=${out.uuid || ''}, vmess-aead=true${out.security === 'tls' ? `, tls=true${out.sni ? `, sni=${out.sni}` : ''}` : ''}${out.transport === 'ws' ? `, ws=true, ws-path=${out.wsPath || '/'}` : ''}`;
    } else if (out.type === 'hysteria2') {
      surgeLine = `${safeName} = hysteria2, ${out.server}, ${out.port}, password=${out.password || ''}${out.sni ? `, sni=${out.sni}` : ''}${out.insecure ? ', skip-cert-verify=true' : ''}`;
    } else if (out.type === 'socks') {
      surgeLine = `${safeName} = socks5, ${out.server}, ${out.port}${out.username ? `, ${out.username}, ${out.password || ''}` : ''}`;
    }

    return {
      name,
      protocol: out.type,
      uri: finalUri,
      clashYaml: `  - ${JSON.stringify(clashObj)}`,
      singboxJson: JSON.stringify(sbOut, null, 2),
      surgeLine
    };
  } catch {
    return null;
  }
}

/**
 * Deduplicates item names across a subscription list so Clash / Sing-box / Surge never reject duplicate proxy names.
 */
function deduplicateSubscriptionItemNames(items) {
  const usedNames = new Map();
  for (const it of items) {
    const baseName = it.link.name || `node-${it.inbound?.port || 443}`;
    const count = usedNames.get(baseName) || 0;
    usedNames.set(baseName, count + 1);
    if (count > 0) {
      const uniqueName = `${baseName} (${count + 1})`;
      it.link.name = uniqueName;
      if (it.link.clashYaml) {
        try {
          const obj = JSON.parse(it.link.clashYaml.replace(/^\s*-\s*/, ''));
          obj.name = uniqueName;
          it.link.clashYaml = `  - ${JSON.stringify(obj)}`;
        } catch { /* ignore */ }
      }
      if (it.link.singboxJson) {
        try {
          const obj = JSON.parse(it.link.singboxJson);
          obj.tag = uniqueName;
          it.link.singboxJson = JSON.stringify(obj, null, 2);
        } catch { /* ignore */ }
      }
    }
  }
  return items;
}

/**
 * Resolves the Master Panel's public base URL for subscription links.
 * Uses `settings.subPublicUrl` if set, otherwise uses the Master Panel's domain (`settings.webDomain` or cert domain) + `webPort`.
 */
function buildMasterSubBaseUrl(state, reqHost = '', protoHint = '') {
  const s = state.settings || {};
  if (s.subPublicUrl && String(s.subPublicUrl).trim()) {
    return String(s.subPublicUrl).trim().replace(/\/+$/, '');
  }
  const realCert = (state.certificates || []).find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false);
  const useHttps = Boolean((s.webCertFile && s.webKeyFile) || protoHint === 'https');
  const proto = protoHint || (useHttps ? 'https' : 'http');
  const cleanReqHost = String(reqHost || '').split(':')[0].replace(/^\[|\]$/g, '');
  const reqPort = String(reqHost || '').includes(':') ? String(reqHost).split(':').pop() : '';
  const host = s.webDomain || realCert?.domain || cleanReqHost || s.publicIPv4 || '127.0.0.1';
  const port = reqPort || s.webPort || 2053;
  const portPart = (proto === 'https' && Number(port) === 443) || (proto === 'http' && Number(port) === 80) ? '' : `:${port}`;
  return `${proto}://${host}${portPart}`;
}

/**
 * Builds the full set of client subscription URLs for a given token (Aggregate or Custom SubGroup).
 */
function buildSubscriptionFormatUrls(state, token, reqHost = '', protoHint = '', extraQuery = '') {
  const base = buildMasterSubBaseUrl(state, reqHost, protoHint);
  const subPath = (state.settings?.subPath || '/sub/').replace(/\/+$/, '');
  const encToken = encodeURIComponent(token);
  const qPrefix = extraQuery ? `?${extraQuery.replace(/^\?/, '')}` : '';
  const qJoin = (fmt) => (qPrefix ? `${qPrefix}&format=${fmt}` : `?format=${fmt}`);

  return {
    baseUrl: base,
    autoUrl: `${base}${subPath}/${encToken}${qPrefix}`,
    base64Url: `${base}${subPath}/${encToken}${qJoin('base64')}`,
    clashUrl: `${base}${subPath}/${encToken}${qJoin('clash')}`,
    singboxUrl: `${base}${subPath}/${encToken}${qJoin('singbox')}`,
    surgeUrl: `${base}${subPath}/${encToken}${qJoin('surge')}`,
    rawUrl: `${base}${subPath}/${encToken}${qJoin('raw')}`,
    vaultAutoUrl: `${base}/s/${encToken}/auto`
  };
}

/**
 * Collects subscription items for a specific Custom Subscription Group (`subGroup`).
 * Supports selecting specific inbounds (`in_xxx`), specific clients (`in_xxx::client_id`),
 * external nodes (`ext_xxx`), and inline `customUris` across any combination of Relay servers!
 */
function collectSubGroupItems(state, subGroup, reqHost = '') {
  if (!subGroup) return [];
  const selectedSet = new Set(Array.isArray(subGroup.selectedItems) ? subGroup.selectedItems.map(String) : []);
  const cleanReqHost = String(reqHost || '').split(':')[0].replace(/^\[|\]$/g, '');
  const realCert = (state.certificates || []).find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false);
  const publicHost = state.settings?.webDomain || realCert?.domain || state.settings?.publicIPv4 || cleanReqHost || '127.0.0.1';
  const items = [];

  // 1. Collect matching cluster inbounds / clients across all Relay & Exit servers
  for (const inbound of state.inbounds || []) {
    if (inbound.enable === false || inbound.protocol === 'direct') continue;
    const inbMatchedAll = selectedSet.has(inbound.id) || selectedSet.has(inbound.tag);
    const inbNodeId = inbound.nodeId || 'node_local';
    const assignedNode = (state.nodes || []).find((n) => n.id === inbNodeId);
    const nodeDomain = assignedNode?.domain || '';
    const nodeHost = inbound.publicHost || nodeDomain || (assignedNode && !assignedNode.isLocal && assignedNode.host ? assignedNode.host : '') || publicHost;
    const nodeSettings = nodeDomain
      ? { ...(state.settings || {}), webDomain: nodeDomain, defaultTlsDomain: nodeDomain }
      : (state.settings || {});
    const links = buildClientLinks(inbound, nodeHost, state.certificates || [], nodeSettings);

    for (let idx = 0; idx < links.length; idx += 1) {
      const link = links[idx];
      const client =
        (inbound.clients || []).find(
          (c) =>
            (link.clientId && c.id === link.clientId) ||
            (link.subId && c.subId === link.subId) ||
            (link.clientName && (c.email === link.clientName || c.name === link.clientName))
        ) ||
        (inbound.clients || [])[idx] ||
        {};
      if (client.enable === false) continue;

      const clientCompositeKey = `${inbound.id}::${client.id || client.email || idx}`;
      const clientEmailKey = `${inbound.id}::${client.email || ''}`;
      const matchedSpecificClient =
        selectedSet.has(clientCompositeKey) ||
        selectedSet.has(clientEmailKey) ||
        (client.id && selectedSet.has(String(client.id))) ||
        (client.subId && selectedSet.has(String(client.subId)));

      if (!inbMatchedAll && !matchedSpecificClient) continue;

      items.push({
        inbound,
        client,
        nodeId: inbNodeId,
        nodeName: assignedNode?.name || '主控本机',
        nodeDomain: nodeDomain || nodeHost,
        link: { ...link }
      });
    }
  }

  // 2. Collect matching external nodes from state.externalNodes
  for (const ext of state.externalNodes || []) {
    if (ext.enabled === false) continue;
    if (!selectedSet.has(ext.id) && !selectedSet.has(ext.name)) continue;
    const extLink = buildLinkFromExternalUri(ext.uri, ext.name);
    if (extLink) {
      items.push({
        inbound: { id: ext.id, remark: ext.name, protocol: extLink.protocol, port: 0, up: 0, down: 0, external: true },
        client: {},
        nodeId: 'external',
        nodeName: ext.groupName || '外部节点',
        link: extLink
      });
    }
  }

  // 3. Collect inline customUris attached to this subGroup
  if (Array.isArray(subGroup.customUris)) {
    for (const rawLine of subGroup.customUris) {
      const extLink = buildLinkFromExternalUri(rawLine);
      if (extLink) {
        items.push({
          inbound: { id: `custom_${hashKey(rawLine).slice(0, 8)}`, remark: extLink.name, protocol: extLink.protocol, port: 0, up: 0, down: 0, external: true },
          client: {},
          nodeId: 'external',
          nodeName: '自定义链接',
          link: extLink
        });
      }
    }
  }

  return deduplicateSubscriptionItemNames(items);
}

/**
 * Computes real-time aggregated traffic, active online IPs/devices across all selected Relay machines,
 * and subscription pull access window metrics for a Custom Subscription Group (`subGroup`).
 */
function computeSubGroupRuntimeStats(state, subGroup, singbox = null) {
  const selectedSet = new Set(Array.isArray(subGroup.selectedItems) ? subGroup.selectedItems.map(String) : []);
  let rawUp = 0;
  let rawDown = 0;
  const liveIpSet = new Set();
  let liveDeviceCount = 0;
  const seenInbounds = new Set();
  const includedNodeSummaries = [];

  for (const inbound of state.inbounds || []) {
    if (inbound.protocol === 'direct') continue;
    const inbMatchedAll = selectedSet.has(inbound.id) || selectedSet.has(inbound.tag);
    const matchedClients = (inbound.clients || []).filter((c, idx) => {
      const cKey = `${inbound.id}::${c.id || c.email || idx}`;
      const eKey = `${inbound.id}::${c.email || ''}`;
      return selectedSet.has(cKey) || selectedSet.has(eKey) || (c.id && selectedSet.has(String(c.id))) || (c.subId && selectedSet.has(String(c.subId)));
    });

    if (!inbMatchedAll && matchedClients.length === 0) continue;

    const assignedNode = (state.nodes || []).find((n) => n.id === (inbound.nodeId || 'node_local'));
    const nodeLabel = assignedNode ? assignedNode.name.replace(/\s*\(Local Master\)/, '') : '主控本机';

    if (inbMatchedAll || (inbound.clients || []).length <= 1) {
      if (!seenInbounds.has(inbound.id)) {
        seenInbounds.add(inbound.id);
        rawUp += Number(inbound.up || 0);
        rawDown += Number(inbound.down || 0);
      }
      const localIps = singbox ? singbox.getActiveIpsForInbound(inbound.tag) : [];
      const remoteIps = Array.isArray(inbound.remoteActiveIps) ? inbound.remoteActiveIps : [];
      for (const ip of [...localIps, ...remoteIps]) {
        if (ip) liveIpSet.add(ip);
      }
      const inbDevs = Math.max(
        singbox ? singbox.getActiveDeviceCountForInbound(inbound.tag) : 0,
        Number(inbound.remoteActiveDevices || 0),
        localIps.length + remoteIps.length
      );
      liveDeviceCount += inbDevs;
      includedNodeSummaries.push({
        id: inbound.id,
        nodeId: inbound.nodeId || 'node_local',
        nodeName: nodeLabel,
        nodeDomain: assignedNode?.domain || inbound.publicHost || assignedNode?.host || '',
        remark: inbound.remark,
        protocol: inbound.protocol,
        port: inbound.port
      });
    } else {
      for (const c of matchedClients) {
        rawUp += Number(c.up || 0);
        rawDown += Number(c.down || 0);
        const cKey = c.email || c.name || c.username || 'default';
        const cIps = singbox ? singbox.getActiveIpsForClient(inbound.tag, cKey, false) : [];
        for (const ip of cIps) {
          if (ip) liveIpSet.add(ip);
        }
        const cDevs = singbox ? singbox.getActiveDeviceCountForClient(inbound.tag, cKey, false) : cIps.length;
        liveDeviceCount += cDevs;
        includedNodeSummaries.push({
          id: `${inbound.id}::${c.id}`,
          nodeId: inbound.nodeId || 'node_local',
          nodeName: nodeLabel,
          nodeDomain: assignedNode?.domain || inbound.publicHost || assignedNode?.host || '',
          remark: `${inbound.remark} (${c.email})`,
          protocol: inbound.protocol,
          port: inbound.port
        });
      }
    }
  }

  for (const ext of state.externalNodes || []) {
    if (selectedSet.has(ext.id) || selectedSet.has(ext.name)) {
      includedNodeSummaries.push({
        id: ext.id,
        nodeId: 'external',
        nodeName: ext.groupName || '外部节点',
        nodeDomain: '外部直连',
        remark: ext.name,
        protocol: ext.protocol || 'vless',
        port: 0
      });
    }
  }

  if (Array.isArray(subGroup.customUris)) {
    for (const u of subGroup.customUris) {
      const parsed = buildLinkFromExternalUri(u);
      if (parsed) {
        includedNodeSummaries.push({
          id: `custom_${hashKey(u).slice(0, 6)}`,
          nodeId: 'external',
          nodeName: '自定义链接',
          nodeDomain: '自定义',
          remark: parsed.name,
          protocol: parsed.protocol,
          port: 0
        });
      }
    }
  }

  const usedUp = Math.max(0, rawUp - Number(subGroup.upOffset || 0));
  const usedDown = Math.max(0, rawDown - Number(subGroup.downOffset || 0));
  const usedBytes = usedUp + usedDown;
  const totalBytes = Number(subGroup.totalBytes || (subGroup.totalGB > 0 ? Math.round(Number(subGroup.totalGB) * (1024 ** 3)) : 0));

  const windowHours = Math.max(1, Number(subGroup.accessWindowHours || 24));
  const cutoffMs = Date.now() - windowHours * 3600 * 1000;
  const activeAccessKeys = (subGroup.accessKeys || []).filter((k) => (Date.parse(k.lastSeenAt || '') || 0) >= cutoffMs);
  const windowIpLabels = activeAccessKeys.filter((k) => k.kind === 'ip').map((k) => k.label);
  const windowDevLabels = activeAccessKeys.filter((k) => k.kind === 'device').map((k) => k.label);

  const combinedIps = [...new Set([...liveIpSet, ...windowIpLabels].filter(Boolean))];
  const combinedDeviceCount = Math.max(liveDeviceCount, windowDevLabels.length, combinedIps.length);

  let status = 'active';
  let statusReason = '正常有效';
  if (subGroup.enabled === false) {
    status = 'disabled';
    statusReason = '已手动停用';
  } else if (subGroup.expiryTime && Number(subGroup.expiryTime) > 0 && Date.now() >= Number(subGroup.expiryTime)) {
    status = 'expired';
    statusReason = '已到期';
  } else if (totalBytes > 0 && usedBytes >= totalBytes) {
    status = 'exhausted';
    statusReason = '流量已耗尽';
  }

  return {
    rawUp,
    rawDown,
    usedUp,
    usedDown,
    usedBytes,
    totalBytes,
    liveOnlineIps: [...liveIpSet],
    liveOnlineDevices: liveDeviceCount,
    windowActiveIps: windowIpLabels,
    windowActiveDevices: windowDevLabels,
    combinedIps,
    combinedIpCount: combinedIps.length,
    combinedDeviceCount,
    includedNodes: includedNodeSummaries,
    includedNodesCount: includedNodeSummaries.length,
    status,
    statusReason
  };
}

/**
 * Evaluates subscription access policy (enabled, expiry, traffic quota, IP limit, Device limit)
 * and records access keys & audit log for a Custom Subscription Group (`subGroup`).
 */
function checkAndRecordSubGroupAccess(store, subGroup, reqMeta = {}, singbox = null) {
  const ip = String(reqMeta.ip || '127.0.0.1').replace(/^::ffff:/i, '').trim() || '127.0.0.1';
  const ua = String(reqMeta.userAgent || 'Unknown-Client').trim();
  const explicitDevice = String(reqMeta.deviceId || '').trim();
  const deviceLabel = (explicitDevice || ua || 'Unknown-Device').slice(0, 140);
  const format = String(reqMeta.format || 'auto').trim();
  const stats = computeSubGroupRuntimeStats(store.state, subGroup, singbox);

  const recordLog = (allowed, reason, responseBytes = 0) => {
    store.transact((st) => {
      if (!Array.isArray(st.subAccessLogs)) st.subAccessLogs = [];
      st.subAccessLogs.unshift({
        id: `slog_${crypto.randomBytes(4).toString('hex')}`,
        subId: subGroup.id,
        subName: subGroup.name,
        groupName: subGroup.groupName || '默认分组',
        at: new Date().toISOString(),
        ip,
        device: deviceLabel,
        userAgent: ua.slice(0, 240),
        format,
        allowed: Boolean(allowed),
        reason,
        responseBytes
      });
      if (st.subAccessLogs.length > 300) st.subAccessLogs.length = 300;
      const sg = (st.subGroups || []).find((g) => g.id === subGroup.id);
      if (sg) {
        if (allowed) {
          sg.pullCount = Number(sg.pullCount || 0) + 1;
          sg.lastAccessAt = new Date().toISOString();
        } else {
          sg.blockedCount = Number(sg.blockedCount || 0) + 1;
        }
      }
    });
  };

  if (stats.status !== 'active') {
    recordLog(false, stats.statusReason);
    return { allowed: false, statusCode: 403, reason: stats.statusReason, stats };
  }

  const windowHours = Math.max(1, Number(subGroup.accessWindowHours || 24));
  const cutoffMs = Date.now() - windowHours * 3600 * 1000;
  const ipHash = hashKey(ip);
  const devHash = hashKey(explicitDevice || `${ip}::${ua}`);
  const ipLimit = Math.max(0, Number(subGroup.ipLimit || 0));
  const devLimit = Math.max(0, Number(subGroup.deviceLimit || 0));

  const activeKeys = (subGroup.accessKeys || []).filter((k) => (Date.parse(k.lastSeenAt || '') || 0) >= cutoffMs);
  const existingIpKey = activeKeys.find((k) => k.kind === 'ip' && (k.hash === ipHash || k.label === ip));
  const existingDevKey = activeKeys.find((k) => k.kind === 'device' && k.hash === devHash);

  // Combine active subscription pull IPs with live node connection IPs
  const activeIpSet = new Set([
    ...stats.liveOnlineIps,
    ...activeKeys.filter((k) => k.kind === 'ip').map((k) => k.label)
  ].filter(Boolean));

  if (ipLimit > 0 && !activeIpSet.has(ip) && activeIpSet.size >= ipLimit) {
    const reason = `活跃连接/拉取 IP 数超限 (上限 ${ipLimit} 个，当前已占 ${activeIpSet.size} 个)`;
    recordLog(false, reason);
    return { allowed: false, statusCode: 403, reason, stats };
  }

  const activeDevCount = Math.max(
    stats.liveOnlineDevices,
    activeKeys.filter((k) => k.kind === 'device').length
  );
  if (devLimit > 0 && !existingDevKey && activeDevCount >= devLimit) {
    const reason = `活跃连接/拉取设备数超限 (上限 ${devLimit} 台，当前已占 ${activeDevCount} 台)`;
    recordLog(false, reason);
    return { allowed: false, statusCode: 403, reason, stats };
  }

  // Allowed: update accessKeys on subGroup
  const nowIso = new Date().toISOString();
  store.transact((st) => {
    const sg = (st.subGroups || []).find((g) => g.id === subGroup.id);
    if (!sg) return;
    if (!Array.isArray(sg.accessKeys)) sg.accessKeys = [];
    // Prune expired keys older than window
    sg.accessKeys = sg.accessKeys.filter((k) => (Date.parse(k.lastSeenAt || '') || 0) >= cutoffMs);

    const upsertKey = (kind, hash, label) => {
      const found = sg.accessKeys.find((k) => k.kind === kind && k.hash === hash);
      if (found) {
        found.label = label;
        found.lastSeenAt = nowIso;
        found.hits = Number(found.hits || 1) + 1;
      } else {
        sg.accessKeys.push({
          kind,
          hash,
          label,
          firstSeenAt: nowIso,
          lastSeenAt: nowIso,
          hits: 1
        });
      }
    };
    upsertKey('ip', ipHash, ip);
    upsertKey('device', devHash, deviceLabel);
  });

  return { allowed: true, statusCode: 200, reason: '允许访问', stats, recordLog };
}

/**
 * Collects all enabled client links across all enabled inbounds (or for a Custom Subscription Group / ad-hoc selection).
 */
function collectSubscriptionItems(state, subToken = '', reqHost = '', filterNodeId = '', filterItemsCsv = '') {
  const token = String(subToken || '').trim();
  const aggregateSecret = String(state.settings?.subToken || '').trim();

  if (!token || token === 'all') {
    return [];
  }

  // 1. Check if token matches a Custom Subscription Group (`state.subGroups`)
  const matchedGroup = (state.subGroups || []).find((g) => g.token === token || g.id === token);
  if (matchedGroup) {
    if (matchedGroup.enabled === false) return [];
    return collectSubGroupItems(state, matchedGroup, reqHost);
  }

  const isAggregateMatch = Boolean(aggregateSecret && token === aggregateSecret);
  if (!isAggregateMatch && token.length < 6) {
    return [];
  }

  const explicitFilterSet = filterItemsCsv
    ? new Set(String(filterItemsCsv).split(',').map((s) => s.trim()).filter(Boolean))
    : null;

  const cleanReqHost = String(reqHost || '').split(':')[0].replace(/^\[|\]$/g, '');
  const realCert = (state.certificates || []).find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false);
  const publicHost = state.settings?.webDomain || realCert?.domain || state.settings?.publicIPv4 || cleanReqHost || '127.0.0.1';
  const items = [];

  const cleanNodeFilter = String(filterNodeId || '').trim();
  for (const inbound of state.inbounds || []) {
    if (inbound.enable === false || inbound.protocol === 'direct') continue;
    const inbNodeId = inbound.nodeId || 'node_local';
    if (cleanNodeFilter && cleanNodeFilter !== 'all' && inbNodeId !== cleanNodeFilter) continue;

    const assignedNode = (state.nodes || []).find((n) => n.id === inbNodeId);
    const nodeDomain = assignedNode?.domain || '';
    const nodeHost = inbound.publicHost || nodeDomain || (assignedNode && !assignedNode.isLocal && assignedNode.host ? assignedNode.host : '') || publicHost;
    const nodeSettings = nodeDomain
      ? { ...(state.settings || {}), webDomain: nodeDomain, defaultTlsDomain: nodeDomain }
      : (state.settings || {});
    const links = buildClientLinks(inbound, nodeHost, state.certificates || [], nodeSettings);
    for (let idx = 0; idx < links.length; idx += 1) {
      const link = links[idx];
      const client =
        (inbound.clients || []).find(
          (c) =>
            (link.clientId && c.id === link.clientId) ||
            (link.subId && c.subId === link.subId) ||
            (link.clientName && (c.email === link.clientName || c.name === link.clientName))
        ) ||
        (inbound.clients || [])[idx] ||
        {};
      if (client.enable === false) continue;

      if (explicitFilterSet && explicitFilterSet.size > 0) {
        const cKey = `${inbound.id}::${client.id || client.email || idx}`;
        const hasMatch =
          explicitFilterSet.has(inbound.id) ||
          explicitFilterSet.has(inbound.tag) ||
          explicitFilterSet.has(cKey) ||
          (client.id && explicitFilterSet.has(String(client.id))) ||
          (client.subId && explicitFilterSet.has(String(client.subId)));
        if (!hasMatch) continue;
      }

      if (!isAggregateMatch) {
        const matchSub = client.subId === token || link.subId === token || inbound.id === token || inbound.tag === token;
        if (!matchSub) continue;
      }
      items.push({
        inbound,
        client,
        link: { ...link }
      });
    }
  }

  // Also include externalNodes if using aggregate token with explicitFilterSet
  if (isAggregateMatch && explicitFilterSet && explicitFilterSet.size > 0) {
    for (const ext of state.externalNodes || []) {
      if (ext.enabled === false) continue;
      if (!explicitFilterSet.has(ext.id)) continue;
      const extLink = buildLinkFromExternalUri(ext.uri, ext.name);
      if (extLink) {
        items.push({
          inbound: { id: ext.id, remark: ext.name, protocol: extLink.protocol, port: 0, up: 0, down: 0, external: true },
          client: {},
          link: extLink
        });
      }
    }
  }

  return deduplicateSubscriptionItemNames(items);
}

/**
 * Computes subscription-userinfo header string (upload, download, total, expire) for Clash / Shadowrocket / v2rayN.
 */
function buildSubUserinfoHeader(items, subGroupStats = null, subGroup = null) {
  if (subGroupStats && subGroup) {
    const expSec = subGroup.expiryTime && Number(subGroup.expiryTime) > 0 ? Math.floor(Number(subGroup.expiryTime) / 1000) : 0;
    return `upload=${subGroupStats.usedUp}; download=${subGroupStats.usedDown}; total=${subGroupStats.totalBytes || 0}; expire=${expSec}`;
  }

  let upload = 0;
  let download = 0;
  let total = 0;
  let expireSec = 0;

  if (items.length === 1 && (items[0].inbound.clients?.length || 0) > 1) {
    const { inbound, client } = items[0];
    upload = Number(client.up || 0);
    download = Number(client.down || 0);
    if (Number(client.totalBytes || 0) > 0) {
      total = Number(client.totalBytes);
    } else if (Number(client.totalGB || 0) > 0) {
      total = Number(client.totalGB) > 1024 * 1024 ? Number(client.totalGB) : Math.round(Number(client.totalGB) * (1024 ** 3));
    } else if (Number(inbound.total || 0) > 0) {
      total = Number(inbound.total);
    }
    const expMs = Number(client.expiryTime || inbound.expiryTime || 0);
    if (expMs > 0) expireSec = Math.floor(expMs / 1000);
    return `upload=${upload}; download=${download}; total=${total}; expire=${expireSec}`;
  }

  const seenInbounds = new Set();
  for (const { inbound, client } of items) {
    if (!seenInbounds.has(inbound.id)) {
      seenInbounds.add(inbound.id);
      upload += Number(inbound.up || client.up || 0);
      download += Number(inbound.down || client.down || 0);
      if (Number(inbound.total || 0) > 0) {
        total += Number(inbound.total);
      } else if (Number(client.totalGB || 0) > 0) {
        total += Number(client.totalGB) > 1024 * 1024 ? Number(client.totalGB) : Number(client.totalGB) * (1024 ** 3);
      }
      const expMs = Number(inbound.expiryTime || client.expiryTime || 0);
      if (expMs > 0) {
        const sec = Math.floor(expMs / 1000);
        if (expireSec === 0 || sec < expireSec) expireSec = sec;
      }
    }
  }
  return `upload=${upload}; download=${download}; total=${total}; expire=${expireSec}`;
}

function buildClashConfigYaml(items) {
  const proxyLines = items.map((x) => x.link.clashYaml).filter(Boolean);
  const names = items.map((x) => x.link.name);
  const nodeList = names.length ? names : ['DIRECT'];

  const fmtList = (arr, indent = '      ') => arr.map((item) => `${indent}- ${JSON.stringify(item)}`).join('\n');

  const lines = [
    'port: 7890',
    'socks-port: 7891',
    'mixed-port: 7892',
    'allow-lan: true',
    'mode: Rule',
    'log-level: info',
    'unified-delay: true',
    'tcp-concurrent: true',
    'external-controller: :9090',
    '',
    'dns:',
    '  enabled: true',
    '  ipv6: false',
    '  nameserver:',
    '    - 119.29.29.29',
    '    - 223.5.5.5',
    '  fallback:',
    '    - 8.8.8.8',
    '    - 8.8.4.4',
    '    - tls://1.0.0.1:853',
    '    - tls://dns.google:853',
    '',
    ...(proxyLines.length ? ['proxies:', ...proxyLines] : ['proxies: []']),
    '',
    'proxy-groups:',
    '  - name: "🔰 节点选择"',
    '    type: select',
    '    proxies:',
    fmtList(['♻️ 自动选择', ...names, '🎯 全球直连']),
    '  - name: "♻️ 自动选择"',
    '    type: url-test',
    '    url: http://www.gstatic.com/generate_204',
    '    interval: 300',
    '    tolerance: 50',
    '    proxies:',
    fmtList(nodeList),
    '  - name: "🤖 AI 专线"',
    '    type: select',
    '    proxies:',
    fmtList(['🔰 节点选择', '♻️ 自动选择', ...names]),
    '  - name: "🎥 NETFLIX"',
    '    type: select',
    '    proxies:',
    fmtList(['🔰 节点选择', '♻️ 自动选择', ...names, '🎯 全球直连']),
    '  - name: "🌍 国外媒体"',
    '    type: select',
    '    proxies:',
    fmtList(['🔰 节点选择', '♻️ 自动选择', ...names, '🎯 全球直连']),
    '  - name: "📲 电报信息"',
    '    type: select',
    '    proxies:',
    fmtList(['🔰 节点选择', '♻️ 自动选择', ...names, '🎯 全球直连']),
    '  - name: "Ⓜ️ 微软服务"',
    '    type: select',
    '    proxies:',
    fmtList(['🎯 全球直连', '🔰 节点选择', '♻️ 自动选择']),
    '  - name: "🍎 苹果服务"',
    '    type: select',
    '    proxies:',
    fmtList(['🎯 全球直连', '🔰 节点选择', '♻️ 自动选择']),
    '  - name: "🌏 国内媒体"',
    '    type: select',
    '    proxies:',
    fmtList(['🎯 全球直连', '🔰 节点选择']),
    '  - name: "🎯 全球直连"',
    '    type: select',
    '    proxies:',
    '      - DIRECT',
    '  - name: "⛔️ 广告拦截"',
    '    type: select',
    '    proxies:',
    '      - REJECT',
    '      - DIRECT',
    '  - name: "🛑 全球拦截"',
    '    type: select',
    '    proxies:',
    '      - REJECT',
    '      - DIRECT',
    '  - name: "🐟 漏网之鱼"',
    '    type: select',
    '    proxies:',
    '      - "🔰 节点选择"',
    '      - "🎯 全球直连"',
    '',
    'rules:',
    '  # 局域网与本地直连',
    '  - DOMAIN-SUFFIX,local,🎯 全球直连',
    '  - IP-CIDR,192.168.0.0/16,🎯 全球直连,no-resolve',
    '  - IP-CIDR,10.0.0.0/8,🎯 全球直连,no-resolve',
    '  - IP-CIDR,172.16.0.0/12,🎯 全球直连,no-resolve',
    '  - IP-CIDR,127.0.0.0/8,🎯 全球直连,no-resolve',
    '  - IP-CIDR,100.64.0.0/10,🎯 全球直连,no-resolve',
    '  - IP-CIDR6,::1/128,🎯 全球直连,no-resolve',
    '  - IP-CIDR6,fc00::/7,🎯 全球直连,no-resolve',
    '  - IP-CIDR6,fe80::/10,🎯 全球直连,no-resolve',
    '  - IP-CIDR6,fd00::/8,🎯 全球直连,no-resolve',
    '',
    '  # AI 平台专线 (ChatGPT / OpenAI / Claude / Gemini / Grok / Perplexity / Cursor)',
    '  - DOMAIN-SUFFIX,openai.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,chatgpt.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,oaistatic.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,anthropic.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,claude.ai,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,claudeusercontent.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,gemini.google.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,aistudio.google.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,generativelanguage.googleapis.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,perplexity.ai,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,grok.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,x.ai,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,cursor.sh,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,cursor.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,copilot.microsoft.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,midjourney.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,poe.com,🤖 AI 专线',
    '  - DOMAIN-SUFFIX,huggingface.co,🤖 AI 专线',
    '',
    '  # Google 服务走代理（解决安卓下载/推送/Chrome卡顿/外贸搜索）',
    '  - DOMAIN-SUFFIX,google,🔰 节点选择',
    '  - DOMAIN-SUFFIX,google.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,googleapis.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,gstatic.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,googleusercontent.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,googlevideo.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,google-analytics.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,youtube.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,ytimg.com,🌍 国外媒体',
    '  - DOMAIN,mtalk.google.com,🔰 节点选择',
    '  - DOMAIN-KEYWORD,google,🔰 节点选择',
    '  - DOMAIN-KEYWORD,googleapis,🔰 节点选择',
    '  - DOMAIN-KEYWORD,gmail,🔰 节点选择',
    '',
    '  # NETFLIX 与流媒体',
    '  - DOMAIN-SUFFIX,netflix.com,🎥 NETFLIX',
    '  - DOMAIN-SUFFIX,netflix.net,🎥 NETFLIX',
    '  - DOMAIN-SUFFIX,nflxvideo.net,🎥 NETFLIX',
    '  - DOMAIN-SUFFIX,nflximg.net,🎥 NETFLIX',
    '  - DOMAIN-SUFFIX,nflxext.com,🎥 NETFLIX',
    '  - DOMAIN-SUFFIX,fast.com,🎥 NETFLIX',
    '',
    '  # 社交媒体 / 短视频 / 外贸跨境电商与通讯',
    '  - DOMAIN-SUFFIX,tiktok.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,tiktokv.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,byteoversea.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,ibytedtos.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,musically.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,facebook.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,fb.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,fbcdn.net,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,instagram.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,cdninstagram.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,twitter.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,x.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,twimg.com,🌍 国外媒体',
    '  - DOMAIN-SUFFIX,whatsapp.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,whatsapp.net,🔰 节点选择',
    '  - DOMAIN-SUFFIX,linkedin.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,amazon.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,shopify.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,paypal.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,stripe.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,github.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,githubusercontent.com,🔰 节点选择',
    '  - DOMAIN-SUFFIX,t.me,📲 电报信息',
    '  - DOMAIN-SUFFIX,telegram.org,📲 电报信息',
    '  - IP-CIDR,91.108.4.0/22,📲 电报信息,no-resolve',
    '  - IP-CIDR,91.108.8.0/22,📲 电报信息,no-resolve',
    '  - IP-CIDR,91.108.16.0/22,📲 电报信息,no-resolve',
    '  - IP-CIDR,91.108.56.0/22,📲 电报信息,no-resolve',
    '  - IP-CIDR,149.154.160.0/20,📲 电报信息,no-resolve',
    '',
    '  # 微软与苹果服务',
    '  - DOMAIN-KEYWORD,microsoft,Ⓜ️ 微软服务',
    '  - DOMAIN-SUFFIX,office.com,Ⓜ️ 微软服务',
    '  - DOMAIN-SUFFIX,bing.com,Ⓜ️ 微软服务',
    '  - DOMAIN-SUFFIX,apple.com,🍎 苹果服务',
    '  - DOMAIN-SUFFIX,icloud.com,🍎 苹果服务',
    '',
    '  # 常用国内软件统计过滤（保持直连提高速度）',
    '  - DOMAIN,app.adjust.com,🎯 全球直连',
    '  - DOMAIN,app.appsflyer.com,🎯 全球直连',
    '  - DOMAIN,log.mmstat.com,🎯 全球直连',
    '  - DOMAIN-SUFFIX,cn,🎯 全球直连',
    '  - DOMAIN-SUFFIX,baidu.com,🎯 全球直连',
    '  - DOMAIN-SUFFIX,qq.com,🎯 全球直连',
    '  - DOMAIN-SUFFIX,taobao.com,🎯 全球直连',
    '  - DOMAIN-SUFFIX,tmall.com,🎯 全球直连',
    '  - DOMAIN-SUFFIX,jd.com,🎯 全球直连',
    '  - DOMAIN-SUFFIX,bilibili.com,🌏 国内媒体',
    '',
    '  # 默认兜底',
    '  - GEOIP,CN,🎯 全球直连,no-resolve',
    '  - MATCH,🐟 漏网之鱼'
  ];

  return lines.join('\n') + '\n';
}

function buildSurgeConfig(items) {
  const policies = [];
  const names = [];
  for (const it of items) {
    const safeName = String(it.link.name || 'Node').replace(/[\r\n,=]/g, '_');
    if (it.link.surgeLine) {
      policies.push(it.link.surgeLine);
      names.push(safeName);
      continue;
    }
    try {
      const parsed = buildLinkFromExternalUri(it.link.uri, safeName);
      if (parsed && parsed.surgeLine) {
        policies.push(parsed.surgeLine);
        names.push(safeName);
      }
    } catch { /* skip unsupported protocol for Surge */ }
  }
  const nameList = names.length ? names.join(', ') : 'DIRECT';
  return [
    '[General]',
    'loglevel = notify',
    'dns-server = 119.29.29.29, 223.5.5.5, 8.8.8.8',
    'skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, *.local',
    '',
    '[Proxy]',
    'DIRECT = direct',
    ...policies,
    '',
    '[Proxy Group]',
    `🔰 节点选择 = select, ♻️ 自动选择, ${nameList}, DIRECT`,
    `♻️ 自动选择 = url-test, ${nameList}, url=http://www.gstatic.com/generate_204, interval=300`,
    '',
    '[Rule]',
    'DOMAIN-SUFFIX,cn,DIRECT',
    'GEOIP,CN,DIRECT',
    'FINAL,🔰 节点选择,dns-failed'
  ].join('\n') + '\n';
}

function formatSubscription(state, subToken = '', format = 'base64', reqHost = '', filterNodeId = '', filterItemsCsv = '', subGroupStats = null, subGroup = null) {
  const items = collectSubscriptionItems(state, subToken, reqHost, filterNodeId, filterItemsCsv);
  if (!items.length) {
    return null;
  }
  const uris = items.map((x) => x.link.uri);
  const userinfo = buildSubUserinfoHeader(items, subGroupStats, subGroup);

  if (format === 'raw' || format === 'uri') {
    return {
      contentType: 'text/plain; charset=utf-8',
      userinfo,
      body: uris.join('\n')
    };
  }

  if (format === 'clash' || format === 'mihomo') {
    return {
      contentType: 'text/yaml; charset=utf-8',
      userinfo,
      body: buildClashConfigYaml(items)
    };
  }

  if (format === 'surge') {
    return {
      contentType: 'text/plain; charset=utf-8',
      userinfo,
      body: buildSurgeConfig(items)
    };
  }

  if (format === 'singbox' || format === 'json') {
    const outbounds = items
      .map((x) => {
        try { return JSON.parse(x.link.singboxJson); } catch { return null; }
      })
      .filter(Boolean);
    const tags = outbounds.map((o) => o.tag);
    const nodeTags = tags.length ? tags : ['direct'];
    return {
      contentType: 'application/json; charset=utf-8',
      userinfo,
      body: JSON.stringify({
        log: { level: 'info', timestamp: true },
        inbounds: [
          { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 7890 }
        ],
        outbounds: [
          { type: 'selector', tag: '🔰 节点选择', outbounds: ['♻️ 自动选择', ...nodeTags, 'direct'] },
          { type: 'urltest', tag: '♻️ 自动选择', outbounds: nodeTags, url: 'http://www.gstatic.com/generate_204', interval: '5m' },
          { type: 'selector', tag: '🤖 AI 专线', outbounds: ['🔰 节点选择', '♻️ 自动选择', ...nodeTags] },
          ...outbounds,
          { type: 'direct', tag: 'direct' },
          { type: 'block', tag: 'block' }
        ],
        route: {
          rules: [
            { action: 'sniff' },
            { ip_is_private: true, outbound: 'direct' },
            {
              domain_suffix: ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'anthropic.com', 'claude.ai', 'gemini.google.com', 'perplexity.ai', 'grok.com', 'cursor.com'],
              outbound: '🤖 AI 专线'
            },
            {
              domain_suffix: ['cn', 'baidu.com', 'qq.com', 'taobao.com', 'jd.com', 'bilibili.com', '163.com', 'aliyun.com'],
              outbound: 'direct'
            }
          ],
          final: '🔰 节点选择',
          auto_detect_interface: true
        }
      }, null, 2)
    };
  }

  return {
    contentType: 'text/plain; charset=utf-8',
    userinfo,
    body: Buffer.from(uris.join('\n'), 'utf8').toString('base64')
  };
}

module.exports = {
  buildLinkFromExternalUri,
  buildMasterSubBaseUrl,
  buildSubscriptionFormatUrls,
  collectSubGroupItems,
  computeSubGroupRuntimeStats,
  checkAndRecordSubGroupAccess,
  collectSubscriptionItems,
  buildSubUserinfoHeader,
  buildClashConfigYaml,
  buildSurgeConfig,
  formatSubscription
};
