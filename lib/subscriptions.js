'use strict';

const { buildClientLinks } = require('./protocols');

/**
 * Collects all enabled client links across all enabled inbounds.
 * Requires either the secret aggregate `settings.subToken` (for all nodes)
 * or a specific client's `subId` (for single-node subscription).
 * Bare `/sub/all` or short/invalid tokens return `[]` to prevent scanning/leaks.
 */
function collectSubscriptionItems(state, subToken = '', reqHost = '') {
  const token = String(subToken || '').trim();
  const aggregateSecret = String(state.settings?.subToken || '').trim();

  if (!token || token === 'all') {
    return [];
  }

  const isAggregateMatch = Boolean(aggregateSecret && token === aggregateSecret);
  if (!isAggregateMatch && token.length < 6) {
    return [];
  }

  const cleanReqHost = String(reqHost || '').split(':')[0].replace(/^\[|\]$/g, '');
  const realCert = (state.certificates || []).find((c) => c.type !== 'self-signed' && c.valid !== false);
  const publicHost = state.settings?.webDomain || realCert?.domain || state.settings?.publicIPv4 || cleanReqHost || '127.0.0.1';
  const items = [];

  for (const inbound of state.inbounds || []) {
    if (inbound.enable === false || inbound.protocol === 'direct') continue;
    const assignedNode = (state.nodes || []).find((n) => n.id === (inbound.nodeId || 'node_local'));
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
  const usedNames = new Map();
  for (const it of items) {
    const baseName = it.link.name || `node-${it.inbound.port}`;
    const count = usedNames.get(baseName) || 0;
    usedNames.set(baseName, count + 1);
    if (count > 0) {
      const uniqueName = `${baseName} (${count + 1})`;
      it.link.name = uniqueName;
      if (it.link.clashYaml) {
        try {
          const obj = JSON.parse(it.link.clashYaml.replace(/^\s*-\s*/, ""));
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
 * Computes subscription-userinfo header string (upload, download, total, expire) for Clash / Shadowrocket / v2rayN.
 */
function buildSubUserinfoHeader(items) {
  let upload = 0;
  let download = 0;
  let total = 0;
  let expireSec = 0;

  // If subscribing to a single client on a multi-client inbound, report that client's individual usage & quota
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

function formatSubscription(state, subToken = '', format = 'base64', reqHost = '') {
  const items = collectSubscriptionItems(state, subToken, reqHost);
  if (!items.length) {
    return null;
  }
  const uris = items.map((x) => x.link.uri);
  const userinfo = buildSubUserinfoHeader(items);

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
  collectSubscriptionItems,
  buildSubUserinfoHeader,
  buildClashConfigYaml,
  formatSubscription
};
