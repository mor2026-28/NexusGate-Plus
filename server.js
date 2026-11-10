'use strict';

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Store, defaultState } = require('./lib/store');
const { hashSecret, verifySecret, randomString, generateStrongCredential, SessionManager } = require('./lib/auth');
const {
  sendJson,
  sendError,
  readBuffer,
  readJson,
  normalizeBasePath,
  stripBasePath,
  route,
  serveStatic
} = require('./lib/http');
const {
  REALITY_PRESETS,
  SS_METHODS,
  INBOUND_PROTOCOLS,
  OUTBOUND_PROTOCOLS,
  ensureUuid,
  normalizeSsMethod,
  sanitizeSsOutboundPasswordAndMethod,
  ensureSsPassword,
  isCertFileSelfSigned,
  generateRealityKeypair,
  deriveRealityPublicKey,
  generateSsKey,
  generateShortId,
  toSingboxOutbound,
  buildClientLinks,
  parseShareUriToOutbound
} = require('./lib/protocols');
const { KNOWN_VERSIONS, computeResetCycleKey, buildSingboxConfig, SingboxManager } = require('./lib/singbox');
const {
  getSystemStatus,
  applyKernelAcceleration,
  cleanupSystemLogsAndMemory,
  inspectCertificate,
  discoverSystemCertificates,
  issueSelfSignedCert,
  saveCustomCert,
  issueAcmeCert,
  tcpPingHostPort,
  openFirewallPorts
} = require('./lib/system');
const { parse3xuiPayload, apply3xuiMigration } = require('./lib/migrate3xui');
const {
  ensureClusterNodes,
  syncExitNodeOutbounds,
  compileNodeSingboxConfig,
  pushConfigToAgentNode,
  handleAgentHeartbeat,
  buildAgentInstallCommand
} = require('./lib/cluster');
const { triggerNodeFailover, triggerNodeFailback, updateCloudflareDnsIp, verifyCloudflareDomainAccess } = require('./lib/failover');
const { collectSubscriptionItems, formatSubscription } = require('./lib/subscriptions');

const VERSION = '1.0.0';
const APP_ROOT = __dirname;
const PUBLIC_DIR = path.join(APP_ROOT, 'public');
const DATA_FILE = process.env.NG_DATA_FILE || path.join(APP_ROOT, 'data', 'nexusgate.json');

const store = new Store(DATA_FILE);
const sessions = new SessionManager(24);
sessions.setMaxAgeMinutes(store.state.settings.sessionMaxAge || 720);
const singbox = new SingboxManager(store);
const loginAttempts = new Map();
let activeServer = null;

function getActiveRealCert(st = store.state) {
  const certs = st.certificates || [];
  const s = st.settings || {};
  return (
    certs.find(
      (c) =>
        (c.certPath === s.webCertFile || c.certPath === s.defaultCertFile || (s.webDomain && c.domain === s.webDomain)) &&
        c.type !== 'self-signed' &&
        !c.isSelfSigned &&
        c.valid !== false
    ) ||
    certs.find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false) ||
    null
  );
}

function bindCertificateEverywhere(st, cert, applyToPanel = true, applyToNodes = true, forceAllTlsNodes = false) {
  const isRealAcme = cert.type !== 'self-signed' && !cert.isSelfSigned;
  const prevDefaultDomain = st.settings.defaultTlsDomain || st.settings.webDomain || '';
  const prevDefaultCert = st.settings.defaultCertFile || st.settings.webCertFile || '';

  if (Array.isArray(st.settings.deletedCertDomains)) {
    st.settings.deletedCertDomains = st.settings.deletedCertDomains.filter((d) => d !== cert.domain);
  }
  if (Array.isArray(st.settings.deletedCertPaths)) {
    st.settings.deletedCertPaths = st.settings.deletedCertPaths.filter((p) => p !== cert.certPath);
  }

  st.certificates = (st.certificates || []).filter((c) => {
    if (c.domain === 'www.bing.com') return false;
    if (c.domain === cert.domain || c.certPath === cert.certPath) return false;
    if (isRealAcme && (c.type === 'self-signed' || c.isSelfSigned)) return false;
    return true;
  });
  st.certificates.unshift(cert);

  if (applyToPanel) {
    st.settings.webCertFile = cert.certPath;
    st.settings.webKeyFile = cert.keyPath;
    if (isRealAcme && cert.domain && cert.domain !== 'www.apple.com') {
      st.settings.webDomain = cert.domain;
    } else if (!isRealAcme && !st.settings.webDomain) {
      st.settings.webDomain = '';
    }
  }
  if (applyToNodes) {
    st.settings.defaultTlsDomain = cert.domain;
    st.settings.defaultCertFile = cert.certPath;
    st.settings.defaultKeyFile = cert.keyPath;
    for (const inb of st.inbounds || []) {
      if (inb.security === 'reality') {
        delete inb.certPath;
        delete inb.keyPath;
      } else if (inb.security === 'tls') {
        const inbCertMissingOrSelf = !inb.certPath || !fs.existsSync(inb.certPath) || isCertFileSelfSigned(inb.certPath);
        const matchesPreviousDefault =
          (prevDefaultDomain && inb.tlsDomain === prevDefaultDomain) ||
          (prevDefaultCert && inb.certPath === prevDefaultCert);
        if (
          forceAllTlsNodes ||
          inbCertMissingOrSelf ||
          matchesPreviousDefault ||
          inb.tlsDomain === 'www.bing.com' ||
          inb.tlsDomain === 'www.apple.com'
        ) {
          inb.tlsDomain = cert.domain;
          inb.certPath = cert.certPath;
          inb.keyPath = cert.keyPath;
        }
      }
    }
  }
}

let _lastSyncCertsAt = 0;
function syncDiscoveredCerts(force = false) {
  const now = Date.now();
  if (!force && _lastSyncCertsAt > 0 && now - _lastSyncCertsAt < 30000) return;
  _lastSyncCertsAt = now;
  const discovered = discoverSystemCertificates(force);
  let changed = false;
  const prevPanelCert = store.state.settings.webCertFile || '';
  const deletedDomains = new Set(store.state.settings.deletedCertDomains || []);
  const deletedPaths = new Set(store.state.settings.deletedCertPaths || []);

  const beforeLen = store.state.certificates.length;
  store.state.certificates = (store.state.certificates || []).filter((c) => {
    if (c.domain === 'www.bing.com') return false;
    if (deletedDomains.has(c.domain) || deletedPaths.has(c.certPath)) return false;
    if (c.certPath && !fs.existsSync(c.certPath)) return false;
    return true;
  });
  if (store.state.certificates.length !== beforeLen) changed = true;

  for (const d of discovered) {
    if (deletedDomains.has(d.domain) || deletedPaths.has(d.certPath)) continue;
    const existingIdx = store.state.certificates.findIndex((c) => c.certPath === d.certPath || c.domain === d.domain);
    if (existingIdx >= 0) {
      if (store.state.certificates[existingIdx].type === 'self-signed' && d.type !== 'self-signed') {
        store.state.certificates[existingIdx] = d;
        changed = true;
      }
    } else {
      const hasRealAtTop = store.state.certificates.some((c) => c.type !== 'self-signed' && !c.isSelfSigned);
      if (d.type !== 'self-signed' && !hasRealAtTop) {
        store.state.certificates.unshift(d);
      } else {
        store.state.certificates.push(d);
      }
      changed = true;
    }
  }

  const hasAnyRealCert = store.state.certificates.some((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false);
  if (hasAnyRealCert && store.state.certificates.some((c) => c.type === 'self-signed' || c.isSelfSigned)) {
    store.state.certificates = store.state.certificates.filter((c) => c.type !== 'self-signed' && !c.isSelfSigned);
    changed = true;
  }

  // If a backup migration restored a specific certificate (e.g. vm.362353.xyz) and an older version
  // accidentally bound a different discovered cert, automatically prioritize the migrated certificate once
  const lastMigDomain = store.state.migrations?.[0]?.restoredCertDomains?.[0] || '';
  if (lastMigDomain && !store.state.settings._migratedCertHealed && store.state.settings.webDomain !== lastMigDomain) {
    const migCert = store.state.certificates.find(
      (c) => c.domain === lastMigDomain && c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false
    );
    if (migCert) {
      store.state.settings._migratedCertHealed = true;
      bindCertificateEverywhere(store.state, migCert, true, true, true);
      changed = true;
    }
  }

  const curCertPath = store.state.settings.webCertFile || store.state.settings.defaultCertFile || '';
  const activeRealCert = store.state.certificates.find(
    (c) =>
      (c.certPath === curCertPath || (store.state.settings.webDomain && c.domain === store.state.settings.webDomain)) &&
      c.type !== 'self-signed' &&
      !c.isSelfSigned &&
      c.valid !== false
  );

  if (activeRealCert) {
    if (
      store.state.settings.webDomain !== activeRealCert.domain ||
      store.state.settings.defaultTlsDomain !== activeRealCert.domain ||
      store.state.settings.webCertFile !== activeRealCert.certPath ||
      store.state.settings.defaultCertFile !== activeRealCert.certPath
    ) {
      bindCertificateEverywhere(store.state, activeRealCert, true, true, false);
      changed = true;
    }
  } else {
    const bestRealCert = store.state.certificates.find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false);
    if (bestRealCert) {
      bindCertificateEverywhere(store.state, bestRealCert, true, true, true);
      changed = true;
    } else if (!store.state.settings.defaultCertFile && store.state.certificates[0]) {
      const c0 = store.state.certificates[0];
      store.state.settings.defaultTlsDomain = c0.domain;
      store.state.settings.defaultCertFile = c0.certPath;
      store.state.settings.defaultKeyFile = c0.keyPath;
      changed = true;
    }
  }

  if (changed) {
    store.save();
    if (activeServer && store.state.settings.webCertFile && store.state.settings.webCertFile !== prevPanelCert) {
      setTimeout(() => restartPanelServer(), 200);
    }
  }
}

syncDiscoveredCerts();

if (process.argv.length > 2 && process.argv[2].startsWith('--')) {
  handleCliCommand(process.argv.slice(2));
  process.exit(0);
}

function isAutoRuleRemark(remark) {
  const s = String(remark || '').trim();
  return !s || /^入站转发\s*[:：]/.test(s) || /^分流规则(\s*#\d+)?(\s*\([^)]*\))?$/.test(s);
}

function buildAutoRuleRemark(inboundList, outboundTag) {
  const inbs = (Array.isArray(inboundList) ? inboundList : String(inboundList || '').split(',')).map((s) => s.trim()).filter(Boolean);
  const out = String(outboundTag || 'direct').trim();
  if (inbs.length > 0) {
    return `入站转发: ${inbs.join(', ')} ➔ ${out}`;
  }
  return `分流规则 (${out})`;
}

function syncInboundRelayToRoutingRule(st, inbound) {
  if (!st.routing) st.routing = { final: 'direct', rules: [] };
  if (!Array.isArray(st.routing.rules)) st.routing.rules = [];

  const existingIdx = st.routing.rules.findIndex(
    (r) => Array.isArray(r.inbound) && r.inbound.length === 1 && r.inbound[0] === inbound.tag &&
      !r.domain?.length && !r.domain_suffix?.length && !r.ip_cidr?.length && !r.port?.length && !r.protocol?.length && !r.ip_is_private
  );

  if (inbound.outboundTag && inbound.outboundTag !== 'default') {
    const prevRemark = existingIdx >= 0 ? st.routing.rules[existingIdx].remark : '';
    const relayRule = {
      id: existingIdx >= 0 ? st.routing.rules[existingIdx].id : `rule_relay_${crypto.randomBytes(4).toString('hex')}`,
      remark: isAutoRuleRemark(prevRemark) ? buildAutoRuleRemark([inbound.tag], inbound.outboundTag) : prevRemark,
      enabled: true,
      action: 'route',
      inbound: [inbound.tag],
      user: [],
      domain: [],
      domain_suffix: [],
      domain_keyword: [],
      ip_cidr: [],
      source_ip_cidr: [],
      port: [],
      source_port: [],
      network: '',
      protocol: [],
      rule_set: [],
      ip_is_private: false,
      outbound: inbound.outboundTag
    };
    if (existingIdx >= 0) {
      st.routing.rules[existingIdx] = relayRule;
    } else {
      const sniffIdx = st.routing.rules.findIndex((r) => r.action === 'sniff');
      st.routing.rules.splice(sniffIdx + 1, 0, relayRule);
    }
  } else if (existingIdx >= 0) {
    st.routing.rules.splice(existingIdx, 1);
  }
}

function syncRoutingRulesToInbounds(st) {
  for (const inb of st.inbounds || []) {
    const matchedRule = (st.routing?.rules || []).find(
      (r) => r.enabled !== false && Array.isArray(r.inbound) && r.inbound.includes(inb.tag) &&
        !r.domain?.length && !r.domain_suffix?.length && !r.ip_cidr?.length && !r.port?.length && !r.protocol?.length && !r.ip_is_private
    );
    inb.outboundTag = matchedRule ? matchedRule.outbound : 'default';
  }
}

function getPanelInfoSummary() {
  const s = store.state.settings;
  const activeCert = getActiveRealCert(store.state);
  const certFile = (s.webCertFile && fs.existsSync(s.webCertFile)) ? s.webCertFile : (activeCert?.certPath || '');
  const keyFile = (s.webKeyFile && fs.existsSync(s.webKeyFile)) ? s.webKeyFile : (activeCert?.keyPath || '');
  const useHttps = Boolean(certFile && keyFile && fs.existsSync(certFile));
  const activeDomain = activeCert?.domain || s.webDomain || s.defaultTlsDomain || '';
  const proto = useHttps ? 'https' : 'http';
  const host = activeDomain || s.publicIPv4 || '127.0.0.1';
  const base = normalizeBasePath(s.webBasePath);
  const cleanUrl = `${proto}://${host}:${s.webPort}${base === '/' ? '/' : `${base}/`}`;
  const subPath = (s.subPath || '/sub/').replace(/\/+$/, '');
  const subUrl = `${proto}://${host}:${s.webPort}${subPath}/${s.subToken || ''}`;
  const initPass = store.state.admin.initialPassword || '';
  const validInitPass = (initPass && verifySecret(initPass, store.state.admin.passwordHash)) ? initPass : '';
  return {
    version: VERSION,
    username: store.state.admin.username,
    initialPassword: validInitPass,
    listen: s.webListen,
    port: s.webPort,
    basePath: base === '/' ? '/' : `${base}/`,
    strictBasePath: Boolean(s.strictBasePath),
    https: useHttps,
    webDomain: activeDomain,
    certFile: certFile || '未绑定 (HTTP)',
    defaultNodeTlsDomain: activeDomain || s.defaultTlsDomain || 'www.apple.com',
    url: cleanUrl,
    subUrl,
    inboundsCount: store.state.inbounds.length,
    outboundsCount: store.state.outbounds.filter((o) => !o.builtin).length,
    rulesCount: (store.state.routing?.rules || []).filter((r) => r.action !== 'sniff').length
  };
}

function printPrettyPanelInfo() {
  const info = getPanelInfoSummary();
  const g = '\x1b[32m';
  const c = '\x1b[36m';
  const y = '\x1b[33m';
  const r = '\x1b[0m';
  console.log(`  面板版本   : ${g}v${info.version}${r}`);
  console.log(`  访问地址   : ${c}${info.url}${r}`);
  console.log(`  面板端口   : ${y}${info.port}${r}`);
  console.log(`  安全路径   : ${y}${info.basePath}${r}`);
  console.log(`  SSL 状态   : ${info.https ? `${g}已开启 (${info.defaultNodeTlsDomain})${r}` : `${y}未开启 (HTTP)${r}`}`);
  console.log(`  节点统计   : 入站 ${c}${info.inboundsCount}${r} 个 | 出站 ${c}${info.outboundsCount}${r} 个 | 转发规则 ${c}${info.rulesCount}${r} 条`);
  console.log(`────────────────────────────────────────────────────────────────`);
  console.log(`  ${y}提示: 如需重置或更换账号密码，请在菜单中输入 6${r}`);
}

function handleCliCommand(args) {
  const cmd = args[0];
  if (cmd === '--show-info' || cmd === '--show-info-pretty') {
    if (args[1] === '--json') {
      console.log(JSON.stringify(getPanelInfoSummary(), null, 2));
    } else {
      printPrettyPanelInfo();
    }
    return;
  }
  if (cmd === '--show-info-json') {
    console.log(JSON.stringify(getPanelInfoSummary(), null, 2));
    return;
  }
  if (cmd === '--cleanup-memory') {
    const res = cleanupSystemLogsAndMemory(singbox, store);
    console.log(`已完成日志清理与内存释放: ${res.actions.join(', ')}`);
    return;
  }
  if (cmd === '--init-panel') {
    const rawPort = String(args[1] || '').trim();
    const rawUser = String(args[2] || '').trim();
    const rawPass = String(args[3] || '').trim();
    const rawPath = String(args[4] || '').trim();
    const rawIp = String(args[5] || '').trim();

    const portNum = Number(rawPort);
    const finalPort = (Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535)
      ? portNum
      : crypto.randomInt(15000, 60001);
    const finalUser = (!rawUser || rawUser === 'auto' || rawUser === '--random' || rawUser === 'admin')
      ? generateStrongCredential(13, { prefix: 'ng_' })
      : rawUser;
    const finalPass = (!rawPass || rawPass === 'auto' || rawPass === '--random' || rawPass === 'admin123456' || rawPass === finalUser)
      ? generateStrongCredential(18, { exclude: finalUser })
      : rawPass;
    const finalPath = (!rawPath || rawPath === 'auto' || rawPath === '--random' || rawPath === '/')
      ? normalizeBasePath(`/${generateStrongCredential(16)}/`)
      : normalizeBasePath(rawPath);

    const realCert = getActiveRealCert(store.state);
    const certToBind = realCert || issueSelfSignedCert({
      domain: store.state.settings.webDomain || 'www.apple.com',
      ip: rawIp || store.state.settings.publicIPv4 || '',
      days: 3650
    });

    store.transact((st) => {
      st.admin.username = finalUser;
      st.admin.passwordHash = hashSecret(finalPass);
      st.admin.initialPassword = finalPass;
      st.admin.updatedAt = new Date().toISOString();
      st.settings.webPort = finalPort;
      st.settings.webBasePath = finalPath;
      st.settings.strictBasePath = true;
      if (rawIp) st.settings.publicIPv4 = rawIp;
      bindCertificateEverywhere(st, certToBind, true, true, !realCert);
    });
    singbox.writeConfig();

    if (!verifySecret(finalPass, store.state.admin.passwordHash)) {
      console.error('初始化密码校验失败');
      process.exit(1);
    }

    const summary = getPanelInfoSummary();
    console.log(JSON.stringify({
      ...summary,
      username: finalUser,
      password: finalPass,
      port: finalPort,
      basePath: summary.basePath
    }));
    return;
  }
  if (cmd === '--set-account') {
    const rawUser = String(args[1] || '').trim();
    const rawPass = String(args[2] || '').trim();
    const username = (!rawUser || rawUser === '--random' || rawUser === 'auto')
      ? generateStrongCredential(13, { prefix: 'ng_' })
      : rawUser;
    const password = (!rawPass || rawPass === '--random' || rawPass === 'auto' || rawPass === username)
      ? generateStrongCredential(18, { exclude: username })
      : rawPass;
    store.transact((st) => {
      st.admin.username = username;
      st.admin.passwordHash = hashSecret(password);
      st.admin.initialPassword = password;
      st.admin.updatedAt = new Date().toISOString();
    });
    console.log(`管理员账号已更新为: ${username}`);
    return;
  }
  if (cmd === '--set-port') {
    const port = Number(args[1]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error('无效端口号 (1-65535)');
      process.exit(1);
    }
    store.transact((st) => {
      st.settings.webPort = port;
    });
    console.log(`面板端口已更改为: ${port}`);
    return;
  }
  if (cmd === '--set-path') {
    const base = normalizeBasePath(args[1] || '/');
    store.transact((st) => {
      st.settings.webBasePath = base;
      st.settings.strictBasePath = true;
    });
    console.log(`面板安全根路径已更改为: ${base}`);
    return;
  }
  if (cmd === '--reset-settings') {
    store.transact((st) => {
      const def = defaultState().settings;
      st.settings = {
        ...def,
        publicIPv4: st.settings.publicIPv4 || '',
        subToken: st.settings.subToken || def.subToken,
        webPort: 2053,
        webBasePath: '/',
        strictBasePath: true
      };
    });
    console.log('面板设置已重置为默认状态 (端口: 2053, 路径: /)');
    return;
  }
  if (cmd === '--issue-selfsigned') {
    const domain = String(args[1] || store.state.settings.webDomain || 'www.apple.com').trim();
    const ip = String(args[2] || store.state.settings.publicIPv4 || '').trim();
    const realCert = getActiveRealCert(store.state);
    if (realCert && args[3] !== '--force') {
      store.transact((st) => {
        bindCertificateEverywhere(st, realCert, true, true);
      });
      singbox.writeConfig();
      console.log(`检测到已有受信任域名证书 (${realCert.domain})，已自动绑定为面板与节点默认证书: ${realCert.certPath}`);
      return;
    }
    const cert = issueSelfSignedCert({ domain, ip, days: 3650 });
    store.transact((st) => {
      bindCertificateEverywhere(st, cert, true, true, true);
    });
    singbox.writeConfig();
    console.log(`10 年自签证书已生成并自动绑定至面板 HTTPS 与 Sing-box 节点默认证书: ${cert.certPath}`);
    return;
  }
  if (cmd === '--set-cert') {
    const certFile = String(args[1] || '').trim();
    const keyFile = String(args[2] || '').trim();
    const domain = String(args[3] || store.state.settings.webDomain || '').trim();
    store.transact((st) => {
      if (!certFile || !keyFile) {
        st.settings.webCertFile = '';
        st.settings.webKeyFile = '';
      } else {
        const cert = saveCustomCert({
          domain: domain || path.basename(path.dirname(certFile)) || 'panel-cert',
          certPath: certFile,
          keyPath: keyFile
        });
        bindCertificateEverywhere(st, cert, true, true, true);
      }
    });
    singbox.writeConfig();
    console.log(certFile ? `SSL 证书已成功绑定至面板与全部 TLS 节点: ${certFile}` : '已关闭面板 HTTPS，恢复为 HTTP 访问');
    return;
  }
  if (cmd === '--open-firewall') {
    const ports = [
      store.state.settings.webPort,
      ...(store.state.inbounds || []).filter((i) => i.enable !== false).map((i) => i.port)
    ];
    const res = openFirewallPorts(ports);
    console.log(`已自动放行端口: ${res.openedPorts.join(', ')}`);
    return;
  }
  if (cmd === '--migrate-3xui') {
    const dbPath = args[1] || '/etc/x-ui/x-ui.db';
    const mode = args[2] || 'merge';
    const parsed = parse3xuiPayload({ dbPath, dryRun: false });
    const rec = apply3xuiMigration(store, parsed, mode);
    syncDiscoveredCerts(true);
    singbox.writeConfig();
    const certMsg = rec.restoredCertsCount ? `, 恢复证书 ${rec.restoredCertsCount} 张 (${rec.restoredCertDomains.join(', ')})` : '';
    console.log(`成功从 ${dbPath} 备份迁移: 入站 ${rec.inboundsCount} 个 (${rec.clientsCount} 客户端), 出站 ${rec.outboundsCount} 个, 分流规则 ${rec.rulesCount} 条${certMsg}`);
    return;
  }
}

function parseExpiryTimeInput(rawVal, fallback = 0) {
  if (rawVal === undefined || rawVal === null) return fallback;
  const s = String(rawVal).trim();
  if (!s || s === '0') return 0;
  if (/^\d+$/.test(s)) {
    const num = Number(s);
    return num > 0 ? num : 0;
  }
  const ts = Date.parse(s);
  return Number.isFinite(ts) && ts > 0 ? ts : 0;
}

function normalizeInboundPayload(body, existing = null) {
  const protocol = String(body.protocol || existing?.protocol || 'vless').toLowerCase();
  const port = Number(body.port || existing?.port || (Math.floor(Math.random() * 40000) + 15000));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    const err = new Error('端口号必须是 1–65535 之间的整数');
    err.statusCode = 400;
    throw err;
  }

  const isDefaultPortTag = existing && existing.tag === `inbound-${existing.port}` && (!body.tag || body.tag === existing.tag);
  const tag = String(isDefaultPortTag ? `inbound-${port}` : (body.tag || existing?.tag || `inbound-${port}`)).trim();
  const remark = String(body.remark || existing?.remark || `${protocol.toUpperCase()}-${port}`).trim();
  const listen = String(body.listen || existing?.listen || '::').trim();
  const publicHost = String(body.publicHost ?? existing?.publicHost ?? '').trim();
  const enable = body.enable !== undefined ? Boolean(body.enable) : (existing ? existing.enable !== false : true);
  const outboundTag = String(body.outboundTag ?? existing?.outboundTag ?? 'default').trim();

  const limitIp = Math.max(0, Number(body.limitIp ?? existing?.limitIp ?? 0));
  const limitDevice = Math.max(0, Number(body.limitDevice ?? existing?.limitDevice ?? 0));

  const totalGB = Math.max(0, Number(body.totalGB ?? (existing?.total ? Math.round((existing.total / (1024 ** 3)) * 100) / 100 : 0)));
  const total = body.total !== undefined ? Number(body.total) : (totalGB > 0 ? Math.round(totalGB * (1024 ** 3)) : 0);
  const expiryTime = parseExpiryTimeInput(body.expiryTime, existing?.expiryTime || 0);
  const resetDay = Math.max(0, Math.min(31, Math.floor(Number(body.resetDay ?? existing?.resetDay ?? 0))));

  let security = String(body.security ?? existing?.security ?? 'none').toLowerCase();
  if (['anytls', 'hysteria2', 'tuic'].includes(protocol)) {
    security = 'tls';
  }
  const transport = String(body.transport ?? existing?.transport ?? 'tcp').toLowerCase();

  const nodeId = String(body.nodeId || existing?.nodeId || 'node_local').trim();
  const inbound = {
    id: existing?.id || `in_${crypto.randomBytes(5).toString('hex')}`,
    nodeId,
    tag,
    remark,
    protocol,
    listen,
    port,
    ...(publicHost ? { publicHost } : {}),
    enable,
    security,
    transport,
    outboundTag,
    limitIp,
    limitDevice,
    up: Number(body.up ?? existing?.up ?? 0),
    down: Number(body.down ?? existing?.down ?? 0),
    total,
    expiryTime,
    resetDay,
    lastResetCycle: resetDay > 0 ? (existing?.lastResetCycle || computeResetCycleKey(resetDay)) : '',
    lastOnline: Number(body.lastOnline ?? existing?.lastOnline ?? 0),
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  if (security === 'reality') {
    const rIn = body.reality || existing?.reality || {};
    let priv = String(rIn.privateKey || '').trim();
    let pub = String(rIn.publicKey || '').trim();
    if (!priv) {
      const pair = generateRealityKeypair();
      priv = pair.privateKey;
      pub = pair.publicKey;
    } else if (!pub) {
      pub = deriveRealityPublicKey(priv);
    }
    let serverName = String(rIn.serverName || 'tesla.com').trim();
    if (['www.cloudflare.com', 'cloudflare.com', 'www.bing.com', 'bing.com', 'www.yahoo.com', 'yahoo.com', 'dl.google.com'].includes(serverName.toLowerCase())) {
      serverName = 'tesla.com';
    }
    const defTarget = serverName === 'tesla.com' ? 'www.tesla.com:443' : `${serverName}:443`;
    let target = String(rIn.target || defTarget).trim();
    if (/cloudflare\.com|bing\.com|yahoo\.com|dl\.google\.com/i.test(target)) {
      target = defTarget;
    }
    const shortIds = Array.isArray(rIn.shortIds)
      ? rIn.shortIds
      : String(rIn.shortIds || rIn.shortId || generateShortId())
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);

    inbound.reality = {
      serverName,
      target,
      privateKey: priv,
      publicKey: pub,
      shortIds: shortIds.length ? shortIds : [generateShortId()],
      fingerprint: rIn.fingerprint || 'chrome'
    };
  }

  if (security === 'tls') {
    const realCert = getActiveRealCert(store.state);
    const defDomain = realCert?.domain || store.state.settings.webDomain || store.state.settings.defaultTlsDomain || 'www.apple.com';
    const defCert = realCert?.certPath || store.state.settings.defaultCertFile || store.state.settings.webCertFile || '';
    const defKey = realCert?.keyPath || store.state.settings.defaultKeyFile || store.state.settings.webKeyFile || '';
    inbound.tlsDomain = String(body.tlsDomain || existing?.tlsDomain || defDomain).trim();
    if (inbound.tlsDomain === 'www.bing.com') inbound.tlsDomain = defDomain;
    inbound.certPath = String(body.certPath || existing?.certPath || defCert).trim();
    inbound.keyPath = String(body.keyPath || existing?.keyPath || defKey).trim();
    inbound.allowInsecure = Boolean(body.allowInsecure ?? existing?.allowInsecure ?? false);
    inbound.alpn = Array.isArray(body.alpn)
      ? body.alpn
      : String(body.alpn ?? (['hysteria2', 'tuic'].includes(protocol) ? 'h3' : ''))
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
  }

  if (['ws', 'httpupgrade', 'http', 'h2'].includes(transport)) {
    inbound.wsPath = String(body.wsPath ?? existing?.wsPath ?? '/').trim();
    inbound.wsHost = String(body.wsHost ?? existing?.wsHost ?? '').trim();
  } else if (transport === 'grpc') {
    inbound.grpcServiceName = String(body.grpcServiceName ?? existing?.grpcServiceName ?? 'grpc').trim();
  }

  const clientIdHint = String(body.clientEmail || body.socksUser || remark || tag).trim();
  if (protocol === 'vless') {
    inbound.flow = String(body.flow ?? existing?.flow ?? (security === 'reality' && transport === 'tcp' ? 'xtls-rprx-vision' : '')).trim();
  } else if (protocol === 'shadowsocks') {
    inbound.method = normalizeSsMethod(body.method || existing?.method || '2022-blake3-aes-128-gcm');
    inbound.password = ensureSsPassword(inbound.method, body.password || existing?.password || '');
    inbound.network = String(body.network || existing?.network || 'tcp,udp').trim();
  } else if (protocol === 'hysteria2') {
    const rawHy2Pass = String(body.password || existing?.password || '').trim();
    inbound.password = (!rawHy2Pass || (!existing && rawHy2Pass === clientIdHint))
      ? generateStrongCredential(20, { exclude: clientIdHint })
      : rawHy2Pass;
    inbound.upMbps = Number(body.upMbps ?? existing?.upMbps ?? 100);
    inbound.downMbps = Number(body.downMbps ?? existing?.downMbps ?? 100);
    inbound.obfsPassword = String(body.obfsPassword ?? existing?.obfsPassword ?? '').trim();
  } else if (protocol === 'anytls') {
    const rawAnyPass = String(body.password || existing?.password || '').trim();
    inbound.password = (!rawAnyPass || (!existing && rawAnyPass === clientIdHint))
      ? generateStrongCredential(20, { exclude: clientIdHint })
      : rawAnyPass;
  } else if (protocol === 'socks' || protocol === 'mixed' || protocol === 'http') {
    const rawUser = String(body.socksUser || existing?.socksUser || '').trim();
    inbound.socksUser = rawUser || generateStrongCredential(10, { prefix: 'u_' });
    const rawPass = String(body.socksPassword || existing?.socksPassword || '').trim();
    inbound.socksPassword = (!rawPass || (!existing && rawPass === inbound.socksUser))
      ? generateStrongCredential(18, { exclude: inbound.socksUser })
      : rawPass;
  } else if (protocol === 'trojan') {
    const rawTrojanPass = String(body.password || existing?.password || '').trim();
    inbound.password = (!rawTrojanPass || (!existing && rawTrojanPass === clientIdHint))
      ? generateStrongCredential(20, { exclude: clientIdHint })
      : rawTrojanPass;
  } else if (protocol === 'tuic') {
    const rawTuicPass = String(body.password || existing?.password || '').trim();
    inbound.password = (!rawTuicPass || (!existing && rawTuicPass === clientIdHint))
      ? generateStrongCredential(18, { exclude: clientIdHint })
      : rawTuicPass;
    inbound.congestionControl = String(body.congestionControl || existing?.congestionControl || 'bbr').trim();
  } else if (protocol === 'direct') {
    inbound.overrideAddress = String(body.overrideAddress ?? existing?.overrideAddress ?? '').trim();
    inbound.overridePort = Number(body.overridePort ?? existing?.overridePort ?? 0);
    inbound.network = String(body.network ?? existing?.network ?? 'tcp,udp').trim();
  }

  if (Array.isArray(body.clients) && body.clients.length > 0) {
    inbound.clients = body.clients.map((c, i) => {
      const prevClient = existing?.clients?.find((ec) => (c.id && ec.id === c.id) || (c.email && ec.email === c.email)) || existing?.clients?.[i] || {};
      const cEmailRaw = String(c.email || c.name || prevClient.email || '').trim();
      const cEmail = (!cEmailRaw || (!existing && cEmailRaw === 'user_1'))
        ? `${protocol}_${generateStrongCredential(6).toLowerCase()}`
        : cEmailRaw;
      const cUsernameRaw = String(c.username || prevClient.username || (i === 0 && inbound.socksUser ? inbound.socksUser : '')).trim();
      const cUsername = cUsernameRaw || generateStrongCredential(10, { prefix: 'u_', exclude: cEmail });
      let rawClientPass = String(c.password ?? prevClient.password ?? inbound.password ?? inbound.socksPassword ?? '').trim();
      if (!rawClientPass || (!existing && protocol !== 'shadowsocks' && (rawClientPass === cUsername || rawClientPass === cEmail))) {
        rawClientPass = generateStrongCredential(20, { exclude: cUsername });
      }
      const clientPass = protocol === 'shadowsocks'
        ? (body.clients.length === 1 ? inbound.password : ensureSsPassword(inbound.method, rawClientPass))
        : rawClientPass;
      const cTotalGB = Math.max(0, Number(c.totalGB ?? prevClient.totalGB ?? (body.clients.length === 1 ? totalGB : 0)));
      const cTotalBytes = c.totalBytes !== undefined ? Number(c.totalBytes) : (cTotalGB > 0 ? Math.round(cTotalGB * (1024 ** 3)) : Number(prevClient.totalBytes || 0));
      const cExpiry = c.expiryTime !== undefined ? parseExpiryTimeInput(c.expiryTime, 0) : Number(prevClient.expiryTime ?? (body.clients.length === 1 ? expiryTime : 0));
      return {
        id: ['vless', 'vmess', 'tuic'].includes(protocol)
          ? ensureUuid(c.id || c.uuid || prevClient.id)
          : String(c.id || prevClient.id || crypto.randomUUID()),
        email: cEmail,
        username: cUsername,
        password: clientPass,
        flow: c.flow !== undefined ? c.flow : (prevClient.flow ?? inbound.flow ?? ''),
        subId: String(c.subId || prevClient.subId || randomString(16)).trim(),
        limitIp: Math.max(0, Number(c.limitIp ?? prevClient.limitIp ?? (body.clients.length === 1 ? inbound.limitIp : 0))),
        limitDevice: Math.max(0, Number(c.limitDevice ?? prevClient.limitDevice ?? (body.clients.length === 1 ? inbound.limitDevice : 0))),
        totalGB: cTotalGB,
        totalBytes: cTotalBytes,
        up: Number(c.up ?? prevClient.up ?? 0),
        down: Number(c.down ?? prevClient.down ?? 0),
        allTime: Number(c.allTime ?? prevClient.allTime ?? 0),
        lastOnline: Number(c.lastOnline ?? prevClient.lastOnline ?? 0),
        createdAt: Number(c.createdAt || prevClient.createdAt || Date.now()),
        updatedAt: Date.now(),
        expiryTime: cExpiry,
        enable: c.enable !== undefined ? Boolean(c.enable) : (prevClient.enable !== false)
      };
    });
  } else if (existing?.clients?.length && !body.resetClients) {
    const isMulti = existing.clients.length > 1;
    inbound.clients = existing.clients.map((c, idx) => ({
      ...c,
      id: idx === 0 && body.uuid
        ? ensureUuid(body.uuid)
        : (['vless', 'vmess', 'tuic'].includes(inbound.protocol) ? ensureUuid(c.id) : String(c.id || crypto.randomUUID())),
      email: idx === 0 && body.clientEmail ? body.clientEmail : c.email,
      username: idx === 0 && ['socks', 'mixed', 'http'].includes(inbound.protocol) && inbound.socksUser ? inbound.socksUser : c.username,
      limitIp: isMulti ? Number(c.limitIp ?? 0) : inbound.limitIp,
      limitDevice: isMulti ? Number(c.limitDevice ?? 0) : inbound.limitDevice,
      totalGB: isMulti ? Number(c.totalGB ?? 0) : totalGB,
      totalBytes: isMulti ? Number(c.totalBytes ?? 0) : total,
      expiryTime: isMulti ? Number(c.expiryTime ?? 0) : inbound.expiryTime,
      updatedAt: idx === 0 ? Date.now() : Number(c.updatedAt || c.createdAt || Date.now()),
      flow: inbound.protocol === 'vless' ? (idx === 0 && body.flow !== undefined ? body.flow : (c.flow ?? inbound.flow ?? '')) : c.flow,
      password: idx === 0 && ['anytls', 'hysteria2', 'trojan', 'shadowsocks', 'tuic'].includes(inbound.protocol) && inbound.password
        ? inbound.password
        : (idx === 0 && ['socks', 'mixed', 'http'].includes(inbound.protocol) && inbound.socksPassword ? inbound.socksPassword : c.password)
    }));
  } else if (protocol !== 'direct') {
    const rawEmail = String(body.clientEmail || '').trim();
    const defEmail = (rawEmail && rawEmail !== 'user_1')
      ? rawEmail
      : `${protocol}_${generateStrongCredential(6).toLowerCase()}`;
    const defUsername = inbound.socksUser || generateStrongCredential(10, { prefix: 'u_', exclude: defEmail });
    let defPass = inbound.password || inbound.socksPassword || generateStrongCredential(20, { exclude: defUsername });
    if (protocol !== 'shadowsocks' && (defPass === defUsername || defPass === defEmail)) {
      defPass = generateStrongCredential(20, { exclude: defUsername });
      if (['socks', 'mixed', 'http'].includes(protocol)) inbound.socksPassword = defPass;
      else inbound.password = defPass;
    }
    inbound.clients = [
      {
        id: ensureUuid(body.uuid),
        email: defEmail,
        username: defUsername,
        password: defPass,
        flow: inbound.flow || '',
        subId: randomString(16),
        limitIp: inbound.limitIp,
        limitDevice: inbound.limitDevice,
        totalGB,
        up: 0,
        down: 0,
        lastOnline: 0,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        expiryTime,
        enable: true
      }
    ];
  } else {
    inbound.clients = [];
  }

  return inbound;
}

function normalizeOutboundPayload(body, existing = null) {
  if (body.rawJson && typeof body.rawJson === 'string') {
    try {
      body.rawJson = JSON.parse(body.rawJson);
    } catch {
      const err = new Error('自定义出站 JSON 格式有误');
      err.statusCode = 400;
      throw err;
    }
  }
  const rawObj = (body.rawJson && typeof body.rawJson === 'object') ? body.rawJson : null;
  const type = String(rawObj?.type || rawObj?.protocol || body.type || existing?.type || 'shadowsocks').toLowerCase();
  const tag = String(rawObj?.tag || body.tag || existing?.tag || `out-${type}-${randomString(4).toLowerCase()}`).trim();
  const remark = String(body.remark || existing?.remark || tag).trim();

  return {
    id: existing?.id || `out_${crypto.randomBytes(5).toString('hex')}`,
    tag,
    type: type === 'freedom' ? 'direct' : (type === 'blackhole' ? 'block' : type),
    remark,
    builtin: Boolean(existing?.builtin),
    enabled: body.enabled !== undefined ? Boolean(body.enabled) : (existing ? existing.enabled !== false : true),
    server: String(rawObj?.server || body.server || existing?.server || '').trim(),
    port: Number(rawObj?.server_port || body.port || existing?.port || 443),
    detour: String(rawObj?.detour ?? body.detour ?? existing?.detour ?? '').trim(),
    security: String(body.security || existing?.security || (['anytls', 'hysteria2', 'tuic'].includes(type) ? 'tls' : 'none')).toLowerCase(),
    transport: String(body.transport || existing?.transport || 'tcp').toLowerCase(),
    uuid: body.uuid || existing?.uuid ? ensureUuid(body.uuid || existing?.uuid) : '',
    ...(type === 'shadowsocks'
      ? sanitizeSsOutboundPasswordAndMethod(
          rawObj?.method || body.method || existing?.method || 'aes-128-gcm',
          rawObj?.password || body.password || existing?.password || ''
        )
      : {
          password: String(rawObj?.password || body.password || existing?.password || '').trim(),
          method: normalizeSsMethod(rawObj?.method || body.method || existing?.method || 'aes-128-gcm')
        }),
    uot: Boolean(body.uot ?? existing?.uot ?? false),
    username: String(rawObj?.username ?? body.username ?? existing?.username ?? '').trim(),
    flow: String(rawObj?.flow ?? body.flow ?? existing?.flow ?? '').trim(),
    sni: String(body.sni ?? existing?.sni ?? '').trim(),
    fingerprint: String(body.fingerprint ?? existing?.fingerprint ?? 'chrome').trim(),
    publicKey: String(body.publicKey ?? existing?.publicKey ?? '').trim(),
    shortId: String(body.shortId ?? existing?.shortId ?? '').trim(),
    insecure: Boolean(body.insecure ?? existing?.insecure ?? false),
    wsPath: String(body.wsPath ?? existing?.wsPath ?? '/').trim(),
    wsHost: String(body.wsHost ?? existing?.wsHost ?? '').trim(),
    grpcServiceName: String(body.grpcServiceName ?? existing?.grpcServiceName ?? '').trim(),
    upMbps: Number(body.upMbps ?? existing?.upMbps ?? 0),
    downMbps: Number(body.downMbps ?? existing?.downMbps ?? 0),
    obfsPassword: String(body.obfsPassword ?? existing?.obfsPassword ?? '').trim(),
    up: Number(body.up ?? existing?.up ?? 0),
    down: Number(body.down ?? existing?.down ?? 0),
    outbounds: Array.isArray(body.outbounds)
      ? body.outbounds
      : String(body.outbounds || (existing?.outbounds || []).join(','))
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
  };
}

function enrichInboundWithLinks(inbound, reqHost = '') {
  const cleanReqHost = String(reqHost || '').split(':')[0].replace(/^\[|\]$/g, '');
  const realCert = getActiveRealCert(store.state);
  const defaultHost = store.state.settings.webDomain || realCert?.domain || store.state.settings.publicIPv4 || cleanReqHost || '127.0.0.1';
  const activeIps = singbox.getActiveIpsForInbound(inbound.tag);
  const activeDeviceCount = singbox.getActiveDeviceCountForInbound(inbound.tag);
  const isSingleClient = (inbound.clients?.length || 0) <= 1;
  const nowMs = Date.now();
  if (activeDeviceCount > 0) {
    inbound.lastOnline = nowMs;
  }
  const enrichedClients = (inbound.clients || []).map((c) => {
    const cKey = c.email || c.name || c.username || 'default';
    const cIps = singbox.getActiveIpsForClient(inbound.tag, cKey, isSingleClient);
    const cDevCount = singbox.getActiveDeviceCountForClient(inbound.tag, cKey, isSingleClient);
    if (cDevCount > 0) {
      c.lastOnline = nowMs;
    }
    const cLastOnline = Number(c.lastOnline || (isSingleClient ? inbound.lastOnline : 0) || 0);
    const cCreatedAt = Number(c.createdAt || Date.parse(inbound.createdAt || '') || nowMs);
    const cUpdatedAt = Number(c.updatedAt || Date.parse(inbound.updatedAt || '') || cCreatedAt);
    return {
      ...c,
      lastOnline: cLastOnline,
      createdAt: cCreatedAt,
      updatedAt: cUpdatedAt,
      activeIps: cIps,
      activeIpCount: cIps.length,
      activeDeviceCount: cDevCount
    };
  });
  const inbLastOnline = Math.max(Number(inbound.lastOnline || 0), ...enrichedClients.map((c) => Number(c.lastOnline || 0)));
  const assignedNode = (store.state.nodes || []).find((n) => n.id === (inbound.nodeId || 'node_local'));
  const nodeDomain = assignedNode?.domain || '';
  const effectiveHost = inbound.publicHost || nodeDomain || (assignedNode && !assignedNode.isLocal && assignedNode.host ? assignedNode.host : '') || defaultHost;
  const effectiveSettings = nodeDomain
    ? { ...(store.state.settings || {}), webDomain: nodeDomain, defaultTlsDomain: nodeDomain }
    : (store.state.settings || {});
  return {
    ...inbound,
    nodeId: inbound.nodeId || 'node_local',
    nodeName: assignedNode?.name || '主控本机 (Local Master)',
    nodeDomain,
    lastOnline: inbLastOnline,
    clients: enrichedClients,
    activeIps,
    activeIpCount: activeIps.length,
    activeDeviceCount,
    links: buildClientLinks(inbound, effectiveHost, store.state.certificates || [], effectiveSettings)
  };
}

let _bgApplyQueued = false;
let _bgHadConfigChange = false;
const _bgPendingPorts = new Set();

function autoApplyIfEnabled(portsToOpen = []) {
  // 1. Always write config.json synchronously (< 2ms) so disk state is immediately consistent
  let writeResult = { changed: false };
  try {
    writeResult = singbox.writeConfig();
  } catch { /* ignore */ }
  if (writeResult.changed) _bgHadConfigChange = true;

  for (const p of portsToOpen) {
    const n = Number(p);
    if (Number.isInteger(n) && n > 0 && n <= 65535) _bgPendingPorts.add(n);
  }

  // 2. Run slow OS child processes (ufw/iptables/systemctl) asynchronously on next tick
  //    so HTTP responses return in < 10ms and modals close instantaneously!
  if (_bgApplyQueued) return;
  _bgApplyQueued = true;
  setImmediate(() => {
    _bgApplyQueued = false;
    const hadConfigChange = _bgHadConfigChange;
    _bgHadConfigChange = false;
    if (_bgPendingPorts.size > 0) {
      const ports = [..._bgPendingPorts];
      _bgPendingPorts.clear();
      try { openFirewallPorts(ports); } catch { /* ignore */ }
    }
    if (store.state.settings.autoApplyConfig !== false) {
      try {
        if (fs.existsSync(singbox.getBinPath())) {
          if (hadConfigChange || singbox.getStatus().state !== 'running') {
            singbox.restart();
          }
        }
      } catch { /* ignore */ }
    }
  });
}

async function handleRequest(req, res) {
  try {
    const reqHostHeader = req.headers.host || 'localhost';
    const url = new URL(req.url || '/', `http://${reqHostHeader}`);
    const rawPathname = url.pathname;
    const method = req.method || 'GET';

    // 1. Health check endpoint
    if (rawPathname === '/healthz' && method === 'GET') {
      return sendJson(res, 200, { status: 'ok', version: VERSION });
    }

    // 2. Public Subscription endpoint (/sub/:token or <basePath>/sub/:token)
    const configuredSubPath = normalizeBasePath(store.state.settings.subPath || '/sub/');
    const strippedForSub = stripBasePath(rawPathname, store.state.settings.webBasePath) || rawPathname;
    for (const candidatePath of [rawPathname, strippedForSub]) {
      const subMatch = route(`${configuredSubPath === '/' ? '/sub' : configuredSubPath}/:token`, candidatePath)
        || route('/sub/:token', candidatePath);
      if (subMatch && method === 'GET') {
        if (store.state.settings.subEnable === false) {
          return sendError(res, 403, '订阅功能已关闭', 'sub_disabled');
        }
        const ua = String(req.headers['user-agent'] || '').toLowerCase();
        const fmt = url.searchParams.get('format')
          || (ua.includes('clash') || ua.includes('mihomo') || ua.includes('stash') ? 'clash' : (ua.includes('sing-box') || ua.includes('sfi') ? 'singbox' : 'base64'));
        const output = formatSubscription(store.state, subMatch.token, fmt, reqHostHeader);
        if (!output) {
          res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
          res.end('404 Not Found');
          return;
        }
        res.writeHead(200, {
          'content-type': output.contentType,
          'profile-update-interval': '12',
          'subscription-userinfo': output.userinfo || 'upload=0; download=0; total=0; expire=0',
          'cache-control': 'no-store'
        });
        res.end(output.body);
        return;
      }
    }

    // 3. Enforce webBasePath
    const basePath = normalizeBasePath(store.state.settings.webBasePath || '/');
    if (basePath !== '/' && rawPathname === basePath && !rawPathname.endsWith('/')) {
      res.writeHead(302, { location: `${basePath}/` });
      res.end();
      return;
    }

    let pathname = stripBasePath(rawPathname, basePath);
    if (pathname === null) {
      if (store.state.settings.strictBasePath === false) {
        if (rawPathname.startsWith('/api/') || rawPathname === '/styles.css' || rawPathname === '/app.js' || rawPathname.startsWith('/vendor/')) {
          pathname = rawPathname;
        } else if (method === 'GET') {
          res.writeHead(302, { location: `${basePath}/` });
          res.end();
          return;
        }
      }
      if (pathname === null) {
        res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
        res.end('404 Not Found');
        return;
      }
    }

    // 4. Static files
    if (method === 'GET' && !pathname.startsWith('/api/')) {
      const served = await serveStatic(PUBLIC_DIR, pathname, res, basePath);
      if (served) return;
      if (!path.extname(pathname)) {
        res.writeHead(302, { location: basePath === '/' ? '/' : `${basePath}/` });
        res.end();
        return;
      }
    }

    // 4.5 Public Cluster Agent Heartbeat Endpoint (Bearer Token Authenticated)
    if (pathname === '/api/cluster/heartbeat' && method === 'POST') {
      const body = await readJson(req);
      const token = String(req.headers.authorization || '').replace(/^Bearer\s+/i, '').trim() || String(body.token || '');
      const nodeId = String(req.headers['x-nexus-node'] || body.nodeId || '').trim();
      const hbResult = handleAgentHeartbeat(store, nodeId, token, body);
      return sendJson(res, 200, hbResult);
    }

    // 5. Public Auth Endpoints
    if (pathname === '/api/auth/session' && method === 'GET') {
      const session = sessions.get(req);
      if (!session) return sendJson(res, 200, { authenticated: false, basePath });
      return sendJson(res, 200, {
        authenticated: true,
        csrf: session.csrf,
        basePath,
        user: { username: store.state.admin.username }
      });
    }

    if (pathname === '/api/auth/login' && method === 'POST') {
      const ip = req.socket.remoteAddress || 'unknown';
      if (loginAttempts.size > 500) loginAttempts.clear();
      const record = loginAttempts.get(ip) || { count: 0, resetAt: Date.now() + 600000 };
      if (Date.now() > record.resetAt) {
        record.count = 0;
        record.resetAt = Date.now() + 600000;
      }
      if (record.count >= 15) {
        return sendError(res, 429, '登录尝试次数过多，请稍后再试', 'rate_limited');
      }
      const body = await readJson(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (username !== store.state.admin.username || !verifySecret(password, store.state.admin.passwordHash)) {
        record.count += 1;
        loginAttempts.set(ip, record);
        return sendError(res, 401, '账号或密码不正确', 'invalid_credentials');
      }
      loginAttempts.delete(ip);
      const session = sessions.create(store.state.admin.id, store.state.admin.username);
      store.transact(() => store.addAudit(username, 'login', '控制台登录'));
      const cookieParts = [`ng_session=${encodeURIComponent(session.id)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${Math.floor(sessions.ttlMs / 1000)}`];
      return sendJson(
        res,
        200,
        { authenticated: true, csrf: session.csrf, basePath, user: { username } },
        { 'set-cookie': cookieParts.join('; ') }
      );
    }

    if (pathname === '/api/auth/logout' && method === 'POST') {
      sessions.delete(req);
      return sendJson(res, 200, { ok: true }, { 'set-cookie': 'ng_session=; Path=/; HttpOnly; Max-Age=0' });
    }

    // 6. Protected API Middleware
    const session = sessions.get(req);
    if (!session) {
      return sendError(res, 401, '登录会话已过期，请重新登录', 'unauthorized');
    }
    if (!['GET', 'HEAD'].includes(method)) {
      const csrf = req.headers['x-csrf-token'];
      if (!csrf || csrf !== session.csrf) {
        return sendError(res, 403, '安全令牌校验失败，请刷新页面重试', 'csrf_error');
      }
    }

    // 7. Overview & System Status
    if (pathname === '/api/overview' && method === 'GET') {
      syncDiscoveredCerts();
      const system = getSystemStatus(singbox, store.state.settings);
      const inbounds = store.state.inbounds || [];
      const outbounds = store.state.outbounds || [];
      const rules = store.state.routing?.rules || [];
      const totalClients = inbounds.reduce((acc, i) => acc + (i.clients?.length || 0), 0);
      const relayInbounds = inbounds.filter((i) => (i.outboundTag && i.outboundTag !== 'default' && i.outboundTag !== 'direct') || i.protocol === 'direct').length;
      const local3xuiExists = fs.existsSync('/etc/x-ui/x-ui.db') || fs.existsSync('/root/3xui_backup.tar.gz');

      ensureClusterNodes(store.state);
      const nodes = store.state.nodes || [];
      return sendJson(res, 200, {
        version: VERSION,
        system,
        local3xuiExists,
        nodes,
        failoverLogs: (store.state.failoverLogs || []).slice(0, 10),
        counts: {
          nodes: nodes.length,
          relayNodes: nodes.filter((n) => n.role === 'relay' || n.role === 'hybrid').length,
          exitNodes: nodes.filter((n) => n.role === 'exit' || n.role === 'hybrid').length,
          standbyNodes: nodes.filter((n) => n.role === 'standby' || n.mirrorStandby).length,
          inbounds: inbounds.length,
          activeInbounds: inbounds.filter((i) => i.enable !== false).length,
          clients: totalClients,
          outbounds: outbounds.filter((o) => !o.builtin).length,
          relayBindings: relayInbounds,
          rules: rules.filter((r) => r.enabled !== false && r.action !== 'sniff').length,
          certificates: (store.state.certificates || []).length
        },
        audit: (store.state.audit || []).slice(0, 15)
      });
    }

    if (pathname === '/api/system/acceleration' && method === 'POST') {
      const body = await readJson(req);
      const accel = applyKernelAcceleration(body.mode || 'all');
      store.transact(() => store.addAudit(session.username, 'enable_bbr_hy2', `模式: ${body.mode || 'all'} (拥塞算法: ${accel.congestion})`));
      return sendJson(res, 200, { acceleration: accel });
    }

    if (pathname === '/api/system/firewall' && method === 'POST') {
      const ports = [
        store.state.settings.webPort,
        ...(store.state.inbounds || []).filter((i) => i.enable !== false).map((i) => i.port)
      ];
      const result = openFirewallPorts(ports);
      store.transact(() => store.addAudit(session.username, 'open_firewall_ports', `放行端口: ${result.openedPorts.join(', ')}`));
      return sendJson(res, 200, result);
    }

    if (pathname === '/api/system/cleanup' && method === 'POST') {
      const result = cleanupSystemLogsAndMemory(singbox, store);
      store.transact(() => store.addAudit(session.username, 'cleanup_memory_logs', `清理日志与缓存 (${result.actions.join(', ')})`));
      return sendJson(res, 200, {
        result,
        system: getSystemStatus(singbox, store.state.settings)
      });
    }

    if (pathname === '/api/catalog' && method === 'GET') {
      return sendJson(res, 200, {
        inboundProtocols: INBOUND_PROTOCOLS,
        outboundProtocols: OUTBOUND_PROTOCOLS,
        ssMethods: SS_METHODS,
        realityPresets: REALITY_PRESETS,
        knownVersions: KNOWN_VERSIONS
      });
    }

    if (pathname === '/api/tools/reality-keypair' && method === 'POST') {
      return sendJson(res, 200, {
        ...generateRealityKeypair(),
        shortId: generateShortId(),
        uuid: crypto.randomUUID()
      });
    }

    if (pathname === '/api/tools/ss-key' && method === 'POST') {
      const body = await readJson(req);
      return sendJson(res, 200, {
        password: generateSsKey(body.method || '2022-blake3-aes-128-gcm'),
        uuid: crypto.randomUUID()
      });
    }

    // 8. Inbounds CRUD + Batch Operations
    if (pathname === '/api/inbounds' && method === 'GET') {
      syncDiscoveredCerts();
      if (Date.now() - singbox._lastPollAt > 1500) {
        setImmediate(() => { singbox.pollConnectionsAndEnforceLimits().catch(() => {}); });
      }
      const realCert = getActiveRealCert(store.state);
      ensureClusterNodes(store.state);
      return sendJson(res, 200, {
        nodes: store.state.nodes || [],
        inbounds: (store.state.inbounds || []).map((i) => enrichInboundWithLinks(i, reqHostHeader)),
        outbounds: store.state.outbounds || [],
        certificates: store.state.certificates || [],
        settings: store.state.settings || {},
        defaultSettings: {
          defaultTlsDomain: realCert?.domain || store.state.settings.webDomain || store.state.settings.defaultTlsDomain || 'www.apple.com',
          defaultCertFile: realCert?.certPath || store.state.settings.defaultCertFile || store.state.settings.webCertFile || '',
          defaultKeyFile: realCert?.keyPath || store.state.settings.defaultKeyFile || store.state.settings.webKeyFile || ''
        }
      });
    }

    if (pathname === '/api/inbounds/batch' && method === 'POST') {
      const body = await readJson(req);
      const act = String(body.action || '');
      const ids = Array.isArray(body.ids) ? new Set(body.ids) : null;
      let count = 0;

      store.transact((st) => {
        for (const inb of st.inbounds || []) {
          if (ids && !ids.has(inb.id)) continue;
          if (act === 'enable-all' || act === 'enable-ids') {
            inb.enable = true;
            delete inb.disabledReason;
            count += 1;
          } else if (act === 'disable-all' || act === 'disable-ids') {
            inb.enable = false;
            singbox.clearInboundLeases(inb.tag);
            count += 1;
          } else if (act === 'reset-all-traffic' || act === 'reset-ids-traffic') {
            inb.up = 0;
            inb.down = 0;
            for (const c of inb.clients || []) { c.up = 0; c.down = 0; }
            singbox.clearInboundLeases(inb.tag);
            if (inb.enable === false && inb.disabledReason === 'quota') {
              inb.enable = true;
              delete inb.disabledReason;
            }
            count += 1;
          }
        }
        store.addAudit(session.username, 'batch_inbounds', `${act} (${count} 个节点)`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true, count });
    }

    if (pathname === '/api/inbounds' && method === 'POST') {
      const body = await readJson(req);
      const inbound = normalizeInboundPayload(body);
      const portConflict = store.state.inbounds.find((x) => (x.nodeId || 'node_local') === (inbound.nodeId || 'node_local') && Number(x.port) === Number(inbound.port));
      if (portConflict) {
        // Idempotent guard: if an identical node (same port & protocol) was just created within the last 15 seconds
        // (e.g. from a user double-click or network retry), return 200 OK with the created node so the modal closes cleanly!
        const createdMs = Date.parse(portConflict.createdAt || '') || 0;
        if (
          portConflict.protocol === inbound.protocol &&
          (Date.now() - createdMs) >= 0 &&
          (Date.now() - createdMs) < 15000
        ) {
          return sendJson(res, 200, {
            inbound: enrichInboundWithLinks(portConflict, reqHostHeader),
            deduplicated: true
          });
        }
        return sendError(res, 400, `端口 ${inbound.port} 已被入站 [${portConflict.remark}] 占用`);
      }
      store.transact((st) => {
        const effNodeId = inbound.nodeId || 'node_local';
        const tagConflictOtherNode = st.inbounds.some((x) => (x.nodeId || 'node_local') !== effNodeId && x.tag === inbound.tag);
        if (tagConflictOtherNode) {
          const prefix = effNodeId.replace(/^node_/, '');
          inbound.tag = `${prefix}-${inbound.tag}`;
        }
        st.inbounds.unshift(inbound);
        syncInboundRelayToRoutingRule(st, inbound);
        syncExitNodeOutbounds(st);
        store.addAudit(session.username, 'create_inbound', `${inbound.remark} (${inbound.protocol}:${inbound.port})`);
      });
      autoApplyIfEnabled([inbound.port]);
      return sendJson(res, 201, { inbound: enrichInboundWithLinks(inbound, reqHostHeader), outbounds: store.state.outbounds });
    }

    const inbMatch = route('/api/inbounds/:id', pathname);
    if (inbMatch && method === 'PUT') {
      const body = await readJson(req);
      const existing = store.state.inbounds.find((x) => x.id === inbMatch.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      const updated = normalizeInboundPayload(body, existing);
      const portConflict = store.state.inbounds.find((x) => x.id !== existing.id && (x.nodeId || 'node_local') === (updated.nodeId || 'node_local') && Number(x.port) === Number(updated.port));
      if (portConflict) {
        return sendError(res, 400, `端口 ${updated.port} 已被入站 [${portConflict.remark}] 占用`);
      }
      const oldInbTag = existing.tag;
      store.transact((st) => {
        const idx = st.inbounds.findIndex((x) => x.id === existing.id);
        st.inbounds[idx] = updated;
        if (oldInbTag !== updated.tag) {
          for (const r of st.routing.rules || []) {
            if (Array.isArray(r.inbound) && r.inbound.includes(oldInbTag)) {
              r.inbound = r.inbound.map((t) => (t === oldInbTag ? updated.tag : t));
              if (isAutoRuleRemark(r.remark)) {
                r.remark = buildAutoRuleRemark(r.inbound, r.outbound);
              }
            }
          }
        }
        const effNodeId = updated.nodeId || 'node_local';
        const tagConflictOtherNode = st.inbounds.some((x) => x.id !== updated.id && (x.nodeId || 'node_local') !== effNodeId && x.tag === updated.tag);
        if (tagConflictOtherNode) {
          const prefix = effNodeId.replace(/^node_/, '');
          updated.tag = `${prefix}-${updated.tag}`;
        }
        syncInboundRelayToRoutingRule(st, updated);
        syncExitNodeOutbounds(st);
        store.addAudit(session.username, 'update_inbound', `${updated.remark} (${updated.protocol}:${updated.port})`);
      });
      autoApplyIfEnabled([updated.port]);
      setImmediate(() => { singbox.pollConnectionsAndEnforceLimits().catch(() => {}); });
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(updated, reqHostHeader), outbounds: store.state.outbounds });
    }

    if (inbMatch && method === 'DELETE') {
      const existing = store.state.inbounds.find((x) => x.id === inbMatch.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      singbox.clearInboundLeases(existing.tag);
      store.transact((st) => {
        st.inbounds = st.inbounds.filter((x) => x.id !== inbMatch.id);
        st.routing.rules = (st.routing.rules || []).filter((r) => !(Array.isArray(r.inbound) && r.inbound.length === 1 && r.inbound[0] === existing.tag));
        syncExitNodeOutbounds(st);
        store.addAudit(session.username, 'delete_inbound', `${existing.remark} (:${existing.port})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true });
    }

    const inbOutboundMatch = route('/api/inbounds/:id/outbound', pathname);
    if (inbOutboundMatch && method === 'POST') {
      const existing = store.state.inbounds.find((x) => x.id === inbOutboundMatch.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      const body = await readJson(req);
      const nextOut = String(body.outboundTag || 'default').trim();
      store.transact((st) => {
        existing.outboundTag = nextOut;
        syncInboundRelayToRoutingRule(st, existing);
        store.addAudit(session.username, 'bind_inbound_outbound', `${existing.remark} ➔ ${nextOut}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(existing, reqHostHeader), routing: store.state.routing });
    }

    const inbToggle = route('/api/inbounds/:id/toggle', pathname);
    if (inbToggle && method === 'POST') {
      const existing = store.state.inbounds.find((x) => x.id === inbToggle.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      store.transact(() => {
        existing.enable = !existing.enable;
        if (existing.enable) delete existing.disabledReason;
        else singbox.clearInboundLeases(existing.tag);
        syncExitNodeOutbounds(store.state);
        store.addAudit(session.username, 'toggle_inbound', `${existing.remark} -> ${existing.enable ? '启用' : '停用'}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(existing, reqHostHeader) });
    }

    const inbReset = route('/api/inbounds/:id/reset-traffic', pathname);
    if (inbReset && method === 'POST') {
      const existing = store.state.inbounds.find((x) => x.id === inbReset.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      singbox.clearInboundLeases(existing.tag);
      store.transact(() => {
        existing.up = 0;
        existing.down = 0;
        for (const c of existing.clients || []) {
          c.up = 0;
          c.down = 0;
          if (c.enable === false && c.disabledReason === 'quota') {
            c.enable = true;
            delete c.disabledReason;
          }
        }
        if (existing.enable === false && existing.disabledReason === 'quota') {
          existing.enable = true;
          delete existing.disabledReason;
        }
        store.addAudit(session.username, 'reset_inbound_traffic', existing.remark);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(existing, reqHostHeader) });
    }

    // Per-Client CRUD on Multi-User Inbounds (3x-ui / X-Panel compatible multi-user management)
    const inbAddClient = route('/api/inbounds/:id/clients', pathname);
    if (inbAddClient && method === 'POST') {
      const existing = store.state.inbounds.find((x) => x.id === inbAddClient.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      const body = await readJson(req);
      if (!Array.isArray(existing.clients)) existing.clients = [];
      const email = String(body.email || body.name || `${existing.protocol}_u_${generateStrongCredential(6).toLowerCase()}`).trim();
      if (existing.clients.some((c) => c.email === email)) {
        return sendError(res, 400, `该节点下已存在同名用户 [${email}]`);
      }
      const isUuidProto = ['vless', 'vmess', 'tuic'].includes(existing.protocol);
      const username = String(body.username || generateStrongCredential(10, { prefix: 'u_', exclude: email })).trim();
      let rawPass = String(body.password || '').trim();
      if (!rawPass || (existing.protocol !== 'shadowsocks' && (rawPass === username || rawPass === email))) {
        rawPass = existing.protocol === 'shadowsocks'
          ? generateSsKey(existing.method)
          : generateStrongCredential(20, { exclude: username });
      }
      const clientPass = existing.protocol === 'shadowsocks'
        ? ensureSsPassword(existing.method, rawPass)
        : rawPass;
      const cTotalGB = Math.max(0, Number(body.totalGB || 0));
      const cTotalBytes = cTotalGB > 0 ? Math.round(cTotalGB * (1024 ** 3)) : 0;
      const cExpiry = parseExpiryTimeInput(body.expiryTime, 0);
      const newClient = {
        id: isUuidProto ? ensureUuid(body.uuid || body.id) : String(body.id || crypto.randomUUID()),
        email,
        username,
        password: clientPass,
        flow: existing.protocol === 'vless' ? String(body.flow ?? existing.flow ?? '') : '',
        subId: String(body.subId || randomString(16)).trim(),
        limitIp: Math.max(0, Number(body.limitIp || 0)),
        limitDevice: Math.max(0, Number(body.limitDevice || 0)),
        totalGB: cTotalGB,
        totalBytes: cTotalBytes,
        up: 0,
        down: 0,
        lastOnline: 0,
        createdAt: Date.now(),
        updatedAt: Date.now(),
        expiryTime: cExpiry,
        enable: body.enable !== false
      };
      store.transact(() => {
        existing.clients.push(newClient);
        store.addAudit(session.username, 'add_inbound_client', `${existing.remark} -> ${email}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { inbound: enrichInboundWithLinks(existing, reqHostHeader), client: newClient });
    }

    const inbClientMatch = route('/api/inbounds/:id/clients/:clientId', pathname);
    if (inbClientMatch && method === 'PUT') {
      const existing = store.state.inbounds.find((x) => x.id === inbClientMatch.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      const client = (existing.clients || []).find((c) => c.id === inbClientMatch.clientId || c.email === inbClientMatch.clientId);
      if (!client) return sendError(res, 404, '未找到该用户');
      const body = await readJson(req);
      const nextEmail = String(body.email || body.name || client.email).trim();
      if ((existing.clients || []).some((c) => c !== client && c.email === nextEmail)) {
        return sendError(res, 400, `该节点下已存在同名用户 [${nextEmail}]`);
      }
      store.transact(() => {
        client.email = nextEmail;
        if (body.username !== undefined) client.username = String(body.username).trim() || nextEmail;
        if (['vless', 'vmess', 'tuic'].includes(existing.protocol) && (body.uuid || body.id)) {
          client.id = ensureUuid(body.uuid || body.id);
        }
        if (body.password !== undefined && String(body.password).trim()) {
          const rawPass = String(body.password).trim();
          client.password = existing.protocol === 'shadowsocks' && existing.clients.length > 1
            ? ensureSsPassword(existing.method, rawPass)
            : rawPass;
          if (existing.clients.length === 1 && ['anytls', 'hysteria2', 'trojan', 'shadowsocks', 'tuic'].includes(existing.protocol)) {
            existing.password = client.password;
          }
        }
        if (body.flow !== undefined && existing.protocol === 'vless') {
          client.flow = String(body.flow).trim();
        }
        if (body.limitIp !== undefined) client.limitIp = Math.max(0, Number(body.limitIp || 0));
        if (body.limitDevice !== undefined) client.limitDevice = Math.max(0, Number(body.limitDevice || 0));
        if (body.totalGB !== undefined) {
          client.totalGB = Math.max(0, Number(body.totalGB || 0));
          client.totalBytes = client.totalGB > 0 ? Math.round(client.totalGB * (1024 ** 3)) : 0;
        }
        if (body.expiryTime !== undefined) {
          client.expiryTime = parseExpiryTimeInput(body.expiryTime, 0);
        }
        if (body.enable !== undefined) {
          client.enable = Boolean(body.enable);
          if (client.enable) delete client.disabledReason;
        }
        client.updatedAt = Date.now();
        // If this inbound has only 1 client, keep the parent inbound limits/quota/expiry in sync with its sole client
        if (existing.clients.length === 1) {
          if (body.limitIp !== undefined) existing.limitIp = client.limitIp;
          if (body.limitDevice !== undefined) existing.limitDevice = client.limitDevice;
          if (body.totalGB !== undefined) existing.total = client.totalBytes;
          if (body.expiryTime !== undefined) existing.expiryTime = client.expiryTime;
          existing.updatedAt = new Date().toISOString();
        }
        store.addAudit(session.username, 'update_inbound_client', `${existing.remark} -> ${client.email}`);
      });
      autoApplyIfEnabled();
      setImmediate(() => { singbox.pollConnectionsAndEnforceLimits().catch(() => {}); });
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(existing, reqHostHeader), client });
    }

    if (inbClientMatch && method === 'DELETE') {
      const existing = store.state.inbounds.find((x) => x.id === inbClientMatch.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      if ((existing.clients || []).length <= 1) {
        return sendError(res, 400, '每个入站节点至少需保留 1 个用户（如需删除整个节点请点击节点删除按钮）');
      }
      const target = (existing.clients || []).find((c) => c.id === inbClientMatch.clientId || c.email === inbClientMatch.clientId);
      if (!target) return sendError(res, 404, '未找到该用户');
      singbox.clearClientLeases(existing.tag, target.email);
      store.transact(() => {
        existing.clients = existing.clients.filter((c) => c !== target);
        store.addAudit(session.username, 'delete_inbound_client', `${existing.remark} -> ${target.email}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(existing, reqHostHeader) });
    }

    const inbClientToggle = route('/api/inbounds/:id/clients/:clientId/toggle', pathname);
    if (inbClientToggle && method === 'POST') {
      const existing = store.state.inbounds.find((x) => x.id === inbClientToggle.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      const client = (existing.clients || []).find((c) => c.id === inbClientToggle.clientId || c.email === inbClientToggle.clientId);
      if (!client) return sendError(res, 404, '未找到该用户');
      store.transact(() => {
        client.enable = client.enable === false;
        if (client.enable) delete client.disabledReason;
        else singbox.clearClientLeases(existing.tag, client.email);
        store.addAudit(session.username, 'toggle_inbound_client', `${existing.remark} [${client.email}] -> ${client.enable ? '启用' : '停用'}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(existing, reqHostHeader), client });
    }

    const inbClientReset = route('/api/inbounds/:id/clients/:clientId/reset-traffic', pathname);
    if (inbClientReset && method === 'POST') {
      const existing = store.state.inbounds.find((x) => x.id === inbClientReset.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      const client = (existing.clients || []).find((c) => c.id === inbClientReset.clientId || c.email === inbClientReset.clientId);
      if (!client) return sendError(res, 404, '未找到该用户');
      singbox.clearClientLeases(existing.tag, client.email);
      store.transact(() => {
        const oldUp = Number(client.up || 0);
        const oldDown = Number(client.down || 0);
        client.up = 0;
        client.down = 0;
        if ((existing.clients || []).length > 1) {
          existing.up = Math.max(0, Number(existing.up || 0) - oldUp);
          existing.down = Math.max(0, Number(existing.down || 0) - oldDown);
        } else {
          existing.up = 0;
          existing.down = 0;
        }
        if (client.enable === false && client.disabledReason === 'quota') {
          client.enable = true;
          delete client.disabledReason;
        }
        store.addAudit(session.username, 'reset_client_traffic', `${existing.remark} [${client.email}]`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(existing, reqHostHeader), client });
    }

    // 9. Outbounds & Relay CRUD + URI Quick Parse + Batch URI Import + Traffic Reset
    if (pathname === '/api/outbounds' && method === 'GET') {
      if (Date.now() - singbox._lastPollAt > 1500) {
        setImmediate(() => { singbox.pollConnectionsAndEnforceLimits().catch(() => {}); });
      }
      return sendJson(res, 200, {
        outbounds: (store.state.outbounds || []).map((o) => ({ ...o, singboxPreview: toSingboxOutbound(o) })),
        inbounds: store.state.inbounds || [],
        routing: store.state.routing || { final: 'direct', rules: [] }
      });
    }

    if (pathname === '/api/outbounds/parse-uri' && method === 'POST') {
      const body = await readJson(req);
      const outbound = parseShareUriToOutbound(body.uri, body.tag || '', body.remark || '');
      return sendJson(res, 200, { outbound, singboxPreview: toSingboxOutbound(outbound) });
    }

    if (pathname === '/api/outbounds' && method === 'POST') {
      const body = await readJson(req);
      const outbound = normalizeOutboundPayload(body);
      if (store.state.outbounds.some((o) => o.tag === outbound.tag)) {
        return sendError(res, 400, `出站标签 Tag [${outbound.tag}] 已存在`);
      }
      store.transact((st) => {
        st.outbounds.push(outbound);
        store.addAudit(session.username, 'create_outbound', `${outbound.remark} (${outbound.type})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { outbound });
    }

    if (pathname === '/api/outbounds/import-uri' && method === 'POST') {
      const body = await readJson(req);
      const lines = String(body.uri || '')
        .split(/[\r\n]+/)
        .map((l) => l.trim())
        .filter(Boolean);
      if (!lines.length) return sendError(res, 400, '请粘贴至少一条节点分享链接');

      const imported = [];
      store.transact((st) => {
        lines.forEach((line, idx) => {
          const customTag = lines.length === 1 ? body.tag : (body.tag ? `${body.tag}-${idx + 1}` : '');
          const customRemark = lines.length === 1 ? body.remark : (body.remark ? `${body.remark}-${idx + 1}` : '');
          const outbound = parseShareUriToOutbound(line, customTag, customRemark);
          while (st.outbounds.some((o) => o.tag === outbound.tag)) {
            outbound.tag = `${outbound.tag}-${randomString(3).toLowerCase()}`;
          }
          st.outbounds.push(outbound);
          imported.push(outbound);
        });
        store.addAudit(session.username, 'import_outbound_uri', `批量导入 ${imported.length} 个出站节点`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { imported, count: imported.length });
    }

    const outPing = route('/api/outbounds/:id/ping', pathname);
    if (outPing && method === 'POST') {
      const existing = store.state.outbounds.find((x) => x.id === outPing.id);
      if (!existing || !existing.server) return sendError(res, 404, '该出站无远程服务器地址');
      const ping = await tcpPingHostPort(existing.server, existing.port || 443);
      return sendJson(res, 200, { id: existing.id, tag: existing.tag, ...ping });
    }

    const outReset = route('/api/outbounds/:id/reset-traffic', pathname);
    if (outReset && method === 'POST') {
      const existing = store.state.outbounds.find((x) => x.id === outReset.id);
      if (!existing) return sendError(res, 404, '未找到该出站节点');
      store.transact(() => {
        existing.up = 0;
        existing.down = 0;
        store.addAudit(session.username, 'reset_outbound_traffic', existing.tag);
      });
      return sendJson(res, 200, { outbound: existing });
    }

    const outMatch = route('/api/outbounds/:id', pathname);
    if (outMatch && method === 'PUT') {
      const body = await readJson(req);
      const existing = store.state.outbounds.find((x) => x.id === outMatch.id);
      if (!existing) return sendError(res, 404, '未找到该出站节点');
      const oldTag = existing.tag;
      const updated = normalizeOutboundPayload(body, existing);
      store.transact((st) => {
        const idx = st.outbounds.findIndex((x) => x.id === existing.id);
        st.outbounds[idx] = updated;
        if (oldTag !== updated.tag) {
          for (const inb of st.inbounds) {
            if (inb.outboundTag === oldTag) inb.outboundTag = updated.tag;
          }
          for (const r of st.routing.rules || []) {
            if (r.outbound === oldTag) {
              r.outbound = updated.tag;
              if (isAutoRuleRemark(r.remark)) {
                r.remark = buildAutoRuleRemark(r.inbound, updated.tag);
              }
            }
          }
        }
        store.addAudit(session.username, 'update_outbound', `${updated.remark} (${updated.tag})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { outbound: updated });
    }

    if (outMatch && method === 'DELETE') {
      const existing = store.state.outbounds.find((x) => x.id === outMatch.id);
      if (!existing) return sendError(res, 404, '未找到该出站节点');
      if (existing.builtin) return sendError(res, 400, '系统内置出站 (direct / block) 不可删除');
      store.transact((st) => {
        st.outbounds = st.outbounds.filter((x) => x.id !== outMatch.id);
        for (const inb of st.inbounds) {
          if (inb.outboundTag === existing.tag) inb.outboundTag = 'default';
        }
        st.routing.rules = (st.routing.rules || []).filter((r) => r.outbound !== existing.tag);
        store.addAudit(session.username, 'delete_outbound', `${existing.remark} (${existing.tag})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true });
    }

    // 10. Routing & Diversion
    if (pathname === '/api/routing' && method === 'GET') {
      ensureClusterNodes(store.state);
      return sendJson(res, 200, {
        nodes: store.state.nodes || [],
        routing: store.state.routing,
        dns: store.state.dns,
        inbounds: store.state.inbounds.map((i) => {
          const nObj = (store.state.nodes || []).find((n) => n.id === (i.nodeId || 'node_local'));
          return {
            id: i.id,
            nodeId: i.nodeId || 'node_local',
            nodeName: nObj?.name || '主控本机',
            nodeDomain: nObj?.domain || '',
            tag: i.tag,
            remark: i.remark,
            port: i.port,
            protocol: i.protocol,
            outboundTag: i.outboundTag
          };
        }),
        outbounds: (store.state.outbounds || []).map((o) => ({ ...o, singboxPreview: toSingboxOutbound(o) }))
      });
    }

    if (pathname === '/api/routing' && method === 'PUT') {
      const body = await readJson(req);
      store.transact((st) => {
        if (body.final) st.routing.final = body.final;
        if (body.dnsStrategy) st.dns.strategy = body.dnsStrategy;
        store.addAudit(session.username, 'update_routing_global', `默认出站 -> ${st.routing.final}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { routing: store.state.routing, dns: store.state.dns });
    }

    if (pathname === '/api/routing/rules' && method === 'POST') {
      const body = await readJson(req);
      const splitList = (v) => (Array.isArray(v) ? v : String(v || '').split(',').map((s) => s.trim()).filter(Boolean));
      const parsedInbounds = splitList(body.inbound);
      const parsedOutbound = String(body.outbound || 'direct').trim();
      const rawPostRemark = String(body.remark || '').trim();
      const newRule = {
        id: `rule_${crypto.randomBytes(5).toString('hex')}`,
        remark: isAutoRuleRemark(rawPostRemark) ? buildAutoRuleRemark(parsedInbounds, parsedOutbound) : rawPostRemark,
        enabled: body.enabled !== false,
        nodeId: String(body.nodeId || '').trim(),
        action: body.action || 'route',
        inbound: parsedInbounds,
        user: splitList(body.user),
        domain: splitList(body.domain),
        domain_suffix: splitList(body.domain_suffix),
        domain_keyword: splitList(body.domain_keyword),
        ip_cidr: splitList(body.ip_cidr),
        source_ip_cidr: splitList(body.source_ip_cidr),
        port: splitList(body.port),
        source_port: splitList(body.source_port),
        network: String(body.network || '').toLowerCase(),
        protocol: splitList(body.protocol),
        rule_set: splitList(body.rule_set),
        ip_is_private: Boolean(body.ip_is_private),
        outbound: String(body.outbound || 'direct').trim()
      };
      store.transact((st) => {
        const isPureInboundRelay =
          newRule.inbound.length === 1 &&
          !newRule.domain.length &&
          !newRule.domain_suffix.length &&
          !newRule.ip_cidr.length &&
          !newRule.port.length &&
          !newRule.protocol.length &&
          !newRule.ip_is_private;
        if (isPureInboundRelay) {
          const existIdx = st.routing.rules.findIndex(
            (r) => Array.isArray(r.inbound) && r.inbound.length === 1 && r.inbound[0] === newRule.inbound[0] &&
              !r.domain?.length && !r.domain_suffix?.length && !r.ip_cidr?.length && !r.port?.length && !r.protocol?.length && !r.ip_is_private
          );
          if (existIdx >= 0) {
            st.routing.rules[existIdx] = { ...newRule, id: st.routing.rules[existIdx].id };
          } else {
            st.routing.rules.push(newRule);
          }
        } else {
          st.routing.rules.push(newRule);
        }
        syncRoutingRulesToInbounds(st);
        store.addAudit(session.username, 'create_route_rule', `${newRule.remark} -> ${newRule.outbound}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { rule: newRule });
    }

    const ruleMatch = route('/api/routing/rules/:id', pathname);
    if (ruleMatch && method === 'PUT') {
      const body = await readJson(req);
      const splitList = (v) => (Array.isArray(v) ? v : String(v || '').split(',').map((s) => s.trim()).filter(Boolean));
      const existing = store.state.routing.rules.find((r) => r.id === ruleMatch.id);
      if (!existing) return sendError(res, 404, '未找到该分流规则');
      store.transact((st) => {
        const idx = st.routing.rules.findIndex((r) => r.id === ruleMatch.id);
        const nextInbound = body.inbound !== undefined ? splitList(body.inbound) : existing.inbound;
        const nextOutbound = body.outbound !== undefined ? String(body.outbound).trim() : existing.outbound;
        const rawPutRemark = body.remark !== undefined ? String(body.remark).trim() : existing.remark;
        const nextRemark = isAutoRuleRemark(rawPutRemark)
          ? buildAutoRuleRemark(nextInbound, nextOutbound)
          : rawPutRemark;
        st.routing.rules[idx] = {
          ...existing,
          remark: nextRemark,
          nodeId: body.nodeId !== undefined ? String(body.nodeId).trim() : (existing.nodeId || ''),
          enabled: body.enabled !== undefined ? Boolean(body.enabled) : existing.enabled,
          inbound: nextInbound,
          user: body.user !== undefined ? splitList(body.user) : (existing.user || []),
          domain: body.domain !== undefined ? splitList(body.domain) : existing.domain,
          domain_suffix: body.domain_suffix !== undefined ? splitList(body.domain_suffix) : existing.domain_suffix,
          domain_keyword: body.domain_keyword !== undefined ? splitList(body.domain_keyword) : existing.domain_keyword,
          ip_cidr: body.ip_cidr !== undefined ? splitList(body.ip_cidr) : existing.ip_cidr,
          source_ip_cidr: body.source_ip_cidr !== undefined ? splitList(body.source_ip_cidr) : existing.source_ip_cidr,
          port: body.port !== undefined ? splitList(body.port) : existing.port,
          source_port: body.source_port !== undefined ? splitList(body.source_port) : existing.source_port,
          network: body.network !== undefined ? String(body.network).toLowerCase() : existing.network,
          protocol: body.protocol !== undefined ? splitList(body.protocol) : existing.protocol,
          rule_set: body.rule_set !== undefined ? splitList(body.rule_set) : existing.rule_set,
          ip_is_private: body.ip_is_private !== undefined ? Boolean(body.ip_is_private) : existing.ip_is_private,
          outbound: body.outbound !== undefined ? String(body.outbound).trim() : existing.outbound
        };
        syncRoutingRulesToInbounds(st);
        store.addAudit(session.username, 'update_route_rule', st.routing.rules[idx].remark);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { rules: store.state.routing.rules });
    }

    if (ruleMatch && method === 'DELETE') {
      store.transact((st) => {
        st.routing.rules = st.routing.rules.filter((r) => r.id !== ruleMatch.id);
        syncRoutingRulesToInbounds(st);
        store.addAudit(session.username, 'delete_route_rule', ruleMatch.id);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true });
    }

    const ruleMove = route('/api/routing/rules/:id/move', pathname);
    if (ruleMove && method === 'POST') {
      const body = await readJson(req);
      const direction = body.direction || 'up';
      store.transact((st) => {
        const idx = st.routing.rules.findIndex((r) => r.id === ruleMove.id);
        if (idx < 0) return;
        const [item] = st.routing.rules.splice(idx, 1);
        if (direction === 'top') {
          st.routing.rules.unshift(item);
        } else if (direction === 'bottom') {
          st.routing.rules.push(item);
        } else if (direction === 'up') {
          st.routing.rules.splice(Math.max(0, idx - 1), 0, item);
        } else {
          st.routing.rules.splice(Math.min(st.routing.rules.length, idx + 1), 0, item);
        }
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { rules: store.state.routing.rules });
    }

    if (pathname === '/api/routing/presets' && method === 'POST') {
      const body = await readJson(req);
      const preset = body.preset;
      const targetOutbound = body.outbound || 'direct';
      const ruleNodeId = String(body.nodeId || '').trim();
      store.transact((st) => {
        if (preset === '3xui-default') {
          const relayRules = (st.routing.rules || []).filter(
            (r) => Array.isArray(r.inbound) && r.inbound.length > 0 && !r.domain?.length && !r.ip_cidr?.length
          );
          st.routing.rules = [
            { id: 'rule_sniff', remark: '协议嗅探 (HTTP/TLS/QUIC)', enabled: true, action: 'sniff', inbound: [], domain: [], domain_suffix: [], domain_keyword: [], ip_cidr: [], source_ip_cidr: [], port: [], source_port: [], network: '', protocol: [], rule_set: [], ip_is_private: false, outbound: '' },
            ...relayRules,
            { id: 'rule_private_block', remark: '阻止私有内网探测 (geoip:private)', enabled: true, action: 'route', inbound: [], domain: [], domain_suffix: [], domain_keyword: [], ip_cidr: [], source_ip_cidr: [], port: [], source_port: [], network: '', protocol: [], rule_set: [], ip_is_private: true, outbound: 'block' },
            { id: 'rule_bt_block', remark: '禁止 BitTorrent 协议下载', enabled: true, action: 'route', inbound: [], domain: [], domain_suffix: [], domain_keyword: [], ip_cidr: [], source_ip_cidr: [], port: [], source_port: [], network: '', protocol: ['bittorrent'], rule_set: [], ip_is_private: false, outbound: 'block' }
          ];
        } else if (preset === 'ai-relay') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: `AI 平台分流 (ChatGPT/Claude/Gemini/Grok/Perplexity/Cursor -> ${targetOutbound})`,
            nodeId: ruleNodeId,
            enabled: true,
            action: 'route',
            inbound: [],
            domain: [],
            domain_suffix: [
              'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'auth0.com',
              'anthropic.com', 'claude.ai', 'claudeusercontent.com',
              'gemini.google.com', 'aistudio.google.com', 'generativelanguage.googleapis.com',
              'perplexity.ai', 'grok.com', 'x.ai', 'cursor.sh', 'cursor.com', 'copilot.microsoft.com',
              'midjourney.com', 'poe.com', 'huggingface.co'
            ],
            domain_keyword: ['openai', 'anthropic', 'claude'],
            ip_cidr: [],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: [],
            ip_is_private: false,
            outbound: targetOutbound
          });
        } else if (preset === 'foreign-trade') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: `外贸跨境与海外社媒分流 (Google/WhatsApp/TikTok/Meta/PayPal/Amazon -> ${targetOutbound})`,
            nodeId: ruleNodeId,
            enabled: true,
            action: 'route',
            inbound: [],
            domain: [],
            domain_suffix: [
              'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'gmail.com',
              'whatsapp.com', 'whatsapp.net', 'tiktok.com', 'tiktokv.com', 'byteoversea.com',
              'facebook.com', 'fb.com', 'fbcdn.net', 'instagram.com', 'cdninstagram.com',
              'twitter.com', 'x.com', 'twimg.com', 'linkedin.com', 't.me', 'telegram.org',
              'amazon.com', 'shopify.com', 'paypal.com', 'stripe.com', 'github.com'
            ],
            domain_keyword: ['google', 'whatsapp', 'tiktok', 'facebook', 'instagram'],
            ip_cidr: ['91.108.4.0/22', '91.108.8.0/22', '91.108.56.0/22', '149.154.160.0/20'],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: [],
            ip_is_private: false,
            outbound: targetOutbound
          });
        } else if (preset === 'block-ads') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: '屏蔽常见广告与追踪域名',
            nodeId: ruleNodeId,
            enabled: true,
            action: 'route',
            inbound: [],
            domain: [],
            domain_suffix: ['doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'adnxs.com', 'adsrvr.org', 'taboola.com', 'outbrain.com'],
            domain_keyword: ['adservice', 'pagead2'],
            ip_cidr: [],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: [],
            ip_is_private: false,
            outbound: 'block'
          });
        } else if (preset === 'cn-direct') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: '中国大陆常见网站与 IP 直连',
            nodeId: ruleNodeId,
            enabled: true,
            action: 'route',
            inbound: [],
            domain: ['geosite:cn'],
            domain_suffix: ['cn', 'baidu.com', 'qq.com', 'taobao.com', 'tmall.com', 'jd.com', 'bilibili.com', '163.com', 'aliyun.com'],
            domain_keyword: [],
            ip_cidr: ['geoip:cn'],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: [],
            ip_is_private: false,
            outbound: 'direct'
          });
        } else if (preset === 'media-relay') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: `流媒体解锁分流 (Netflix/Disney+/YouTube -> ${targetOutbound})`,
            nodeId: ruleNodeId,
            enabled: true,
            action: 'route',
            inbound: [],
            domain: [],
            domain_suffix: ['netflix.com', 'netflix.net', 'nflxvideo.net', 'nflximg.net', 'nflxext.com', 'disneyplus.com', 'bamgrid.com', 'youtube.com', 'googlevideo.com', 'ytimg.com'],
            domain_keyword: ['netflix'],
            ip_cidr: [],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: [],
            ip_is_private: false,
            outbound: targetOutbound
          });
        }
        store.addAudit(session.username, 'apply_routing_preset', preset);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { rules: store.state.routing.rules });
    }

    // 11. Backup Migration Endpoints
    if (pathname === '/api/migrate/3xui' && method === 'POST') {
      const contentType = String(req.headers['content-type'] || '');
      let parsed;
      const mode = url.searchParams.get('mode') || 'merge';
      const dryRun = url.searchParams.get('dryRun') === 'true';

      if (contentType.includes('application/octet-stream')) {
        const dbBuffer = await readBuffer(req, 64 * 1024 * 1024);
        parsed = parse3xuiPayload({ dbBuffer, dryRun });
      } else {
        const body = await readJson(req);
        if (body.source === 'local') {
          let localPath = body.dbPath || '/etc/x-ui/x-ui.db';
          if (!fs.existsSync(localPath) && fs.existsSync('/root/3xui_backup.tar.gz')) {
            localPath = '/root/3xui_backup.tar.gz';
          }
          parsed = parse3xuiPayload({ dbPath: localPath, dryRun });
        } else if (body.dbBase64) {
          const dbBuffer = Buffer.from(body.dbBase64, 'base64');
          parsed = parse3xuiPayload({ dbBuffer, dryRun });
        } else if (body.jsonPayload) {
          parsed = parse3xuiPayload({ jsonPayload: typeof body.jsonPayload === 'string' ? JSON.parse(body.jsonPayload) : body.jsonPayload, dryRun });
        } else {
          throw new Error('请上传 x-ui.db / 3xui_backup.tar.gz 备份文件、选择本机路径或粘贴配置 JSON');
        }
      }

      if (dryRun) {
        return sendJson(res, 200, { preview: true, ...parsed });
      }

      const migOptions = {
        targetNodeId: url.searchParams.get('targetNodeId') || '',
        nodeName: url.searchParams.get('nodeName') || '',
        nodeDomain: url.searchParams.get('nodeDomain') || '',
        nodeIp: url.searchParams.get('nodeIp') || '',
        deduplicateExits: url.searchParams.get('deduplicateExits') !== 'false'
      };
      const prevPanelCert = store.state.settings.webCertFile || '';
      const record = apply3xuiMigration(store, parsed, mode, migOptions);
      syncDiscoveredCerts(true);
      store.transact(() => store.addAudit(
        session.username,
        'backup_migrate',
        `入站 ${record.inboundsCount} 个 / 出站 ${record.outboundsCount} 个 / 规则 ${record.rulesCount} 条${record.restoredCertsCount ? ` / 证书 ${record.restoredCertsCount} 张` : ''}`
      ));
      const allPorts = (store.state.inbounds || []).filter((i) => i.enable !== false).map((i) => i.port);
      openFirewallPorts(allPorts);
      autoApplyIfEnabled();
      if (store.state.settings.webCertFile && store.state.settings.webCertFile !== prevPanelCert) {
        setTimeout(() => restartPanelServer(), 300);
      }
      return sendJson(res, 200, {
        migrated: true,
        record,
        summary: parsed.summary
      });
    }

    // 11.5 Cluster Nodes (Relay / Exit / Standby) & Failover Orchestration Endpoints
    if (pathname === '/api/cluster/nodes' && method === 'GET') {
      ensureClusterNodes(store.state);
      const nodesWithStats = (store.state.nodes || []).map((n) => {
        const nodeInbounds = (store.state.inbounds || []).filter((i) => (i.nodeId || 'node_local') === n.id);
        const nodeClients = nodeInbounds.reduce((acc, i) => acc + (i.clients?.length || 0), 0);
        const upTotal = nodeInbounds.reduce((acc, i) => acc + Number(i.up || 0), 0);
        const downTotal = nodeInbounds.reduce((acc, i) => acc + Number(i.down || 0), 0);
        return {
          ...n,
          inboundsCount: nodeInbounds.length,
          clientsCount: nodeClients,
          upTotal,
          downTotal,
          installCommand: buildAgentInstallCommand(store.state, n, reqHostHeader)
        };
      });
      return sendJson(res, 200, {
        nodes: nodesWithStats,
        outbounds: store.state.outbounds || [],
        inbounds: (store.state.inbounds || []).map((i) => ({
          id: i.id,
          nodeId: i.nodeId || 'node_local',
          tag: i.tag,
          remark: i.remark,
          protocol: i.protocol,
          port: i.port,
          outboundTag: i.outboundTag || 'default',
          enable: i.enable !== false
        })),
        failoverLogs: store.state.failoverLogs || [],
        cfConfigured: Boolean(store.state.settings?.cfApiToken)
      });
    }

    if (pathname === '/api/cluster/nodes' && method === 'POST') {
      const body = await readJson(req);
      const name = String(body.name || '').trim();
      if (!name) return sendError(res, 400, '请输入服务器节点名称');
      const role = ['relay', 'exit', 'standby', 'hybrid'].includes(body.role) ? body.role : 'relay';
      const host = String(body.host || '127.0.0.1').trim();
      const domain = String(body.domain || '').trim();
      const agentPort = Number(body.agentPort || 19090);
      const exitPort = Number(body.exitPort || body.exitConfig?.port || 28388);
      const exitMethod = normalizeSsMethod(body.exitMethod || body.exitConfig?.method || '2022-blake3-aes-128-gcm');
      const exitPassword = String(body.exitPassword || body.exitConfig?.password || '').trim() || generateSsKey(exitMethod);

      let createdNode;
      store.transact((st) => {
        ensureClusterNodes(st);
        createdNode = {
          id: `node_${crypto.randomBytes(4).toString('hex')}`,
          name,
          role,
          isLocal: false,
          enabled: body.enabled !== false,
          host,
          agentPort,
          domain,
          token: `ag_${randomString(20)}`,
          region: String(body.region || (role === 'exit' ? 'Exit' : 'Relay')).trim(),
          isp: String(body.isp || '').trim(),
          standbyNodeId: String(body.standbyNodeId || '').trim(),
          mirrorStandby: body.mirrorStandby !== false,
          activeFailoverTo: '',
          failoverAt: '',
          cfApiToken: String(body.cfApiToken || '').trim(),
          cfZoneId: String(body.cfZoneId || '').trim(),
          cfRecordId: String(body.cfRecordId || '').trim(),
          cfRecordName: String(body.cfRecordName || domain || '').trim(),
          cfProxied: Boolean(body.cfProxied),
          exitConfig: {
            enabled: body.exitEnabled !== false && (role === 'exit' || role === 'hybrid' || Boolean(body.exitPort || body.exitConfig?.enabled)),
            protocol: 'shadowsocks',
            port: exitPort,
            method: exitMethod,
            password: exitPassword,
            uot: true
          },
          status: 'online',
          lastSeenAt: new Date().toISOString(),
          metrics: {
            cpuPct: 1.2,
            memPct: 12.8,
            memUsedMB: 24,
            memTotalMB: 1024,
            diskPct: 14.0,
            sbRunning: true,
            sbVersion: '1.12.23'
          },
          createdAt: new Date().toISOString()
        };
        st.nodes.push(createdNode);
        syncExitNodeOutbounds(st);
        store.addAudit(session.username, 'create_cluster_node', `${createdNode.name} (${role} · ${domain || host})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, {
        node: {
          ...createdNode,
          installCommand: buildAgentInstallCommand(store.state, createdNode, reqHostHeader)
        },
        outbounds: store.state.outbounds
      });
    }

    const clusterNodeMatch = route('/api/cluster/nodes/:id', pathname);
    if (clusterNodeMatch && method === 'PUT') {
      const body = await readJson(req);
      let updatedNode;
      store.transact((st) => {
        ensureClusterNodes(st);
        const existing = st.nodes.find((n) => n.id === clusterNodeMatch.id);
        if (!existing) {
          const err = new Error('未找到该集群节点');
          err.statusCode = 404;
          throw err;
        }
        if (body.name !== undefined) existing.name = String(body.name).trim() || existing.name;
        if (body.role !== undefined && ['relay', 'exit', 'standby', 'hybrid'].includes(body.role)) {
          existing.role = body.role;
        }
        if (body.host !== undefined) existing.host = String(body.host).trim() || existing.host;
        if (body.agentPort !== undefined) existing.agentPort = Number(body.agentPort || 19090);
        if (body.domain !== undefined) existing.domain = String(body.domain).trim();
        if (body.region !== undefined) existing.region = String(body.region).trim();
        if (body.isp !== undefined) existing.isp = String(body.isp).trim();
        if (body.standbyNodeId !== undefined) existing.standbyNodeId = String(body.standbyNodeId).trim();
        if (body.mirrorStandby !== undefined) existing.mirrorStandby = Boolean(body.mirrorStandby);
        if (body.cfApiToken !== undefined) existing.cfApiToken = String(body.cfApiToken).trim();
        if (body.cfZoneId !== undefined) existing.cfZoneId = String(body.cfZoneId).trim();
        if (body.cfRecordName !== undefined) existing.cfRecordName = String(body.cfRecordName).trim();
        if (body.cfProxied !== undefined) existing.cfProxied = Boolean(body.cfProxied);
        if (body.exitPort !== undefined || body.exitMethod !== undefined || body.exitPassword !== undefined || body.exitConfig) {
          const ec = existing.exitConfig || {};
          const nextMethod = normalizeSsMethod(body.exitMethod || body.exitConfig?.method || ec.method || '2022-blake3-aes-128-gcm');
          existing.exitConfig = {
            enabled: existing.role === 'exit' || existing.role === 'hybrid' || Boolean(body.exitConfig?.enabled ?? ec.enabled),
            protocol: 'shadowsocks',
            port: Number(body.exitPort || body.exitConfig?.port || ec.port || 28388),
            method: nextMethod,
            password: String(body.exitPassword || body.exitConfig?.password || ec.password || '').trim() || generateSsKey(nextMethod),
            uot: true
          };
        }
        syncExitNodeOutbounds(st);
        updatedNode = existing;
        store.addAudit(session.username, 'update_cluster_node', `${existing.name} (${existing.domain || existing.host})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { node: updatedNode, outbounds: store.state.outbounds });
    }

    if (clusterNodeMatch && method === 'DELETE') {
      if (clusterNodeMatch.id === 'node_local') {
        return sendError(res, 400, '主控本机节点不可删除');
      }
      store.transact((st) => {
        ensureClusterNodes(st);
        const target = st.nodes.find((n) => n.id === clusterNodeMatch.id);
        if (!target) {
          const err = new Error('未找到该集群节点');
          err.statusCode = 404;
          throw err;
        }
        st.nodes = st.nodes.filter((n) => n.id !== clusterNodeMatch.id);
        for (const inb of st.inbounds || []) {
          if (inb.nodeId === clusterNodeMatch.id) inb.nodeId = 'node_local';
        }
        st.outbounds = (st.outbounds || []).filter((o) => o.exitNodeId !== clusterNodeMatch.id);
        store.addAudit(session.username, 'delete_cluster_node', target.name);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true });
    }

    const clusterNodeConfig = route('/api/cluster/nodes/:id/config', pathname);
    if (clusterNodeConfig && method === 'GET') {
      const compiled = compileNodeSingboxConfig(store.state, clusterNodeConfig.id);
      return sendJson(res, 200, compiled);
    }

    if (pathname === '/api/cluster/sync-all' && method === 'POST') {
      ensureClusterNodes(store.state);
      const results = await Promise.all(
        (store.state.nodes || []).map((n) => pushConfigToAgentNode(store.state, n.id))
      );
      store.save();
      return sendJson(res, 200, { ok: true, count: results.length, results });
    }

    const clusterNodeTestCf = route('/api/cluster/nodes/:id/test-cf', pathname);
    if (clusterNodeTestCf && method === 'POST') {
      ensureClusterNodes(store.state);
      const node = (store.state.nodes || []).find((n) => n.id === clusterNodeTestCf.id);
      if (!node) return sendError(res, 404, '未找到该集群节点');
      const body = await readJson(req);
      const combinedTokens = [body.cfApiToken, node.cfApiToken, store.state.settings?.cfApiToken].filter(Boolean).join('\n');
      const result = await verifyCloudflareDomainAccess({
        apiToken: combinedTokens,
        zoneId: body.cfZoneId || node.cfZoneId || '',
        domain: body.domain || node.domain || ''
      });
      if (result.zoneId) {
        store.transact((st) => {
          const target = st.nodes.find((n) => n.id === node.id);
          if (target) {
            target.cfZoneId = result.zoneId;
            if (result.recordId) target.cfRecordId = result.recordId;
          }
        });
      }
      return sendJson(res, 200, result);
    }

    const clusterNodeSync = route('/api/cluster/nodes/:id/sync', pathname);
    if (clusterNodeSync && method === 'POST') {
      const syncRes = await pushConfigToAgentNode(store.state, clusterNodeSync.id);
      store.save();
      return sendJson(res, 200, syncRes);
    }

    if (pathname === '/api/cluster/failover' && method === 'POST') {
      const body = await readJson(req);
      const result = await triggerNodeFailover(store, body.primaryNodeId, body.standbyNodeId, {
        reason: body.reason || '管理员手动触发一键容灾切换'
      });
      store.transact(() => store.addAudit(
        session.username,
        'cluster_failover',
        `${result.event.primaryNodeName} ➔ ${result.event.standbyNodeName} (${result.event.domain} -> ${result.event.newIp})`
      ));
      return sendJson(res, 200, result);
    }

    if (pathname === '/api/cluster/failback' && method === 'POST') {
      const body = await readJson(req);
      const result = await triggerNodeFailback(store, body.primaryNodeId, {
        reason: body.reason || '主力中转机恢复，一键回切流量与 DNS'
      });
      store.transact(() => store.addAudit(
        session.username,
        'cluster_failback',
        `${result.event.primaryNodeName} 已恢复回切 (${result.event.domain} -> ${result.event.newIp})`
      ));
      return sendJson(res, 200, result);
    }

    // 12. Sing-box Core Management & Version Switching
    if (pathname === '/api/singbox/config' && method === 'GET') {
      const { config } = singbox.writeConfig();
      return sendJson(res, 200, {
        status: singbox.getStatus(),
        config,
        knownVersions: KNOWN_VERSIONS
      });
    }

    if (pathname === '/api/singbox/control' && method === 'POST') {
      const body = await readJson(req);
      const action = body.action || 'restart';
      let result;
      if (action === 'stop') {
        result = singbox.stop();
      } else if (action === 'check') {
        result = singbox.checkConfig();
      } else {
        result = singbox.restart();
      }
      store.transact(() => store.addAudit(session.username, `singbox_${action}`, 'Sing-box 核心操作'));
      return sendJson(res, 200, { result, status: singbox.getStatus() });
    }

    if (pathname === '/api/singbox/logs' && method === 'GET') {
      return sendJson(res, 200, { logs: singbox.getLogs(), status: singbox.getStatus() });
    }

    if (pathname === '/api/singbox/version' && method === 'POST') {
      const body = await readJson(req);
      const ver = await singbox.installVersion(body.version || 'v1.12.23');
      store.transact(() => store.addAudit(session.username, 'switch_singbox_version', body.version));
      return sendJson(res, 200, { version: ver, status: singbox.getStatus() });
    }

    // 13. SSL Certificates Management
    if (pathname === '/api/certificates' && method === 'GET') {
      syncDiscoveredCerts();
      const certs = (store.state.certificates || []).map((c) => ({
        ...c,
        ...inspectCertificate(c.certPath, c.keyPath)
      }));
      return sendJson(res, 200, {
        certificates: certs,
        settings: store.state.settings,
        inbounds: (store.state.inbounds || []).map((i) => enrichInboundWithLinks(i, reqHostHeader))
      });
    }

    if (pathname === '/api/certificates/self-signed' && method === 'POST') {
      const body = await readJson(req);
      const cert = issueSelfSignedCert({
        domain: body.domain || store.state.settings.webDomain || 'www.apple.com',
        ip: store.state.settings.publicIPv4 || '',
        days: Number(body.days || 3650)
      });
      const bindPanel = body.applyToPanel !== false;
      store.transact((st) => {
        bindCertificateEverywhere(st, cert, bindPanel, true, true);
        store.addAudit(session.username, 'issue_selfsigned_cert', cert.domain);
      });
      autoApplyIfEnabled();
      if (bindPanel) setTimeout(() => restartPanelServer(), 300);
      return sendJson(res, 201, { certificate: cert });
    }

    if (pathname === '/api/certificates/custom' && method === 'POST') {
      const body = await readJson(req);
      const cert = saveCustomCert({
        domain: body.domain,
        certPem: body.certPem,
        keyPem: body.keyPem,
        certPath: body.certPath,
        keyPath: body.keyPath
      });
      const bindPanel = body.applyToPanel !== false;
      store.transact((st) => {
        bindCertificateEverywhere(st, cert, bindPanel, true, true);
        store.addAudit(session.username, 'save_custom_cert', cert.domain);
      });
      autoApplyIfEnabled();
      if (bindPanel) setTimeout(() => restartPanelServer(), 300);
      return sendJson(res, 201, { certificate: cert });
    }

    if (pathname === '/api/certificates/acme' && method === 'POST') {
      const body = await readJson(req);
      const cert = issueAcmeCert({
        domain: body.domain,
        email: body.email,
        mode: body.mode || 'standalone',
        cfToken: body.cfToken || '',
        cfKey: body.cfKey || '',
        cfEmail: body.cfEmail || '',
        webPort: Number(body.webPort || 80)
      });
      const bindPanel = body.applyToPanel !== false;
      store.transact((st) => {
        bindCertificateEverywhere(st, cert, bindPanel, true, true);
        store.addAudit(session.username, 'issue_acme_cert', `${cert.domain} (${cert.type})`);
      });
      autoApplyIfEnabled();
      if (bindPanel) setTimeout(() => restartPanelServer(), 300);
      return sendJson(res, 201, { certificate: cert });
    }

    if (pathname === '/api/certificates/bind-all' && method === 'POST') {
      const body = await readJson(req);
      const cert = store.state.certificates.find((c) => c.id === body.id || c.certPath === body.certPath);
      if (!cert) return sendError(res, 404, '未找到该证书');
      store.transact((st) => {
        bindCertificateEverywhere(st, cert, true, true, true);
        store.addAudit(session.username, 'bind_cert_all', cert.domain);
      });
      autoApplyIfEnabled();
      setTimeout(() => restartPanelServer(), 300);
      return sendJson(res, 200, { ok: true, certificate: cert });
    }

    const certMatch = route('/api/certificates/:id', pathname);
    if (certMatch && method === 'DELETE') {
      syncDiscoveredCerts();
      const prevPanelCert = store.state.settings.webCertFile || '';
      let deletedDomain = '';
      let switchedDomain = '';
      store.transact((st) => {
        const target = (st.certificates || []).find((c) => c.id === certMatch.id || c.domain === certMatch.id);
        if (!target) {
          const err = new Error('未找到该证书记录');
          err.statusCode = 404;
          throw err;
        }
        deletedDomain = target.domain || '';
        if (!Array.isArray(st.settings.deletedCertDomains)) st.settings.deletedCertDomains = [];
        if (!Array.isArray(st.settings.deletedCertPaths)) st.settings.deletedCertPaths = [];
        if (target.domain && !st.settings.deletedCertDomains.includes(target.domain)) {
          st.settings.deletedCertDomains.push(target.domain);
        }
        if (target.certPath && !st.settings.deletedCertPaths.includes(target.certPath)) {
          st.settings.deletedCertPaths.push(target.certPath);
        }

        st.certificates = (st.certificates || []).filter(
          (c) => c.id !== target.id && c.domain !== target.domain && c.certPath !== target.certPath
        );

        for (const baseRoot of ['/etc/nexusgate/certs', '/root/cert']) {
          if (target.domain && target.domain !== 'www.apple.com') {
            try { fs.rmSync(path.join(baseRoot, target.domain), { recursive: true, force: true }); } catch { /* ignore */ }
          }
        }
        if (target.certPath && (target.certPath.startsWith('/etc/nexusgate/certs/') || target.certPath.startsWith('/root/cert/'))) {
          try { fs.rmSync(path.dirname(target.certPath), { recursive: true, force: true }); } catch { /* ignore */ }
        }

        const wasActive =
          st.settings.webCertFile === target.certPath ||
          st.settings.defaultCertFile === target.certPath ||
          st.settings.webDomain === target.domain ||
          st.settings.defaultTlsDomain === target.domain;

        if (wasActive) {
          const nextCert =
            st.certificates.find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false) ||
            st.certificates[0] ||
            null;
          if (nextCert) {
            bindCertificateEverywhere(st, nextCert, true, true, true);
            switchedDomain = nextCert.domain;
          } else {
            st.settings.webDomain = '';
            st.settings.webCertFile = '';
            st.settings.webKeyFile = '';
            st.settings.defaultTlsDomain = 'www.apple.com';
            st.settings.defaultCertFile = '';
            st.settings.defaultKeyFile = '';
          }
        }
        store.addAudit(
          session.username,
          'delete_cert',
          `${deletedDomain || certMatch.id}${switchedDomain ? ` (已自动切换默认证书至 ${switchedDomain})` : ''}`
        );
      });
      try { discoverSystemCertificates(true); } catch { /* ignore */ }
      autoApplyIfEnabled();
      if (store.state.settings.webCertFile !== prevPanelCert) {
        setTimeout(() => restartPanelServer(), 300);
      }
      return sendJson(res, 200, {
        ok: true,
        deletedDomain,
        switchedDomain,
        settings: store.state.settings
      });
    }

    // 14. Panel Security & Settings
    if (pathname === '/api/settings' && method === 'GET') {
      syncDiscoveredCerts();
      const subCount = (store.state.inbounds || [])
        .filter((i) => i.enable !== false && i.protocol !== 'direct')
        .reduce((acc, i) => acc + Math.max(1, (i.clients || []).filter((c) => c.enable !== false).length), 0);
      const certs = (store.state.certificates || []).map((c) => ({
        ...c,
        ...inspectCertificate(c.certPath, c.keyPath)
      }));
      return sendJson(res, 200, {
        settings: store.state.settings,
        admin: { username: store.state.admin.username, updatedAt: store.state.admin.updatedAt },
        certificates: certs,
        migrations: store.state.migrations || [],
        local3xuiExists: fs.existsSync('/etc/x-ui/x-ui.db') || fs.existsSync('/root/3xui_backup.tar.gz'),
        subscriptionLinksCount: subCount
      });
    }

    if (pathname === '/api/settings' && method === 'PUT') {
      const body = await readJson(req);
      let needServerRestart = false;
      store.transact((st) => {
        const s = st.settings;
        if (body.webListen !== undefined && body.webListen !== s.webListen) {
          s.webListen = String(body.webListen).trim() || '0.0.0.0';
          needServerRestart = true;
        }
        if (body.webPort !== undefined) {
          const p = Number(body.webPort);
          if (!Number.isInteger(p) || p < 1 || p > 65535) {
            throw new Error('面板端口必须是 1–65535 之间的整数');
          }
          if (p !== s.webPort) needServerRestart = true;
          s.webPort = p;
        }
        if (body.webBasePath !== undefined) {
          s.webBasePath = normalizeBasePath(body.webBasePath);
        }
        if (body.strictBasePath !== undefined) {
          s.strictBasePath = Boolean(body.strictBasePath);
        }
        if (body.webDomain !== undefined) s.webDomain = String(body.webDomain).trim();
        if (body.publicIPv4 !== undefined) s.publicIPv4 = String(body.publicIPv4).trim();
        if (body.publicIPv6 !== undefined) s.publicIPv6 = String(body.publicIPv6).trim();
        if (body.trafficResetDay !== undefined) {
          s.trafficResetDay = Math.max(0, Math.min(31, Math.floor(Number(body.trafficResetDay || 0))));
        }
        if (body.webCertFile !== undefined) {
          if (body.webCertFile !== s.webCertFile) needServerRestart = true;
          s.webCertFile = String(body.webCertFile).trim();
          if (s.webCertFile) s.defaultCertFile = s.webCertFile;
        }
        if (body.webKeyFile !== undefined) {
          if (body.webKeyFile !== s.webKeyFile) needServerRestart = true;
          s.webKeyFile = String(body.webKeyFile).trim();
          if (s.webKeyFile) s.defaultKeyFile = s.webKeyFile;
        }
        if (body.subEnable !== undefined) s.subEnable = Boolean(body.subEnable);
        if (body.subPath !== undefined) s.subPath = normalizeBasePath(body.subPath);
        if (body.subToken !== undefined) {
          const cleaned = String(body.subToken).trim().replace(/[^a-zA-Z0-9_-]/g, '');
          s.subToken = (cleaned && cleaned !== 'all' && cleaned.length >= 12) ? cleaned : randomString(20);
        }
        if (body.singboxBin !== undefined) s.singboxBin = String(body.singboxBin).trim();
        if (body.singboxLogLevel !== undefined) s.singboxLogLevel = String(body.singboxLogLevel).trim();
        if (body.autoApplyConfig !== undefined) s.autoApplyConfig = Boolean(body.autoApplyConfig);
        if (body.cfApiToken !== undefined) s.cfApiToken = String(body.cfApiToken).trim();
        if (body.cfDefaultZoneId !== undefined) s.cfDefaultZoneId = String(body.cfDefaultZoneId).trim();
        if (body.autoFailover !== undefined) s.autoFailover = Boolean(body.autoFailover);
        if (body.failoverThresholdSec !== undefined) s.failoverThresholdSec = Math.max(30, Number(body.failoverThresholdSec || 90));
        if (body.sessionMaxAge !== undefined) {
          s.sessionMaxAge = Math.max(5, Number(body.sessionMaxAge || 720));
          sessions.setMaxAgeMinutes(s.sessionMaxAge);
        }
        store.addAudit(session.username, 'update_settings', `端口:${s.webPort} 路径:${s.webBasePath}`);
      });

      if (needServerRestart) {
        setTimeout(() => restartPanelServer(), 300);
      }

      return sendJson(res, 200, {
        settings: store.state.settings,
        restarting: needServerRestart
      });
    }

    if (pathname === '/api/auth/account' && method === 'POST') {
      const body = await readJson(req);
      const currentPassword = String(body.currentPassword || '');
      if (!verifySecret(currentPassword, store.state.admin.passwordHash)) {
        return sendError(res, 400, '当前登录密码验证不正确');
      }
      const nextUser = String(body.username || store.state.admin.username).trim();
      const nextPass = String(body.newPassword || '').trim();
      if (!nextUser) return sendError(res, 400, '管理员账号不能为空');
      if (nextPass && nextPass.length < 6) return sendError(res, 400, '新密码长度至少 6 位');
      if (nextPass && nextPass === nextUser) return sendError(res, 400, '安全策略限制：登录密码不能与管理员账号相同');

      store.transact((st) => {
        st.admin.username = nextUser;
        if (nextPass) {
          st.admin.passwordHash = hashSecret(nextPass);
          st.admin.initialPassword = '';
        }
        st.admin.updatedAt = new Date().toISOString();
        store.addAudit(nextUser, 'update_account', '修改面板登录凭据');
      });
      sessions.clearAll();
      return sendJson(res, 200, { ok: true, message: '账号密码已更新，请重新登录' });
    }

    // 15. Backup & Restore
    if (pathname === '/api/backup' && method === 'GET') {
      const payload = JSON.stringify(store.state, null, 2);
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'content-disposition': `attachment; filename="nexusgate-backup-${new Date().toISOString().slice(0, 10)}.json"`
      });
      res.end(payload);
      return;
    }

    if (pathname === '/api/restore' && method === 'POST') {
      const body = await readJson(req);
      const data = body.backup || body;
      if (!data || !Array.isArray(data.inbounds) || !Array.isArray(data.outbounds)) {
        return sendError(res, 400, '备份文件结构无效');
      }
      store.transact((st) => {
        st.inbounds = data.inbounds;
        st.outbounds = data.outbounds;
        if (data.routing) st.routing = data.routing;
        if (data.dns) st.dns = data.dns;
        if (data.certificates) st.certificates = data.certificates;
        syncRoutingRulesToInbounds(st);
        store.addAudit(session.username, 'restore_backup', `恢复 ${data.inbounds.length} 个入站`);
      });
      const restoredPorts = (store.state.inbounds || []).filter((i) => i.enable !== false).map((i) => i.port);
      autoApplyIfEnabled(restoredPorts);
      return sendJson(res, 200, { ok: true, inboundsCount: store.state.inbounds.length, outboundsCount: store.state.outbounds.length });
    }

    return sendError(res, 404, `未找到接口: ${pathname}`, 'not_found');
  } catch (error) {
    return sendError(res, error.statusCode || 500, error.message || '服务器内部错误');
  }
}

function createPanelServer() {
  const s = store.state.settings;
  const useTls = Boolean(s.webCertFile && s.webKeyFile && fs.existsSync(s.webCertFile) && fs.existsSync(s.webKeyFile));
  if (useTls) {
    try {
      const cert = fs.readFileSync(s.webCertFile);
      const key = fs.readFileSync(s.webKeyFile);
      return { server: https.createServer({ cert, key }, handleRequest), proto: 'https' };
    } catch (err) {
      console.error('加载面板 SSL 证书失败，回退至 HTTP 模式:', err.message);
    }
  }
  return { server: http.createServer(handleRequest), proto: 'http' };
}

function startPanelServer(callback) {
  const s = store.state.settings;
  const host = s.webListen || '0.0.0.0';
  const port = Number(s.webPort || 2053);
  const basePath = normalizeBasePath(s.webBasePath || '/');
  const { server, proto } = createPanelServer();
  activeServer = server;

  server.listen(port, host, () => {
    console.log(`[NexusGate Plus · 枢门集群 v${VERSION}] 面板已启动: ${proto}://${host}:${port}${basePath === '/' ? '/' : `${basePath}/`}`);
    try {
      if (fs.existsSync(singbox.getBinPath())) {
        singbox.reloadIfChanged();
      } else {
        singbox.writeConfig();
      }
    } catch (err) {
      console.warn('[NexusGate] 初始化写入 Sing-box 配置提示:', err.message);
    }
    if (callback) callback(server, proto);
  });
  return server;
}

function restartPanelServer() {
  if (!activeServer) return;
  const prev = activeServer;
  activeServer = null;
  try {
    if (typeof prev.closeIdleConnections === 'function') prev.closeIdleConnections();
    if (typeof prev.closeAllConnections === 'function') prev.closeAllConnections();
  } catch { /* ignore */ }
  prev.close(() => {
    startPanelServer();
  });
}

if (require.main === module) {
  startPanelServer();
  setInterval(() => {
    sessions.prune();
    const now = Date.now();
    for (const [ip, rec] of loginAttempts.entries()) {
      if (now > rec.resetAt) loginAttempts.delete(ip);
    }
    if (loginAttempts.size > 2000) loginAttempts.clear();
    store.flushIfDirty();
    if (typeof global.gc === 'function') {
      const m = process.memoryUsage();
      const unusedHeap = m.heapTotal - m.heapUsed;
      if (unusedHeap > 20 * 1024 * 1024 || m.external > 10 * 1024 * 1024) {
        try { global.gc(); } catch { /* ignore */ }
      }
    }
  }, 60000).unref();
  setInterval(() => {
    try { cleanupSystemLogsAndMemory(singbox, store); } catch { /* ignore */ }
  }, 6 * 3600 * 1000).unref();
  setInterval(() => singbox.pollConnectionsAndEnforceLimits().catch(() => {}), 1000).unref();

  const gracefulShutdown = () => {
    try { singbox.clearAllTempIpBlocks(); } catch { /* ignore */ }
    try { store.flushIfDirty(); } catch { /* ignore */ }
    process.exit(0);
  };
  process.on('SIGINT', gracefulShutdown);
  process.on('SIGTERM', gracefulShutdown);
}

module.exports = {
  store,
  singbox,
  startPanelServer,
  handleRequest
};
