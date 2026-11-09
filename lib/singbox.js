'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const net = require('node:net');
const http = require('node:http');
const { spawn, spawnSync } = require('node:child_process');
const { toSingboxInbound, toSingboxOutbound } = require('./protocols');

const KNOWN_VERSIONS = [
  'v1.12.23',
  'v1.12.15',
  'v1.12.0',
  'v1.11.15',
  'v1.11.8',
  'v1.10.7'
];

// Rolling active lease window (60 seconds) so online IP/device counts remain visible
// and enforced across request bursts without flickering to 0 between HTTP requests.
const ACTIVE_LEASE_TTL_MS = 60000;
const EXCESS_IP_BLOCK_TTL_MS = 30000;

const BUILTIN_GEOSITE_EXPANSIONS = {
  'category-ads-all': {
    domain_suffix: ['doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'adnxs.com', 'adsrvr.org', 'criteo.com', 'taboola.com', 'outbrain.com', 'scorecardresearch.com'],
    domain_keyword: ['adservice', 'pagead2', 'omtrdc']
  },
  openai: {
    domain_suffix: [
      'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'auth0.com',
      'anthropic.com', 'claude.ai', 'claudeusercontent.com',
      'gemini.google.com', 'bard.google.com', 'generativelanguage.googleapis.com', 'aistudio.google.com',
      'perplexity.ai', 'x.ai', 'grok.com', 'cursor.sh', 'cursor.com', 'copilot.microsoft.com',
      'huggingface.co', 'midjourney.com', 'poe.com', 'coze.com', 'dify.ai'
    ]
  },
  google: {
    domain_suffix: ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'googlevideo.com', 'youtube.com', 'ytimg.com', 'ggpht.com', 'gmail.com', 'android.com', 'play.googleapis.com']
  },
  netflix: {
    domain_suffix: ['netflix.com', 'netflix.net', 'nflxvideo.net', 'nflximg.net', 'nflximg.com', 'nflxext.com', 'nflxso.net', 'fast.com']
  },
  cn: {
    domain_suffix: ['cn', 'baidu.com', 'qq.com', 'weixin.qq.com', 'taobao.com', 'tmall.com', 'alipay.com', 'aliyun.com', '163.com', '126.com', 'jd.com', 'bilibili.com', 'hdslb.com', 'douyin.com', 'bytedance.com', 'weibo.com', 'zhihu.com', 'xiaomi.com', 'huawei.com']
  },
  'geolocation-!cn': {
    domain_suffix: ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'tiktok.com', 'whatsapp.com', 'telegram.org', 't.me', 'github.com', 'openai.com', 'chatgpt.com', 'claude.ai', 'netflix.com', 'amazon.com', 'shopify.com', 'paypal.com', 'stripe.com', 'linkedin.com']
  }
};

const BUILTIN_GEOIP_CIDRS = {
  cn: [
    '1.0.1.0/24', '1.0.2.0/23', '1.0.8.0/21', '1.1.0.0/24', '1.2.0.0/22', '1.4.1.0/24',
    '14.0.0.0/8', '27.0.0.0/8', '36.0.0.0/8', '39.0.0.0/8', '42.0.0.0/8', '49.0.0.0/8',
    '58.0.0.0/8', '59.0.0.0/8', '60.0.0.0/8', '61.0.0.0/8', '101.0.0.0/8', '103.0.0.0/8',
    '106.0.0.0/8', '110.0.0.0/7', '112.0.0.0/6', '116.0.0.0/6', '120.0.0.0/6', '124.0.0.0/7',
    '139.0.0.0/8', '140.205.0.0/16', '171.0.0.0/8', '175.0.0.0/8', '180.0.0.0/6', '182.0.0.0/8',
    '183.0.0.0/8', '202.0.0.0/8', '210.0.0.0/7', '218.0.0.0/7', '220.0.0.0/6'
  ]
};

function stripAnsi(str) {
  return String(str || '').replace(/\x1b\[[0-9;]*m/g, '');
}

function cleanArray(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
  return String(val)
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

function normalizeClientIp(rawIp) {
  const s = String(rawIp || '').trim().replace(/^\[|\]$/g, '').replace(/^::ffff:/i, '');
  if (!s || s === '127.0.0.1' || s === '::1' || s === '0.0.0.0' || s === '::') return '';
  return s;
}

function compileRouteRule(rule, neededRuleSets) {
  const sbRule = {};

  const inbounds = cleanArray(rule.inbound || rule.inboundTag);
  if (inbounds.length) sbRule.inbound = inbounds;

  const protocols = cleanArray(rule.protocol);
  if (protocols.length) sbRule.protocol = protocols;

  if (rule.network && ['tcp', 'udp'].includes(String(rule.network).toLowerCase())) {
    sbRule.network = String(rule.network).toLowerCase();
  }

  const domains = cleanArray(rule.domain);
  const domainSuffix = cleanArray(rule.domain_suffix);
  const domainKeyword = cleanArray(rule.domain_keyword);
  const domainRegex = cleanArray(rule.domain_regex);
  const rawRuleSets = cleanArray(rule.rule_set);
  const localRuleSets = new Set();

  const applyGeositeName = (name) => {
    const cleanName = String(name || '').trim().toLowerCase();
    if (!cleanName) return;
    const localSrs = `/etc/nexusgate/sing-box/rulesets/geosite-${cleanName}.srs`;
    if (fs.existsSync(localSrs)) {
      const tag = `geosite-${cleanName}`;
      localRuleSets.add(tag);
      neededRuleSets.set(tag, localSrs);
      return;
    }
    const builtin = BUILTIN_GEOSITE_EXPANSIONS[cleanName];
    if (builtin) {
      if (builtin.domain_suffix) domainSuffix.push(...builtin.domain_suffix);
      if (builtin.domain_keyword) domainKeyword.push(...builtin.domain_keyword);
    } else {
      domainKeyword.push(cleanName);
    }
  };

  const applyGeoipName = (name, ipCidrsArr) => {
    const cleanName = String(name || '').trim().toLowerCase();
    if (!cleanName) return;
    const localSrs = `/etc/nexusgate/sing-box/rulesets/geoip-${cleanName}.srs`;
    if (fs.existsSync(localSrs)) {
      const tag = `geoip-${cleanName}`;
      localRuleSets.add(tag);
      neededRuleSets.set(tag, localSrs);
      return;
    }
    const builtinCidrs = BUILTIN_GEOIP_CIDRS[cleanName];
    if (builtinCidrs) {
      ipCidrsArr.push(...builtinCidrs);
    }
  };

  for (const rs of rawRuleSets) {
    if (rs.startsWith('geosite-')) {
      applyGeositeName(rs.slice(8));
    }
  }

  const exactDomains = [];
  for (const item of domains) {
    if (item.startsWith('geosite:')) {
      applyGeositeName(item.slice(8));
    } else if (item.startsWith('domain:')) {
      domainSuffix.push(item.slice(7).trim());
    } else if (item.startsWith('full:')) {
      exactDomains.push(item.slice(5).trim());
    } else if (item.startsWith('keyword:')) {
      domainKeyword.push(item.slice(8).trim());
    } else if (item.startsWith('regexp:') || item.startsWith('regex:')) {
      domainRegex.push(item.replace(/^regex(p)?:/, '').trim());
    } else if (!item.startsWith('ext:')) {
      domainSuffix.push(item);
    }
  }

  if (exactDomains.length) sbRule.domain = [...new Set(exactDomains)];
  if (domainSuffix.length) sbRule.domain_suffix = [...new Set(domainSuffix)];
  if (domainKeyword.length) sbRule.domain_keyword = [...new Set(domainKeyword)];
  if (domainRegex.length) sbRule.domain_regex = [...new Set(domainRegex)];

  const ipCidrs = [];
  let ipIsPrivate = Boolean(rule.ip_is_private);
  for (const rs of rawRuleSets) {
    if (rs.startsWith('geoip-')) {
      applyGeoipName(rs.slice(6), ipCidrs);
    }
  }
  for (const item of cleanArray(rule.ip || rule.ip_cidr)) {
    if (item === 'geoip:private') {
      ipIsPrivate = true;
    } else if (item.startsWith('geoip:')) {
      applyGeoipName(item.slice(6), ipCidrs);
    } else {
      ipCidrs.push(item);
    }
  }
  if (ipIsPrivate) sbRule.ip_is_private = true;
  if (ipCidrs.length) sbRule.ip_cidr = [...new Set(ipCidrs)];

  const sourceIpCidrs = cleanArray(rule.source_ip_cidr || rule.sourceIP).filter((x) => !x.startsWith('geoip:'));
  if (sourceIpCidrs.length) sbRule.source_ip_cidr = sourceIpCidrs;

  const parsePorts = (rawPorts) => {
    const ports = [];
    const ranges = [];
    for (const p of cleanArray(rawPorts)) {
      if (p.includes('-')) {
        const [a, b] = p.split('-').map((n) => Number(n.trim()));
        if (Number.isInteger(a) && Number.isInteger(b)) ranges.push(`${a}:${b}`);
      } else if (p.includes(':')) {
        ranges.push(p);
      } else {
        const num = Number(p);
        if (Number.isInteger(num) && num > 0) ports.push(num);
      }
    }
    return { ports, ranges };
  };

  const dstP = parsePorts(rule.port);
  if (dstP.ports.length) sbRule.port = dstP.ports;
  if (dstP.ranges.length) sbRule.port_range = dstP.ranges;

  const srcP = parsePorts(rule.source_port || rule.sourcePort);
  if (srcP.ports.length) sbRule.source_port = srcP.ports;
  if (srcP.ranges.length) sbRule.source_port_range = srcP.ranges;

  const authUsers = cleanArray(rule.auth_user || rule.user);
  if (authUsers.length) sbRule.auth_user = authUsers;

  if (localRuleSets.size) sbRule.rule_set = [...localRuleSets];

  const targetOutbound = rule.outbound || rule.outboundTag || 'direct';
  if (rule.action === 'sniff') {
    sbRule.action = 'sniff';
  } else if (rule.action === 'reject' || targetOutbound === 'block' || targetOutbound === 'blocked') {
    sbRule.outbound = 'block';
  } else {
    sbRule.outbound = targetOutbound;
  }

  return sbRule;
}

function buildSingboxConfig(state) {
  const settings = state.settings || {};
  const activeInbounds = (state.inbounds || []).filter((i) => i.enable !== false);
  const activeOutbounds = (state.outbounds || []).filter((o) => o.enabled !== false);

  const validInboundTags = new Set(activeInbounds.map((i) => i.tag || `in-${i.protocol}-${i.port}`));
  const sbInbounds = activeInbounds.map((item) => toSingboxInbound(item, state.certificates || [], settings));
  const sbOutbounds = activeOutbounds.map((item) => toSingboxOutbound(item));

  if (!sbOutbounds.some((o) => o.tag === 'direct')) {
    sbOutbounds.unshift({ type: 'direct', tag: 'direct' });
  }
  if (!sbOutbounds.some((o) => o.tag === 'block')) {
    sbOutbounds.push({ type: 'block', tag: 'block' });
  }

  const validOutboundTags = new Set(sbOutbounds.map((o) => o.tag));
  const neededRuleSets = new Map();
  const routeRules = [];

  routeRules.push({ action: 'sniff' });

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
      for (const t of r.inbound) existingRuleInbounds.add(t);
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
    if (rule.enabled === false) continue;
    if (rule.action === 'sniff') continue;
    const compiled = compileRouteRule(rule, neededRuleSets);

    if (Array.isArray(compiled.inbound)) {
      compiled.inbound = compiled.inbound.filter((t) => validInboundTags.has(t));
      if (compiled.inbound.length === 0) {
        continue;
      }
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

  return {
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
}

function computeResetCycleKey(resetDay, nowDate = new Date()) {
  const rDay = Number(resetDay || 0);
  if (!Number.isInteger(rDay) || rDay < 1 || rDay > 31) return '';
  let year = nowDate.getFullYear();
  let month = nowDate.getMonth();
  const daysInThisMonth = new Date(year, month + 1, 0).getDate();
  const effectiveResetDay = Math.min(rDay, daysInThisMonth);
  if (nowDate.getDate() < effectiveResetDay) {
    month -= 1;
    if (month < 0) {
      month = 11;
      year -= 1;
    }
  }
  return `${year}-${String(month + 1).padStart(2, '0')}`;
}

/**
 * Extracts the inbound tag from a Sing-box Clash API connection object.
 * Sing-box sets `metadata.type = "<inbound_type>/<inbound_tag>"` (e.g. "anytls/inbound-21735").
 */
function resolveInboundFromClashConn(c, inboundByTag, inboundByPort) {
  const meta = c?.metadata || {};
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

  if (c.rule) {
    const ruleStr = String(c.rule);
    const m = ruleStr.match(/inbound=\[?([^\],=\s]+)\]?/i);
    if (m && m[1]) candidates.push(m[1].trim());
  }

  for (const cand of candidates) {
    if (cand && inboundByTag.has(cand)) {
      return inboundByTag.get(cand);
    }
  }

  if (meta.inboundPort && inboundByPort.has(Number(meta.inboundPort))) {
    return inboundByPort.get(Number(meta.inboundPort));
  }

  return null;
}

class SingboxManager {
  constructor(store) {
    this.store = store;
    this.childProcess = null;
    this.lastError = '';
    this.logRing = [];
    this.startedAt = null;
    this.connTrafficCache = new Map();
    // Map<inboundTag, Map<deviceFp, { ip, deviceFp, user, firstSeenAt, lastSeenAt }>>
    this.activeSessionLeases = new Map();
    // Map<`${ip}:${port}`, { ip, port, inboundTag, expiresAt }>
    this.tempBlockedExcessIps = new Map();
    this._recentSocketKillAt = new Map();
    this.activeIpsByTag = new Map();
    this.activeDevicesByTag = new Map();
    this.activeClientIpsByTag = new Map();
    this.activeClientDevicesByTag = new Map();
    this._polling = false;
    this._lastPollAt = 0;
    this._lastKernelScanAt = 0;
    this._cachedKernelPeers = new Map();
    this._cachedVersion = { key: '', value: null };
    this._cachedStatus = { at: 0, value: null };
    this._lastClashAliveAt = 0;
    this._lastKnownPid = 0;
    this._lastSlowProbeAt = 0;
    this._systemdUnitPatched = false;
  }

  appendLog(line) {
    const clean = stripAnsi(line).trim().slice(0, 400);
    if (!clean) return;
    this.logRing.push(`${new Date().toISOString()} ${clean}`);
    if (this.logRing.length > 150) {
      this.logRing.shift();
    }
  }

  getBinPath() {
    return this.store.state.settings.singboxBin || '/usr/local/bin/sing-box';
  }

  getConfigPath() {
    const cfg = this.store.state.settings.singboxConfigPath || '/etc/nexusgate/sing-box/config.json';
    try {
      fs.mkdirSync(path.dirname(cfg), { recursive: true });
      return cfg;
    } catch {
      const fallback = path.join(path.dirname(this.store.filePath), 'sing-box-config.json');
      fs.mkdirSync(path.dirname(fallback), { recursive: true });
      return fallback;
    }
  }

  ensureFallbackSelfSignedCert() {
    const certDir = '/etc/nexusgate/certs/selfsigned';
    let targetDir = certDir;
    try {
      fs.mkdirSync(certDir, { recursive: true });
    } catch {
      targetDir = path.join(path.dirname(this.store.filePath), 'certs', 'selfsigned');
      fs.mkdirSync(targetDir, { recursive: true });
    }
    const certFile = path.join(targetDir, 'fullchain.pem');
    const keyFile = path.join(targetDir, 'privkey.pem');
    const cn = this.store.state.settings.webDomain || 'www.apple.com';
    if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
      spawnSync('openssl', [
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
        '-days', '3650', '-nodes', '-subj', `/CN=${cn}`,
        '-keyout', keyFile, '-out', certFile
      ], { encoding: 'utf8', timeout: 10000 });
    }
    return { certFile, keyFile };
  }

  writeConfig() {
    const fallbackCert = this.ensureFallbackSelfSignedCert();
    const config = buildSingboxConfig(this.store.state);
    for (const inb of config.inbounds || []) {
      if (inb.tls && inb.tls.reality?.enabled) {
        delete inb.tls.certificate_path;
        delete inb.tls.key_path;
      } else if (inb.tls && (!inb.tls.certificate_path || !fs.existsSync(inb.tls.certificate_path))) {
        inb.tls.certificate_path = fallbackCert.certFile;
        inb.tls.key_path = fallbackCert.keyFile;
      }
    }
    const configPath = this.getConfigPath();
    const json = JSON.stringify(config, null, 2);
    let prevJson = '';
    try {
      if (fs.existsSync(configPath)) prevJson = fs.readFileSync(configPath, 'utf8');
    } catch { /* ignore */ }
    const changed = prevJson !== json;
    if (changed || !fs.existsSync(configPath)) {
      fs.writeFileSync(configPath, json, { mode: 0o600 });
    }
    return { configPath, config, changed };
  }

  getVersion() {
    const bin = this.getBinPath();
    if (!fs.existsSync(bin)) return { installed: false, version: '未安装', binary: bin };
    try {
      const stat = fs.statSync(bin);
      const cacheKey = `${bin}:${stat.mtimeMs}:${stat.size}`;
      if (this._cachedVersion.key === cacheKey && this._cachedVersion.value) {
        return this._cachedVersion.value;
      }
      const res = spawnSync(bin, ['version'], { encoding: 'utf8', timeout: 5000 });
      const out = stripAnsi(res.stdout || res.stderr || '');
      const match = out.match(/sing-box\s+version\s+([^\s\n]+)/i);
      const val = {
        installed: true,
        version: match ? match[1] : out.split('\n')[0].trim() || '已安装',
        detail: out.trim(),
        binary: bin
      };
      this._cachedVersion = { key: cacheKey, value: val };
      return val;
    } catch (err) {
      return { installed: false, version: '检测失败', error: err.message, binary: bin };
    }
  }

  checkConfig() {
    const { configPath, config, changed } = this.writeConfig();
    const bin = this.getBinPath();
    if (!fs.existsSync(bin)) {
      this.lastError = '';
      return { valid: true, changed, warning: 'sing-box 二进制尚未安装，已生成合法配置文件', configPath, config };
    }
    const res = spawnSync(bin, ['check', '-c', configPath], { encoding: 'utf8', timeout: 10000 });
    if (res.status !== 0) {
      const msg = stripAnsi(res.stderr || res.stdout || '配置检查失败').trim();
      this.lastError = msg;
      return { valid: false, changed, error: msg, configPath, config };
    }
    this.lastError = '';
    return { valid: true, changed, configPath, config };
  }

  reloadIfChanged() {
    const check = this.checkConfig();
    if (!check.valid) {
      throw new Error(`Sing-box 配置校验未通过: ${check.error}`);
    }
    if (!check.changed && this.getStatus().state === 'running') {
      return { status: 'running', unchanged: true };
    }
    return this.restart(check);
  }

  getStatus() {
    const now = Date.now();
    if (this._cachedStatus.value && now - this._cachedStatus.at < 8000) {
      return this._cachedStatus.value;
    }

    const ver = this.getVersion();
    const hasFatalError = Boolean(this.lastError);
    const cacheAndReturn = (obj) => {
      if (obj.pid) this._lastKnownPid = obj.pid;
      this._cachedStatus = { at: now, value: obj };
      return obj;
    };

    // Fast path 1: Cgroup v2 / v1 procs file on Linux systemd (0 child processes spawned!)
    for (const cgPath of [
      '/sys/fs/cgroup/system.slice/nexusgate-singbox.service/cgroup.procs',
      '/sys/fs/cgroup/systemd/system.slice/nexusgate-singbox.service/cgroup.procs'
    ]) {
      if (fs.existsSync(cgPath)) {
        try {
          const pids = fs.readFileSync(cgPath, 'utf8').trim();
          if (pids) {
            return cacheAndReturn({
              state: hasFatalError ? 'error' : 'running',
              mode: 'systemd',
              pid: Number(pids.split('\n')[0]),
              version: ver.version,
              installed: ver.installed,
              binary: ver.binary,
              configPath: this.getConfigPath(),
              lastError: this.lastError
            });
          }
        } catch { /* fallback */ }
      }
    }

    // Fast path 2: Direct /proc/<lastKnownPid>/comm check (0 child processes spawned!)
    if (this._lastKnownPid > 0) {
      try {
        const comm = fs.readFileSync(`/proc/${this._lastKnownPid}/comm`, 'utf8').trim();
        if (comm.includes('sing-box')) {
          return cacheAndReturn({
            state: hasFatalError ? 'error' : 'running',
            mode: 'systemd',
            pid: this._lastKnownPid,
            version: ver.version,
            installed: ver.installed,
            binary: ver.binary,
            configPath: this.getConfigPath(),
            lastError: this.lastError
          });
        }
      } catch {
        this._lastKnownPid = 0;
      }
    }

    // Fast path 3: Direct child process or recent Clash API heartbeat
    if (this.childProcess && this.childProcess.exitCode === null) {
      return cacheAndReturn({
        state: hasFatalError ? 'error' : 'running',
        mode: 'process',
        pid: this.childProcess.pid,
        version: ver.version,
        installed: ver.installed,
        binary: ver.binary,
        configPath: this.getConfigPath(),
        lastError: this.lastError
      });
    }
    if (now - this._lastClashAliveAt < 8000) {
      return cacheAndReturn({
        state: hasFatalError ? 'error' : 'running',
        mode: 'systemd',
        version: ver.version,
        installed: ver.installed,
        binary: ver.binary,
        configPath: this.getConfigPath(),
        lastError: this.lastError
      });
    }

    // Throttle slow child-process probes (systemctl / pgrep) to at most once every 15 seconds
    if (this._cachedStatus.value && now - this._lastSlowProbeAt < 15000) {
      return this._cachedStatus.value;
    }
    this._lastSlowProbeAt = now;

    if (fs.existsSync('/run/systemd/system')) {
      const sys = spawnSync('systemctl', ['is-active', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 2000 });
      if (String(sys.stdout || '').trim() === 'active') {
        return cacheAndReturn({
          state: hasFatalError ? 'error' : 'running',
          mode: 'systemd',
          version: ver.version,
          installed: ver.installed,
          binary: ver.binary,
          configPath: this.getConfigPath(),
          lastError: this.lastError
        });
      }
    }
    const pgrep = spawnSync('pgrep', ['-f', 'sing-box run'], { encoding: 'utf8', timeout: 1500 });
    if (pgrep.status === 0 && String(pgrep.stdout || '').trim()) {
      return cacheAndReturn({
        state: hasFatalError ? 'error' : 'running',
        mode: 'daemon',
        pid: Number(String(pgrep.stdout).trim().split('\n')[0]),
        version: ver.version,
        installed: ver.installed,
        binary: ver.binary,
        configPath: this.getConfigPath(),
        lastError: this.lastError
      });
    }
    return cacheAndReturn({
      state: this.lastError ? 'error' : 'stop',
      mode: 'none',
      version: ver.version,
      installed: ver.installed,
      binary: ver.binary,
      configPath: this.getConfigPath(),
      lastError: this.lastError
    });
  }

  ensureSystemdServiceNoRateLimit() {
    if (this._systemdUnitPatched) return;
    const unitFile = '/etc/systemd/system/nexusgate-singbox.service';
    if (!fs.existsSync('/run/systemd/system') || !fs.existsSync(unitFile)) return;
    try {
      const content = fs.readFileSync(unitFile, 'utf8');
      if (!content.includes('StartLimitIntervalSec=0')) {
        const updated = `[Unit]
Description=NexusGate Sing-box Core Engine
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
ExecStartPre=-/usr/bin/pkill -9 -f "sing-box run -c /etc/nexusgate/sing-box/config.json"
ExecStart=/usr/local/bin/sing-box run -c /etc/nexusgate/sing-box/config.json
ExecReload=/bin/kill -HUP $MAINPID
Restart=always
RestartSec=1
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`;
        fs.writeFileSync(unitFile, updated, { mode: 0o644 });
        spawnSync('systemctl', ['daemon-reload'], { encoding: 'utf8', timeout: 5000 });
      }
      this._systemdUnitPatched = true;
    } catch { /* ignore */ }
  }

  killDirectChildAndStrays() {
    if (this.childProcess) {
      try {
        this.childProcess.kill('SIGKILL');
      } catch { /* ignore */ }
      this.childProcess = null;
    }
  }

  restart(preChecked = null) {
    this._cachedStatus.at = 0;
    this._lastSlowProbeAt = 0;
    const check = (preChecked && preChecked.configPath) ? preChecked : this.checkConfig();
    if (!check.valid) {
      throw new Error(`Sing-box 配置校验未通过: ${check.error}`);
    }
    const bin = this.getBinPath();
    if (!fs.existsSync(bin)) {
      this.appendLog(`配置文件已更新并写入 ${check.configPath} (等待安装 sing-box 内核后启动)`);
      return { status: 'configured', message: '配置已保存（当前环境尚未安装 sing-box 二进制，可在内核版本管理中一键安装）', configPath: check.configPath };
    }

    // Always terminate any direct child process first so it can never hold port 10086 or node ports
    this.killDirectChildAndStrays();

    if (fs.existsSync('/run/systemd/system') && fs.existsSync('/etc/systemd/system/nexusgate-singbox.service')) {
      this.ensureSystemdServiceNoRateLimit();
      spawnSync('systemctl', ['stop', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 6000 });
      spawnSync('pkill', ['-9', '-f', 'sing-box run'], { encoding: 'utf8', timeout: 2000 });
      spawnSync('systemctl', ['reset-failed', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 3000 });
      const res = spawnSync('systemctl', ['start', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 12000 });
      if (res.status === 0) {
        this.lastError = '';
        this.appendLog('已通过 systemd 重启 nexusgate-singbox 服务并绑定全部节点端口');
        return { status: 'running', mode: 'systemd' };
      }
    }

    this.stop();
    const child = spawn(bin, ['run', '-c', check.configPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false
    });
    this.childProcess = child;
    this.startedAt = Date.now();
    this.lastError = '';
    child.stdout.on('data', (d) => this.appendLog(d.toString()));
    child.stderr.on('data', (d) => this.appendLog(d.toString()));
    child.on('exit', (code) => {
      if (code !== 0 && code !== null) {
        this.lastError = `Sing-box 进程退出 (code ${code})`;
        this.appendLog(this.lastError);
      }
    });
    this.appendLog(`已启动 Sing-box 进程 (PID: ${child.pid})`);
    return { status: 'running', pid: child.pid };
  }

  stop() {
    this._cachedStatus.at = 0;
    this._lastSlowProbeAt = 0;
    this._lastKnownPid = 0;
    this.killDirectChildAndStrays();
    this.clearAllTempIpBlocks();
    if (fs.existsSync('/run/systemd/system') && fs.existsSync('/etc/systemd/system/nexusgate-singbox.service')) {
      spawnSync('systemctl', ['stop', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 10000 });
    }
    spawnSync('pkill', ['-9', '-f', 'sing-box run'], { encoding: 'utf8', timeout: 3000 });
    this.appendLog('已停止 Sing-box 服务');
    return { status: 'stopped' };
  }

  getLogs() {
    if (fs.existsSync('/run/systemd/system') && fs.existsSync('/etc/systemd/system/nexusgate-singbox.service')) {
      const j = spawnSync('journalctl', ['-u', 'nexusgate-singbox.service', '-n', '80', '--no-pager'], { encoding: 'utf8', timeout: 4000 });
      if (j.status === 0 && j.stdout.trim()) {
        return stripAnsi(j.stdout).trim().split('\n');
      }
    }
    return this.logRing.length ? this.logRing : ['暂无运行日志，启动或重载 Sing-box 后将在此显示实时输出。'];
  }

  checkAndResetMonthlyTraffic(nowDate = new Date()) {
    let resetCount = 0;
    let needReload = false;
    const globalResetDay = Number(this.store.state.settings?.trafficResetDay || 0);

    for (const inb of this.store.state.inbounds || []) {
      const rDay = Number(inb.resetDay !== undefined ? inb.resetDay : globalResetDay);
      if (!rDay || rDay < 1 || rDay > 31) continue;

      const cycleKey = computeResetCycleKey(rDay, nowDate);
      if (!cycleKey) continue;

      if (!inb.lastResetCycle) {
        inb.lastResetCycle = cycleKey;
        continue;
      }

      if (inb.lastResetCycle !== cycleKey) {
        inb.up = 0;
        inb.down = 0;
        for (const c of inb.clients || []) {
          c.up = 0;
          c.down = 0;
          const cExpired = c.expiryTime && c.expiryTime > 0 && nowDate.getTime() > c.expiryTime;
          if (c.enable === false && c.disabledReason === 'quota' && !cExpired) {
            c.enable = true;
            delete c.disabledReason;
            needReload = true;
          }
        }
        inb.lastResetCycle = cycleKey;
        inb.lastResetAt = nowDate.toISOString();
        resetCount += 1;

        const isExpired = inb.expiryTime && inb.expiryTime > 0 && nowDate.getTime() > inb.expiryTime;
        if (inb.enable === false && inb.disabledReason === 'quota' && !isExpired) {
          inb.enable = true;
          delete inb.disabledReason;
          needReload = true;
        }
        this.appendLog(`[月度流量自动重置] 入站 ${inb.remark} 已到达每月 ${rDay} 号重置周期 (${cycleKey})，已自动清零流量`);
      }
    }

    if (resetCount > 0) {
      this.store.save();
    }
    return { resetCount, needReload };
  }

  /**
   * Scans Linux established TCP sockets on inbound ports as a supplementary source
   * for persistent multiplexed tunnels (e.g. AnyTLS, VLESS, Trojan, Shadowsocks).
   */
  scanKernelSocketsByPort(inboundByPort) {
    const portPeers = new Map();
    if (!inboundByPort.size) return portPeers;
    const now = Date.now();
    if (now - this._lastKernelScanAt < 5000 && this._cachedKernelPeers.size > 0) {
      for (const [p, set] of this._cachedKernelPeers.entries()) {
        if (inboundByPort.has(p)) portPeers.set(p, set);
      }
      return portPeers;
    }
    this._lastKernelScanAt = now;
    try {
      const res = spawnSync('ss', ['-tnH', 'state', 'established'], { encoding: 'utf8', timeout: 1200 });
      if (res.status !== 0 || !res.stdout) return portPeers;
      const lines = res.stdout.split('\n');
      for (const line of lines) {
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
        if (!peerIp) continue;
        if (!portPeers.has(localPort)) portPeers.set(localPort, new Set());
        portPeers.get(localPort).add(peerIp);
      }
      this._cachedKernelPeers = portPeers;
    } catch { /* ignore if ss unavailable */ }
    return portPeers;
  }

  /**
   * Temporarily blocks an excess 3rd+ IP on the specific inbound port in iptables/ip6tables
   * while the allowed N device/IP slots are full, without affecting the first N connected IPs!
   */
  applyTempIpPortBlock(srcIp, inboundPort, inboundTag, nowMs = Date.now()) {
    if (!srcIp || !inboundPort) return;
    const key = `${srcIp}:${inboundPort}`;
    if (this.tempBlockedExcessIps.has(key)) {
      this.tempBlockedExcessIps.get(key).expiresAt = nowMs + EXCESS_IP_BLOCK_TTL_MS;
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
    this.tempBlockedExcessIps.set(key, {
      ip: srcIp,
      port: Number(inboundPort),
      inboundTag,
      isV6,
      expiresAt: nowMs + EXCESS_IP_BLOCK_TTL_MS
    });
  }

  removeTempIpPortBlock(key) {
    const item = this.tempBlockedExcessIps.get(key);
    if (!item) return;
    this.tempBlockedExcessIps.delete(key);
    const bin = item.isV6 ? 'ip6tables' : 'iptables';
    try {
      for (const proto of ['tcp', 'udp']) {
        spawnSync(bin, ['-D', 'INPUT', '-s', item.ip, '-p', proto, '--dport', String(item.port), '-j', 'REJECT'], { timeout: 1000 });
      }
    } catch { /* ignore */ }
  }

  pruneExpiredTempIpBlocks(nowMs = Date.now(), inboundByTag = new Map()) {
    for (const [key, item] of this.tempBlockedExcessIps.entries()) {
      const inb = inboundByTag.get(item.inboundTag);
      const leaseMap = this.activeSessionLeases.get(item.inboundTag);
      const limitIp = Number(inb?.limitIp || 0);
      const limitDevice = Number(inb?.limitDevice || 0);
      const curCount = leaseMap ? leaseMap.size : 0;
      const slotsAvailable = !inb || inb.enable === false ||
        (limitIp === 0 && limitDevice === 0) ||
        (limitDevice > 0 && curCount < limitDevice) ||
        (limitIp > 0 && limitDevice === 0 && curCount < limitIp);

      if (nowMs >= item.expiresAt || slotsAvailable) {
        this.removeTempIpPortBlock(key);
      }
    }
  }

  clearAllTempIpBlocks() {
    for (const key of [...this.tempBlockedExcessIps.keys()]) {
      this.removeTempIpPortBlock(key);
    }
  }

  /**
   * Terminates ONLY the excess (3rd+) client connection without disturbing the first N allowed devices!
   * - If `isIpAllowed` is false (the excess client is on a 3rd IP not used by any allowed device),
   *   we close its Clash API stream, kill all sockets from that 3rd IP to `:inboundPort`, and apply a temporary per-IP port block.
   * - If `isIpAllowed` is true (the excess device shares the same NAT/Wi-Fi IP as an already-online allowed device),
   *   we ONLY close its specific `connId` and specific `srcPort` so the allowed device(s) on the same Wi-Fi are NEVER interrupted!
   */
  terminateExcessClient(connId, srcIp, srcPort, inboundPort, inboundTag, isIpAllowed = false, nowMs = Date.now()) {
    if (connId) {
      this.closeConnection(connId);
    }
    if (!srcIp || !inboundPort) return;
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    const killKey = isIpAllowed ? `${srcIp}:${inboundPort}:${srcPort}` : `${srcIp}:${inboundPort}:all`;
    const lastKill = this._recentSocketKillAt.get(killKey) || 0;
    if (this._recentSocketKillAt.size > 2000) this._recentSocketKillAt.clear();

    if (!isIpAllowed) {
      if (isRoot && nowMs - lastKill > 3000) {
        this._recentSocketKillAt.set(killKey, nowMs);
        try {
          spawnSync('ss', ['-K', 'dst', srcIp, 'sport', '=', `:${inboundPort}`], { encoding: 'utf8', timeout: 1000 });
        } catch { /* ignore */ }
      }
      this.applyTempIpPortBlock(srcIp, inboundPort, inboundTag, nowMs);
    } else if (srcPort > 0 && isRoot && nowMs - lastKill > 3000) {
      this._recentSocketKillAt.set(killKey, nowMs);
      try {
        spawnSync('ss', ['-K', 'dst', srcIp, 'sport', '=', `:${inboundPort}`, 'dport', '=', `:${srcPort}`], { encoding: 'utf8', timeout: 1000 });
      } catch { /* ignore */ }
    }
  }

  /**
   * Memory-bounded, non-overlapping Clash API + kernel socket connection poller.
   * Accurately attributes traffic to inbounds & outbounds, maintains 60s online IP/device leases,
   * and enforces limitIp & limitDevice in real time (blocking only excess devices while keeping existing devices online).
   */
  async pollConnectionsAndEnforceLimits(nowDate = new Date()) {
    if (this._polling) return;
    this._polling = true;
    this._lastPollAt = Date.now();
    try {
      const allInbounds = this.store.state.inbounds || [];
      const hasActiveInbounds = allInbounds.some((i) => i.enable !== false);
      if (!hasActiveInbounds) {
        if (this.connTrafficCache.size > 0) this.connTrafficCache.clear();
        if (this.activeSessionLeases.size > 0) this.activeSessionLeases.clear();
        if (this.activeIpsByTag.size > 0) this.activeIpsByTag.clear();
        if (this.activeDevicesByTag.size > 0) this.activeDevicesByTag.clear();
        if (this.activeClientIpsByTag.size > 0) this.activeClientIpsByTag.clear();
        if (this.activeClientDevicesByTag.size > 0) this.activeClientDevicesByTag.clear();
        return;
      }

      const port = this.store.state.settings.clashApiPort || 10086;
      const secret = this.store.state.settings.clashApiSecret || '';

      const fetchClashConnections = () => new Promise((resolve) => {
        const req = http.request({
          hostname: '127.0.0.1',
          port,
          path: '/connections',
          method: 'GET',
          headers: secret ? { Authorization: `Bearer ${secret}` } : {},
          timeout: 1500
        }, (res) => {
          const chunks = [];
          let totalBytes = 0;
          res.on('data', (c) => {
            totalBytes += c.length;
            if (totalBytes <= 4 * 1024 * 1024) chunks.push(c);
          });
          res.on('end', () => {
            try {
              resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
            } catch {
              resolve(null);
            }
          });
        });
        req.on('error', () => resolve(null));
        req.on('timeout', () => { req.destroy(); resolve(null); });
        req.end();
      });

      const data = await fetchClashConnections();
      if (data) this._lastClashAliveAt = Date.now();
      const conns = (data && Array.isArray(data.connections)) ? data.connections : [];

      const nowMs = nowDate.getTime();
      const currentConnIds = new Set();
      let trafficChanged = false;
      let stateMutatedImmediately = false;
      let needReload = false;

      // Index inbounds by tag and port
      const inboundByTag = new Map();
      const inboundByPort = new Map();
      for (const inb of this.store.state.inbounds || []) {
        inboundByTag.set(inb.tag, inb);
        inboundByTag.set(`in-${inb.protocol}-${inb.port}`, inb);
        if (inb.enable !== false && inb.port) {
          inboundByPort.set(Number(inb.port), inb);
        }
      }
      const outboundByTag = new Map();
      for (const outObj of this.store.state.outbounds || []) {
        outboundByTag.set(outObj.tag, outObj);
      }

      // Prune expired leases (> 60s old) and trim to current limitIp/limitDevice (preserving first N devices)
      for (const [tag, leaseMap] of this.activeSessionLeases.entries()) {
        const inb = inboundByTag.get(tag);
        if (!inb || inb.enable === false) {
          this.activeSessionLeases.delete(tag);
          continue;
        }
        const isSingleClient = (inb.clients?.length || 0) <= 1;
        const limitIp = isSingleClient ? Number(inb.limitIp ?? inb.clients?.[0]?.limitIp ?? 0) : 0;
        const limitDevice = isSingleClient ? Number(inb.limitDevice ?? inb.clients?.[0]?.limitDevice ?? 0) : 0;
        const keptIps = new Set();
        let keptDevs = 0;
        const userKeptIps = new Map();
        const userKeptDevs = new Map();

        for (const [devKey, entry] of leaseMap.entries()) {
          if (nowMs - entry.lastSeenAt > ACTIVE_LEASE_TTL_MS) {
            leaseMap.delete(devKey);
            continue;
          }
          if (limitIp > 0 && !keptIps.has(entry.ip) && keptIps.size >= limitIp) {
            leaseMap.delete(devKey);
            continue;
          }
          if (limitDevice > 0 && keptDevs >= limitDevice) {
            leaseMap.delete(devKey);
            continue;
          }
          if (!isSingleClient && entry.user && entry.user !== 'default') {
            const cl = (inb.clients || []).find((c) => c.email === entry.user || c.name === entry.user || c.username === entry.user);
            if (cl) {
              if (cl.enable === false) {
                leaseMap.delete(devKey);
                continue;
              }
              const cLimIp = Number(cl.limitIp ?? inb.limitIp ?? 0);
              const cLimDev = Number(cl.limitDevice ?? inb.limitDevice ?? 0);
              if (!userKeptIps.has(entry.user)) userKeptIps.set(entry.user, new Set());
              const uIps = userKeptIps.get(entry.user);
              const uDevs = userKeptDevs.get(entry.user) || 0;
              if (cLimIp > 0 && !uIps.has(entry.ip) && uIps.size >= cLimIp) {
                leaseMap.delete(devKey);
                continue;
              }
              if (cLimDev > 0 && uDevs >= cLimDev) {
                leaseMap.delete(devKey);
                continue;
              }
              uIps.add(entry.ip);
              userKeptDevs.set(entry.user, uDevs + 1);
            }
          }
          keptIps.add(entry.ip);
          keptDevs += 1;
        }
      }

      // Prune any expired temporary excess-IP blocks
      this.pruneExpiredTempIpBlocks(nowMs, inboundByTag);

      // Helper to register an allowed client or block ONLY the excess (N+1)th client
      const registerOrEnforceClient = (inb, srcIp, authUser = 'default', srcPort = 0, connId = '') => {
        if (!inb || !srcIp) return true;
        if (!this.activeSessionLeases.has(inb.tag)) {
          this.activeSessionLeases.set(inb.tag, new Map());
        }
        const leaseMap = this.activeSessionLeases.get(inb.tag);

        // If called from kernel ss fallback (authUser === 'default') and this IP already has an active lease
        // on this inbound (e.g. with a known user name from Clash API), refresh it without adding a duplicate #default entry.
        if (authUser === 'default' && !connId) {
          for (const existingEntry of leaseMap.values()) {
            if (existingEntry.ip === srcIp) {
              existingEntry.lastSeenAt = nowMs;
              return true;
            }
          }
        } else if (authUser !== 'default') {
          // Upgrade any placeholder #default entry for this IP to the authenticated user
          const defaultKey = `${srcIp}#default`;
          if (leaseMap.has(defaultKey)) {
            leaseMap.delete(defaultKey);
          }
        }

        

        const allowedIps = new Set();
        for (const entry of leaseMap.values()) {
          allowedIps.add(entry.ip);
        }

        const isSingleClient = (inb.clients?.length || 0) <= 1;
        const limitIp = isSingleClient ? Number(inb.limitIp ?? inb.clients?.[0]?.limitIp ?? 0) : 0;
        const limitDevice = isSingleClient ? Number(inb.limitDevice ?? inb.clients?.[0]?.limitDevice ?? 0) : 0;

        const matchedClient = !isSingleClient && authUser !== 'default'
          ? (inb.clients || []).find((cl) => cl.email === authUser || cl.name === authUser || cl.username === authUser)
          : null;
        const canonicalUser = matchedClient ? (matchedClient.email || matchedClient.name || matchedClient.username || authUser) : authUser;
        const deviceFp = `${srcIp}#${canonicalUser}`;

        if (matchedClient && matchedClient.enable === false) {
          this.terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, allowedIps.has(srcIp), nowMs);
          return false;
        }

        // If this device is ALREADY one of the admitted online devices (e.g. Device #1 or #2),
        // refresh its lease timestamp and allow its traffic with zero interruption!
        if (leaseMap.has(deviceFp)) {
          leaseMap.get(deviceFp).lastSeenAt = nowMs;
          return true;
        }

        const isIpAlreadyAllowed = allowedIps.has(srcIp);

        // Per-client limits on multi-client inbounds (each client gets its own independent IP/device slots)
        if (matchedClient) {
          const cLimIp = Number(matchedClient.limitIp ?? inb.limitIp ?? 0);
          const cLimDev = Number(matchedClient.limitDevice ?? inb.limitDevice ?? 0);
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
              this.terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, isIpAlreadyAllowed, nowMs);
              this.appendLog(`[用户IP限制生效] 入站 ${inb.remark} 用户 ${canonicalUser} 前 ${clientIps.size}/${cLimIp} 个 IP 保持正常在线，已拦截新接入的第 ${clientIps.size + 1} 个 IP: ${srcIp}`);
              return false;
            }
            if (cLimDev > 0 && clientDevCount >= cLimDev) {
              this.terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, isIpAlreadyAllowed, nowMs);
              this.appendLog(`[用户设备限制生效] 入站 ${inb.remark} 用户 ${canonicalUser} 前 ${clientDevCount}/${cLimDev} 台设备保持正常在线，已拦截新接入的第 ${clientDevCount + 1} 台设备: ${srcIp}`);
              return false;
            }
          }
        } else {
          // Single-client inbound or unauthenticated protocol: enforce node-level limitIp and limitDevice
          if (limitIp > 0 && !isIpAlreadyAllowed && allowedIps.size >= limitIp) {
            this.terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, false, nowMs);
            this.appendLog(`[IP限制生效] 入站 ${inb.remark} (:${inb.port}) 前 ${allowedIps.size}/${limitIp} 个 IP 保持正常在线，已拦截并断开新接入的第 ${allowedIps.size + 1} 个 IP: ${srcIp}`);
            return false;
          }
          if (limitDevice > 0 && leaseMap.size >= limitDevice) {
            this.terminateExcessClient(connId, srcIp, srcPort, inb.port, inb.tag, isIpAlreadyAllowed, nowMs);
            this.appendLog(`[设备限制生效] 入站 ${inb.remark} (:${inb.port}) 前 ${leaseMap.size}/${limitDevice} 台设备保持正常在线，已拦截并断开新接入的第 ${leaseMap.size + 1} 台设备: ${srcIp}`);
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
      };

      // 1. Process Sing-box Clash API connections
      for (const c of conns) {
        if (!c || !c.id) continue;
        currentConnIds.add(c.id);
        const srcIp = normalizeClientIp(c.metadata?.sourceIP);
        const srcPort = Number(c.metadata?.sourcePort || 0);
        const authUser = c.metadata?.user || c.metadata?.authUser || 'default';
        const chains = Array.isArray(c.chains) ? c.chains : [];
        const up = Number(c.upload || 0);
        const down = Number(c.download || 0);

        const prev = this.connTrafficCache.get(c.id);
        let deltaUp = 0;
        let deltaDown = 0;
        if (prev) {
          deltaUp = Math.max(0, up - prev.up);
          deltaDown = Math.max(0, down - prev.down);
        } else {
          // If this connection was opened more than 15s ago (e.g. before panel restart), baseline it at {up, down}
          // so pre-existing long-lived connections never get their historical bytes double-counted!
          const connStartMs = c.start ? Date.parse(c.start) : 0;
          const isPreExisting = connStartMs > 0 && (nowMs - connStartMs) > 15000;
          if (!isPreExisting) {
            deltaUp = up;
            deltaDown = down;
          }
        }
        this.connTrafficCache.set(c.id, { up, down });

        if (deltaUp > 0 || deltaDown > 0) {
          for (const outTag of chains) {
            const outObj = outboundByTag.get(outTag);
            if (outObj) {
              outObj.up = Number(outObj.up || 0) + deltaUp;
              outObj.down = Number(outObj.down || 0) + deltaDown;
              trafficChanged = true;
            }
          }
        }

        const inb = resolveInboundFromClashConn(c, inboundByTag, inboundByPort);
        if (inb) {
          const allowed = srcIp ? registerOrEnforceClient(inb, srcIp, authUser, srcPort, c.id) : true;
          if (allowed) {
            if (nowMs - Number(inb.lastOnline || 0) >= 1000) {
              inb.lastOnline = nowMs;
              trafficChanged = true;
            }
            if (Array.isArray(inb.clients) && inb.clients.length > 0) {
              const matchedClient = inb.clients.find((cl) => cl.email === authUser || cl.name === authUser || cl.username === authUser) || inb.clients[0];
              if (matchedClient) {
                if (nowMs - Number(matchedClient.lastOnline || 0) >= 1000) {
                  matchedClient.lastOnline = nowMs;
                  trafficChanged = true;
                }
                if (deltaUp > 0 || deltaDown > 0) {
                  matchedClient.up = Number(matchedClient.up || 0) + deltaUp;
                  matchedClient.down = Number(matchedClient.down || 0) + deltaDown;
                }
              }
            }
            if (deltaUp > 0 || deltaDown > 0) {
              inb.up = Number(inb.up || 0) + deltaUp;
              inb.down = Number(inb.down || 0) + deltaDown;
              trafficChanged = true;
            }
          }
        }
      }

      // 2. Fallback to Linux kernel TCP socket scan ONLY if Clash API was unreachable (data === null)
      if (!data && inboundByPort.size > 0) {
        const kernelPortPeers = this.scanKernelSocketsByPort(inboundByPort);
        for (const [localPort, peerIpSet] of kernelPortPeers.entries()) {
          const inb = inboundByPort.get(localPort);
          if (!inb) continue;
          for (const peerIp of peerIpSet) {
            if (registerOrEnforceClient(inb, peerIp, 'default', 0, '')) {
              inb.lastOnline = nowMs;
              if (inb.clients?.[0]) inb.clients[0].lastOnline = nowMs;
              trafficChanged = true;
            }
          }
        }
      }

      // 3. Rebuild activeIpsByTag, activeDevicesByTag, and per-client maps from active leases
      const nextIpsByTag = new Map();
      const nextDevicesByTag = new Map();
      const nextClientIpsByTag = new Map();
      const nextClientDevsByTag = new Map();
      for (const [tag, leaseMap] of this.activeSessionLeases.entries()) {
        const inb = inboundByTag.get(tag);
        if (!inb) continue;
        const isSingleClient = (inb.clients?.length || 0) <= 1;
        const limitIp = Number(inb.limitIp ?? (isSingleClient ? inb.clients?.[0]?.limitIp : 0) ?? 0);
        const limitDevice = Number(inb.limitDevice ?? (isSingleClient ? inb.clients?.[0]?.limitDevice : 0) ?? 0);

        const ipSet = new Set();
        const devSet = new Set();
        const clientIpsMap = new Map();
        const clientDevsMap = new Map();
        for (const [devKey, entry] of leaseMap.entries()) {
          if (limitIp > 0 && !ipSet.has(entry.ip) && ipSet.size >= limitIp) {
            leaseMap.delete(devKey);
            this.terminateExcessClient('', entry.ip, 0, inb.port, inb.tag, false, nowMs);
            continue;
          }
          if (limitDevice > 0 && devSet.size >= limitDevice) {
            leaseMap.delete(devKey);
            this.terminateExcessClient('', entry.ip, 0, inb.port, inb.tag, ipSet.has(entry.ip), nowMs);
            continue;
          }
          ipSet.add(entry.ip);
          devSet.add(devKey);
          const uKey = entry.user || 'default';
          if (!clientIpsMap.has(uKey)) clientIpsMap.set(uKey, new Set());
          if (!clientDevsMap.has(uKey)) clientDevsMap.set(uKey, new Set());
          clientIpsMap.get(uKey).add(entry.ip);
          clientDevsMap.get(uKey).add(devKey);
        }
        nextIpsByTag.set(tag, ipSet);
        nextDevicesByTag.set(tag, devSet);
        nextClientIpsByTag.set(tag, clientIpsMap);
        nextClientDevsByTag.set(tag, clientDevsMap);
      }

      // Prune closed connections from cache & strictly bound cache size <= 4000
      for (const id of this.connTrafficCache.keys()) {
        if (!currentConnIds.has(id)) this.connTrafficCache.delete(id);
      }
      if (this.connTrafficCache.size > 20000) {
        const excess = this.connTrafficCache.size - 20000;
        let removed = 0;
        for (const k of this.connTrafficCache.keys()) {
          this.connTrafficCache.delete(k);
          removed += 1;
          if (removed >= excess) break;
        }
      }

      this.activeIpsByTag = nextIpsByTag;
      this.activeDevicesByTag = nextDevicesByTag;
      this.activeClientIpsByTag = nextClientIpsByTag;
      this.activeClientDevicesByTag = nextClientDevsByTag;

      const monthlyReset = this.checkAndResetMonthlyTraffic(nowDate);
      if (monthlyReset.needReload) needReload = true;

      for (const inb of this.store.state.inbounds) {
        if (inb.enable === false) continue;

        // Per-client expiry and traffic quota enforcement on multi-client inbounds
        if (Array.isArray(inb.clients) && inb.clients.length > 1) {
          for (const cl of inb.clients) {
            if (cl.enable === false) continue;
            const cQuotaBytes = Number(
              cl.totalBytes ||
              (cl.totalGB > 0 ? (cl.totalGB > 1024 * 1024 ? cl.totalGB : Math.round(cl.totalGB * (1024 ** 3))) : 0)
            );
            if (cl.expiryTime && cl.expiryTime > 0 && nowMs > cl.expiryTime) {
              cl.enable = false;
              cl.disabledReason = 'expired';
              stateMutatedImmediately = true;
              needReload = true;
              this.appendLog(`[用户到期停用] 入站 ${inb.remark} 的用户 ${cl.email} 已到期自动停用`);
            } else if (cQuotaBytes > 0 && (Number(cl.up || 0) + Number(cl.down || 0)) >= cQuotaBytes) {
              cl.enable = false;
              cl.disabledReason = 'quota';
              stateMutatedImmediately = true;
              needReload = true;
              this.appendLog(`[用户流量达标停用] 入站 ${inb.remark} 的用户 ${cl.email} 已用尽配额自动停用`);
            }
          }
        }

        if (inb.expiryTime && inb.expiryTime > 0 && nowMs > inb.expiryTime) {
          inb.enable = false;
          inb.disabledReason = 'expired';
          stateMutatedImmediately = true;
          needReload = true;
          this.appendLog(`[到期自动停用] 入站 ${inb.remark} 已到期`);
        } else if (inb.total && inb.total > 0 && (Number(inb.up || 0) + Number(inb.down || 0)) >= inb.total) {
          inb.enable = false;
          inb.disabledReason = 'quota';
          stateMutatedImmediately = true;
          needReload = true;
          this.appendLog(`[流量达标停用] 入站 ${inb.remark} 已用尽配额`);
        }
      }

      if (stateMutatedImmediately) {
        this.store.save();
      } else if (trafficChanged) {
        this.store.saveTrafficThrottled();
      }
      if (needReload) {
        try { this.restart(); } catch { /* ignore */ }
      }
    } finally {
      this._polling = false;
    }
  }

  closeConnection(connId) {
    const port = this.store.state.settings.clashApiPort || 10086;
    const secret = this.store.state.settings.clashApiSecret || '';
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: `/connections/${encodeURIComponent(connId)}`,
      method: 'DELETE',
      headers: secret ? { Authorization: `Bearer ${secret}` } : {},
      timeout: 2000
    });
    req.on('error', () => {});
    req.end();
  }

  getActiveIpsForInbound(tag) {
    return [...(this.activeIpsByTag.get(tag) || [])];
  }

  getActiveDeviceCountForInbound(tag) {
    const devSet = this.activeDevicesByTag.get(tag);
    const ipSet = this.activeIpsByTag.get(tag);
    return Math.max(devSet ? devSet.size : 0, ipSet ? ipSet.size : 0);
  }

  getActiveIpsForClient(tag, email, isSingleClient = false) {
    if (isSingleClient) return this.getActiveIpsForInbound(tag);
    const cMap = this.activeClientIpsByTag.get(tag);
    if (!cMap) return [];
    return [...(cMap.get(email) || [])];
  }

  getActiveDeviceCountForClient(tag, email, isSingleClient = false) {
    if (isSingleClient) return this.getActiveDeviceCountForInbound(tag);
    const dMap = this.activeClientDevsByTag ? this.activeClientDevsByTag.get(tag) : this.activeClientDevicesByTag.get(tag);
    const cMap = this.activeClientIpsByTag.get(tag);
    const dSet = dMap ? dMap.get(email) : null;
    const iSet = cMap ? cMap.get(email) : null;
    return Math.max(dSet ? dSet.size : 0, iSet ? iSet.size : 0);
  }

  clearClientLeases(tag, email) {
    const leaseMap = this.activeSessionLeases.get(tag);
    if (leaseMap) {
      for (const [k, entry] of leaseMap.entries()) {
        if (entry.user === email) leaseMap.delete(k);
      }
    }
    this.activeClientIpsByTag.get(tag)?.delete(email);
    this.activeClientDevicesByTag.get(tag)?.delete(email);
    for (const [key, item] of this.tempBlockedExcessIps.entries()) {
      if (item.inboundTag === tag) {
        this.removeTempIpPortBlock(key);
      }
    }
  }

  clearInboundLeases(tag) {
    this.activeSessionLeases.delete(tag);
    this.activeIpsByTag.delete(tag);
    this.activeDevicesByTag.delete(tag);
    this.activeClientIpsByTag.delete(tag);
    this.activeClientDevicesByTag.delete(tag);
    for (const [key, item] of this.tempBlockedExcessIps.entries()) {
      if (item.inboundTag === tag) {
        this.removeTempIpPortBlock(key);
      }
    }
  }

  async installVersion(versionTag = 'v1.12.23') {
    const cleanVer = String(versionTag || 'v1.12.23').trim().replace(/^v/, '');
    if (!/^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$/.test(cleanVer)) {
      throw new Error('版本号格式无效，例如 v1.12.23');
    }
    const archMap = { x64: 'amd64', arm64: 'arm64', arm: 'armv7' };
    const sbArch = archMap[os.arch()] || 'amd64';
    const tarball = `sing-box-${cleanVer}-linux-${sbArch}.tar.gz`;
    const url = `https://github.com/SagerNet/sing-box/releases/download/v${cleanVer}/${tarball}`;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-sb-'));
    try {
      this.appendLog(`开始下载 Sing-box v${cleanVer} (${sbArch}): ${url}`);
      const dl = spawnSync('curl', ['-fL', '--retry', '3', '--connect-timeout', '15', url, '-o', path.join(tmpDir, tarball)], {
        encoding: 'utf8',
        timeout: 120000
      });
      if (dl.status !== 0) {
        throw new Error(`下载 Sing-box v${cleanVer} 失败 (请检查服务器网络或 GitHub 连接): ${dl.stderr || dl.stdout}`);
      }
      const ex = spawnSync('tar', ['-xzf', path.join(tmpDir, tarball), '-C', tmpDir, '--strip-components=1'], {
        encoding: 'utf8',
        timeout: 30000
      });
      const extractedBin = path.join(tmpDir, 'sing-box');
      if (ex.status !== 0 || !fs.existsSync(extractedBin)) {
        throw new Error('解压 Sing-box 安装包失败');
      }

      const targetBin = this.getBinPath();
      fs.mkdirSync(path.dirname(targetBin), { recursive: true });
      fs.copyFileSync(extractedBin, `${targetBin}.next`);
      fs.chmodSync(`${targetBin}.next`, 0o755);
      fs.renameSync(`${targetBin}.next`, targetBin);

      this.appendLog(`成功切换 Sing-box 内核版本至 v${cleanVer}`);
      try {
        this.restart();
      } catch { /* ignore */ }
      return this.getVersion();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
}

module.exports = {
  KNOWN_VERSIONS,
  BUILTIN_GEOSITE_EXPANSIONS,
  computeResetCycleKey,
  resolveInboundFromClashConn,
  buildSingboxConfig,
  compileRouteRule,
  SingboxManager
};
