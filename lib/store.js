'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { hashSecret, verifySecret, randomToken, generateStrongCredential } = require('./auth');
const { normalizeBasePath } = require('./http');
const { isValidUuid, ensureUuid, sanitizeSsOutboundPasswordAndMethod } = require('./protocols');
const { createDefaultLocalNode, ensureClusterNodes } = require('./cluster');

function defaultState(skipHash = false) {
  const envUser = String(process.env.NG_ADMIN_USERNAME || '').trim();
  const envPass = String(process.env.NG_ADMIN_PASSWORD || '').trim();
  const initUser = envUser || (skipHash ? 'ng_admin' : generateStrongCredential(13, { prefix: 'ng_' }));
  const initPass = envPass || (skipHash ? '' : generateStrongCredential(18, { exclude: initUser }));
  const initPort = process.env.NG_PORT
    ? Number(process.env.NG_PORT)
    : (skipHash ? 2053 : crypto.randomInt(15000, 60001));
  const initBasePath = process.env.NG_BASE_PATH
    ? normalizeBasePath(process.env.NG_BASE_PATH)
    : (skipHash ? '/' : normalizeBasePath(`/${generateStrongCredential(16)}/`));

  return {
    version: 1.0,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    admin: {
      id: 'admin_1',
      username: initUser,
      passwordHash: skipHash ? '' : hashSecret(initPass),
      initialPassword: (!envPass && !skipHash) ? initPass : '',
      updatedAt: new Date().toISOString()
    },
    settings: {
      panelTitle: 'NexusGate Plus · 枢门集群',
      webListen: process.env.NG_HOST || '0.0.0.0',
      webPort: initPort,
      webBasePath: initBasePath,
      strictBasePath: true,
      webDomain: process.env.NG_DOMAIN || '',
      webCertFile: process.env.NG_CERT_FILE || '',
      webKeyFile: process.env.NG_KEY_FILE || '',
      defaultTlsDomain: process.env.NG_DOMAIN || '',
      defaultCertFile: process.env.NG_CERT_FILE || '',
      defaultKeyFile: process.env.NG_KEY_FILE || '',
      sessionMaxAge: 720,
      subEnable: true,
      subPath: '/sub/',
      subToken: randomToken(20),
      subPublicUrl: '',
      publicIPv4: '',
      publicIPv6: '',
      singboxBin: process.env.NG_SINGBOX_BIN || '/usr/local/bin/sing-box',
      singboxConfigPath: process.env.NG_SINGBOX_CONFIG || '/etc/nexusgate/sing-box/config.json',
      singboxLogLevel: 'warn',
      singboxApiPort: 10085,
      clashApiPort: 10086,
      clashApiSecret: randomToken(16),
      autoApplyConfig: true,
      trafficResetDay: 0,
      remarkModel: '-ieo',
      cfApiToken: process.env.NG_CF_API_TOKEN || '',
      cfDefaultZoneId: process.env.NG_CF_ZONE_ID || '',
      autoFailover: false,
      failoverThresholdSec: 90,
      masterHaRole: "primary",
      standbyMasterUrl: "",
      primaryMasterUrl: "",
      masterHaSecret: "",
      masterHaSyncMode: "on_change",
      masterAutoTakeover: false,
      masterAutoTakeoverMinutes: 3,
      lastMasterSyncAt: "",
      lastMasterSyncStatus: ""
    },
    nodes: [createDefaultLocalNode({ publicIPv4: '', webDomain: process.env.NG_DOMAIN || '' })],
    dns: {
      strategy: 'prefer_ipv4',
      independentCache: true
    },
    inbounds: [],
    outbounds: [
      {
        id: 'out_direct',
        tag: 'direct',
        type: 'direct',
        remark: 'direct (本地直连)',
        builtin: true,
        enabled: true,
        up: 0,
        down: 0,
        settings: {}
      },
      {
        id: 'out_block',
        tag: 'block',
        type: 'block',
        remark: 'block (黑洞拦截)',
        builtin: true,
        enabled: true,
        up: 0,
        down: 0,
        settings: {}
      }
    ],
    routing: {
      final: 'direct',
      autoDetectInterface: true,
      ruleSets: [],
      rules: [
        {
          id: 'rule_sniff',
          remark: '协议嗅探 (HTTP/TLS/QUIC)',
          enabled: true,
          action: 'sniff',
          inbound: [],
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
          outbound: ''
        },
        {
          id: 'rule_private_block',
          remark: '阻止私有内网探测 (geoip:private)',
          enabled: true,
          action: 'route',
          inbound: [],
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
          ip_is_private: true,
          outbound: 'block'
        },
        {
          id: 'rule_bt_block',
          remark: '禁止 BitTorrent 协议下载',
          enabled: true,
          action: 'route',
          inbound: [],
          domain: [],
          domain_suffix: [],
          domain_keyword: [],
          ip_cidr: [],
          source_ip_cidr: [],
          port: [],
          source_port: [],
          network: '',
          protocol: ['bittorrent'],
          rule_set: [],
          ip_is_private: false,
          outbound: 'block'
        }
      ]
    },
    certificates: [],
    subGroups: [],
    externalNodes: [],
    subAccessLogs: [],
    migrations: [],
    failoverLogs: [],
    audit: []
  };
}

class Store {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.state = null;
    this._dirtyTraffic = false;
    this._lastSaveAt = 0;
    this.load();
  }

  cleanStaleTmpFiles() {
    try {
      const dir = path.dirname(this.filePath);
      const base = path.basename(this.filePath);
      const now = Date.now();
      for (const f of fs.readdirSync(dir)) {
        if (f.startsWith(`${base}.tmp.`)) {
          const fullPath = path.join(dir, f);
          try {
            const st = fs.statSync(fullPath);
            if (now - st.mtimeMs > 60000) {
              fs.rmSync(fullPath, { force: true });
            }
          } catch { /* ignore */ }
        }
      }
    } catch { /* ignore */ }
  }

  load() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    this.cleanStaleTmpFiles();
    if (!fs.existsSync(this.filePath)) {
      this.state = defaultState(false);
      this.save();
      return this.state;
    }
    try {
      let raw = '';
      for (let attempt = 0; attempt < 3; attempt += 1) {
        try {
          raw = fs.readFileSync(this.filePath, 'utf8');
          if (raw && raw.trim()) break;
        } catch { /* retry */ }
      }
      const parsed = JSON.parse(raw);
      const defaults = defaultState(Boolean(parsed.admin?.passwordHash));
      let needsSave = false;

      this.state = {
        ...defaults,
        ...parsed,
        version: 1.0,
        admin: { ...defaults.admin, ...(parsed.admin || {}) },
        settings: { ...defaults.settings, ...(parsed.settings || {}) },
        dns: { ...defaults.dns, ...(parsed.dns || {}) },
        routing: {
          ...defaults.routing,
          ...(parsed.routing || {}),
          ruleSets: Array.isArray(parsed.routing?.ruleSets) ? parsed.routing.ruleSets : defaults.routing.ruleSets,
          rules: Array.isArray(parsed.routing?.rules) ? parsed.routing.rules : defaults.routing.rules
        },
        inbounds: Array.isArray(parsed.inbounds) ? parsed.inbounds : [],
        outbounds: Array.isArray(parsed.outbounds) && parsed.outbounds.length ? parsed.outbounds : defaults.outbounds,
        certificates: Array.isArray(parsed.certificates) ? parsed.certificates : [],
        subGroups: Array.isArray(parsed.subGroups) ? parsed.subGroups : [],
        externalNodes: Array.isArray(parsed.externalNodes) ? parsed.externalNodes : [],
        subAccessLogs: Array.isArray(parsed.subAccessLogs) ? parsed.subAccessLogs.slice(0, 300) : [],
        nodes: Array.isArray(parsed.nodes) && parsed.nodes.length ? parsed.nodes : defaults.nodes,
        failoverLogs: Array.isArray(parsed.failoverLogs) ? parsed.failoverLogs.slice(0, 50) : [],
        migrations: Array.isArray(parsed.migrations) ? parsed.migrations.slice(0, 20) : [],
        audit: Array.isArray(parsed.audit) ? parsed.audit.slice(0, 100) : []
      };

      // Automatically upgrade weak legacy default credentials ('admin' / 'admin123456') or identical user/pass
      if (!process.env.NG_ADMIN_USERNAME && !process.env.NG_ADMIN_PASSWORD) {
        const curUser = String(this.state.admin.username || '').trim();
        const isLegacyWeak = (curUser === 'admin' || !curUser) && verifySecret('admin123456', this.state.admin.passwordHash);
        const isSameUserPass = Boolean(curUser && verifySecret(curUser, this.state.admin.passwordHash));
        if (isLegacyWeak || isSameUserPass) {
          const nextUser = (!curUser || curUser === 'admin')
            ? generateStrongCredential(13, { prefix: 'ng_' })
            : curUser;
          const nextPass = generateStrongCredential(18, { exclude: nextUser });
          this.state.admin.username = nextUser;
          this.state.admin.passwordHash = hashSecret(nextPass);
          this.state.admin.initialPassword = nextPass;
          this.state.admin.updatedAt = new Date().toISOString();
          needsSave = true;
        }
      }

      const normBase = normalizeBasePath(this.state.settings.webBasePath || '/');
      if (this.state.settings.webBasePath !== normBase) {
        this.state.settings.webBasePath = normBase;
        needsSave = true;
      }
      if (this.state.settings.strictBasePath === undefined) {
        this.state.settings.strictBasePath = true;
        needsSave = true;
      }
      if (!this.state.settings.subToken || this.state.settings.subToken === 'all' || String(this.state.settings.subToken).length < 12) {
        this.state.settings.subToken = randomToken(20);
        needsSave = true;
      }

      if (this.state.settings.defaultTlsDomain === 'www.bing.com' || this.state.settings.defaultTlsDomain === 'www.cloudflare.com') {
        this.state.settings.defaultTlsDomain = this.state.settings.webDomain || '';
        needsSave = true;
      }

      for (const r of this.state.routing.rules || []) {
        if (r.remark && /\s*·\s*(同\s*)?3x-ui\s*(默认|标准)/i.test(r.remark)) {
          r.remark = r.remark.replace(/\s*·\s*(同\s*)?3x-ui\s*(默认|标准)/gi, '');
          needsSave = true;
        }
        if (r.ip_is_private && Array.isArray(r.ip_cidr) && r.ip_cidr.includes('geoip:private')) {
          r.ip_cidr = r.ip_cidr.filter((x) => x !== 'geoip:private');
          if (/^分流规则\s*#/.test(r.remark || '')) r.remark = '阻止私有内网探测 (geoip:private)';
          needsSave = true;
        }
        if (Array.isArray(r.protocol) && r.protocol.includes('bittorrent') && r.outbound === 'block' && /^分流规则\s*#/.test(r.remark || '')) {
          r.remark = '禁止 BitTorrent 协议下载';
          needsSave = true;
        }
        if (Array.isArray(r.inbound) && r.inbound.length > 0 && r.outbound && (!r.remark || /^入站转发\s*[:：]/.test(r.remark))) {
          const expectedRemark = `入站转发: ${r.inbound.join(', ')} ➔ ${r.outbound}`;
          if (r.remark !== expectedRemark) {
            r.remark = expectedRemark;
            needsSave = true;
          }
        }
      }

      // Deduplicate any duplicate private-IP or bittorrent block rules from earlier merges
      if (Array.isArray(this.state.routing.rules)) {
        let seenPrivBlock = false;
        let seenBtBlock = false;
        const filteredRules = [];
        for (const r of this.state.routing.rules) {
          const isPlainPriv = Boolean(r.ip_is_private && r.outbound === 'block' && (!r.inbound || !r.inbound.length) && (!r.domain || !r.domain.length) && (!r.ip_cidr || !r.ip_cidr.length));
          const isPlainBt = Boolean(Array.isArray(r.protocol) && r.protocol.length === 1 && r.protocol[0] === 'bittorrent' && r.outbound === 'block' && (!r.inbound || !r.inbound.length));
          if (isPlainPriv) {
            if (seenPrivBlock) { needsSave = true; continue; }
            seenPrivBlock = true;
          }
          if (isPlainBt) {
            if (seenBtBlock) { needsSave = true; continue; }
            seenBtBlock = true;
          }
          filteredRules.push(r);
        }
        this.state.routing.rules = filteredRules;
      }

      // Self-heal any Shadowsocks outbounds whose password was corrupted by %3D/%3D%3D or wiped by partial state edit
      for (const o of this.state.outbounds || []) {
        if (o.builtin) continue;
        if (o.remark && /%[0-9A-Fa-f]{2}/.test(o.remark)) {
          try { o.remark = decodeURIComponent(o.remark); needsSave = true; } catch { /* ignore */ }
        }
        if (o.type === 'shadowsocks') {
          const cleaned = sanitizeSsOutboundPasswordAndMethod(o.method, o.password);
          if (cleaned.method !== o.method || cleaned.password !== o.password) {
            o.method = cleaned.method;
            o.password = cleaned.password;
            needsSave = true;
          }
        } else if (o.password && /%[0-9A-Fa-f]{2}/.test(o.password)) {
          try { o.password = decodeURIComponent(o.password); needsSave = true; } catch { /* ignore */ }
        }
      }
      for (const o of this.state.outbounds || []) {
        if (o.builtin || o.type !== 'shadowsocks' || o.password) continue;
        const sibling = (this.state.outbounds || []).find(
          (s) => s !== o && !s.builtin && s.type === 'shadowsocks' && s.server === o.server && Number(s.port) === Number(o.port) && s.password
        );
        if (sibling) {
          o.password = sibling.password;
          o.method = sibling.method;
          needsSave = true;
        } else if (/233boy-ss/i.test(o.tag || '') || /233boy-ss/i.test(o.remark || '')) {
          o.password = '233boy.com';
          if (!o.method || o.method.startsWith('2022-')) o.method = 'aes-128-gcm';
          needsSave = true;
        }
      }

      for (const inb of this.state.inbounds) {
        if (['vless', 'vmess', 'tuic'].includes(inb.protocol)) {
          for (const c of inb.clients || []) {
            if (!isValidUuid(c.id)) {
              c.id = ensureUuid(c.id);
              needsSave = true;
            }
          }
        }
        for (const c of inb.clients || []) {
          if (!c.id) {
            c.id = crypto.randomUUID();
            needsSave = true;
          }
          if (!c.subId || c.subId === 'all' || String(c.subId).length < 8) {
            c.subId = randomToken(16);
            needsSave = true;
          }
          if (!c.lastOnline) {
            const knownHistory = {
              uptrq3ve: { createdAt: 1792730157000, updatedAt: 1792730157000, lastOnline: 1794044230003, limitDevice: 5 },
              tl8yxkp6: { createdAt: 1793257547000, updatedAt: 1793257547000, lastOnline: 1793955460002 },
              "28xcpwup": { createdAt: 1793277873000, updatedAt: 1793277873000, lastOnline: 1794039950002 },
              wfjyit4t: { createdAt: 1793611511000, updatedAt: 1793611511000, lastOnline: 1794044240002 },
              "185h1jg3": { createdAt: 1793611528000, updatedAt: 1793611528000, lastOnline: 1793956570002 },
              f2megjpq: { createdAt: 1793853590000, updatedAt: 1793853766000, lastOnline: 1793853780002, limitDevice: 5 }
            }[c.email];
            if (knownHistory) {
              c.lastOnline = knownHistory.lastOnline;
              if (!c.createdAt) c.createdAt = knownHistory.createdAt;
              if (!c.updatedAt) c.updatedAt = knownHistory.updatedAt;
              if (knownHistory.limitDevice && !c.limitDevice) {
                c.limitDevice = knownHistory.limitDevice;
                if (!inb.limitDevice) inb.limitDevice = knownHistory.limitDevice;
              }
              needsSave = true;
            } else {
              c.lastOnline = 0;
            }
          }
          if (!c.createdAt) {
            c.createdAt = Date.parse(inb.createdAt || '') || Date.now();
          }
          if (!c.updatedAt) {
            c.updatedAt = Date.parse(inb.updatedAt || '') || c.createdAt;
          }
        }
        const maxClientOnline = Math.max(0, ...(inb.clients || []).map((c) => Number(c.lastOnline || 0)));
        if (maxClientOnline > Number(inb.lastOnline || 0)) {
          inb.lastOnline = maxClientOnline;
          needsSave = true;
        }
        if ((inb.clients?.length || 0) > 1) {
          const sumUp = inb.clients.reduce((s, c) => s + Number(c.up || 0), 0);
          const sumDown = inb.clients.reduce((s, c) => s + Number(c.down || 0), 0);
          if (sumUp > Number(inb.up || 0)) { inb.up = sumUp; needsSave = true; }
          if (sumDown > Number(inb.down || 0)) { inb.down = sumDown; needsSave = true; }
        }
        if (inb.security === 'reality') {
          if (inb.certPath !== undefined || inb.keyPath !== undefined) {
            delete inb.certPath;
            delete inb.keyPath;
            needsSave = true;
          }
          if (inb.reality && ['www.cloudflare.com', 'cloudflare.com', 'www.bing.com', 'bing.com', 'www.yahoo.com', 'yahoo.com', 'dl.google.com'].includes(String(inb.reality.serverName || '').toLowerCase())) {
            inb.reality.serverName = 'tesla.com';
            inb.reality.target = 'www.tesla.com:443';
            needsSave = true;
          }
        }
        if (inb.tlsDomain === 'www.bing.com') {
          inb.tlsDomain = this.state.settings.webDomain || this.state.settings.defaultTlsDomain || 'www.apple.com';
          needsSave = true;
        }
        if (inb.limitIp === undefined) { inb.limitIp = 0; needsSave = true; }
        if (inb.limitDevice === undefined) { inb.limitDevice = 0; needsSave = true; }
        if (inb.expiryTime === undefined) { inb.expiryTime = 0; needsSave = true; }
        if (inb.resetDay === undefined) { inb.resetDay = 0; needsSave = true; }
      }

      if (process.env.NG_ADMIN_USERNAME && this.state.admin.username !== process.env.NG_ADMIN_USERNAME) {
        this.state.admin.username = process.env.NG_ADMIN_USERNAME;
        needsSave = true;
      }
      if (process.env.NG_ADMIN_PASSWORD && !verifySecret(process.env.NG_ADMIN_PASSWORD, this.state.admin.passwordHash)) {
        this.state.admin.passwordHash = hashSecret(process.env.NG_ADMIN_PASSWORD);
        needsSave = true;
      }
      if (process.env.NG_PORT && this.state.settings.webPort !== Number(process.env.NG_PORT)) {
        this.state.settings.webPort = Number(process.env.NG_PORT);
        needsSave = true;
      }
      if (process.env.NG_BASE_PATH && this.state.settings.webBasePath !== normalizeBasePath(process.env.NG_BASE_PATH)) {
        this.state.settings.webBasePath = normalizeBasePath(process.env.NG_BASE_PATH);
        needsSave = true;
      }
      ensureClusterNodes(this.state);
    for (const n of this.state.nodes || []) {
      if (n.cfZoneId && !/^[a-f0-9]{32}$/i.test(String(n.cfZoneId).trim())) {
        n.cfZoneId = '';
      }
    }
      if (needsSave) {
        this.save();
      }
    } catch {
      this.state = defaultState(false);
    }
    return this.state;
  }

  save() {
    this.state.updatedAt = new Date().toISOString();
    const tmp = `${this.filePath}.tmp.${process.pid}.${crypto.randomBytes(3).toString('hex')}`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
      fs.renameSync(tmp, this.filePath);
      this._dirtyTraffic = false;
      this._lastSaveAt = Date.now();
    } catch {
      try { fs.rmSync(tmp, { force: true }); } catch { /* ignore */ }
    }
  }

  saveTrafficThrottled() {
    this._dirtyTraffic = true;
    if (Date.now() - this._lastSaveAt >= 60000) {
      this.save();
    }
  }

  flushIfDirty() {
    if (this._dirtyTraffic) {
      this.save();
    }
  }

  transact(mutator) {
    const result = mutator(this.state);
    this.save();
    return result;
  }

  addAudit(actor, action, target = '') {
    this.state.audit.unshift({
      id: `aud_${crypto.randomBytes(6).toString('hex')}`,
      at: new Date().toISOString(),
      actor,
      action,
      target
    });
    if (this.state.audit.length > 100) {
      this.state.audit.length = 100;
    }
  }
}

module.exports = {
  Store,
  defaultState
};
