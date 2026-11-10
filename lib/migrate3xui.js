'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { deriveRealityPublicKey, normalizeSsMethod, ensureUuid, inferDomainFromCertPath } = require('./protocols');
const { inspectCertificate, discoverSystemCertificates } = require('./system');

function safeJson(str, fallback = {}) {
  if (!str) return fallback;
  if (typeof str === 'object') return str;
  try {
    return JSON.parse(String(str));
  } catch {
    return fallback;
  }
}

/**
 * Copies directory recursively.
 */
function copyDirRecursiveSync(srcDir, destDir) {
  if (!fs.existsSync(srcDir)) return;
  fs.mkdirSync(destDir, { recursive: true });
  for (const entry of fs.readdirSync(srcDir, { withFileTypes: true })) {
    const srcPath = path.join(srcDir, entry.name);
    const destPath = path.join(destDir, entry.name);
    if (entry.isDirectory()) {
      copyDirRecursiveSync(srcPath, destPath);
    } else if (entry.isFile()) {
      fs.copyFileSync(srcPath, destPath);
      if (entry.name.endsWith('.key') || entry.name.includes('privkey')) {
        try { fs.chmodSync(destPath, 0o600); } catch { /* ignore */ }
      } else if (entry.name === 'acme.sh' || entry.name.endsWith('.sh')) {
        try { fs.chmodSync(destPath, 0o755); } catch { /* ignore */ }
      }
    }
  }
}

/**
 * Ensures acme.sh cronjob and cron daemon are active when /root/.acme.sh/acme.sh exists.
 */
function ensureAcmeRenewalCron(acmeDir = '/root/.acme.sh') {
  const acmeBin = path.join(acmeDir, 'acme.sh');
  if (!fs.existsSync(acmeBin)) return false;
  try {
    fs.chmodSync(acmeBin, 0o755);
    spawnSync(acmeBin, ['--install-cronjob'], {
      encoding: 'utf8',
      timeout: 10000,
      env: { ...process.env, HOME: path.dirname(acmeDir) }
    });
    spawnSync('systemctl', ['enable', '--now', 'cron'], { encoding: 'utf8', timeout: 5000 });
    spawnSync('systemctl', ['enable', '--now', 'crond'], { encoding: 'utf8', timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Extracts and restores certificates (`root/cert/*`), `.acme.sh` (`root/.acme.sh/*`), and `sublink.db`
 * from an extracted 3x-ui / X-Panel `.tar.gz` backup directory.
 */
function extractArchiveAssets(tmpExtract, dryRun = false) {
  const certPathRemap = new Map();
  const restoredCerts = [];
  let hasAcmeSh = false;

  const archiveAcmeDir = path.join(tmpExtract, 'root', '.acme.sh');
  if (fs.existsSync(path.join(archiveAcmeDir, 'acme.sh'))) {
    hasAcmeSh = true;
    if (!dryRun) {
      let targetAcmeDir = '/root/.acme.sh';
      try {
        fs.mkdirSync('/root', { recursive: true });
        fs.accessSync('/root', fs.constants.W_OK);
      } catch {
        targetAcmeDir = path.join(process.env.NG_CERT_DIR || path.join(os.tmpdir(), 'ng-certs'), '.acme.sh');
      }
      try {
        copyDirRecursiveSync(archiveAcmeDir, targetAcmeDir);
        ensureAcmeRenewalCron(targetAcmeDir);
      } catch { /* ignore */ }
    }
  }

  const archiveSublinkDb = path.join(tmpExtract, 'usr', 'local', 'bin', 'sublink', 'db', 'sublink.db');
  if (!dryRun && fs.existsSync(archiveSublinkDb)) {
    try {
      const targetSublinkDir = '/usr/local/bin/sublink/db';
      fs.mkdirSync(targetSublinkDir, { recursive: true });
      fs.copyFileSync(archiveSublinkDb, path.join(targetSublinkDir, 'sublink.db'));
    } catch { /* ignore on non-root */ }
  }

  const archiveCertRoot = path.join(tmpExtract, 'root', 'cert');
  if (fs.existsSync(archiveCertRoot)) {
    let targetCertRoot = '/root/cert';
    try {
      fs.mkdirSync(targetCertRoot, { recursive: true });
      fs.accessSync(targetCertRoot, fs.constants.W_OK);
    } catch {
      targetCertRoot = process.env.NG_CERT_DIR || path.join(os.tmpdir(), 'ng-restored-certs');
      fs.mkdirSync(targetCertRoot, { recursive: true });
    }

    for (const entry of fs.readdirSync(archiveCertRoot, { withFileTypes: true })) {
      if (!entry.isDirectory()) continue;
      const domainDir = path.basename(entry.name).replace(/[^a-zA-Z0-9._-]/g, '');
      if (!domainDir) continue;
      const srcSub = path.join(archiveCertRoot, domainDir);
      const destSub = dryRun ? srcSub : path.join(targetCertRoot, domainDir);

      if (!dryRun) {
        copyDirRecursiveSync(srcSub, destSub);
        try {
          copyDirRecursiveSync(srcSub, path.join('/etc/nexusgate/certs', domainDir));
        } catch { /* ignore */ }
      }

      const files = fs.readdirSync(destSub);
      const certFile = files.find((f) => /^(fullchain\.pem|cert\.pem|.*\.cer|.*\.crt)$/i.test(f));
      const keyFile = files.find((f) => /^(privkey\.pem|key\.pem|private\.key|.*\.key)$/i.test(f));
      if (certFile && keyFile) {
        const fullCertPath = path.join(destSub, certFile);
        const fullKeyPath = path.join(destSub, keyFile);
        const origCertPath = `/root/cert/${domainDir}/${certFile}`;
        const origKeyPath = `/root/cert/${domainDir}/${keyFile}`;
        certPathRemap.set(origCertPath, fullCertPath);
        certPathRemap.set(origKeyPath, fullKeyPath);

        const meta = inspectCertificate(fullCertPath, fullKeyPath);
        const inferredDomain = inferDomainFromCertPath(fullCertPath) || domainDir;
        restoredCerts.push({
          id: `cert_${crypto.createHash('md5').update(fullCertPath).digest('hex').slice(0, 10)}`,
          domain: inferredDomain,
          type: meta.isSelfSigned ? 'self-signed' : 'acme- Let\'s Encrypt',
          certPath: fullCertPath,
          keyPath: fullKeyPath,
          createdAt: new Date().toISOString(),
          ...meta
        });
      }
    }
  }

  try { discoverSystemCertificates(true); } catch { /* ignore */ }
  return { restoredCerts, certPathRemap, hasAcmeSh };
}

/**
 * Selects the genuine 3x-ui / X-Panel SQLite database (`x-ui.db`) inside an extracted directory,
 * never mistaking `sublink.db` or other auxiliary databases for `x-ui.db`.
 */
function findXuiDbInDir(tmpExtract) {
  const directCandidates = [
    path.join(tmpExtract, 'etc', 'x-ui', 'x-ui.db'),
    path.join(tmpExtract, 'x-ui', 'x-ui.db'),
    path.join(tmpExtract, 'x-ui.db')
  ];
  for (const c of directCandidates) {
    if (fs.existsSync(c)) return c;
  }

  const findRes = spawnSync('find', [tmpExtract, '-name', '*.db'], { encoding: 'utf8', timeout: 5000 });
  const allDbs = String(findRes.stdout || '')
    .trim()
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean);

  // Prefer any file named x-ui.db first
  const namedXui = allDbs.find((p) => path.basename(p).toLowerCase() === 'x-ui.db');
  if (namedXui) return namedXui;

  // Otherwise check which .db file actually has an `inbounds` table
  for (const candidate of allDbs) {
    const check = spawnSync(
      'python3',
      ['-c', 'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); r=c.execute("SELECT name FROM sqlite_master WHERE type=\'table\' AND name=\'inbounds\'").fetchone(); sys.exit(0 if r else 1)', candidate],
      { encoding: 'utf8', timeout: 3000 }
    );
    if (check.status === 0) return candidate;
  }

  return allDbs[0] || '';
}

/**
 * Reads tables from a 3x-ui SQLite database file (x-ui.db) or a .tar.gz / .tgz backup archive containing x-ui.db.
 */
function readSqliteDb(dbFilePath, dryRun = false) {
  if (!fs.existsSync(dbFilePath)) {
    throw new Error(`未找到文件: ${dbFilePath}`);
  }

  if (dbFilePath.endsWith('.tar.gz') || dbFilePath.endsWith('.tgz')) {
    const tmpExtract = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-xui-tar-'));
    try {
      spawnSync('tar', ['-xzf', dbFilePath, '-C', tmpExtract], { encoding: 'utf8', timeout: 20000 });
      const dbFound = findXuiDbInDir(tmpExtract);
      if (!dbFound || !fs.existsSync(dbFound)) {
        throw new Error('压缩包内未找到 x-ui.db 数据库文件');
      }
      const archiveAssets = extractArchiveAssets(tmpExtract, dryRun);
      const dbData = readSqliteDb(dbFound, dryRun);
      return {
        ...dbData,
        ...archiveAssets
      };
    } finally {
      fs.rmSync(tmpExtract, { recursive: true, force: true });
    }
  }

  const pyScript = `
import sqlite3, json, sys
conn = sqlite3.connect(sys.argv[1])
conn.row_factory = sqlite3.Row
cur = conn.cursor()
def fetch_table(name):
    try:
        rows = cur.execute(f"SELECT * FROM {name}").fetchall()
        res = []
        for r in rows:
            item = {}
            for k in r.keys():
                val = r[k]
                if isinstance(val, bytes):
                    try:
                        val = val.decode('utf-8', errors='ignore')
                    except Exception:
                        val = ''
                item[k] = val
            res.append(item)
        return res
    except Exception:
        return []
out = {
    "inbounds": fetch_table("inbounds"),
    "client_traffics": fetch_table("client_traffics"),
    "settings": fetch_table("settings"),
    "outbound_traffics": fetch_table("outbound_traffics"),
    "users": fetch_table("users")
}
print(json.dumps(out))
`;

  const pyRes = spawnSync('python3', ['-c', pyScript, dbFilePath], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 15000
  });

  if (pyRes.status === 0 && pyRes.stdout.trim()) {
    return JSON.parse(pyRes.stdout.trim());
  }

  const queryTable = (table) => {
    const res = spawnSync('sqlite3', ['-json', dbFilePath, `SELECT * FROM ${table};`], {
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      timeout: 10000
    });
    if (res.status === 0 && res.stdout.trim()) {
      return safeJson(res.stdout.trim(), []);
    }
    return [];
  };

  return {
    inbounds: queryTable('inbounds'),
    client_traffics: queryTable('client_traffics'),
    settings: queryTable('settings'),
    outbound_traffics: queryTable('outbound_traffics'),
    users: queryTable('users')
  };
}

function toBytesQuota(rawVal) {
  const n = Number(rawVal || 0);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return n > 1048576 ? Math.round(n) : Math.round(n * (1024 ** 3));
}

/**
 * Converts a single 3x-ui Inbound record into a NexusGate Sing-box Inbound object.
 */
function convert3xuiInbound(row, clientTraffics = [], certPathRemap = new Map()) {
  const settings = safeJson(row.settings, {});
  const stream = safeJson(row.streamSettings || row.stream_settings, {});
  const rawProto = String(row.protocol || 'vless').toLowerCase();
  const protocol = rawProto === 'dokodemo-door' || rawProto === 'tunnel'
    ? 'direct'
    : (rawProto === 'hysteria' ? 'hysteria2' : rawProto);
  const port = Number(row.port || 443);
  const tag = row.tag || `inbound-${port}`;
  const remark = row.remark || tag;
  const listen = (!row.listen || row.listen === '0.0.0.0') ? '::' : String(row.listen).replace(/^"|"$/g, '');

  const security = String(stream.security || 'none').toLowerCase();
  const network = String(stream.network || 'tcp').toLowerCase();
  const transport = (network === 'raw' || network === 'tcp' || network === 'xhttp') ? 'tcp' : network;

  const trafficReset = String(row.trafficReset || row.traffic_reset || '').toLowerCase();
  const resetDay = trafficReset === 'monthly' ? 1 : 0;

  const inbound = {
    id: `in_${crypto.randomBytes(5).toString('hex')}`,
    tag,
    remark,
    protocol,
    listen,
    port,
    enable: row.enable !== undefined ? Boolean(row.enable) : true,
    up: Number(row.up || 0),
    down: Number(row.down || 0),
    total: Number(row.total || 0),
    expiryTime: Number(row.expiryTime || row.expiry_time || 0) > 0 ? Number(row.expiryTime || row.expiry_time) : 0,
    resetDay,
    limitIp: Math.max(0, Number(row.limit_ip || row.limitIp || 0)),
    limitDevice: Math.max(0, Number(row.device_limit || row.deviceLimit || 0)),
    security,
    transport,
    outboundTag: 'default',
    clients: [],
    migratedFrom3xui: true
  };

  if (Array.isArray(stream.externalProxy) && stream.externalProxy[0]?.dest) {
    inbound.publicHost = String(stream.externalProxy[0].dest).trim();
  }

  if (security === 'reality') {
    const r = stream.realitySettings || {};
    const rSub = r.settings || {};
    const serverNames = Array.isArray(r.serverNames)
      ? r.serverNames
      : String(r.serverNames || 'www.apple.com').split(',').map((s) => s.trim()).filter(Boolean);
    const shortIds = Array.isArray(r.shortIds)
      ? r.shortIds
      : String(r.shortIds || '').split(',').map((s) => s.trim()).filter(Boolean);
    const privateKey = r.privateKey || '';
    const publicKey = rSub.publicKey || deriveRealityPublicKey(privateKey);
    let primarySni = serverNames[0] || 'tesla.com';
    if (['www.cloudflare.com', 'cloudflare.com', 'www.bing.com', 'bing.com', 'www.yahoo.com', 'yahoo.com', 'dl.google.com'].includes(primarySni.toLowerCase())) {
      primarySni = 'tesla.com';
    }
    const rawTarget = r.target || r.dest || `${primarySni === 'tesla.com' ? 'www.tesla.com' : primarySni}:443`;
    const target = /cloudflare\.com|bing\.com|yahoo\.com|dl\.google\.com/i.test(String(rawTarget))
      ? 'www.tesla.com:443'
      : String(rawTarget);

    inbound.reality = {
      target,
      serverName: primarySni,
      serverNames,
      privateKey,
      publicKey,
      shortIds: shortIds.length ? shortIds : [''],
      fingerprint: rSub.fingerprint || 'chrome'
    };
  }

  if (security === 'tls') {
    const t = stream.tlsSettings || {};
    const certs = Array.isArray(t.certificates) && t.certificates[0] ? t.certificates[0] : {};
    const rawCertPath = certs.certificateFile || certs.certFile || '';
    const rawKeyPath = certs.keyFile || '';
    inbound.certPath = certPathRemap.get(rawCertPath) || rawCertPath;
    inbound.keyPath = certPathRemap.get(rawKeyPath) || rawKeyPath;
    inbound.tlsDomain = t.serverName || (t.settings && t.settings.serverName) || inferDomainFromCertPath(inbound.certPath) || inferDomainFromCertPath(rawCertPath) || '';
    inbound.alpn = (transport === 'ws' || transport === 'httpupgrade')
      ? ['http/1.1']
      : (Array.isArray(t.alpn) ? t.alpn : []);
    inbound.allowInsecure = Boolean(t.settings && t.settings.allowInsecure);
  }

  if (transport === 'ws') {
    const ws = stream.wsSettings || {};
    inbound.wsPath = ws.path || '/';
    inbound.wsHost = ws.host || (ws.headers && (ws.headers.Host || ws.headers.host)) || '';
  } else if (transport === 'grpc') {
    const grpc = stream.grpcSettings || {};
    inbound.grpcServiceName = grpc.serviceName || 'grpc';
  } else if (transport === 'httpupgrade') {
    const hu = stream.httpupgradeSettings || {};
    inbound.wsPath = hu.path || '/';
    inbound.wsHost = hu.host || '';
  }

  const rawClients = Array.isArray(settings.clients)
    ? settings.clients
    : (Array.isArray(settings.shadowsockses) ? settings.shadowsockses : []);
  const statsByEmail = new Map();
  for (const st of clientTraffics) {
    if (st.email) statsByEmail.set(st.email, st);
  }

  if (protocol === 'vless' || protocol === 'vmess' || protocol === 'trojan') {
    inbound.clients = rawClients.map((c, idx) => {
      const stat = statsByEmail.get(c.email) || {};
      const totalBytes = toBytesQuota(c.totalGB || stat.total || 0);
      const expTime = Number(c.expiryTime || stat.expiry_time || 0) > 0 ? Number(c.expiryTime || stat.expiry_time) : 0;
      const createdAt = Number(c.created_at || c.createdAt || 0);
      const updatedAt = Number(c.updated_at || c.updatedAt || createdAt || 0);
      const lastOnline = Number(stat.last_online || stat.lastOnline || c.last_online || c.lastOnline || 0);
      const allTime = Number(stat.all_time || stat.allTime || 0);
      return {
        id: ensureUuid(c.id),
        password: protocol === 'trojan' ? (c.password || c.id || '') : (c.password || ''),
        email: c.email || `${tag}_user_${idx + 1}`,
        flow: c.flow || '',
        alterId: Number(c.alterId || 0),
        subId: c.subId || crypto.randomBytes(8).toString('hex'),
        limitIp: Math.max(0, Number(c.limitIp || c.limit_ip || (rawClients.length === 1 ? inbound.limitIp : 0) || 0)),
        limitDevice: Math.max(0, Number(c.limitDevice || c.deviceLimit || c.device_limit || (rawClients.length === 1 ? inbound.limitDevice : 0) || 0)),
        totalBytes,
        totalGB: totalBytes > 0 ? Math.round((totalBytes / (1024 ** 3)) * 100) / 100 : 0,
        up: Number(stat.up || 0),
        down: Number(stat.down || 0),
        allTime,
        createdAt,
        updatedAt,
        lastOnline,
        expiryTime: expTime,
        reset: Number(c.reset || 0),
        enable: c.enable !== undefined ? Boolean(c.enable) : (stat.enable !== undefined ? Boolean(stat.enable) : true)
      };
    });
    if (inbound.clients[0]?.flow) inbound.flow = inbound.clients[0].flow;
    if (inbound.clients.length === 1) {
      if (inbound.clients[0]?.limitIp > 0 && !inbound.limitIp) inbound.limitIp = inbound.clients[0].limitIp;
      if (inbound.clients[0]?.limitDevice > 0 && !inbound.limitDevice) inbound.limitDevice = inbound.clients[0].limitDevice;
    }
    if (inbound.protocol === 'trojan' && inbound.clients[0]?.password) {
      inbound.password = inbound.clients[0].password;
    }
    if (!inbound.total && inbound.clients.length === 1 && inbound.clients[0].totalBytes > 0) {
      inbound.total = inbound.clients[0].totalBytes;
    }
    if (!inbound.expiryTime && inbound.clients.length === 1 && inbound.clients[0].expiryTime > 0) {
      inbound.expiryTime = inbound.clients[0].expiryTime;
    }
    if (!inbound.resetDay && inbound.clients[0]?.reset > 0) {
      inbound.resetDay = 1;
    }
  } else if (protocol === 'shadowsocks') {
    inbound.method = normalizeSsMethod(settings.method || 'aes-128-gcm');
    inbound.password = settings.password || '';
    inbound.network = settings.network || 'tcp,udp';
    inbound.clients = rawClients.map((c, idx) => {
      const stat = statsByEmail.get(c.email) || {};
      const totalBytes = toBytesQuota(c.totalGB || stat.total || 0);
      const expTime = Number(c.expiryTime || stat.expiry_time || 0) > 0 ? Number(c.expiryTime || stat.expiry_time) : 0;
      const createdAt = Number(c.created_at || c.createdAt || 0);
      const updatedAt = Number(c.updated_at || c.updatedAt || createdAt || 0);
      const lastOnline = Number(stat.last_online || stat.lastOnline || c.last_online || c.lastOnline || 0);
      const allTime = Number(stat.all_time || stat.allTime || 0);
      return {
        id: crypto.randomUUID(),
        email: c.email || `${tag}_ss_${idx + 1}`,
        password: c.password || settings.password || '',
        subId: c.subId || crypto.randomBytes(8).toString('hex'),
        limitIp: Number(c.limitIp || 0),
        limitDevice: Math.max(0, Number(c.limitDevice || c.deviceLimit || c.device_limit || (rawClients.length === 1 ? inbound.limitDevice : 0) || 0)),
        totalBytes,
        totalGB: totalBytes > 0 ? Math.round((totalBytes / (1024 ** 3)) * 100) / 100 : 0,
        up: Number(stat.up || 0),
        down: Number(stat.down || 0),
        allTime,
        createdAt,
        updatedAt,
        lastOnline,
        expiryTime: expTime,
        enable: c.enable !== undefined ? Boolean(c.enable) : true
      };
    });
    if (!inbound.method.startsWith('2022-') && inbound.clients.length === 1 && inbound.clients[0].password) {
      inbound.password = inbound.clients[0].password;
    }
    if (!inbound.clients.length && inbound.password) {
      inbound.clients.push({
        id: crypto.randomUUID(),
        email: remark,
        password: inbound.password,
        subId: crypto.randomBytes(8).toString('hex'),
        enable: true
      });
    }
    if (inbound.clients.length === 1 && inbound.clients[0]?.limitIp) inbound.limitIp = inbound.clients[0].limitIp;
    if (!inbound.total && inbound.clients.length === 1 && inbound.clients[0].totalBytes > 0) {
      inbound.total = inbound.clients[0].totalBytes;
    }
    if (!inbound.expiryTime && inbound.clients.length === 1 && inbound.clients[0].expiryTime > 0) {
      inbound.expiryTime = inbound.clients[0].expiryTime;
    }
  } else if (protocol === 'socks' || protocol === 'mixed' || protocol === 'http') {
    const useAuth = settings.auth ? settings.auth === 'password' : true;
    const accounts = useAuth && Array.isArray(settings.accounts) ? settings.accounts : [];
    if (accounts[0]) {
      inbound.socksUser = accounts[0].user || '';
      inbound.socksPassword = accounts[0].pass || '';
    }
    inbound.clients = accounts.map((acc, idx) => ({
      id: crypto.randomUUID(),
      username: acc.user || `user${idx + 1}`,
      email: acc.user || `user${idx + 1}`,
      password: acc.pass || '',
      subId: crypto.randomBytes(8).toString('hex'),
      enable: true
    }));
  } else if (protocol === 'direct') {
    inbound.overrideAddress = settings.address || '';
    inbound.overridePort = Number(settings.port || 0);
    inbound.network = settings.network || 'tcp,udp';
  } else if (protocol === 'hysteria2' || protocol === 'anytls' || protocol === 'tuic') {
    const users = settings.clients || settings.users || [];
    inbound.clients = users.map((u, idx) => {
      const email = u.email || u.name || `${tag}_${protocol}_${idx + 1}`;
      const stat = statsByEmail.get(email) || {};
      const totalBytes = toBytesQuota(u.totalGB || stat.total || 0);
      const expTime = Number(u.expiryTime || stat.expiry_time || 0) > 0 ? Number(u.expiryTime || stat.expiry_time) : 0;
      const createdAt = Number(u.created_at || u.createdAt || 0);
      const updatedAt = Number(u.updated_at || u.updatedAt || createdAt || 0);
      const lastOnline = Number(stat.last_online || stat.lastOnline || u.last_online || u.lastOnline || 0);
      const allTime = Number(stat.all_time || stat.allTime || 0);
      return {
        id: protocol === 'tuic' ? ensureUuid(u.id || u.uuid) : crypto.randomUUID(),
        email,
        password: u.auth || u.password || '',
        subId: u.subId || crypto.randomBytes(8).toString('hex'),
        limitIp: Math.max(0, Number(u.limitIp || u.limit_ip || (users.length === 1 ? inbound.limitIp : 0) || 0)),
        limitDevice: Math.max(0, Number(u.limitDevice || u.deviceLimit || u.device_limit || (users.length === 1 ? inbound.limitDevice : 0) || 0)),
        totalBytes,
        totalGB: totalBytes > 0 ? Math.round((totalBytes / (1024 ** 3)) * 100) / 100 : 0,
        up: Number(stat.up || 0),
        down: Number(stat.down || 0),
        allTime,
        createdAt,
        updatedAt,
        lastOnline,
        expiryTime: expTime,
        enable: u.enable !== undefined ? Boolean(u.enable) : (stat.enable !== undefined ? Boolean(stat.enable) : true)
      };
    });
    if (inbound.clients[0]?.password) inbound.password = inbound.clients[0].password;
  }

  if (Array.isArray(inbound.clients) && inbound.clients.length > 0) {
    const sumUp = inbound.clients.reduce((acc, c) => acc + Number(c.up || 0), 0);
    const sumDown = inbound.clients.reduce((acc, c) => acc + Number(c.down || 0), 0);
    if (sumUp > inbound.up) inbound.up = sumUp;
    if (sumDown > inbound.down) inbound.down = sumDown;
    const maxLastOnline = Math.max(0, ...inbound.clients.map((c) => Number(c.lastOnline || 0)));
    if (maxLastOnline > 0) inbound.lastOnline = maxLastOnline;
    const minCreated = Math.min(...inbound.clients.map((c) => Number(c.createdAt || 0)).filter((v) => v > 0));
    if (Number.isFinite(minCreated) && minCreated > 0) inbound.createdAt = new Date(minCreated).toISOString();
    const maxUpdated = Math.max(0, ...inbound.clients.map((c) => Number(c.updatedAt || 0)));
    if (maxUpdated > 0) inbound.updatedAt = new Date(maxUpdated).toISOString();
  }

  return inbound;
}

function convert3xuiOutbound(raw, index = 0, outboundTrafficsMap = new Map()) {
  const proto = String(raw.protocol || 'freedom').toLowerCase();
  const tag = raw.tag || `outbound-${index + 1}`;
  const stat = outboundTrafficsMap.get(tag) || {};
  const up = Number(stat.up || raw.up || 0);
  const down = Number(stat.down || raw.down || 0);

  if (proto === 'freedom' || proto === 'direct') {
    return {
      id: tag === 'direct' ? 'out_direct' : `out_${crypto.randomBytes(4).toString('hex')}`,
      tag: tag === 'freedom' ? 'direct' : tag,
      type: 'direct',
      remark: raw.remark || 'direct (本地直连)',
      builtin: tag === 'direct' || tag === 'freedom',
      enabled: true,
      up,
      down
    };
  }
  if (proto === 'blackhole' || proto === 'block') {
    return {
      id: tag === 'block' || tag === 'blocked' ? 'out_block' : `out_${crypto.randomBytes(4).toString('hex')}`,
      tag: tag === 'blocked' ? 'block' : tag,
      type: 'block',
      remark: raw.remark || 'block (黑洞拦截)',
      builtin: tag === 'block' || tag === 'blocked',
      enabled: true,
      up,
      down
    };
  }

  const settings = raw.settings || {};
  const stream = raw.streamSettings || {};
  const security = String(stream.security || 'none').toLowerCase();
  const network = String(stream.network || 'tcp').toLowerCase();
  const transport = (network === 'raw' || network === 'tcp' || network === 'xhttp') ? 'tcp' : network;
  const detour = stream.sockopt?.dialerProxy || raw.proxySettings?.tag || raw.detour || '';

  const out = {
    id: `out_${crypto.randomBytes(5).toString('hex')}`,
    tag,
    type: proto === 'hysteria' ? 'hysteria2' : proto,
    remark: raw.remark || tag,
    enabled: true,
    security,
    transport,
    up,
    down,
    ...(detour ? { detour } : {}),
    migratedFrom3xui: true
  };

  if (security === 'reality') {
    const r = stream.realitySettings || {};
    out.sni = r.serverName || '';
    out.fingerprint = r.fingerprint || 'chrome';
    out.publicKey = r.publicKey || '';
    out.shortId = r.shortId || '';
  } else if (security === 'tls') {
    const t = stream.tlsSettings || {};
    out.sni = t.serverName || '';
    out.insecure = Boolean(t.allowInsecure);
    out.fingerprint = t.fingerprint || 'chrome';
  }

  if (transport === 'ws') {
    const ws = stream.wsSettings || {};
    out.wsPath = ws.path || '/';
    out.wsHost = ws.host || (ws.headers && (ws.headers.Host || ws.headers.host)) || '';
  } else if (transport === 'grpc') {
    out.grpcServiceName = stream.grpcSettings?.serviceName || 'grpc';
  } else if (transport === 'httpupgrade') {
    const hu = stream.httpupgradeSettings || {};
    out.wsPath = hu.path || '/';
    out.wsHost = hu.host || '';
  }

  if (proto === 'vless' || proto === 'vmess') {
    const vnext = (Array.isArray(settings.vnext) && settings.vnext[0]) || settings || {};
    const user = (Array.isArray(vnext.users) && vnext.users[0]) || settings || {};
    out.server = vnext.address || settings.address || raw.server || '';
    out.port = Number(vnext.port || settings.port || raw.server_port || 443);
    out.uuid = ensureUuid(user.id || settings.id || raw.uuid || '');
    out.flow = user.flow || settings.flow || '';
    out.alterId = Number(user.alterId || settings.alterId || 0);
    out.cipher = user.security || settings.security || 'auto';
  } else if (proto === 'shadowsocks') {
    const srv = (Array.isArray(settings.servers) && settings.servers[0]) || settings;
    out.server = srv.address || raw.server || '';
    out.port = Number(srv.port || raw.server_port || 8388);
    out.method = normalizeSsMethod(srv.method || raw.method || 'aes-128-gcm');
    out.password = srv.password || raw.password || '';
    out.uot = Boolean(srv.uot || raw.uot);
  } else if (proto === 'trojan') {
    const srv = (Array.isArray(settings.servers) && settings.servers[0]) || settings;
    out.server = srv.address || raw.server || '';
    out.port = Number(srv.port || raw.server_port || 443);
    out.password = srv.password || raw.password || '';
  } else if (proto === 'socks' || proto === 'http') {
    const srv = (Array.isArray(settings.servers) && settings.servers[0]) || settings;
    const usr = (Array.isArray(srv.users) && srv.users[0]) || {};
    out.server = srv.address || raw.server || '';
    out.port = Number(srv.port || raw.server_port || 1080);
    out.username = usr.user || srv.user || raw.username || '';
    out.password = usr.pass || srv.pass || raw.password || '';
  } else if (proto === 'hysteria2' || proto === 'hysteria' || proto === 'anytls') {
    out.server = settings.address || raw.server || '';
    out.port = Number(settings.port || raw.server_port || 443);
    out.password = settings.password || settings.auth || raw.password || '';
  }

  return out;
}

function convert3xuiRouteRule(raw, index = 0) {
  const inbound = Array.isArray(raw.inboundTag)
    ? raw.inboundTag
    : (Array.isArray(raw.inbound) ? raw.inbound : (raw.inboundTag ? [raw.inboundTag] : []));
  const outboundRaw = raw.outboundTag || raw.outbound || 'direct';
  const outbound = outboundRaw === 'blocked' ? 'block' : (outboundRaw === 'freedom' ? 'direct' : outboundRaw);

  return {
    id: `rule_3xui_${crypto.randomBytes(4).toString('hex')}_${index}`,
    remark: raw.remark || (inbound.length ? `入站转发: ${inbound.join(', ')} ➔ ${outbound}` : `分流规则 #${index + 1} (${outbound})`),
    enabled: true,
    action: 'route',
    inbound,
    user: Array.isArray(raw.user) ? raw.user : (raw.user ? [raw.user] : []),
    domain: Array.isArray(raw.domain) ? raw.domain : (raw.domain ? [raw.domain] : []),
    domain_suffix: Array.isArray(raw.domain_suffix) ? raw.domain_suffix : [],
    domain_keyword: Array.isArray(raw.domain_keyword) ? raw.domain_keyword : [],
    ip_cidr: (Array.isArray(raw.ip) ? raw.ip : (Array.isArray(raw.ip_cidr) ? raw.ip_cidr : [])).filter((x) => x !== 'geoip:private'),
    source_ip_cidr: Array.isArray(raw.sourceIP) ? raw.sourceIP : (Array.isArray(raw.source_ip_cidr) ? raw.source_ip_cidr : []),
    port: raw.port ? String(raw.port).split(',').map((s) => s.trim()).filter(Boolean) : [],
    source_port: raw.sourcePort ? String(raw.sourcePort).split(',').map((s) => s.trim()).filter(Boolean) : [],
    network: raw.network ? String(raw.network).toLowerCase() : '',
    protocol: Array.isArray(raw.protocol) ? raw.protocol : (raw.protocol ? [raw.protocol] : []),
    rule_set: Array.isArray(raw.rule_set) ? raw.rule_set : [],
    ip_is_private: Array.isArray(raw.ip) && raw.ip.includes('geoip:private'),
    outbound,
    migratedFrom3xui: true
  };
}

function parse3xuiPayload({ dbPath = '', dbBuffer = null, jsonPayload = null, dryRun = false }) {
  let rawInbounds = [];
  let clientTraffics = [];
  let outboundTraffics = [];
  let rawSettings = [];
  let templateConfig = {};
  let restoredCerts = [];
  let certPathRemap = new Map();
  let hasAcmeSh = false;

  if (dbBuffer && Buffer.isBuffer(dbBuffer) && dbBuffer.length > 16) {
    const header = dbBuffer.subarray(0, 15).toString('utf8');
    const isGzip = dbBuffer[0] === 0x1f && dbBuffer[1] === 0x8b;
    if (header.startsWith('SQLite format 3') || isGzip) {
      const ext = isGzip ? '.tar.gz' : '.db';
      const tmpFile = path.join(os.tmpdir(), `x-ui-import-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext}`);
      fs.writeFileSync(tmpFile, dbBuffer, { mode: 0o600 });
      try {
        const dump = readSqliteDb(tmpFile, dryRun);
        rawInbounds = dump.inbounds || [];
        clientTraffics = dump.client_traffics || [];
        outboundTraffics = dump.outbound_traffics || [];
        rawSettings = dump.settings || [];
        restoredCerts = dump.restoredCerts || [];
        certPathRemap = dump.certPathRemap || new Map();
        hasAcmeSh = Boolean(dump.hasAcmeSh);
      } finally {
        fs.rmSync(tmpFile, { force: true });
      }
    } else if (dbBuffer.length > 4 && dbBuffer[0] === 0x50 && dbBuffer[1] === 0x4b) {
      try {
        const { extractMasterBackupPayload } = require('./zip');
        const extracted = extractMasterBackupPayload(dbBuffer);
        jsonPayload = extracted.stateData;
      } catch {
        jsonPayload = safeJson(dbBuffer.toString('utf8'), null);
      }
    } else {
      jsonPayload = safeJson(dbBuffer.toString('utf8'), null);
    }
  } else if (dbPath) {
    const dump = readSqliteDb(dbPath, dryRun);
    rawInbounds = dump.inbounds || [];
    clientTraffics = dump.client_traffics || [];
    outboundTraffics = dump.outbound_traffics || [];
    rawSettings = dump.settings || [];
    restoredCerts = dump.restoredCerts || [];
    certPathRemap = dump.certPathRemap || new Map();
    hasAcmeSh = Boolean(dump.hasAcmeSh);

    // If user already unpacked /root/3xui_backup.tar.gz to / and imported /etc/x-ui/x-ui.db directly
    if (!dryRun && fs.existsSync('/root/.acme.sh/acme.sh')) {
      hasAcmeSh = ensureAcmeRenewalCron('/root/.acme.sh') || true;
    }
  }

  // Detect if jsonPayload is a native NexusGate / NexusGate Plus backup JSON
  if (
    jsonPayload &&
    typeof jsonPayload === 'object' &&
    !Array.isArray(jsonPayload) &&
    Array.isArray(jsonPayload.inbounds) &&
    (jsonPayload.version || (jsonPayload.inbounds[0] && !jsonPayload.inbounds[0].settings && Array.isArray(jsonPayload.inbounds[0].clients)))
  ) {
    const ngInbounds = jsonPayload.inbounds.map((inb) => ({
      ...inb,
      id: inb.id || `in_${crypto.randomBytes(5).toString('hex')}`,
      migratedFromNexusGate: true
    }));
    const ngOutbounds = (jsonPayload.outbounds || []).filter((o) => !o.builtin && !['direct', 'block'].includes(o.tag));
    const ngRules = ((jsonPayload.routing && jsonPayload.routing.rules) || []).filter((r) => r.action !== 'sniff');
    const ngCerts = Array.isArray(jsonPayload.certificates) ? jsonPayload.certificates : [];
    return {
      summary: {
        inboundsCount: ngInbounds.length,
        clientsCount: ngInbounds.reduce((acc, item) => acc + (item.clients?.length || 0), 0),
        outboundsCount: ngOutbounds.length,
        rulesCount: ngRules.length,
        restoredCertsCount: ngCerts.length,
        restoredCertDomains: ngCerts.map((c) => c.domain).filter(Boolean),
        hasAcmeSh: false,
        acmeRestored: false,
        skippedDanglingRules: []
      },
      inbounds: ngInbounds,
      outbounds: ngOutbounds,
      rules: ngRules,
      restoredCerts: ngCerts,
      panelSettings: jsonPayload.settings || {}
    };
  }

  if (jsonPayload) {
    if (Array.isArray(jsonPayload)) {
      rawInbounds = jsonPayload;
    } else if (typeof jsonPayload === 'object') {
      if (Array.isArray(jsonPayload.inbounds)) rawInbounds = jsonPayload.inbounds;
      if (Array.isArray(jsonPayload.client_traffics)) clientTraffics = jsonPayload.client_traffics;
      if (Array.isArray(jsonPayload.outbound_traffics)) outboundTraffics = jsonPayload.outbound_traffics;
      if (Array.isArray(jsonPayload.settings)) rawSettings = jsonPayload.settings;
      if (jsonPayload.outbounds || jsonPayload.routing) {
        templateConfig = jsonPayload;
      }
    }
  }

  const settingsMap = {};
  for (const row of rawSettings) {
    if (row.key) settingsMap[row.key] = row.value;
  }

  if (settingsMap.xrayTemplateConfig) {
    templateConfig = safeJson(settingsMap.xrayTemplateConfig, templateConfig);
  }

  const outboundTrafficsMap = new Map();
  for (const ot of outboundTraffics) {
    if (ot.tag) outboundTrafficsMap.set(ot.tag, ot);
  }

  const convertedInbounds = [];
  for (const row of rawInbounds) {
    if (row.tag === 'api' || ((row.protocol === 'dokodemo-door' || row.protocol === 'tunnel') && row.listen === '127.0.0.1' && Number(row.port) === 62789)) {
      continue;
    }
    convertedInbounds.push(convert3xuiInbound(row, clientTraffics, certPathRemap));
  }

  const validInboundTags = new Set(convertedInbounds.map((i) => i.tag));

  const convertedOutbounds = [];
  const rawOutbounds = Array.isArray(templateConfig.outbounds) ? templateConfig.outbounds : [];
  for (let i = 0; i < rawOutbounds.length; i += 1) {
    const o = rawOutbounds[i];
    if (o.tag === 'api' || o.protocol === 'dns') continue;
    convertedOutbounds.push(convert3xuiOutbound(o, i, outboundTrafficsMap));
  }

  const rawRules = Array.isArray(templateConfig.routing?.rules)
    ? templateConfig.routing.rules
    : (Array.isArray(templateConfig.route?.rules) ? templateConfig.route.rules : []);

  const skippedDanglingRules = [];
  const relayRules = [];
  const otherRules = [];
  for (let i = 0; i < rawRules.length; i += 1) {
    const r = rawRules[i];
    if (r.outboundTag === 'api' || (Array.isArray(r.inboundTag) && r.inboundTag.includes('api'))) {
      continue;
    }
    const rule = convert3xuiRouteRule(r, i);

    const isPureInboundRelay =
      rule.inbound.length > 0 &&
      !rule.domain.length &&
      !rule.domain_suffix.length &&
      !rule.ip_cidr.length &&
      !rule.port.length &&
      !rule.protocol.length &&
      !rule.ip_is_private;

    if (isPureInboundRelay) {
      const invalidTags = rule.inbound.filter((t) => !validInboundTags.has(t));
      if (invalidTags.length > 0) {
        skippedDanglingRules.push({ inboundTag: invalidTags.join(", "), outboundTag: rule.outbound });
      }
      rule.inbound = rule.inbound.filter((t) => validInboundTags.has(t));
      if (rule.inbound.length === 0) {
        continue;
      }
      const matchedInbs = [];
      for (const inb of convertedInbounds) {
        if (rule.inbound.includes(inb.tag)) {
          inb.outboundTag = rule.outbound;
          matchedInbs.push(inb);
        }
      }
      rule.remark = `入站转发: ${rule.inbound.join(', ')} ➔ ${rule.outbound}`;
      relayRules.push(rule);
    } else {
      if (rule.ip_is_private && !rule.domain.length && !rule.protocol.length && rule.outbound === 'block') {
        rule.remark = '阻止私有内网探测 (geoip:private)';
      } else if (rule.protocol.includes('bittorrent') && rule.outbound === 'block') {
        rule.remark = '禁止 BitTorrent 协议下载';
      }
      otherRules.push(rule);
    }
  }
  const convertedRules = [...relayRules, ...otherRules];

  const panelSettings = {};
  if (settingsMap.webPort) panelSettings.webPort = Number(settingsMap.webPort);
  if (settingsMap.webBasePath) panelSettings.webBasePath = settingsMap.webBasePath;
  if (settingsMap.webCertFile) {
    panelSettings.webCertFile = certPathRemap.get(settingsMap.webCertFile) || settingsMap.webCertFile;
  }
  if (settingsMap.webKeyFile) {
    panelSettings.webKeyFile = certPathRemap.get(settingsMap.webKeyFile) || settingsMap.webKeyFile;
  }
  if (settingsMap.subPath) panelSettings.subPath = settingsMap.subPath;

  // If panelSettings has a valid cert file on disk that wasn't in restoredCerts yet, register it
  if (
    panelSettings.webCertFile &&
    panelSettings.webKeyFile &&
    fs.existsSync(panelSettings.webCertFile) &&
    fs.existsSync(panelSettings.webKeyFile) &&
    !restoredCerts.some((c) => c.certPath === panelSettings.webCertFile)
  ) {
    const meta = inspectCertificate(panelSettings.webCertFile, panelSettings.webKeyFile);
    const inferredDomain = inferDomainFromCertPath(panelSettings.webCertFile) || 'panel-cert';
    restoredCerts.push({
      id: `cert_${crypto.createHash('md5').update(panelSettings.webCertFile).digest('hex').slice(0, 10)}`,
      domain: inferredDomain,
      type: meta.isSelfSigned ? 'self-signed' : 'acme- Let\'s Encrypt',
      certPath: panelSettings.webCertFile,
      keyPath: panelSettings.webKeyFile,
      createdAt: new Date().toISOString(),
      ...meta
    });
  }

  // Also discover any on-disk certificates referenced by migrated TLS inbounds
  for (const inb of convertedInbounds) {
    if (inb.security === 'tls' && inb.certPath && inb.keyPath && fs.existsSync(inb.certPath) && fs.existsSync(inb.keyPath)) {
      const exists = restoredCerts.some((c) => c.certPath === inb.certPath || (inb.tlsDomain && c.domain === inb.tlsDomain));
      if (!exists) {
        const meta = inspectCertificate(inb.certPath, inb.keyPath);
        if (meta.valid) {
          const inferredDomain = inb.tlsDomain || inferDomainFromCertPath(inb.certPath) || 'migrated-cert';
          restoredCerts.push({
            id: `cert_${crypto.createHash('md5').update(inb.certPath).digest('hex').slice(0, 10)}`,
            domain: inferredDomain,
            type: meta.isSelfSigned ? 'self-signed' : "acme- Let's Encrypt",
            certPath: inb.certPath,
            keyPath: inb.keyPath,
            createdAt: new Date().toISOString(),
            ...meta
          });
        }
      }
    }
  }

  return {
    summary: {
      inboundsCount: convertedInbounds.length,
      clientsCount: convertedInbounds.reduce((acc, item) => acc + (item.clients?.length || 0), 0),
      outboundsCount: convertedOutbounds.filter((o) => !o.builtin).length,
      rulesCount: convertedRules.length,
      protocols: [...new Set(convertedInbounds.map((i) => i.protocol))],
      restoredCertsCount: restoredCerts.length,
      restoredCertDomains: restoredCerts.map((c) => c.domain),
      hasAcmeSh,
      acmeRestored: hasAcmeSh,
      skippedDanglingRules
    },
    inbounds: convertedInbounds,
    outbounds: convertedOutbounds,
    rules: convertedRules,
    restoredCerts,
    panelSettings
  };
}

function apply3xuiMigration(store, parsed, mode = 'merge', options = {}) {
  return store.transact((state) => {
    const { ensureClusterNodes } = require('./cluster');
    const { randomToken } = require('./auth');
    ensureClusterNodes(state);

    let targetNodeId = String(options.targetNodeId || '').trim();
    const nodeName = String(options.nodeName || '').trim();
    const nodeDomain = String(options.nodeDomain || '').trim();
    const nodeIp = String(options.nodeIp || '').trim();
    const deduplicateExits = options.deduplicateExits !== false;

    if (targetNodeId === '__create__' || (!targetNodeId && (nodeName || nodeDomain || nodeIp))) {
      const existingNode = state.nodes.find(
        (n) => (nodeDomain && n.domain === nodeDomain) || (nodeIp && n.host === nodeIp && !n.isLocal)
      );
      if (existingNode) {
        targetNodeId = existingNode.id;
        if (nodeName) existingNode.name = nodeName;
        if (nodeDomain) existingNode.domain = nodeDomain;
        if (nodeIp) existingNode.host = nodeIp;
      } else {
        const newId = `node_${crypto.randomBytes(3).toString('hex')}`;
        state.nodes.push({
          id: newId,
          name: nodeName || (nodeDomain ? `中转机 (${nodeDomain})` : `迁移中转机 ${state.nodes.length}`),
          role: 'relay',
          isLocal: false,
          enabled: true,
          host: nodeIp || nodeDomain || '127.0.0.1',
          agentPort: 19090,
          domain: nodeDomain || '',
          token: `ag_${randomToken(18)}`,
          region: 'Relay',
          isp: '3x-ui Migrated',
          standbyNodeId: '',
          mirrorStandby: true,
          activeFailoverTo: '',
          status: 'online',
          lastSeenAt: new Date().toISOString(),
          metrics: { cpuPct: 1.5, memPct: 16.0, memUsedMB: 30, memTotalMB: 1024, diskPct: 15.0, sbRunning: true, sbVersion: '1.12.23' },
          createdAt: new Date().toISOString()
        });
        targetNodeId = newId;
      }
    }

    const effectiveNodeId = targetNodeId || 'node_local';
    const targetNodeObj = state.nodes.find((n) => n.id === effectiveNodeId);
    if (targetNodeObj) {
      if (nodeDomain && !targetNodeObj.domain) targetNodeObj.domain = nodeDomain;
      if (nodeIp && (!targetNodeObj.host || targetNodeObj.host === '127.0.0.1')) targetNodeObj.host = nodeIp;
    }

    if (Array.isArray(parsed.restoredCerts) && parsed.restoredCerts.length > 0) {
      for (const rc of parsed.restoredCerts) {
        if (!rc.certPem && rc.certPath && fs.existsSync(rc.certPath)) {
          try { rc.certPem = fs.readFileSync(rc.certPath, 'utf8'); } catch { /* ignore */ }
        }
        if (!rc.keyPem && rc.keyPath && fs.existsSync(rc.keyPath)) {
          try { rc.keyPem = fs.readFileSync(rc.keyPath, 'utf8'); } catch { /* ignore */ }
        }
      }
      if (Array.isArray(state.settings.deletedCertDomains)) {
        const restoredDomains = new Set(parsed.restoredCerts.map((c) => c.domain));
        state.settings.deletedCertDomains = state.settings.deletedCertDomains.filter((d) => !restoredDomains.has(d));
      }
      if (Array.isArray(state.settings.deletedCertPaths)) {
        const restoredPaths = new Set(parsed.restoredCerts.map((c) => c.certPath));
        state.settings.deletedCertPaths = state.settings.deletedCertPaths.filter((p) => !restoredPaths.has(p));
      }
      for (let idx = parsed.restoredCerts.length - 1; idx >= 0; idx -= 1) {
        const rc = parsed.restoredCerts[idx];
        state.certificates = (state.certificates || []).filter(
          (c) => c.domain !== rc.domain && c.certPath !== rc.certPath && (rc.type !== 'self-signed' ? c.type !== 'self-signed' : true)
        );
        state.certificates.unshift(rc);
      }
      const bestCert = parsed.restoredCerts.find((c) => c.type !== 'self-signed' && !c.isSelfSigned) || parsed.restoredCerts[0];
      if (bestCert) {
        if (effectiveNodeId === 'node_local') {
          state.settings.defaultTlsDomain = bestCert.domain;
          state.settings.defaultCertFile = bestCert.certPath;
          state.settings.defaultKeyFile = bestCert.keyPath;
          if (bestCert.type !== 'self-signed' && !bestCert.isSelfSigned && bestCert.domain) {
            state.settings.webDomain = bestCert.domain;
          }
          state.settings.webCertFile = bestCert.certPath;
          state.settings.webKeyFile = bestCert.keyPath;
        } else if (targetNodeObj && bestCert.domain && bestCert.type !== 'self-signed' && !bestCert.isSelfSigned) {
          if (!targetNodeObj.domain) targetNodeObj.domain = bestCert.domain;
        }
      }
    }

    // Tag inbounds with effectiveNodeId & nodeDomain, and namespace tags if merging multiple Relay servers
    const inboundTagRemap = new Map();
    const outboundTagRemap = new Map();
    const shortPrefix = effectiveNodeId !== 'node_local' ? effectiveNodeId.replace(/^node_/, '') : '';

    const relayBestCert = (parsed.restoredCerts || []).find((c) => c.type !== 'self-signed' && !c.isSelfSigned)
      || (targetNodeObj?.domain ? (state.certificates || []).find((c) => c.domain === targetNodeObj.domain && c.valid !== false) : null);

    for (const inb of parsed.inbounds) {
      inb.nodeId = effectiveNodeId;
      if (targetNodeObj?.domain && (!inb.publicHost || inb.publicHost === targetNodeObj.host)) {
        inb.publicHost = targetNodeObj.domain;
      }
      if (inb.security === 'tls') {
        if (relayBestCert) {
          if (!inb.tlsDomain || inb.tlsDomain === 'www.apple.com' || inb.tlsDomain === 'www.bing.com') {
            inb.tlsDomain = relayBestCert.domain;
          }
          if (!inb.certPath || inb.certPath.includes('selfsigned')) {
            inb.certPath = relayBestCert.certPath;
            inb.keyPath = relayBestCert.keyPath;
          }
        } else if (targetNodeObj?.domain && (!inb.tlsDomain || inb.tlsDomain === 'www.apple.com' || inb.tlsDomain === 'www.bing.com')) {
          inb.tlsDomain = targetNodeObj.domain;
        }
      }
      if (mode !== 'replace' && shortPrefix) {
        const conflictOtherNode = state.inbounds.some(
          (x) => (x.nodeId || 'node_local') !== effectiveNodeId && x.tag === inb.tag
        );
        if (conflictOtherNode && !inb.tag.startsWith(`${shortPrefix}-`)) {
          const newTag = `${shortPrefix}-${inb.tag}`;
          inboundTagRemap.set(inb.tag, newTag);
          inb.tag = newTag;
        }
      }
    }

    // Smart deduplication of Shared Exit Outbounds across multiple Relay 3x-ui databases
    let deduplicatedExitsCount = 0;
    if (mode !== 'replace' && deduplicateExits) {
      for (const out of parsed.outbounds) {
        if (['direct', 'block'].includes(out.tag) || !out.server || !out.port) continue;
        const sameServerOut = state.outbounds.find(
          (x) => !x.builtin && x.type === out.type && x.server === out.server && Number(x.port) === Number(out.port)
        );
        if (sameServerOut) {
          sameServerOut.sharedExit = true;
          sameServerOut.up = Math.max(Number(sameServerOut.up || 0), Number(out.up || 0));
          sameServerOut.down = Math.max(Number(sameServerOut.down || 0), Number(out.down || 0));
          if (sameServerOut.tag !== out.tag) {
            outboundTagRemap.set(out.tag, sameServerOut.tag);
            out.tag = sameServerOut.tag;
          }
          deduplicatedExitsCount += 1;
        } else if (shortPrefix && state.outbounds.some((x) => x.tag === out.tag)) {
          const newOutTag = `${shortPrefix}-${out.tag}`;
          outboundTagRemap.set(out.tag, newOutTag);
          out.tag = newOutTag;
        }
      }
    }

    if (inboundTagRemap.size > 0 || outboundTagRemap.size > 0) {
      for (const inb of parsed.inbounds) {
        if (inb.outboundTag && outboundTagRemap.has(inb.outboundTag)) {
          inb.outboundTag = outboundTagRemap.get(inb.outboundTag);
        }
      }
      for (const rule of parsed.rules) {
        if (!rule.nodeId && effectiveNodeId) {
          rule.nodeId = effectiveNodeId;
        }
        if (!rule.id || state.routing.rules.some((r) => r.id === rule.id)) {
          rule.id = `rule_${crypto.randomBytes(5).toString('hex')}`;
        }
        if (Array.isArray(rule.inbound)) {
          rule.inbound = rule.inbound.map((t) => inboundTagRemap.get(t) || t);
        }
        if (rule.outbound && outboundTagRemap.has(rule.outbound)) {
          rule.outbound = outboundTagRemap.get(rule.outbound);
        }
        if (rule.inbound?.length && rule.outbound && /^入站转发:/.test(rule.remark || '')) {
          rule.remark = `入站转发: ${rule.inbound.join(', ')} ➔ ${rule.outbound}`;
        }
      }
    }

    if (mode === 'replace') {
      state.inbounds = parsed.inbounds;
      const customOutbounds = parsed.outbounds.filter((o) => !['direct', 'block'].includes(o.tag));
      state.outbounds = [
        ...state.outbounds.filter((o) => o.builtin),
        ...customOutbounds
      ];
      state.routing.rules = [
        ...state.routing.rules.filter((r) => r.action === 'sniff'),
        ...parsed.rules
      ];
    } else {
      for (const inb of parsed.inbounds) {
        const existingIdx = state.inbounds.findIndex(
          (x) => (x.nodeId || 'node_local') === (inb.nodeId || 'node_local') && (x.tag === inb.tag || Number(x.port) === Number(inb.port))
        );
        if (existingIdx >= 0) {
          state.inbounds[existingIdx] = { ...state.inbounds[existingIdx], ...inb, id: state.inbounds[existingIdx].id };
        } else {
          if (!inb.id || state.inbounds.some((x) => x.id === inb.id)) {
            inb.id = `in_${crypto.randomBytes(5).toString('hex')}`;
          }
          state.inbounds.push(inb);
        }
      }
      for (const out of parsed.outbounds) {
        if (['direct', 'block'].includes(out.tag)) continue;
        const existingIdx = state.outbounds.findIndex((x) => x.tag === out.tag);
        if (existingIdx >= 0) {
          state.outbounds[existingIdx] = { ...state.outbounds[existingIdx], ...out, id: state.outbounds[existingIdx].id };
        } else {
          state.outbounds.push(out);
        }
      }
      for (const rule of parsed.rules) {
        const existingIdx = state.routing.rules.findIndex(
          (r) =>
            (rule.inbound?.length === 1 && r.inbound?.length === 1 && r.inbound[0] === rule.inbound[0] && !r.domain?.length && !r.ip_cidr?.length && !r.protocol?.length && !r.ip_is_private) ||
            (JSON.stringify(r.inbound || []) === JSON.stringify(rule.inbound || []) &&
              JSON.stringify(r.domain || []) === JSON.stringify(rule.domain || []) &&
              JSON.stringify(r.ip_cidr || []) === JSON.stringify(rule.ip_cidr || []) &&
              JSON.stringify(r.protocol || []) === JSON.stringify(rule.protocol || []) &&
              Boolean(r.ip_is_private) === Boolean(rule.ip_is_private) &&
              r.outbound === rule.outbound)
        );
        if (existingIdx >= 0) {
          state.routing.rules[existingIdx] = { ...state.routing.rules[existingIdx], ...rule, id: state.routing.rules[existingIdx].id };
        } else if (rule.inbound?.length > 0 && !rule.domain?.length && !rule.ip_cidr?.length && !rule.protocol?.length && !rule.ip_is_private) {
          // Insert inbound relay rules before generic block rules so relay rules always stay grouped at the top
          const firstBlockIdx = state.routing.rules.findIndex((r) => r.outbound === 'block' && (!r.inbound || !r.inbound.length));
          if (firstBlockIdx >= 0) {
            state.routing.rules.splice(firstBlockIdx, 0, rule);
          } else {
            state.routing.rules.push(rule);
          }
        } else {
          state.routing.rules.push(rule);
        }
      }
    }

    const record = {
      id: `mig_${crypto.randomBytes(4).toString('hex')}`,
      at: new Date().toISOString(),
      mode,
      targetNodeId: effectiveNodeId,
      targetNodeName: targetNodeObj?.name || '主控本机',
      targetDomain: targetNodeObj?.domain || '',
      deduplicatedExitsCount,
      ...parsed.summary
    };
    state.migrations.unshift(record);
    if (state.migrations.length > 20) state.migrations.length = 20;
    return record;
  });
}

module.exports = {
  readSqliteDb,
  ensureAcmeRenewalCron,
  convert3xuiInbound,
  convert3xuiOutbound,
  convert3xuiRouteRule,
  parse3xuiPayload,
  apply3xuiMigration
};
