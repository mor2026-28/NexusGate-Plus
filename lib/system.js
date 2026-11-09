'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const net = require('node:net');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

let lastCpuSample = null;
let lastNetSample = null;
let cachedPublicIp = { ipv4: '', ipv6: '', checkedAt: 0 };

// Memory caches to prevent repeated OpenSSL X.509 allocations & disk scans on 1C-1G servers
const certMetaCache = new Map();
let discoveredCertsCache = { at: 0, items: [] };

const SYS_ENV = {
  ...process.env,
  PATH: `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:${process.env.PATH || ''}`
};

const cmdPathCache = new Map();
function findCmd(cmd) {
  if (cmdPathCache.has(cmd)) return cmdPathCache.get(cmd);
  const candidates = [`/usr/sbin/${cmd}`, `/sbin/${cmd}`, `/usr/bin/${cmd}`, `/bin/${cmd}`, `/usr/local/sbin/${cmd}`, `/usr/local/bin/${cmd}`];
  for (const p of candidates) {
    if (fs.existsSync(p)) {
      cmdPathCache.set(cmd, p);
      return p;
    }
  }
  const w = spawnSync('which', [cmd], { env: SYS_ENV, encoding: 'utf8', timeout: 2000 });
  const resolved = (w.status === 0 && String(w.stdout || '').trim())
    ? String(w.stdout).trim().split('\n')[0]
    : '';
  cmdPathCache.set(cmd, resolved);
  return resolved;
}

function sampleCpuTimes() {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    for (const type of Object.keys(cpu.times)) {
      total += cpu.times[type];
    }
    idle += cpu.times.idle;
  }
  return { idle, total, cores: cpus.length, model: cpus[0]?.model || 'Generic CPU', speedMhz: cpus[0]?.speed || 0 };
}

function getCpuUsage() {
  const current = sampleCpuTimes();
  if (!lastCpuSample) {
    lastCpuSample = current;
    const loadPct = Math.min(100, Math.round(((os.loadavg()[0] || 0) / Math.max(1, current.cores)) * 100));
    return { percent: loadPct, cores: current.cores, model: current.model, speedMhz: current.speedMhz };
  }
  const idleDiff = current.idle - lastCpuSample.idle;
  const totalDiff = current.total - lastCpuSample.total;
  lastCpuSample = current;
  const percent = totalDiff > 0 ? Math.max(0, Math.min(100, Math.round((1 - idleDiff / totalDiff) * 1000) / 10)) : 0;
  return { percent, cores: current.cores, model: current.model, speedMhz: current.speedMhz };
}

function getMemoryAndSwap() {
  const total = os.totalmem();
  let available = os.freemem();
  let swapTotal = 0;
  let swapFree = 0;

  if (fs.existsSync('/proc/meminfo')) {
    try {
      const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
      const availMatch = meminfo.match(/^MemAvailable:\s+(\d+)\s+kB/m);
      if (availMatch) available = Number(availMatch[1]) * 1024;
      const stMatch = meminfo.match(/^SwapTotal:\s+(\d+)\s+kB/m);
      const sfMatch = meminfo.match(/^SwapFree:\s+(\d+)\s+kB/m);
      if (stMatch) swapTotal = Number(stMatch[1]) * 1024;
      if (sfMatch) swapFree = Number(sfMatch[1]) * 1024;
    } catch { /* fallback to os.freemem */ }
  }

  return {
    mem: { used: Math.max(0, total - available), total, available },
    swap: { used: Math.max(0, swapTotal - swapFree), total: swapTotal }
  };
}

let lastStatusGcAt = 0;
let cachedDisk = { at: 0, value: null };
let cachedAccel = { at: 0, value: null };

function getDiskUsage() {
  const now = Date.now();
  if (cachedDisk.value && now - cachedDisk.at < 30000) return cachedDisk.value;
  const saveDisk = (v) => { cachedDisk = { at: now, value: v }; return v; };
  if (typeof fs.statfsSync === 'function') {
    try {
      const s = fs.statfsSync('/');
      const bsize = Number(s.bsize || s.frsize || 4096);
      const total = bsize * Number(s.blocks || 0);
      const free = bsize * Number(s.bfree || 0);
      const available = bsize * Number(s.bavail || s.bfree || 0);
      const used = Math.max(0, total - free);
      if (total > 0) return saveDisk({ used, total, available });
    } catch { /* fallback to df */ }
  }
  try {
    const out = spawnSync('df', ['-B1', '/'], { env: SYS_ENV, encoding: 'utf8', timeout: 2000 }).stdout || '';
    const lines = out.trim().split('\n');
    if (lines.length >= 2) {
      const parts = lines[lines.length - 1].trim().split(/\s+/);
      if (parts.length >= 4) {
        const total = Number(parts[1]) || 0;
        const used = Number(parts[2]) || 0;
        const avail = Number(parts[3]) || 0;
        return saveDisk({ used, total, available: avail });
      }
    }
  } catch { /* ignore */ }
  return { used: 0, total: 0, available: 0 };
}

function getNetworkStats() {
  let rxBytes = 0;
  let txBytes = 0;
  if (fs.existsSync('/proc/net/dev')) {
    try {
      const lines = fs.readFileSync('/proc/net/dev', 'utf8').split('\n').slice(2);
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('lo:')) continue;
        const parts = trimmed.split(/[:\s]+/);
        if (parts.length >= 10) {
          rxBytes += Number(parts[1]) || 0;
          txBytes += Number(parts[9]) || 0;
        }
      }
    } catch { /* ignore */ }
  }

  const now = Date.now();
  let upSpeed = 0;
  let downSpeed = 0;
  if (lastNetSample && now > lastNetSample.at) {
    const dt = (now - lastNetSample.at) / 1000;
    downSpeed = Math.max(0, Math.round((rxBytes - lastNetSample.rxBytes) / dt));
    upSpeed = Math.max(0, Math.round((txBytes - lastNetSample.txBytes) / dt));
  }
  lastNetSample = { rxBytes, txBytes, at: now };

  return {
    sent: txBytes,
    recv: rxBytes,
    upSpeed,
    downSpeed
  };
}

function getSocketCounts() {
  if (fs.existsSync('/proc/net/sockstat')) {
    try {
      let tcp = 0;
      let udp = 0;
      const s4 = fs.readFileSync('/proc/net/sockstat', 'utf8');
      const mTcp4 = s4.match(/TCP:\s+inuse\s+(\d+)/);
      const mUdp4 = s4.match(/UDP:\s+inuse\s+(\d+)/);
      if (mTcp4) tcp += Number(mTcp4[1]);
      if (mUdp4) udp += Number(mUdp4[1]);
      if (fs.existsSync('/proc/net/sockstat6')) {
        const s6 = fs.readFileSync('/proc/net/sockstat6', 'utf8');
        const mTcp6 = s6.match(/TCP6:\s+inuse\s+(\d+)/);
        const mUdp6 = s6.match(/UDP6:\s+inuse\s+(\d+)/);
        if (mTcp6) tcp += Number(mTcp6[1]);
        if (mUdp6) udp += Number(mUdp6[1]);
      }
      return { tcp, udp };
    } catch { /* fallback */ }
  }
  const countLines = (file) => {
    try {
      if (!fs.existsSync(file)) return 0;
      return Math.max(0, fs.readFileSync(file, 'utf8').trim().split('\n').length - 1);
    } catch {
      return 0;
    }
  };
  return {
    tcp: countLines('/proc/net/tcp') + countLines('/proc/net/tcp6'),
    udp: countLines('/proc/net/udp') + countLines('/proc/net/udp6')
  };
}

function getLocalAddresses() {
  const nets = os.networkInterfaces();
  let ipv4 = '';
  let ipv6 = '';
  for (const name of Object.keys(nets)) {
    if (name === 'lo') continue;
    for (const netInfo of nets[name] || []) {
      if (netInfo.internal) continue;
      if (netInfo.family === 'IPv4' && !ipv4) ipv4 = netInfo.address;
      if (netInfo.family === 'IPv6' && !netInfo.address.startsWith('fe80') && !ipv6) ipv6 = netInfo.address;
    }
  }
  return { ipv4: ipv4 || '127.0.0.1', ipv6 };
}

function getAccelerationStatus(force = false) {
  const now = Date.now();
  if (!force && cachedAccel.value && now - cachedAccel.at < 30000) return cachedAccel.value;
  const readSysctl = (file, fallback = '') => {
    try {
      return fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim() : fallback;
    } catch {
      return fallback;
    }
  };
  const congestion = readSysctl('/proc/sys/net/ipv4/tcp_congestion_control', 'cubic');
  const qdisc = readSysctl('/proc/sys/net/core/default_qdisc', 'pfifo_fast');
  const rmemMax = Number(readSysctl('/proc/sys/net/core/rmem_max', '212992'));
  const wmemMax = Number(readSysctl('/proc/sys/net/core/wmem_max', '212992'));
  const fastopen = Number(readSysctl('/proc/sys/net/ipv4/tcp_fastopen', '1'));

  const res = {
    congestion,
    qdisc,
    rmemMax,
    wmemMax,
    fastopen,
    bbrEnabled: congestion === 'bbr',
    hy2Tuned: rmemMax >= 16777216
  };
  cachedAccel = { at: now, value: res };
  return res;
}

function applyKernelAcceleration(mode = 'all') {
  spawnSync('modprobe', ['tcp_bbr'], { env: SYS_ENV, encoding: 'utf8', timeout: 3000 });
  const lines = [
    '# NexusGate Sing-box BBR + FQ + HY2 Kernel Tuning',
    'fs.file-max = 2097152',
    'net.core.somaxconn = 65535',
    'net.core.netdev_max_backlog = 250000',
    'net.ipv4.tcp_fastopen = 3',
    'net.ipv4.tcp_tw_reuse = 1',
    'net.ipv4.ip_local_port_range = 10240 65535',
    'net.ipv4.ip_forward = 1',
    'net.ipv6.conf.all.forwarding = 1'
  ];

  if (mode === 'bbr' || mode === 'all') {
    lines.push(
      'net.core.default_qdisc = fq',
      'net.ipv4.tcp_congestion_control = bbr'
    );
  }

  if (mode === 'hy2' || mode === 'all') {
    lines.push(
      'net.core.rmem_max = 67108864',
      'net.core.wmem_max = 67108864',
      'net.core.rmem_default = 2097152',
      'net.core.wmem_default = 2097152',
      'net.ipv4.udp_rmem_min = 16384',
      'net.ipv4.udp_wmem_min = 16384'
    );
  }

  const content = lines.join('\n') + '\n';
  try {
    fs.mkdirSync('/etc/sysctl.d', { recursive: true });
    fs.writeFileSync('/etc/sysctl.d/99-nexusgate-acceleration.conf', content, { mode: 0o644 });
    spawnSync('sysctl', ['--system'], { env: SYS_ENV, encoding: 'utf8', timeout: 8000 });
  } catch { /* ignore in sandbox */ }
  return getAccelerationStatus(true);
}

function getSystemStatus(singboxManager, storeSettings = {}) {
  const cpu = getCpuUsage();
  const { mem, swap } = getMemoryAndSwap();
  const disk = getDiskUsage();
  const netStats = getNetworkStats();
  const sockets = getSocketCounts();
  const localIps = getLocalAddresses();
  const sbStatus = singboxManager ? singboxManager.getStatus() : { state: 'stop', version: '未知' };
  const accel = getAccelerationStatus();
  const processMem = process.memoryUsage();
  const panelPrivateBytes = processMem.heapUsed + processMem.external + (processMem.arrayBuffers || 0);

  return {
    timestamp: new Date().toISOString(),
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()} (${os.arch()})`,
    uptime: Math.floor(os.uptime()),
    panelUptime: Math.floor(process.uptime()),
    panelMemoryBytes: panelPrivateBytes,
    panelRssBytes: processMem.rss,
    panelHeapUsedBytes: processMem.heapUsed,
    loads: os.loadavg().map((n) => Number(n.toFixed(2))),
    cpu,
    mem,
    swap,
    disk,
    netTraffic: { sent: netStats.sent, recv: netStats.recv },
    netIO: { up: netStats.upSpeed, down: netStats.downSpeed },
    tcpCount: sockets.tcp,
    udpCount: sockets.udp,
    acceleration: accel,
    publicIP: {
      ipv4: storeSettings.publicIPv4 || cachedPublicIp.ipv4 || localIps.ipv4,
      ipv6: storeSettings.publicIPv6 || cachedPublicIp.ipv6 || localIps.ipv6
    },
    singbox: sbStatus
  };
}

function inspectCertificate(certPath, keyPath) {
  try {
    if (!certPath || !fs.existsSync(certPath)) return { valid: false, error: '证书文件不存在' };
    const stat = fs.statSync(certPath);
    const cacheKey = `${certPath}:${stat.mtimeMs}`;
    if (certMetaCache.has(cacheKey)) {
      const cached = certMetaCache.get(cacheKey);
      return { ...cached, keyExists: keyPath ? fs.existsSync(keyPath) : false };
    }

    const pem = fs.readFileSync(certPath, 'utf8');
    const x509 = new crypto.X509Certificate(pem);
    const isSelfSigned = String(x509.issuer || '') === String(x509.subject || '');
    const result = {
      valid: true,
      isSelfSigned,
      subject: x509.subject,
      issuer: x509.issuer,
      validFrom: x509.validFrom,
      validTo: x509.validTo,
      serialNumber: x509.serialNumber,
      fingerprint256: x509.fingerprint256,
      keyExists: keyPath ? fs.existsSync(keyPath) : false
    };
    if (certMetaCache.size > 64) certMetaCache.clear();
    certMetaCache.set(cacheKey, result);
    return result;
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

/**
 * Discovers existing SSL certificates in /root/cert/* and /etc/nexusgate/certs/*.
 * Cached for 60s to avoid repetitive filesystem & OpenSSL overhead during dashboard polling.
 */
function discoverSystemCertificates(force = false) {
  const now = Date.now();
  if (!force && discoveredCertsCache.at > 0 && (now - discoveredCertsCache.at) < 60000) {
    return discoveredCertsCache.items;
  }

  const found = [];
  const searchRoots = ['/root/cert', '/etc/nexusgate/certs'];
  for (const rootDir of searchRoots) {
    if (!fs.existsSync(rootDir)) continue;
    try {
      for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
        if (!entry.isDirectory()) continue;
        if (entry.name === 'www.bing.com') continue;
        const dirPath = path.join(rootDir, entry.name);
        const candidatesCert = ['fullchain.pem', 'cert.pem', `${entry.name}.cer`, `${entry.name}.crt`];
        const candidatesKey = ['privkey.pem', 'key.pem', `${entry.name}.key`];
        const certFile = candidatesCert.map((f) => path.join(dirPath, f)).find((p) => fs.existsSync(p));
        const keyFile = candidatesKey.map((f) => path.join(dirPath, f)).find((p) => fs.existsSync(p));
        if (certFile && keyFile) {
          const meta = inspectCertificate(certFile, keyFile);
          if (meta.valid) {
            const isSelf = Boolean(meta.isSelfSigned);
            const cleanDomain = (entry.name === 'panel' || entry.name === 'selfsigned') ? 'www.apple.com' : entry.name;
            const certObj = {
              id: `cert_${crypto.createHash('md5').update(certFile).digest('hex').slice(0, 10)}`,
              domain: cleanDomain,
              type: isSelf ? 'self-signed' : 'acme-discovered',
              certPath: certFile,
              keyPath: keyFile,
              createdAt: new Date().toISOString(),
              ...meta
            };
            const existingIdx = found.findIndex((f) => f.domain === cleanDomain);
            if (existingIdx >= 0) {
              if (found[existingIdx].type === 'self-signed' && !isSelf) {
                found[existingIdx] = certObj;
              }
            } else {
              found.push(certObj);
            }
          }
        }
      }
    } catch { /* ignore */ }
  }
  found.sort((a, b) => (a.type === 'self-signed' ? 1 : -1) - (b.type === 'self-signed' ? 1 : -1));
  discoveredCertsCache = { at: now, items: found };
  return found;
}

function issueSelfSignedCert({ domain = 'www.apple.com', ip = '', days = 3650, baseDir = '/etc/nexusgate/certs' }) {
  const cleanDomain = String(domain || 'www.apple.com').trim().replace(/[^a-zA-Z0-9._-]/g, '') || 'www.apple.com';
  let targetDir = path.join(baseDir, cleanDomain);
  try {
    fs.mkdirSync(targetDir, { recursive: true });
  } catch {
    targetDir = path.join(os.tmpdir(), 'nexusgate-certs', cleanDomain);
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const certPath = path.join(targetDir, 'fullchain.pem');
  const keyPath = path.join(targetDir, 'privkey.pem');

  const sanParts = [`DNS:${cleanDomain}`, 'DNS:localhost', 'IP:127.0.0.1'];
  if (ip && net.isIP(ip)) sanParts.push(`IP:${ip}`);
  const localIps = getLocalAddresses();
  if (localIps.ipv4 && net.isIP(localIps.ipv4) && !sanParts.includes(`IP:${localIps.ipv4}`)) {
    sanParts.push(`IP:${localIps.ipv4}`);
  }

  const res = spawnSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-days', String(days), '-nodes',
    '-subj', `/CN=${cleanDomain}`,
    '-addext', `subjectAltName=${sanParts.join(',')}`,
    '-keyout', keyPath,
    '-out', certPath
  ], { env: SYS_ENV, encoding: 'utf8', timeout: 15000 });

  if (res.status !== 0) {
    throw new Error(`生成自签证书失败: ${res.stderr || res.stdout}`);
  }
  try {
    fs.chmodSync(keyPath, 0o600);
    fs.chmodSync(certPath, 0o644);
  } catch { /* ignore */ }

  discoveredCertsCache.at = 0;
  const meta = inspectCertificate(certPath, keyPath);
  return {
    id: `cert_${crypto.randomBytes(5).toString('hex')}`,
    domain: cleanDomain,
    type: 'self-signed',
    certPath,
    keyPath,
    createdAt: new Date().toISOString(),
    ...meta
  };
}

function saveCustomCert({ domain, certPem, keyPem, certPath, keyPath, baseDir = '/etc/nexusgate/certs' }) {
  const cleanDomain = String(domain || 'custom').trim().replace(/[^a-zA-Z0-9._-]/g, '') || 'custom';
  let finalCertPath = certPath;
  let finalKeyPath = keyPath;

  if (certPem && keyPem) {
    let targetDir = path.join(baseDir, cleanDomain);
    try {
      fs.mkdirSync(targetDir, { recursive: true });
    } catch {
      targetDir = path.join(os.tmpdir(), 'nexusgate-certs', cleanDomain);
      fs.mkdirSync(targetDir, { recursive: true });
    }
    finalCertPath = path.join(targetDir, 'fullchain.pem');
    finalKeyPath = path.join(targetDir, 'privkey.pem');
    fs.writeFileSync(finalCertPath, String(certPem).trim() + '\n', { mode: 0o644 });
    fs.writeFileSync(finalKeyPath, String(keyPem).trim() + '\n', { mode: 0o600 });
  }

  if (!finalCertPath || !finalKeyPath || !fs.existsSync(finalCertPath) || !fs.existsSync(finalKeyPath)) {
    throw new Error('证书或私钥文件不存在，请检查路径或直接粘贴 PEM 内容');
  }

  discoveredCertsCache.at = 0;
  const meta = inspectCertificate(finalCertPath, finalKeyPath);
  if (!meta.valid) {
    throw new Error(`证书内容校验失败: ${meta.error}`);
  }

  return {
    id: `cert_${crypto.randomBytes(5).toString('hex')}`,
    domain: cleanDomain,
    type: meta.isSelfSigned ? 'self-signed' : 'acme-custom',
    certPath: finalCertPath,
    keyPath: finalKeyPath,
    createdAt: new Date().toISOString(),
    ...meta
  };
}

function issueAcmeCert({ domain, email = '', mode = 'standalone', cfToken = '', cfKey = '', cfEmail = '', webPort = 80, baseDir = '/etc/nexusgate/certs' }) {
  const cleanDomain = String(domain || '').trim();
  if (!cleanDomain) throw new Error('请输入要申请证书的域名或公网 IP');

  let targetDir = path.join(baseDir, cleanDomain);
  try {
    fs.mkdirSync(targetDir, { recursive: true });
  } catch {
    targetDir = path.join(os.tmpdir(), 'nexusgate-certs', cleanDomain);
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const certPath = path.join(targetDir, 'fullchain.pem');
  const keyPath = path.join(targetDir, 'privkey.pem');
  const acmeBin = path.join(os.homedir(), '.acme.sh', 'acme.sh');

  if (!fs.existsSync(acmeBin)) {
    const installRes = spawnSync('bash', ['-c', 'curl -fsSL https://get.acme.sh | sh'], { env: SYS_ENV, encoding: 'utf8', timeout: 60000 });
    if (installRes.status !== 0 && !fs.existsSync(acmeBin)) {
      throw new Error('当前环境无法自动下载安装 acme.sh，请先确保服务器联网或使用“一键生成 10 年自签证书”');
    }
  }

  spawnSync(acmeBin, ['--set-default-ca', '--server', 'letsencrypt'], { env: SYS_ENV, encoding: 'utf8', timeout: 10000 });
  if (email) {
    spawnSync(acmeBin, ['--register-account', '-m', email], { env: SYS_ENV, encoding: 'utf8', timeout: 15000 });
  }

  const issueArgs = ['--issue', '-d', cleanDomain, '--force'];
  const env = { ...SYS_ENV };
  if (mode === 'cf') {
    if (cfToken) env.CF_Token = cfToken;
    if (cfKey) env.CF_Key = cfKey;
    if (cfEmail) env.CF_Email = cfEmail;
    issueArgs.push('--dns', 'dns_cf');
  } else if (mode === 'ip') {
    issueArgs.push('--standalone', '--server', 'letsencrypt', '--certificate-profile', 'shortlived', '--days', '6', '--httpport', String(webPort || 80));
  } else {
    issueArgs.push('--standalone', '--httpport', String(webPort || 80));
  }

  const issueRes = spawnSync(acmeBin, issueArgs, { encoding: 'utf8', env, timeout: 120000 });
  if (issueRes.status !== 0) {
    throw new Error(`ACME 证书签发失败: ${(issueRes.stderr || issueRes.stdout || '').slice(0, 500)}`);
  }

  spawnSync(acmeBin, [
    '--installcert', '-d', cleanDomain,
    '--key-file', keyPath,
    '--fullchain-file', certPath
  ], { env: SYS_ENV, encoding: 'utf8', timeout: 20000 });

  try {
    if (fs.existsSync('/root')) {
      const rootCertDir = path.join('/root/cert', cleanDomain);
      fs.mkdirSync(rootCertDir, { recursive: true });
      fs.copyFileSync(certPath, path.join(rootCertDir, 'fullchain.pem'));
      fs.copyFileSync(keyPath, path.join(rootCertDir, 'privkey.pem'));
    }
  } catch { /* ignore */ }

  discoveredCertsCache.at = 0;
  const meta = inspectCertificate(certPath, keyPath);
  if (!meta.valid) {
    throw new Error('ACME 证书安装后未找到有效 PEM 文件');
  }

  return {
    id: `cert_${crypto.randomBytes(5).toString('hex')}`,
    domain: cleanDomain,
    type: mode === 'cf' ? 'acme-cf-dns' : (mode === 'ip' ? 'acme-ip' : 'acme-http'),
    certPath,
    keyPath,
    createdAt: new Date().toISOString(),
    ...meta
  };
}

function tcpPingHostPort(host, port, timeoutMs = 4000) {
  return new Promise((resolve) => {
    const start = Date.now();
    const socket = net.createConnection({ host: String(host).replace(/^\[|\]$/g, ''), port: Number(port) });
    let done = false;
    const finish = (result) => {
      if (done) return;
      done = true;
      try { socket.destroy(); } catch { /* ignore */ }
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.on('connect', () => finish({ reachable: true, latencyMs: Date.now() - start }));
    socket.on('timeout', () => finish({ reachable: false, error: '连接超时' }));
    socket.on('error', (err) => finish({ reachable: false, error: err.code || err.message }));
  });
}

function openFirewallPorts(ports = []) {
  const uniquePorts = [...new Set(ports.map(Number).filter((p) => Number.isInteger(p) && p > 0 && p <= 65535))];
  const logs = [];
  const ufwBin = findCmd('ufw');
  const fwCmdBin = findCmd('firewall-cmd');
  const iptBin = findCmd('iptables');
  const ip6tBin = findCmd('ip6tables');

  for (const p of uniquePorts) {
    if (ufwBin) {
      try {
        spawnSync(ufwBin, ['allow', `${p}/tcp`], { env: SYS_ENV, timeout: 3000 });
        spawnSync(ufwBin, ['allow', `${p}/udp`], { env: SYS_ENV, timeout: 3000 });
        logs.push(`ufw allow ${p}/tcp & udp`);
      } catch { /* ignore */ }
    }
    if (fwCmdBin) {
      try {
        spawnSync(fwCmdBin, ['--permanent', `--add-port=${p}/tcp`], { env: SYS_ENV, timeout: 3000 });
        spawnSync(fwCmdBin, ['--permanent', `--add-port=${p}/udp`], { env: SYS_ENV, timeout: 3000 });
        logs.push(`firewall-cmd add-port ${p}`);
      } catch { /* ignore */ }
    }
    if (iptBin) {
      try {
        if (spawnSync(iptBin, ['-C', 'INPUT', '-p', 'tcp', '--dport', String(p), '-j', 'ACCEPT'], { env: SYS_ENV, timeout: 2000 }).status !== 0) {
          spawnSync(iptBin, ['-I', 'INPUT', '-p', 'tcp', '--dport', String(p), '-j', 'ACCEPT'], { env: SYS_ENV, timeout: 2000 });
        }
        if (spawnSync(iptBin, ['-C', 'INPUT', '-p', 'udp', '--dport', String(p), '-j', 'ACCEPT'], { env: SYS_ENV, timeout: 2000 }).status !== 0) {
          spawnSync(iptBin, ['-I', 'INPUT', '-p', 'udp', '--dport', String(p), '-j', 'ACCEPT'], { env: SYS_ENV, timeout: 2000 });
        }
        logs.push(`iptables ACCEPT ${p}`);
      } catch { /* ignore */ }
    }
    if (ip6tBin) {
      try {
        if (spawnSync(ip6tBin, ['-C', 'INPUT', '-p', 'tcp', '--dport', String(p), '-j', 'ACCEPT'], { env: SYS_ENV, timeout: 2000 }).status !== 0) {
          spawnSync(ip6tBin, ['-I', 'INPUT', '-p', 'tcp', '--dport', String(p), '-j', 'ACCEPT'], { env: SYS_ENV, timeout: 2000 });
        }
        if (spawnSync(ip6tBin, ['-C', 'INPUT', '-p', 'udp', '--dport', String(p), '-j', 'ACCEPT'], { env: SYS_ENV, timeout: 2000 }).status !== 0) {
          spawnSync(ip6tBin, ['-I', 'INPUT', '-p', 'udp', '--dport', String(p), '-j', 'ACCEPT'], { env: SYS_ENV, timeout: 2000 });
        }
      } catch { /* ignore */ }
    }
  }
  if (fwCmdBin) {
    try { spawnSync(fwCmdBin, ['--reload'], { env: SYS_ENV, timeout: 4000 }); } catch { /* ignore */ }
  }
  return { openedPorts: uniquePorts, logs };
}

/**
 * Cleans up system journald logs, temporary files, and triggers V8 garbage collection
 * to protect relay servers from running out of disk or memory.
 */
function cleanupSystemLogsAndMemory(singboxManager = null, storeObj = null) {
  const actions = [];
  const jctlBin = findCmd('journalctl');
  if (jctlBin) {
    try {
      spawnSync(jctlBin, ['--vacuum-size=32M'], { env: SYS_ENV, timeout: 5000 });
      spawnSync(jctlBin, ['--vacuum-time=2d'], { env: SYS_ENV, timeout: 5000 });
      actions.push('journald 系统日志已压缩至 <=32MB');
    } catch { /* ignore */ }
  }

  // Clean stale /tmp/ng-* temporary directories (> 1 hour old, never touching active migrations or certs)
  try {
    const tmpRoot = os.tmpdir();
    const now = Date.now();
    for (const entry of fs.readdirSync(tmpRoot)) {
      if (entry === 'nexusgate-certs' || entry === 'ng-certs' || entry === 'ng-restored-certs') continue;
      if (entry.startsWith('ng-') || entry.startsWith('x-ui-import-')) {
        const fullTmp = path.join(tmpRoot, entry);
        try {
          const st = fs.statSync(fullTmp);
          if (now - st.mtimeMs > 3600 * 1000) {
            fs.rmSync(fullTmp, { recursive: true, force: true });
          }
        } catch { /* ignore */ }
      }
    }
    actions.push('过期临时安装包与解压缓存目录已清理');
  } catch { /* ignore */ }

  if (singboxManager) {
    if (singboxManager.logRing.length > 50) {
      singboxManager.logRing.splice(0, singboxManager.logRing.length - 50);
    }
    actions.push('面板内存日志环已精简 (保持活跃连接零中断)');
  }

  if (storeObj && Array.isArray(storeObj.state?.audit) && storeObj.state.audit.length > 50) {
    storeObj.state.audit.length = 50;
    storeObj.save();
  }

  certMetaCache.clear();
  if (typeof global.gc === 'function') {
    try { global.gc(); actions.push('V8 垃圾回收 (GC) 已触发'); } catch { /* ignore */ }
  }

  return {
    ok: true,
    actions,
    panelMemoryBytes: process.memoryUsage().rss,
    disk: getDiskUsage()
  };
}

module.exports = {
  getSystemStatus,
  getAccelerationStatus,
  applyKernelAcceleration,
  inspectCertificate,
  discoverSystemCertificates,
  issueSelfSignedCert,
  saveCustomCert,
  issueAcmeCert,
  tcpPingHostPort,
  openFirewallPorts,
  cleanupSystemLogsAndMemory
};
