'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');

// Proven non-Cloudflare, non-Microsoft TLS 1.3 + H2 targets for Sing-box VLESS Reality
const REALITY_PRESETS = Object.freeze([
  { id: 'tesla', label: 'Tesla (tesla.com · 默认推荐)', serverName: 'tesla.com', target: 'www.tesla.com:443' },
  { id: 'tesla-www', label: 'Tesla 官网 (www.tesla.com)', serverName: 'www.tesla.com', target: 'www.tesla.com:443' },
  { id: 'apple', label: 'Apple 官网 (www.apple.com)', serverName: 'www.apple.com', target: 'www.apple.com:443' },
  { id: 'itunes', label: 'Apple iTunes (itunes.apple.com)', serverName: 'itunes.apple.com', target: 'itunes.apple.com:443' },
  { id: 'aws', label: 'Amazon AWS (aws.amazon.com)', serverName: 'aws.amazon.com', target: 'aws.amazon.com:443' },
  { id: 'amd', label: 'AMD (www.amd.com)', serverName: 'www.amd.com', target: 'www.amd.com:443' },
  { id: 'nvidia', label: 'NVIDIA (www.nvidia.com)', serverName: 'www.nvidia.com', target: 'www.nvidia.com:443' },
  { id: 'lovelive', label: 'LoveLive JP (www.lovelive-anime.jp · 日本机推荐)', serverName: 'www.lovelive-anime.jp', target: 'www.lovelive-anime.jp:443' }
]);

const SS_METHODS = Object.freeze([
  { id: '2022-blake3-aes-128-gcm', label: '2022-blake3-aes-128-gcm (SS2022 128位 · 推荐)', keyBytes: 16, is2022: true },
  { id: '2022-blake3-aes-256-gcm', label: '2022-blake3-aes-256-gcm (SS2022 256位)', keyBytes: 32, is2022: true },
  { id: '2022-blake3-chacha20-poly1305', label: '2022-blake3-chacha20-poly1305 (SS2022 ChaCha20)', keyBytes: 32, is2022: true },
  { id: 'aes-128-gcm', label: 'aes-128-gcm (经典 AEAD 128位)', keyBytes: 16, is2022: false },
  { id: 'aes-256-gcm', label: 'aes-256-gcm (经典 AEAD 256位)', keyBytes: 24, is2022: false },
  { id: 'chacha20-ietf-poly1305', label: 'chacha20-ietf-poly1305 (经典 ChaCha20)', keyBytes: 24, is2022: false }
]);

const INBOUND_PROTOCOLS = Object.freeze([
  { id: 'vless', name: 'VLESS (Reality / TLS / WS / gRPC)', badge: 'VLESS', desc: '支持 Reality Vision 免证书、WebSocket、gRPC 与标准 TLS' },
  { id: 'anytls', name: 'AnyTLS (Sing-box 原生伪装填充)', badge: 'AnyTLS', desc: 'Sing-box 1.12+ 强特征消除协议，支持 TLS 与自适应长度填充' },
  { id: 'hysteria2', name: 'Hysteria 2 (HY2 高速 QUIC UDP)', badge: 'HY2', desc: '基于 QUIC 的高速抗丢包 UDP 协议，支持 Salamander 混淆与带宽控制' },
  { id: 'shadowsocks', name: 'Shadowsocks (SS 128/256 & SS 2022)', badge: 'SS/SS2022', desc: '支持 AES-128-GCM、AES-256-GCM 及 2022-blake3-aes-128/256-gcm' },
  { id: 'socks', name: 'SOCKS5 (标准代理 / 中转入口)', badge: 'SOCKS5', desc: '支持账号密码认证与 UDP 转发，常用于内网或前置中转接入' },
  { id: 'mixed', name: 'Mixed (SOCKS5 + HTTP 混合代理)', badge: 'MIXED', desc: '同端口同时支持 SOCKS5 与 HTTP 代理' },
  { id: 'trojan', name: 'Trojan (TLS / Reality / WS)', badge: 'Trojan', desc: '经典 TLS 伪装协议，支持证书 TLS、Reality 或 WebSocket 传输' },
  { id: 'vmess', name: 'VMess (TCP / WS / TLS / gRPC)', badge: 'VMess', desc: '广泛兼容主流客户端，支持 WebSocket + TLS 或中转隧道' },
  { id: 'tuic', name: 'TUIC v5 (QUIC 0-RTT UDP)', badge: 'TUIC', desc: '基于 QUIC 的低延迟 UDP 协议，支持 BBR 拥塞控制' },
  { id: 'direct', name: 'Direct 端口转发 (Dokodemo 隧道中转)', badge: '端口转发', desc: '将本机端口 TCP/UDP 流量直接转发至目标 IP:Port 或通过指定出站中转' }
]);

const OUTBOUND_PROTOCOLS = Object.freeze([
  { id: 'shadowsocks', name: 'Shadowsocks 出站 (SS 128/256 / SS 2022)' },
  { id: 'vless', name: 'VLESS 出站 (Reality / TLS / WS / TCP)' },
  { id: 'anytls', name: 'AnyTLS 出站 (TLS)' },
  { id: 'hysteria2', name: 'Hysteria 2 出站 (UDP QUIC)' },
  { id: 'socks', name: 'SOCKS5 出站' },
  { id: 'trojan', name: 'Trojan 出站' },
  { id: 'vmess', name: 'VMess 出站' },
  { id: 'tuic', name: 'TUIC v5 出站' },
  { id: 'http', name: 'HTTP/HTTPS 代理出站' },
  { id: 'urltest', name: 'URLTest 自动测速负载均衡组' },
  { id: 'selector', name: 'Selector 手动/故障切换出站组' },
  { id: 'direct', name: 'Direct 本地直连 (Freedom)' },
  { id: 'block', name: 'Block 黑洞拦截 (Blackhole)' }
]);

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const certSelfSignedCache = new Map();
const certDomainCache = new Map();
const realityPubKeyCache = new Map();
const clientLinksCache = new Map();

function isValidUuid(str) {
  return UUID_REGEX.test(String(str || '').trim());
}

function ensureUuid(str) {
  const s = String(str || '').trim();
  return isValidUuid(s) ? s : crypto.randomUUID();
}

function normalizeSsMethod(method = '2022-blake3-aes-128-gcm') {
  const m = String(method || '2022-blake3-aes-128-gcm').trim().toLowerCase();
  if (m === 'chacha20-poly1305') return 'chacha20-ietf-poly1305';
  if (m === 'xchacha20-poly1305') return 'xchacha20-ietf-poly1305';
  return m;
}

function sanitizeSsOutboundPasswordAndMethod(rawMethod, rawPassword) {
  let method = normalizeSsMethod(rawMethod || 'aes-128-gcm');
  let password = String(rawPassword || '');
  // 1) Heal %3D%3D Base64 corruption which appended "\r\ufffd\ufffd" to passwords
  if (/[\r\n\ufffd]+$/.test(password)) {
    password = password.replace(/[\r\n\ufffd]+$/, '');
  }
  // 2) Heal %3D Base64 corruption which appended "7" to 36-char UUID passwords or Base64 keys
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}7$/i.test(password)) {
    password = password.slice(0, 36);
  } else if (/^[A-Za-z0-9+/]{22}==7$/.test(password) || /^[A-Za-z0-9+/]{43}=7$/.test(password)) {
    password = password.slice(0, -1);
  }
  // 3) Decode percent-encoded characters (%2F, %2B, %3D) if present
  if (/%[0-9A-Fa-f]{2}/.test(password)) {
    try { password = decodeURIComponent(password); } catch { /* ignore */ }
  }
  password = password.trim();
  // 4) If method is set to 2022-blake3-* but password is a plain non-Base64 string (e.g. "233boy.com" or UUID), fall back to aes-128-gcm so Sing-box never fails key length check
  if (method.startsWith('2022-') && password) {
    const reqBytes = method.includes('128') ? 16 : 32;
    let validB64 = false;
    try {
      const buf = Buffer.from(password, 'base64');
      validB64 = buf.length === reqBytes && buf.toString('base64') === password;
    } catch { validB64 = false; }
    if (!validB64) {
      method = 'aes-128-gcm';
    }
  }
  return { method, password };
}

function generateRealityKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const privJwk = privateKey.export({ format: 'jwk' });
  const pubJwk = publicKey.export({ format: 'jwk' });
  return {
    privateKey: privJwk.d,
    publicKey: pubJwk.x
  };
}

function deriveRealityPublicKey(privateKeyStr) {
  if (!privateKeyStr) return '';
  const trimmed = String(privateKeyStr).trim();
  if (realityPubKeyCache.has(trimmed)) return realityPubKeyCache.get(trimmed);
  try {
    const rawPriv = Buffer.from(trimmed, 'base64url');
    if (rawPriv.length !== 32) return '';
    const pkcs8Header = Buffer.from('302e020100300506032b656e04220420', 'hex');
    const privObj = crypto.createPrivateKey({
      key: Buffer.concat([pkcs8Header, rawPriv]),
      format: 'der',
      type: 'pkcs8'
    });
    const pub = crypto.createPublicKey(privObj).export({ format: 'jwk' }).x;
    if (realityPubKeyCache.size > 256) realityPubKeyCache.clear();
    realityPubKeyCache.set(trimmed, pub);
    return pub;
  } catch {
    return '';
  }
}

function generateSsKey(method = '2022-blake3-aes-128-gcm') {
  const normMethod = normalizeSsMethod(method);
  const spec = SS_METHODS.find((m) => m.id === normMethod);
  if (spec && spec.is2022) {
    return crypto.randomBytes(spec.keyBytes).toString('base64');
  }
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = crypto.randomBytes(22);
  let out = '';
  for (let i = 0; i < 22; i += 1) out += chars[bytes[i] % chars.length];
  return out;
}

/**
 * Ensures that a Shadowsocks password is valid for the selected cipher method.
 * Specifically, SS-2022 methods require exact-length Base64 PSKs (16 bytes for 128-gcm, 32 bytes for 256-gcm/chacha20).
 * If a plain string or wrong-length Base64 key is passed, deterministically derives a compliant Base64 key of exact byte length.
 */
function ensureSsPassword(method = '2022-blake3-aes-128-gcm', rawPassword = '') {
  const normMethod = normalizeSsMethod(method);
  const spec = SS_METHODS.find((m) => m.id === normMethod);
  const trimmed = String(rawPassword || '').trim();
  if (!spec || !spec.is2022) {
    return trimmed || generateSsKey(normMethod);
  }
  if (!trimmed) {
    return crypto.randomBytes(spec.keyBytes).toString('base64');
  }
  // Check if trimmed is already a valid Base64 key of exact spec.keyBytes
  try {
    const buf = Buffer.from(trimmed, 'base64');
    if (buf.length === spec.keyBytes && buf.toString('base64') === trimmed) {
      return trimmed;
    }
  } catch { /* derive below */ }
  // Deterministic SHA-256 derivation so inbound & client links stay 100% in sync
  return crypto.createHash('sha256').update(trimmed).digest().subarray(0, spec.keyBytes).toString('base64');
}

function generateShortId() {
  return crypto.randomBytes(4).toString('hex');
}

function uriHost(address) {
  const str = String(address || '127.0.0.1').trim();
  if (str.startsWith('[') && str.endsWith(']')) return str;
  return net.isIP(str) === 6 ? `[${str}]` : str;
}

function parseTargetHostPort(target = 'www.apple.com:443', defaultServerName = 'www.apple.com') {
  const str = String(target || '').trim();
  if (!str) return { server: defaultServerName, server_port: 443 };
  const idx = str.lastIndexOf(':');
  if (idx > 0 && !str.endsWith(']')) {
    const host = str.slice(0, idx).replace(/^\[|\]$/g, '');
    const port = Number(str.slice(idx + 1)) || 443;
    return { server: host || defaultServerName, server_port: port };
  }
  return { server: str, server_port: 443 };
}

function inferDomainFromCertPath(certPath) {
  if (!certPath) return '';
  if (certDomainCache.has(certPath)) return certDomainCache.get(certPath);
  let domain = '';
  if (fs.existsSync(certPath)) {
    try {
      const x509 = new crypto.X509Certificate(fs.readFileSync(certPath, 'utf8'));
      const sanMatch = String(x509.subjectAltName || '').match(/DNS:([^\s,]+)/);
      const cnMatch = String(x509.subject || '').match(/CN=([^\s,\n/]+)/);
      domain = (sanMatch && sanMatch[1]) || (cnMatch && cnMatch[1]) || '';
    } catch { /* ignore */ }
  }
  if (!domain) {
    const dirName = path.basename(path.dirname(certPath));
    if (dirName && dirName.includes('.') && !['certs', 'cert', 'selfsigned', 'etc', 'root'].includes(dirName)) {
      domain = dirName;
    }
  }
  if (domain) {
    if (certDomainCache.size > 64) certDomainCache.clear();
    certDomainCache.set(certPath, domain);
  }
  return domain;
}

function isCertFileSelfSigned(certPath) {
  if (!certPath || !fs.existsSync(certPath)) return true;
  if (certPath.includes('selfsigned')) return true;
  try {
    const stat = fs.statSync(certPath);
    const cacheKey = `${certPath}:${stat.mtimeMs}`;
    if (certSelfSignedCache.has(cacheKey)) {
      return certSelfSignedCache.get(cacheKey);
    }
    const x509 = new crypto.X509Certificate(fs.readFileSync(certPath, 'utf8'));
    const isSelf = String(x509.issuer || '') === String(x509.subject || '');
    if (certSelfSignedCache.size > 64) certSelfSignedCache.clear();
    certSelfSignedCache.set(cacheKey, isSelf);
    return isSelf;
  } catch {
    return true;
  }
}

/**
 * Resolves the active certificate and SNI domain for a standard TLS inbound.
 * Automatically infers domain from certificate file if inbound.tlsDomain is empty (e.g. migrated 3x-ui WS+TLS nodes).
 */
function certMatchesDomain(certDomain = '', targetDomain = '') {
  const cd = String(certDomain || '').trim().toLowerCase();
  const td = String(targetDomain || '').trim().toLowerCase();
  if (!cd || !td) return false;
  if (cd === td) return true;
  if (cd.startsWith('*.') && td.endsWith(cd.slice(1)) && td.split('.').length >= cd.split('.').length) {
    return true;
  }
  return false;
}

function resolveInboundCertAndDomain(inbound, certificates = [], defaultSettings = {}) {
  const preferredDomain = inbound.tlsDomain || defaultSettings.webDomain || defaultSettings.defaultTlsDomain || '';
  const domainMatchedCert = preferredDomain
    ? (certificates.find((c) => certMatchesDomain(c.domain, preferredDomain) && c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false) ||
       certificates.find((c) => certMatchesDomain(c.domain, preferredDomain)))
    : null;
  const anyNonSelfCert = certificates.find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false);
  const nonSelfCert = domainMatchedCert || (!preferredDomain ? anyNonSelfCert : null);

  let certPath = inbound.certPath || '';
  let keyPath = inbound.keyPath || '';
  let domain = inbound.tlsDomain || '';

  if (!domain && certPath) {
    domain = inferDomainFromCertPath(certPath);
  }
  if (!domain && preferredDomain) {
    domain = preferredDomain;
  }

  const certRecordByPath = certPath ? certificates.find((c) => c.certPath === certPath) : null;
  const hasEmbeddedPem = Boolean(certRecordByPath && certRecordByPath.certPem && certRecordByPath.keyPem);
  const filesExist = Boolean((certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath)) || hasEmbeddedPem);
  const curIsSelf = !filesExist || (certRecordByPath ? Boolean(certRecordByPath.type === 'self-signed' || certRecordByPath.isSelfSigned) : isCertFileSelfSigned(certPath));

  if (domainMatchedCert && (!filesExist || curIsSelf || (certRecordByPath && !certMatchesDomain(certRecordByPath.domain, preferredDomain)))) {
    certPath = domainMatchedCert.certPath;
    keyPath = domainMatchedCert.keyPath;
    domain = preferredDomain || domainMatchedCert.domain;
  } else if (nonSelfCert && (curIsSelf || domain === 'www.bing.com' || domain === 'www.apple.com' || !domain)) {
    if (!filesExist || curIsSelf) {
      certPath = nonSelfCert.certPath;
      keyPath = nonSelfCert.keyPath;
    }
    domain = domain && domain !== 'www.bing.com' && domain !== 'www.apple.com' ? domain : nonSelfCert.domain;
  }

  if ((!certPath || !keyPath || !filesExist) && domain) {
    const matched = certificates.find((c) => certMatchesDomain(c.domain, domain) && c.certPath && (c.certPem || fs.existsSync(c.certPath)));
    if (matched) {
      certPath = matched.certPath;
      keyPath = matched.keyPath;
    }
  }

  if (!certPath || !keyPath || (!filesExist && !domainMatchedCert)) {
    if (domainMatchedCert) {
      certPath = domainMatchedCert.certPath;
      keyPath = domainMatchedCert.keyPath;
      domain = domain || preferredDomain || domainMatchedCert.domain;
    } else if (nonSelfCert) {
      certPath = nonSelfCert.certPath;
      keyPath = nonSelfCert.keyPath;
      domain = domain || nonSelfCert.domain;
    } else if (defaultSettings.defaultCertFile && defaultSettings.defaultKeyFile && fs.existsSync(defaultSettings.defaultCertFile)) {
      certPath = defaultSettings.defaultCertFile;
      keyPath = defaultSettings.defaultKeyFile;
      domain = domain || defaultSettings.defaultTlsDomain || defaultSettings.webDomain || inferDomainFromCertPath(certPath) || 'www.apple.com';
    } else if (anyNonSelfCert?.certPath && anyNonSelfCert?.keyPath) {
      certPath = anyNonSelfCert.certPath;
      keyPath = anyNonSelfCert.keyPath;
      domain = domain || anyNonSelfCert.domain || 'www.apple.com';
    } else if (certificates[0]?.certPath && certificates[0]?.keyPath) {
      certPath = certificates[0].certPath;
      keyPath = certificates[0].keyPath;
      domain = domain || certificates[0].domain || 'www.apple.com';
    } else {
      certPath = '/etc/nexusgate/certs/selfsigned/fullchain.pem';
      keyPath = '/etc/nexusgate/certs/selfsigned/privkey.pem';
      domain = domain || defaultSettings.webDomain || 'www.apple.com';
    }
  }

  if (!domain && certPath) {
    domain = inferDomainFromCertPath(certPath);
  }

  const matchedCertObj = certificates.find((c) => c.certPath === certPath || (domain && certMatchesDomain(c.domain, domain)));
  const isSelfSigned = Boolean(
    inbound.allowInsecure === true ||
    (matchedCertObj ? (matchedCertObj.type === 'self-signed' || matchedCertObj.isSelfSigned) : isCertFileSelfSigned(certPath))
  );

  return { certPath, keyPath, domain: domain || 'www.apple.com', isSelfSigned };
}

/**
 * Converts a panel Inbound object into a native Sing-box inbound configuration object.
 */
function toSingboxInbound(inbound, certificates = [], defaultSettings = {}) {
  const listen = inbound.listen || '::';
  const port = Number(inbound.port);
  const tag = inbound.tag || `in-${inbound.protocol}-${port}`;
  const base = {
    type: inbound.protocol,
    tag,
    listen,
    listen_port: port
  };

  const activeClients = (inbound.clients || []).filter((c) => c.enable !== false);
  const tlsConfig = buildInboundTls(inbound, certificates, defaultSettings);
  const transportConfig = buildInboundTransport(inbound);

  switch (inbound.protocol) {
    case 'vless': {
      const isReality = inbound.security === 'reality';
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || `user_${ensureUuid(c.id || c.uuid).slice(0, 6)}`,
          uuid: ensureUuid(c.id || c.uuid),
          flow: (isReality || inbound.security === 'tls') && (!inbound.transport || inbound.transport === 'tcp')
            ? (c.flow ?? inbound.flow ?? '')
            : ''
        })).map((u) => {
          if (!u.flow) delete u.flow;
          return u;
        }),
        ...(tlsConfig ? { tls: tlsConfig } : {}),
        ...(transportConfig ? { transport: transportConfig } : {})
      };
    }

    case 'anytls': {
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'anytls_user',
          password: c.password || inbound.password || generateSsKey('aes-128-gcm')
        })),
        padding_scheme: Array.isArray(inbound.paddingScheme) && inbound.paddingScheme.length
          ? inbound.paddingScheme
          : undefined,
        tls: tlsConfig
      };
    }

    case 'hysteria2': {
      const hy2 = {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'hy2_user',
          password: c.password || inbound.password || generateSsKey('aes-128-gcm')
        })),
        tls: tlsConfig
      };
      if (Number(inbound.upMbps) > 0) hy2.up_mbps = Number(inbound.upMbps);
      if (Number(inbound.downMbps) > 0) hy2.down_mbps = Number(inbound.downMbps);
      if (inbound.obfsPassword) {
        hy2.obfs = { type: 'salamander', password: inbound.obfsPassword };
      }
      if (inbound.masquerade) {
        hy2.masquerade = inbound.masquerade;
      }
      return hy2;
    }

    case 'shadowsocks': {
      const method = normalizeSsMethod(inbound.method || '2022-blake3-aes-128-gcm');
      const is2022 = method.startsWith('2022-');
      const firstClientPass = activeClients[0]?.password || '';
      const rawServerPass = is2022
        ? (inbound.password || firstClientPass)
        : (firstClientPass || inbound.password);
      const serverPassword = ensureSsPassword(method, rawServerPass);

      const ss = {
        ...base,
        network: inbound.network === 'tcp' || inbound.network === 'udp' ? inbound.network : undefined,
        method,
        password: serverPassword
      };

      if ((inbound.clients || []).length > 1 && activeClients.length > 0) {
        ss.users = activeClients.map((c) => ({
          name: c.email || c.name || 'ss_user',
          password: is2022 ? ensureSsPassword(method, c.password || serverPassword) : (c.password || serverPassword)
        }));
      }
      return ss;
    }

    case 'socks':
    case 'mixed':
    case 'http': {
      const users = activeClients
        .filter((c) => (c.username || c.email) && c.password)
        .map((c) => ({
          username: c.username || c.email,
          password: c.password
        }));
      if (!users.length && inbound.socksUser && inbound.socksPassword) {
        users.push({ username: inbound.socksUser, password: inbound.socksPassword });
      }
      return {
        ...base,
        ...(users.length ? { users } : {})
      };
    }

    case 'trojan': {
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'trojan_user',
          password: c.password || inbound.password || generateSsKey('aes-128-gcm')
        })),
        ...(tlsConfig ? { tls: tlsConfig } : {}),
        ...(transportConfig ? { transport: transportConfig } : {})
      };
    }

    case 'vmess': {
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'vmess_user',
          uuid: ensureUuid(c.id || c.uuid),
          alterId: Number(c.alterId || 0)
        })),
        ...(tlsConfig ? { tls: tlsConfig } : {}),
        ...(transportConfig ? { transport: transportConfig } : {})
      };
    }

    case 'tuic': {
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'tuic_user',
          uuid: ensureUuid(c.id || c.uuid),
          password: c.password || inbound.password || ''
        })),
        congestion_control: inbound.congestionControl || 'bbr',
        tls: tlsConfig
      };
    }

    case 'direct': {
      const d = {
        ...base,
        network: inbound.network === 'tcp' || inbound.network === 'udp' ? inbound.network : undefined
      };
      if (inbound.overrideAddress) d.override_address = inbound.overrideAddress;
      if (Number(inbound.overridePort) > 0) d.override_port = Number(inbound.overridePort);
      return d;
    }

    default:
      return base;
  }
}

function buildInboundTls(inbound, certificates = [], defaultSettings = {}) {
  const security = inbound.security || (['anytls', 'hysteria2', 'tuic'].includes(inbound.protocol) ? 'tls' : 'none');
  if (security === 'none') return null;

  if (security === 'reality') {
    const r = inbound.reality || {};
    let serverName = r.serverName || (Array.isArray(r.serverNames) && r.serverNames[0]) || 'tesla.com';
    if (['www.cloudflare.com', 'cloudflare.com', 'www.bing.com', 'bing.com', 'www.yahoo.com', 'yahoo.com', 'dl.google.com'].includes(serverName.toLowerCase())) {
      serverName = 'tesla.com';
    }
    const defaultTarget = serverName === 'tesla.com' ? 'www.tesla.com:443' : `${serverName}:443`;
    const rawTarget = (r.target && !/cloudflare\.com|bing\.com|yahoo\.com|dl\.google\.com/i.test(r.target))
      ? r.target
      : defaultTarget;
    const handshake = parseTargetHostPort(rawTarget, serverName);
    const shortIds = Array.isArray(r.shortIds)
      ? r.shortIds
      : String(r.shortIds || r.shortId || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
    return {
      enabled: true,
      server_name: serverName,
      reality: {
        enabled: true,
        handshake,
        private_key: r.privateKey,
        short_id: shortIds.length ? shortIds : ['']
      }
    };
  }

  if (security === 'tls') {
    const resolved = resolveInboundCertAndDomain(inbound, certificates, defaultSettings);
    const tls = {
      enabled: true,
      server_name: resolved.domain,
      certificate_path: resolved.certPath,
      key_path: resolved.keyPath
    };
    const netType = inbound.transport || inbound.streamNetwork || 'tcp';
    if (netType === 'ws' || netType === 'httpupgrade') {
      tls.alpn = ['http/1.1'];
    } else if (inbound.alpn && inbound.alpn.length) {
      tls.alpn = Array.isArray(inbound.alpn) ? inbound.alpn : String(inbound.alpn).split(',').map((s) => s.trim()).filter(Boolean);
    } else if (['hysteria2', 'tuic'].includes(inbound.protocol)) {
      tls.alpn = ['h3'];
    }
    return tls;
  }

  return null;
}

function buildInboundTransport(inbound) {
  const netType = inbound.transport || inbound.streamNetwork || 'tcp';
  if (netType === 'ws') {
    const rawPath = inbound.wsPath || '/';
    const qIdx = rawPath.indexOf('?');
    const cleanPath = qIdx >= 0 ? (rawPath.slice(0, qIdx) || '/') : rawPath;
    const ws = {
      type: 'ws',
      path: cleanPath
    };
    if (inbound.wsHost) {
      ws.headers = { Host: inbound.wsHost };
    }
    if (qIdx >= 0 && rawPath.includes('ed=')) {
      const m = rawPath.match(/ed=(\d+)/);
      if (m) {
        ws.max_early_data = Number(m[1]);
        ws.early_data_header_name = 'Sec-WebSocket-Protocol';
      }
    }
    return ws;
  }
  if (netType === 'grpc') {
    return {
      type: 'grpc',
      service_name: inbound.grpcServiceName || 'grpc'
    };
  }
  if (netType === 'httpupgrade') {
    const hu = {
      type: 'httpupgrade',
      path: inbound.wsPath || '/'
    };
    if (inbound.wsHost) hu.host = inbound.wsHost;
    return hu;
  }
  if (netType === 'http' || netType === 'h2') {
    return {
      type: 'http',
      path: inbound.wsPath || '/',
      ...(inbound.wsHost ? { host: [inbound.wsHost] } : {})
    };
  }
  return null;
}

/**
 * Converts a panel Outbound object into a native Sing-box outbound configuration object.
 */
function toSingboxOutbound(outbound) {
  if (outbound.rawJson && typeof outbound.rawJson === 'object' && outbound.rawJson.type) {
    return { ...outbound.rawJson, tag: outbound.tag };
  }
  if (outbound.type === 'direct' || outbound.type === 'freedom') {
    return { type: 'direct', tag: outbound.tag };
  }
  if (outbound.type === 'block' || outbound.type === 'blackhole') {
    return { type: 'block', tag: outbound.tag };
  }
  if (outbound.type === 'urltest') {
    return {
      type: 'urltest',
      tag: outbound.tag,
      outbounds: Array.isArray(outbound.outbounds) && outbound.outbounds.length ? outbound.outbounds : ['direct'],
      url: outbound.url || 'https://www.gstatic.com/generate_204',
      interval: outbound.interval || '3m'
    };
  }
  if (outbound.type === 'selector') {
    return {
      type: 'selector',
      tag: outbound.tag,
      outbounds: Array.isArray(outbound.outbounds) && outbound.outbounds.length ? outbound.outbounds : ['direct'],
      default: outbound.defaultOutbound || (outbound.outbounds && outbound.outbounds[0]) || 'direct'
    };
  }

  const s = outbound.settings || outbound;
  const base = {
    type: outbound.type,
    tag: outbound.tag,
    server: s.server || outbound.server || '127.0.0.1',
    server_port: Number(s.server_port || s.port || outbound.port || 443)
  };
  if (outbound.detour) {
    base.detour = outbound.detour;
  }

  const tls = buildOutboundTls(outbound);
  const transport = buildOutboundTransport(outbound);

  switch (outbound.type) {
    case 'vless':
      return {
        ...base,
        uuid: ensureUuid(s.uuid || s.id || outbound.uuid),
        ...(s.flow || outbound.flow ? { flow: s.flow || outbound.flow } : {}),
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {})
      };

    case 'anytls':
      return {
        ...base,
        password: s.password || outbound.password || '',
        tls: tls || {
          enabled: true,
          server_name: s.sni || s.server_name || base.server,
          insecure: Boolean(s.insecure || outbound.insecure)
        }
      };

    case 'hysteria2': {
      const hy2 = {
        ...base,
        password: s.password || outbound.password || '',
        tls: tls || {
          enabled: true,
          alpn: ['h3'],
          server_name: s.sni || s.server_name || base.server,
          insecure: Boolean(s.insecure || outbound.insecure)
        }
      };
      if (Number(s.upMbps || outbound.upMbps) > 0) hy2.up_mbps = Number(s.upMbps || outbound.upMbps);
      if (Number(s.downMbps || outbound.downMbps) > 0) hy2.down_mbps = Number(s.downMbps || outbound.downMbps);
      if (s.obfsPassword || outbound.obfsPassword) {
        hy2.obfs = { type: 'salamander', password: s.obfsPassword || outbound.obfsPassword };
      }
      return hy2;
    }

    case 'shadowsocks': {
      const cleanSs = sanitizeSsOutboundPasswordAndMethod(
        s.method || outbound.method || 'aes-128-gcm',
        s.password || outbound.password || ''
      );
      const ssOut = {
        ...base,
        method: cleanSs.method,
        password: cleanSs.password
      };
      if (s.uot || outbound.uot) {
        ssOut.udp_over_tcp = true;
      }
      return ssOut;
    }

    case 'socks': {
      const sk = {
        ...base,
        version: '5'
      };
      if (s.username || outbound.username) sk.username = s.username || outbound.username;
      if (s.password || outbound.password) sk.password = s.password || outbound.password;
      return sk;
    }

    case 'trojan':
      return {
        ...base,
        password: s.password || outbound.password || '',
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {})
      };

    case 'vmess':
      return {
        ...base,
        uuid: ensureUuid(s.uuid || s.id || outbound.uuid),
        security: s.security || outbound.cipher || 'auto',
        alter_id: Number(s.alterId || outbound.alterId || 0),
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {})
      };

    case 'tuic':
      return {
        ...base,
        uuid: ensureUuid(s.uuid || outbound.uuid),
        password: s.password || outbound.password || '',
        congestion_control: s.congestionControl || outbound.congestionControl || 'bbr',
        tls: tls || {
          enabled: true,
          alpn: ['h3'],
          server_name: s.sni || base.server,
          insecure: Boolean(s.insecure || outbound.insecure)
        }
      };

    case 'http': {
      const hp = { ...base };
      if (s.username || outbound.username) hp.username = s.username || outbound.username;
      if (s.password || outbound.password) hp.password = s.password || outbound.password;
      if (tls) hp.tls = tls;
      return hp;
    }

    default:
      return { ...base, ...(s.raw || {}) };
  }
}

function buildOutboundTls(outbound) {
  const s = outbound.settings || outbound;
  const security = s.securityMode || outbound.security || (['anytls', 'hysteria2', 'tuic'].includes(outbound.type) ? 'tls' : 'none');
  if (security === 'none') return null;

  if (security === 'reality') {
    return {
      enabled: true,
      server_name: s.sni || outbound.sni || s.server || outbound.server || 'www.apple.com',
      utls: {
        enabled: true,
        fingerprint: s.fingerprint || outbound.fingerprint || 'chrome'
      },
      reality: {
        enabled: true,
        public_key: s.publicKey || outbound.publicKey || '',
        short_id: s.shortId || outbound.shortId || ''
      }
    };
  }

  if (security === 'tls') {
    const tls = {
      enabled: true,
      server_name: s.sni || outbound.sni || s.server || outbound.server || '',
      insecure: Boolean(s.insecure || outbound.insecure)
    };
    if (s.fingerprint || outbound.fingerprint) {
      tls.utls = { enabled: true, fingerprint: s.fingerprint || outbound.fingerprint };
    }
    if (['hysteria2', 'tuic'].includes(outbound.type)) {
      tls.alpn = ['h3'];
    }
    return tls;
  }
  return null;
}

function buildOutboundTransport(outbound) {
  const s = outbound.settings || outbound;
  const netType = s.transport || outbound.transport || 'tcp';
  if (netType === 'ws') {
    const rawPath = s.wsPath || outbound.wsPath || '/';
    const qIdx = rawPath.indexOf('?');
    const cleanPath = qIdx >= 0 ? (rawPath.slice(0, qIdx) || '/') : rawPath;
    const ws = {
      type: 'ws',
      path: cleanPath,
      ...(s.wsHost || outbound.wsHost ? { headers: { Host: s.wsHost || outbound.wsHost } } : {})
    };
    if (qIdx >= 0 && rawPath.includes('ed=')) {
      const m = rawPath.match(/ed=(\d+)/);
      if (m) {
        ws.max_early_data = Number(m[1]);
        ws.early_data_header_name = 'Sec-WebSocket-Protocol';
      }
    }
    return ws;
  }
  if (netType === 'grpc') {
    return {
      type: 'grpc',
      service_name: s.grpcServiceName || outbound.grpcServiceName || 'grpc'
    };
  }
  if (netType === 'httpupgrade') {
    return {
      type: 'httpupgrade',
      path: s.wsPath || outbound.wsPath || '/',
      ...(s.wsHost || outbound.wsHost ? { host: s.wsHost || outbound.wsHost } : {})
    };
  }
  return null;
}

/**
 * Generates client share links (URI), Clash/Mihomo YAML snippets, and Sing-box JSON snippets.
 */
function buildClientLinks(inbound, publicHost = '127.0.0.1', certificates = [], defaultSettings = {}) {
  const resolvedTls = resolveInboundCertAndDomain(inbound, certificates, defaultSettings);
  const nonSelfCert0 = certificates.find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false);
  const sigClients = (inbound.clients || []).map((c) => `${c.id}:${c.email}:${c.username}:${c.password}:${c.flow}:${c.subId}:${c.enable}:${c.limitIp}:${c.limitDevice}:${c.totalBytes}:${c.expiryTime}`).join('|');
  const cacheSig = `${inbound.id}|${inbound.remark}|${inbound.tag}|${inbound.protocol}|${inbound.port}|${inbound.security}|${inbound.transport}|${inbound.flow}|${inbound.method}|${inbound.password}|${inbound.socksUser}|${inbound.socksPassword}|${inbound.wsPath}|${inbound.wsHost}|${inbound.grpcServiceName}|${inbound.obfsPassword}|${inbound.publicHost}|${publicHost}|${defaultSettings.webDomain}|${nonSelfCert0?.domain}|${resolvedTls.domain}|${resolvedTls.certPath}|${resolvedTls.isSelfSigned}|${JSON.stringify(inbound.reality || {})}|${sigClients}`;
  const cachedEntry = inbound.id ? clientLinksCache.get(inbound.id) : null;
  if (cachedEntry && cachedEntry.sig === cacheSig) {
    const clientMap = new Map((inbound.clients || []).map((c) => [c.id || c.email, c]));
    return cachedEntry.links.map((l) => {
      const c = clientMap.get(l.clientId) || clientMap.get(l.clientName);
      return c ? { ...l, up: Number(c.up || 0), down: Number(c.down || 0) } : l;
    });
  }
  const preferredNodeDomain = defaultSettings.webDomain || '';
  // If publicHost is explicitly provided (such as a remote Relay server's pure IP or distinct domain),
  // it must take precedence over master's unrelated TLS certificates!
  const isExplicitNodeHost = Boolean(publicHost && publicHost !== '127.0.0.1' && publicHost !== defaultSettings.webDomain);
  const nonSelfCert =
    (preferredNodeDomain && certificates.find((c) => c.domain === preferredNodeDomain && c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false)) ||
    (!isExplicitNodeHost && certificates.find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false));
  const realDomain = preferredNodeDomain || (nonSelfCert ? nonSelfCert.domain : '') || (inbound.security === 'tls' && !resolvedTls.isSelfSigned ? resolvedTls.domain : '');
  const connectAddr = inbound.publicHost || (isExplicitNodeHost ? publicHost : (realDomain || publicHost || '127.0.0.1'));
  const host = uriHost(connectAddr);
  const rawServer = connectAddr.replace(/^\[|\]$/g, '');
  const port = Number(inbound.port);
  const isSelfSigned = resolvedTls.isSelfSigned;
  const sniDomain = resolvedTls.domain;

  const clients = (inbound.clients && inbound.clients.length)
    ? inbound.clients
    : [{ email: inbound.remark || inbound.tag, id: ensureUuid(inbound.uuid), password: inbound.password }];

  const links = [];

  for (const client of clients) {
    if (client.enable === false) continue;
    const labelName = clients.length === 1
      ? (inbound.remark || inbound.tag)
      : `${inbound.remark || inbound.tag}-${client.email || client.name || 'client'}`;
    const label = encodeURIComponent(labelName);
    let uri = '';
    let altUri = '';
    let clashProxy = null;
    let singboxOut = null;

    const transport = inbound.transport || 'tcp';
    const wsOptsClash = (transport === 'ws' || transport === 'httpupgrade')
      ? { 'ws-opts': { path: inbound.wsPath || '/', ...(inbound.wsHost ? { headers: { Host: inbound.wsHost } } : {}) } }
      : (transport === 'grpc' ? { 'grpc-opts': { 'grpc-service-name': inbound.grpcServiceName || 'grpc' } } : {});
    const sbTransport = (transport === 'ws' || transport === 'httpupgrade')
      ? (() => {
          const rawP = inbound.wsPath || '/';
          const qI = transport === 'ws' ? rawP.indexOf('?') : -1;
          const cleanP = qI >= 0 ? (rawP.slice(0, qI) || '/') : rawP;
          const tr = { type: transport, path: cleanP };
          if (inbound.wsHost) {
            if (transport === 'httpupgrade') tr.host = inbound.wsHost;
            else tr.headers = { Host: inbound.wsHost };
          }
          if (qI >= 0 && rawP.includes('ed=')) {
            const m = rawP.match(/ed=(\d+)/);
            if (m) {
              tr.max_early_data = Number(m[1]);
              tr.early_data_header_name = 'Sec-WebSocket-Protocol';
            }
          }
          return { transport: tr };
        })()
      : (transport === 'grpc' ? { transport: { type: 'grpc', service_name: inbound.grpcServiceName || 'grpc' } } : {});

    if (inbound.protocol === 'vless') {
      const uuid = ensureUuid(client.id || client.uuid);
      const params = new URLSearchParams({ encryption: 'none', type: transport });
      const flow = (inbound.security === 'reality' || inbound.security === 'tls') && transport === 'tcp'
        ? (client.flow ?? inbound.flow ?? '')
        : '';

      if (inbound.security === 'reality') {
        const r = inbound.reality || {};
        const pubKey = r.publicKey || deriveRealityPublicKey(r.privateKey);
        let sni = r.serverName || (Array.isArray(r.serverNames) && r.serverNames[0]) || 'tesla.com';
        if (['www.cloudflare.com', 'cloudflare.com', 'www.bing.com', 'bing.com', 'www.yahoo.com', 'yahoo.com', 'dl.google.com'].includes(sni.toLowerCase())) sni = 'tesla.com';
        const sid = Array.isArray(r.shortIds) ? (r.shortIds[0] || '') : String(r.shortIds || r.shortId || '').split(',')[0].trim();
        params.set('security', 'reality');
        params.set('sni', sni);
        params.set('fp', r.fingerprint || 'chrome');
        if (pubKey) params.set('pbk', pubKey);
        if (sid) params.set('sid', sid);
        if (flow) params.set('flow', flow);
        params.set('headerType', 'none');

        clashProxy = {
          name: labelName, type: 'vless', server: rawServer, port, uuid, udp: true, tls: true,
          network: transport, ...(flow ? { flow } : {}), servername: sni, 'client-fingerprint': r.fingerprint || 'chrome',
          'reality-opts': { 'public-key': pubKey, 'short-id': sid },
          ...wsOptsClash
        };
        singboxOut = {
          type: 'vless', tag: labelName, server: rawServer, server_port: port, uuid, ...(flow ? { flow } : {}),
          tls: { enabled: true, server_name: sni, utls: { enabled: true, fingerprint: r.fingerprint || 'chrome' }, reality: { enabled: true, public_key: pubKey, short_id: sid } },
          ...sbTransport
        };
      } else if (inbound.security === 'tls') {
        params.set('security', 'tls');
        params.set('sni', sniDomain);
        params.set('fp', 'chrome');
        if (flow) params.set('flow', flow);
        if (isSelfSigned) {
          params.set('allowInsecure', '1');
          params.set('insecure', '1');
        }
        clashProxy = {
          name: labelName, type: 'vless', server: rawServer, port, uuid, udp: true, tls: true,
          network: transport, ...(flow ? { flow } : {}), servername: sniDomain, 'skip-cert-verify': isSelfSigned,
          ...wsOptsClash
        };
        singboxOut = {
          type: 'vless', tag: labelName, server: rawServer, server_port: port, uuid, ...(flow ? { flow } : {}),
          tls: { enabled: true, server_name: sniDomain, insecure: isSelfSigned },
          ...sbTransport
        };
      } else {
        params.set('security', 'none');
        clashProxy = { name: labelName, type: 'vless', server: rawServer, port, uuid, udp: true, tls: false, network: transport, ...wsOptsClash };
        singboxOut = { type: 'vless', tag: labelName, server: rawServer, server_port: port, uuid, ...sbTransport };
      }

      if (transport === 'ws' || transport === 'httpupgrade') {
        params.set('path', inbound.wsPath || '/');
        if (inbound.wsHost) params.set('host', inbound.wsHost);
      } else if (transport === 'grpc') {
        params.set('serviceName', inbound.grpcServiceName || 'grpc');
      }

      uri = `vless://${uuid}@${host}:${port}?${params.toString()}#${label}`;
    } else if (inbound.protocol === 'anytls') {
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ sni: sniDomain, fp: 'chrome' });
      if (isSelfSigned) {
        params.set('insecure', '1');
        params.set('allowInsecure', '1');
      }
      uri = `anytls://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      clashProxy = {
        name: labelName, type: 'anytls', server: rawServer, port, password: pass, udp: true,
        sni: sniDomain, 'client-fingerprint': 'chrome', 'skip-cert-verify': isSelfSigned
      };
      singboxOut = {
        type: 'anytls', tag: labelName, server: rawServer, server_port: port, password: pass,
        tls: { enabled: true, server_name: sniDomain, insecure: isSelfSigned }
      };
    } else if (inbound.protocol === 'hysteria2') {
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ sni: sniDomain, alpn: 'h3' });
      if (isSelfSigned) {
        params.set('insecure', '1');
        params.set('allowInsecure', '1');
      }
      if (inbound.obfsPassword) {
        params.set('obfs', 'salamander');
        params.set('obfs-password', inbound.obfsPassword);
      }
      uri = `hysteria2://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      altUri = `hy2://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      clashProxy = {
        name: labelName, type: 'hysteria2', server: rawServer, port, password: pass,
        sni: sniDomain, alpn: ['h3'], 'skip-cert-verify': isSelfSigned,
        ...(inbound.obfsPassword ? { obfs: 'salamander', 'obfs-password': inbound.obfsPassword } : {})
      };
      singboxOut = {
        type: 'hysteria2', tag: labelName, server: rawServer, server_port: port, password: pass,
        ...(inbound.obfsPassword ? { obfs: { type: 'salamander', password: inbound.obfsPassword } } : {}),
        tls: { enabled: true, alpn: ['h3'], server_name: sniDomain, insecure: isSelfSigned }
      };
    } else if (inbound.protocol === 'shadowsocks') {
      const method = normalizeSsMethod(inbound.method || '2022-blake3-aes-128-gcm');
      const is2022 = method.startsWith('2022-');
      const rawServerPass = is2022 ? (inbound.password || client.password) : (client.password || inbound.password);
      const serverPass = ensureSsPassword(method, rawServerPass);
      let userPass = serverPass;
      if (clients.length > 1) {
        const cPass = is2022 ? ensureSsPassword(method, client.password || serverPass) : (client.password || serverPass);
        userPass = is2022 ? `${serverPass}:${cPass}` : cPass;
      }
      const safeB64 = Buffer.from(`${method}:${userPass}`, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
      uri = `ss://${safeB64}@${host}:${port}#${label}`;
      altUri = `ss://${encodeURIComponent(method)}:${encodeURIComponent(userPass)}@${host}:${port}#${label}`;
      clashProxy = { name: labelName, type: 'ss', server: rawServer, port, cipher: method, password: userPass, udp: true };
      singboxOut = { type: 'shadowsocks', tag: labelName, server: rawServer, server_port: port, method, password: userPass };
    } else if (inbound.protocol === 'socks' || inbound.protocol === 'mixed' || inbound.protocol === 'http') {
      const user = client.username || client.email || inbound.socksUser || '';
      const pass = client.password || inbound.socksPassword || '';
      const scheme = inbound.protocol === 'http' ? 'http' : 'socks';
      if (user && pass) {
        if (scheme === 'http') {
          uri = `http://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}#${label}`;
        } else {
          const safeB64 = Buffer.from(`${user}:${pass}`, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
          uri = `socks://${safeB64}@${host}:${port}#${label}`;
          altUri = `socks5://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}#${label}`;
        }
      } else {
        uri = `${scheme === 'http' ? 'http' : 'socks5'}://${host}:${port}#${label}`;
      }
      clashProxy = {
        name: labelName,
        type: scheme === 'http' ? 'http' : 'socks5',
        server: rawServer,
        port,
        ...(user ? { username: user, password: pass } : {}),
        ...(scheme !== 'http' ? { udp: true } : {})
      };
      singboxOut = {
        type: scheme === 'http' ? 'http' : 'socks',
        tag: labelName,
        server: rawServer,
        server_port: port,
        ...(scheme !== 'http' ? { version: '5' } : {}),
        ...(user ? { username: user, password: pass } : {})
      };
    } else if (inbound.protocol === 'trojan') {
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ type: transport });
      if (inbound.security === 'reality') {
        const r = inbound.reality || {};
        params.set('security', 'reality');
        params.set('sni', r.serverName || 'www.apple.com');
        params.set('pbk', r.publicKey || deriveRealityPublicKey(r.privateKey));
        params.set('sid', Array.isArray(r.shortIds) ? (r.shortIds[0] || '') : String(r.shortIds || '').split(',')[0]);
      } else {
        params.set('security', 'tls');
        params.set('sni', sniDomain);
        if (isSelfSigned) {
          params.set('allowInsecure', '1');
          params.set('insecure', '1');
        }
      }
      if (transport === 'ws') {
        params.set('path', inbound.wsPath || '/');
        if (inbound.wsHost) params.set('host', inbound.wsHost);
      }
      uri = `trojan://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      clashProxy = { name: labelName, type: 'trojan', server: rawServer, port, password: pass, udp: true, sni: sniDomain, 'skip-cert-verify': isSelfSigned, network: transport, ...wsOptsClash };
      singboxOut = { type: 'trojan', tag: labelName, server: rawServer, server_port: port, password: pass, tls: { enabled: true, server_name: sniDomain, insecure: isSelfSigned }, ...sbTransport };
    } else if (inbound.protocol === 'vmess') {
      const uuid = ensureUuid(client.id || client.uuid);
      const vmessJson = {
        v: '2',
        ps: labelName,
        add: rawServer,
        port: String(port),
        id: uuid,
        aid: String(client.alterId || 0),
        scy: 'auto',
        net: transport,
        type: 'none',
        host: inbound.wsHost || (inbound.security === 'tls' ? sniDomain : ''),
        path: inbound.wsPath || inbound.grpcServiceName || '',
        tls: inbound.security === 'tls' ? 'tls' : '',
        sni: inbound.security === 'tls' ? sniDomain : ''
      };
      uri = `vmess://${Buffer.from(JSON.stringify(vmessJson)).toString('base64')}`;
      clashProxy = { name: labelName, type: 'vmess', server: rawServer, port, uuid, alterId: Number(client.alterId || 0), cipher: 'auto', udp: true, tls: inbound.security === 'tls', ...(inbound.security === 'tls' ? { servername: sniDomain, 'skip-cert-verify': isSelfSigned } : {}), network: transport, ...wsOptsClash };
      singboxOut = { type: 'vmess', tag: labelName, server: rawServer, server_port: port, uuid, security: 'auto', alter_id: Number(client.alterId || 0), ...(inbound.security === 'tls' ? { tls: { enabled: true, server_name: sniDomain, insecure: isSelfSigned } } : {}), ...sbTransport };
    } else if (inbound.protocol === 'tuic') {
      const uuid = ensureUuid(client.id || client.uuid);
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ congestion_control: inbound.congestionControl || 'bbr', alpn: 'h3', sni: sniDomain });
      if (isSelfSigned) {
        params.set('allow_insecure', '1');
        params.set('insecure', '1');
      }
      uri = `tuic://${encodeURIComponent(uuid)}:${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      clashProxy = { name: labelName, type: 'tuic', server: rawServer, port, uuid, password: pass, 'congestion-controller': inbound.congestionControl || 'bbr', alpn: ['h3'], sni: sniDomain, 'skip-cert-verify': isSelfSigned };
      singboxOut = { type: 'tuic', tag: labelName, server: rawServer, server_port: port, uuid, password: pass, congestion_control: inbound.congestionControl || 'bbr', tls: { enabled: true, alpn: ['h3'], server_name: sniDomain, insecure: isSelfSigned } };
    }

    if (uri) {
      links.push({
        clientId: client.id || '',
        clientName: client.email || client.name || 'default',
        subId: client.subId || '',
        up: Number(client.up || 0),
        down: Number(client.down || 0),
        totalGB: Number(client.totalGB || 0),
        totalBytes: Number(client.totalBytes || 0),
        expiryTime: Number(client.expiryTime || 0),
        limitIp: Number(client.limitIp || 0),
        limitDevice: Number(client.limitDevice || 0),
        protocol: inbound.protocol,
        name: labelName,
        uri,
        altUri,
        sniDomain,
        isSelfSigned,
        clashYaml: clashProxy ? `  - ${JSON.stringify(clashProxy)}` : '',
        singboxJson: singboxOut ? JSON.stringify(singboxOut, null, 2) : ''
      });
    }
  }

  if (inbound.id) {
    if (clientLinksCache.size > 500) clientLinksCache.clear();
    clientLinksCache.set(inbound.id, { sig: cacheSig, links });
  }
  return links;
}

/**
 * Parses a share URI into a panel Outbound object.
 */
function safeDecUri(val) {
  try { return decodeURIComponent(String(val || '')); } catch { return String(val || ''); }
}

function parseShareUriToOutbound(rawUri, customTag = '', customRemark = '') {
  const uri = String(rawUri || '').trim();
  if (!uri) throw new Error('节点链接不能为空');

  if (uri.startsWith('vmess://')) {
    const b64 = uri.slice(8).trim().replace(/-/g, '+').replace(/_/g, '/');
    const json = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
    const remark = customRemark || json.ps || `VMess-${json.add}:${json.port}`;
    const tag = customTag || remark.replace(/\s+/g, '-') || `out-vmess-${crypto.randomBytes(3).toString('hex')}`;
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'vmess',
      remark,
      enabled: true,
      server: json.add,
      port: Number(json.port || 443),
      uuid: ensureUuid(json.id),
      alterId: Number(json.aid || 0),
      cipher: json.scy || 'auto',
      transport: json.net === 'ws' ? 'ws' : (json.net === 'grpc' ? 'grpc' : 'tcp'),
      wsPath: json.path || '/',
      wsHost: json.host || '',
      security: json.tls === 'tls' ? 'tls' : 'none',
      sni: json.sni || json.host || json.add,
      up: 0,
      down: 0
    };
  }

  if (uri.toLowerCase().startsWith('ss://')) {
    const withoutScheme = uri.slice(5).trim();
    const hashIdx = withoutScheme.indexOf('#');
    const rawHash = hashIdx >= 0 ? withoutScheme.slice(hashIdx + 1) : '';
    const beforeHash = hashIdx >= 0 ? withoutScheme.slice(0, hashIdx) : withoutScheme;
    const qIdx = beforeHash.indexOf('?');
    let mainPart = safeDecUri(qIdx >= 0 ? beforeHash.slice(0, qIdx) : beforeHash).trim();

    if (!mainPart.includes('@')) {
      try {
        const cleanB64 = mainPart.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/=]/g, '');
        const padded = cleanB64 + '='.repeat((4 - (cleanB64.length % 4)) % 4);
        const decoded = Buffer.from(padded, 'base64').toString('utf8');
        if (decoded.includes('@')) mainPart = decoded;
      } catch { /* ignore */ }
    }

    const atIdx = mainPart.lastIndexOf('@');
    if (atIdx > 0) {
      const userInfo = safeDecUri(mainPart.slice(0, atIdx)).trim();
      const hostPort = mainPart.slice(atIdx + 1).trim().replace(/\/+$/, '');
      const colonIdx = hostPort.lastIndexOf(':');
      if (colonIdx > 0) {
        const server = hostPort.slice(0, colonIdx).replace(/^\[|\]$/g, '');
        const port = Number(hostPort.slice(colonIdx + 1) || 8388);
        const remark = customRemark || safeDecUri(rawHash) || `SS-${server}:${port}`;
        const tag = customTag || remark.replace(/\s+/g, '-') || `out-ss-${crypto.randomBytes(3).toString('hex')}`;

        let method = 'aes-128-gcm';
        let password = '';
        const knownCipherMatch = userInfo.match(/^(2022-[a-z0-9-]+|aes-\d+-[a-z0-9-]+|(?:x?chacha20|rc4|bf|camellia|salsa20|none)[a-z0-9-]*):(.*)$/i);
        if (knownCipherMatch) {
          method = normalizeSsMethod(knownCipherMatch[1]);
          password = safeDecUri(knownCipherMatch[2]);
        } else {
          const cleanB64 = userInfo.replace(/-/g, '+').replace(/_/g, '/').replace(/[^A-Za-z0-9+/=]/g, '');
          const padded = cleanB64 + '='.repeat((4 - (cleanB64.length % 4)) % 4);
          const decoded = Buffer.from(padded, 'base64').toString('utf8');
          const cIdx = decoded.indexOf(':');
          if (cIdx > 0) {
            method = normalizeSsMethod(decoded.slice(0, cIdx));
            password = decoded.slice(cIdx + 1);
          } else if (userInfo.includes(':')) {
            const uIdx = userInfo.indexOf(':');
            method = normalizeSsMethod(userInfo.slice(0, uIdx));
            password = safeDecUri(userInfo.slice(uIdx + 1));
          }
        }
        const cleaned = sanitizeSsOutboundPasswordAndMethod(method, password);
        return {
          id: `out_${crypto.randomBytes(5).toString('hex')}`,
          tag,
          type: 'shadowsocks',
          remark,
          enabled: true,
          server,
          port,
          method: cleaned.method,
          password: cleaned.password,
          up: 0,
          down: 0
        };
      }
    }
  }

  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error('无法解析该节点 URI 格式');
  }

  const proto = parsed.protocol.replace(':', '').toLowerCase();
  const server = parsed.hostname.replace(/^\[|\]$/g, '');
  const port = Number(parsed.port || 443);
  const remark = customRemark || safeDecUri(parsed.hash ? parsed.hash.slice(1) : '') || `${proto.toUpperCase()}-${server}:${port}`;
  const tag = customTag || remark.replace(/\s+/g, '-') || `out-${proto}-${crypto.randomBytes(3).toString('hex')}`;
  const q = parsed.searchParams;

  if (proto === 'vless') {
    const security = q.get('security') || 'none';
    const rawNet = q.get('type') || 'tcp';
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'vless',
      remark,
      enabled: true,
      server,
      port,
      uuid: ensureUuid(safeDecUri(parsed.username)),
      flow: q.get('flow') || '',
      security,
      sni: q.get('sni') || q.get('host') || server,
      fingerprint: q.get('fp') || 'chrome',
      publicKey: q.get('pbk') || '',
      shortId: q.get('sid') || '',
      insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1',
      transport: rawNet === 'raw' ? 'tcp' : rawNet,
      wsPath: q.get('path') || '/',
      wsHost: q.get('host') || '',
      grpcServiceName: q.get('serviceName') || '',
      up: 0,
      down: 0
    };
  }

  if (proto === 'anytls') {
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'anytls',
      remark,
      enabled: true,
      server,
      port,
      password: safeDecUri(parsed.username || parsed.password),
      security: 'tls',
      sni: q.get('sni') || server,
      insecure: q.get('insecure') === '1' || q.get('allowInsecure') === '1',
      up: 0,
      down: 0
    };
  }

  if (proto === 'hysteria2' || proto === 'hy2') {
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'hysteria2',
      remark,
      enabled: true,
      server,
      port,
      password: safeDecUri(parsed.username || parsed.password),
      security: 'tls',
      sni: q.get('sni') || server,
      insecure: q.get('insecure') === '1' || q.get('allowInsecure') === '1',
      obfsPassword: q.get('obfs-password') || '',
      up: 0,
      down: 0
    };
  }

  if (proto === 'ss') {
    let method = 'aes-128-gcm';
    let password = '';
    if (parsed.password) {
      method = normalizeSsMethod(safeDecUri(parsed.username));
      password = safeDecUri(parsed.password);
    } else {
      const rawUser = safeDecUri(parsed.username).replace(/-/g, '+').replace(/_/g, '/');
      const decoded = Buffer.from(rawUser, 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      if (idx > 0) {
        method = normalizeSsMethod(decoded.slice(0, idx));
        password = decoded.slice(idx + 1);
      }
    }
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'shadowsocks',
      remark,
      enabled: true,
      server,
      port,
      method,
      password,
      up: 0,
      down: 0
    };
  }

  if (proto === 'socks' || proto === 'socks5' || proto === 'http' || proto === 'https') {
    let username = safeDecUri(parsed.username || '');
    let password = safeDecUri(parsed.password || '');
    if (username && !password) {
      try {
        const normB64 = username.replace(/-/g, '+').replace(/_/g, '/');
        const dec = Buffer.from(normB64, 'base64').toString('utf8');
        if (dec.includes(':')) {
          const idx = dec.indexOf(':');
          username = dec.slice(0, idx);
          password = dec.slice(idx + 1);
        }
      } catch { /* ignore */ }
    }
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: (proto === 'http' || proto === 'https') ? 'http' : 'socks',
      remark,
      enabled: true,
      server,
      port,
      username,
      password,
      ...(proto === 'https' ? { security: 'tls', sni: server } : {}),
      up: 0,
      down: 0
    };
  }

  if (proto === 'trojan') {
    const rawNet = q.get('type') || 'tcp';
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'trojan',
      remark,
      enabled: true,
      server,
      port,
      password: safeDecUri(parsed.username),
      security: q.get('security') || 'tls',
      sni: q.get('sni') || server,
      publicKey: q.get('pbk') || '',
      shortId: q.get('sid') || '',
      insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1',
      transport: rawNet === 'raw' ? 'tcp' : rawNet,
      wsPath: q.get('path') || '/',
      wsHost: q.get('host') || '',
      up: 0,
      down: 0
    };
  }

  if (proto === 'tuic') {
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'tuic',
      remark,
      enabled: true,
      server,
      port,
      uuid: ensureUuid(safeDecUri(parsed.username)),
      password: safeDecUri(parsed.password),
      congestionControl: q.get('congestion_control') || 'bbr',
      security: 'tls',
      sni: q.get('sni') || server,
      insecure: q.get('allow_insecure') === '1' || q.get('insecure') === '1',
      up: 0,
      down: 0
    };
  }

  throw new Error(`暂不支持自动解析协议: ${proto}`);
}

module.exports = {
  REALITY_PRESETS,
  SS_METHODS,
  INBOUND_PROTOCOLS,
  OUTBOUND_PROTOCOLS,
  isValidUuid,
  ensureUuid,
  normalizeSsMethod,
  sanitizeSsOutboundPasswordAndMethod,
  ensureSsPassword,
  inferDomainFromCertPath,
  isCertFileSelfSigned,
  generateRealityKeypair,
  deriveRealityPublicKey,
  generateSsKey,
  generateShortId,
  resolveInboundCertAndDomain,
  toSingboxInbound,
  toSingboxOutbound,
  buildClientLinks,
  parseShareUriToOutbound
};
