'use strict';

const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');

// Precompute CRC32 table for standard PKZIP archive creation
const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i += 1) {
  let c = i;
  for (let k = 0; k < 8; k += 1) {
    c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
  }
  CRC_TABLE[i] = c >>> 0;
}

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i += 1) {
    crc = CRC_TABLE[(crc ^ buf[i]) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

/**
 * Creates a standard PKZIP (.zip) archive Buffer from an array of `{ name, data }` entries.
 * Zero external dependencies — uses Node.js built-in `zlib.deflateRawSync`.
 */
function createZipBuffer(entries = []) {
  const localParts = [];
  const centralParts = [];
  let offset = 0;

  const now = new Date();
  const dosTime = ((now.getHours() & 0x1f) << 11) | ((now.getMinutes() & 0x3f) << 5) | ((now.getSeconds() >> 1) & 0x1f);
  const dosDate = (((now.getFullYear() - 1980) & 0x7f) << 9) | (((now.getMonth() + 1) & 0x0f) << 5) | (now.getDate() & 0x1f);

  for (const item of entries) {
    const nameBuf = Buffer.from(String(item.name || '').replace(/^\/+/, ''), 'utf8');
    const rawBuf = Buffer.isBuffer(item.data) ? item.data : Buffer.from(String(item.data ?? ''), 'utf8');
    const crc = crc32(rawBuf);
    const deflated = zlib.deflateRawSync(rawBuf, { level: 6 });
    const useDeflate = deflated.length < rawBuf.length;
    const compBuf = useDeflate ? deflated : rawBuf;
    const method = useDeflate ? 8 : 0;

    // Local file header (30 bytes + name)
    const lfh = Buffer.alloc(30);
    lfh.writeUInt32LE(0x04034b50, 0); // PK\x03\x04
    lfh.writeUInt16LE(20, 4);         // version needed
    lfh.writeUInt16LE(0x0800, 6);     // UTF-8 flag
    lfh.writeUInt16LE(method, 8);     // compression method
    lfh.writeUInt16LE(dosTime, 10);
    lfh.writeUInt16LE(dosDate, 12);
    lfh.writeUInt32LE(crc, 14);
    lfh.writeUInt32LE(compBuf.length, 18);
    lfh.writeUInt32LE(rawBuf.length, 22);
    lfh.writeUInt16LE(nameBuf.length, 26);
    lfh.writeUInt16LE(0, 28);

    localParts.push(lfh, nameBuf, compBuf);

    // Central directory file header (46 bytes + name)
    const cdfh = Buffer.alloc(46);
    cdfh.writeUInt32LE(0x02014b50, 0); // PK\x01\x02
    cdfh.writeUInt16LE(20, 4);         // version made by
    cdfh.writeUInt16LE(20, 6);         // version needed
    cdfh.writeUInt16LE(0x0800, 8);     // UTF-8 flag
    cdfh.writeUInt16LE(method, 10);
    cdfh.writeUInt16LE(dosTime, 12);
    cdfh.writeUInt16LE(dosDate, 14);
    cdfh.writeUInt32LE(crc, 16);
    cdfh.writeUInt32LE(compBuf.length, 20);
    cdfh.writeUInt32LE(rawBuf.length, 24);
    cdfh.writeUInt16LE(nameBuf.length, 28);
    cdfh.writeUInt16LE(0, 30);
    cdfh.writeUInt16LE(0, 32);
    cdfh.writeUInt16LE(0, 34);
    cdfh.writeUInt16LE(0, 36);
    cdfh.writeUInt32LE(0, 38);
    cdfh.writeUInt32LE(offset, 42);

    centralParts.push(cdfh, nameBuf);
    offset += lfh.length + nameBuf.length + compBuf.length;
  }

  const centralSize = centralParts.reduce((a, b) => a + b.length, 0);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // PK\x05\x06
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(offset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([...localParts, ...centralParts, eocd]);
}

/**
 * Parses a standard PKZIP (.zip) Buffer and returns a Map of `entryName -> Buffer`.
 */
function parseZipBuffer(zipBuf) {
  const buf = Buffer.isBuffer(zipBuf) ? zipBuf : Buffer.from(zipBuf);
  const files = new Map();

  // Locate End of Central Directory (EOCD) signature 0x06054b50 from end of buffer
  let eocdPos = -1;
  const minPos = Math.max(0, buf.length - 65557);
  for (let i = buf.length - 22; i >= minPos; i -= 1) {
    if (buf.readUInt32LE(i) === 0x06054b50) {
      eocdPos = i;
      break;
    }
  }

  if (eocdPos >= 0) {
    const totalEntries = buf.readUInt16LE(eocdPos + 10);
    const cdOffset = buf.readUInt32LE(eocdPos + 16);
    let ptr = cdOffset;
    for (let idx = 0; idx < totalEntries && ptr + 46 <= buf.length; idx += 1) {
      if (buf.readUInt32LE(ptr) !== 0x02014b50) break;
      const method = buf.readUInt16LE(ptr + 10);
      const compSize = buf.readUInt32LE(ptr + 20);
      const nameLen = buf.readUInt16LE(ptr + 28);
      const extraLen = buf.readUInt16LE(ptr + 30);
      const commentLen = buf.readUInt16LE(ptr + 32);
      const localOffset = buf.readUInt32LE(ptr + 42);
      const name = buf.subarray(ptr + 46, ptr + 46 + nameLen).toString('utf8');
      ptr += 46 + nameLen + extraLen + commentLen;

      if (localOffset + 30 <= buf.length && buf.readUInt32LE(localOffset) === 0x04034b50) {
        const lNameLen = buf.readUInt16LE(localOffset + 26);
        const lExtraLen = buf.readUInt16LE(localOffset + 28);
        const dataStart = localOffset + 30 + lNameLen + lExtraLen;
        const compSlice = buf.subarray(dataStart, dataStart + compSize);
        if (!name.endsWith('/')) {
          const content = method === 8 ? zlib.inflateRawSync(compSlice) : Buffer.from(compSlice);
          files.set(name, content);
        }
      }
    }
    return files;
  }

  // Fallback sequential local file header scan
  let pos = 0;
  while (pos + 30 <= buf.length && buf.readUInt32LE(pos) === 0x04034b50) {
    const method = buf.readUInt16LE(pos + 8);
    const compSize = buf.readUInt32LE(pos + 18);
    const nameLen = buf.readUInt16LE(pos + 26);
    const extraLen = buf.readUInt16LE(pos + 28);
    const name = buf.subarray(pos + 30, pos + 30 + nameLen).toString('utf8');
    const dataStart = pos + 30 + nameLen + extraLen;
    const compSlice = buf.subarray(dataStart, dataStart + compSize);
    if (!name.endsWith('/')) {
      const content = method === 8 ? zlib.inflateRawSync(compSlice) : Buffer.from(compSlice);
      files.set(name, content);
    }
    pos = dataStart + compSize;
  }
  return files;
}

/**
 * Builds a complete, self-contained Master Panel Backup `.zip` archive Buffer containing:
 * - `nexusgate.json` (full state + embedded PEMs for all SSL certificates)
 * - `certs/<domain>/fullchain.pem` & `privkey.pem` (physical SSL cert files)
 * - `sing-box/config.json` (compiled Sing-box kernel config)
 * - `README-RESTORE.txt` (human-readable summary of port, safe path, and 1-click restore command)
 */
function buildMasterBackupZip(store, singbox) {
  const stateClone = JSON.parse(JSON.stringify(store.state));
  const entries = [];
  const addedCertFiles = new Set();

  // Embed certPem & keyPem into every certificate record and pack physical cert files into certs/<domain>/
  for (const cert of stateClone.certificates || []) {
    if (!cert.certPem && cert.certPath && fs.existsSync(cert.certPath)) {
      try { cert.certPem = fs.readFileSync(cert.certPath, 'utf8'); } catch { /* ignore */ }
    }
    if (!cert.keyPem && cert.keyPath && fs.existsSync(cert.keyPath)) {
      try { cert.keyPem = fs.readFileSync(cert.keyPath, 'utf8'); } catch { /* ignore */ }
    }
    const safeDom = String(cert.domain || 'default').replace(/[^a-zA-Z0-9._-]/g, '_');
    if (cert.certPem && !addedCertFiles.has(`${safeDom}/fullchain.pem`)) {
      entries.push({ name: `certs/${safeDom}/fullchain.pem`, data: cert.certPem });
      addedCertFiles.add(`${safeDom}/fullchain.pem`);
    }
    if (cert.keyPem && !addedCertFiles.has(`${safeDom}/privkey.pem`)) {
      entries.push({ name: `certs/${safeDom}/privkey.pem`, data: cert.keyPem });
      addedCertFiles.add(`${safeDom}/privkey.pem`);
    }
  }

  entries.unshift({
    name: 'nexusgate.json',
    data: JSON.stringify(stateClone, null, 2)
  });

  try {
    const { buildSingboxConfig } = require("./singbox");
    const sbCfg = buildSingboxConfig(store.state);
    if (sbCfg) {
      entries.push({
        name: 'sing-box/config.json',
        data: JSON.stringify(sbCfg, null, 2)
      });
    }
  } catch { /* ignore */ }

  const s = stateClone.settings || {};
  const readmeLines = [
    '================================================================',
    '  NexusGate Plus · 枢门集群 主控全量灾备包 (Full Master Backup)',
    '================================================================',
    `备份时间 : ${new Date().toISOString()}`,
    `面板端口 : ${s.webPort || 2053}`,
    `安全路径 : ${s.webBasePath || '/'}`,
    `面板域名 : ${s.webDomain || '未绑定'}`,
    `登录账号 : ${stateClone.admin?.username || 'admin'}`,
    `集群规模 : ${(stateClone.nodes || []).length} 台服务器 | ${(stateClone.inbounds || []).length} 个入站节点 | ${(stateClone.outbounds || []).length} 个出站`,
    '',
    '【异机迁移 / 备用服务器恢复主控说明】',
    '1. Web 面板一键恢复：在备用主控面板进入《面板设置与安全》-> 点击「⬆ 导入恢复备份」-> 直接选择本 .zip 压缩包即可！',
    '2. SSH 命令一键恢复：将本 .zip 文件上传至新主控服务器 /root/ 目录，执行：',
    '   ng restore /root/nexusgate-master-backup.zip',
    '恢复后，新主控的访问端口、安全根路径、登录账号密码、订阅链接与 SSL 证书将与原主控 100% 完全一致！',
    '================================================================'
  ];
  entries.push({ name: 'README-RESTORE.txt', data: readmeLines.join('\n') + '\n' });

  return createZipBuffer(entries);
}

/**
 * Extracts and parses a Master backup from either:
 * - A `.zip` archive Buffer
 * - A `{ zipBase64: "..." }` object or data URI string
 * - A `{ backup: { ... } }` or raw JSON state object/string
 * Also extracts embedded SSL certificates so they can be written to disk upon restore.
 */
function extractMasterBackupPayload(input) {
  let zipBuf = null;

  if (Buffer.isBuffer(input)) {
    if (input.length >= 4 && input.readUInt32LE(0) === 0x04034b50) {
      zipBuf = input;
    } else {
      const str = input.toString('utf8').trim();
      const parsedObj = JSON.parse(str);
      return extractMasterBackupPayload(parsedObj);
    }
  } else if (typeof input === 'string') {
    const str = input.trim();
    if (str.startsWith('{')) {
      return extractMasterBackupPayload(JSON.parse(str));
    }
    const cleanB64 = str.replace(/^data:[^;]+;base64,/, '');
    const decoded = Buffer.from(cleanB64, 'base64');
    if (decoded.length >= 4 && decoded.readUInt32LE(0) === 0x04034b50) {
      zipBuf = decoded;
    } else {
      return extractMasterBackupPayload(JSON.parse(decoded.toString('utf8')));
    }
  } else if (input && typeof input === 'object') {
    if (input.zipBase64 && typeof input.zipBase64 === 'string') {
      const cleanB64 = input.zipBase64.replace(/^data:[^;]+;base64,/, '');
      const decoded = Buffer.from(cleanB64, 'base64');
      if (decoded.length >= 4 && decoded.readUInt32LE(0) === 0x04034b50) {
        zipBuf = decoded;
      } else {
        const asJson = JSON.parse(decoded.toString('utf8'));
        return { stateData: asJson.backup || asJson, certFiles: new Map() };
      }
    } else {
      const stateData = input.backup || input;
      return { stateData, certFiles: new Map() };
    }
  }

  if (zipBuf) {
    const entries = parseZipBuffer(zipBuf);
    const jsonBuf = entries.get('nexusgate.json') || entries.get('data/nexusgate.json');
    if (!jsonBuf) {
      throw new Error('ZIP 备份包内未找到 nexusgate.json 核心数据文件');
    }
    const stateData = JSON.parse(jsonBuf.toString('utf8'));
    const certFiles = new Map();
    for (const [entryName, contentBuf] of entries.entries()) {
      if (entryName.startsWith('certs/') && (entryName.endsWith('.pem') || entryName.endsWith('.crt') || entryName.endsWith('.key'))) {
        certFiles.set(entryName, contentBuf.toString('utf8'));
      }
    }
    return { stateData, certFiles };
  }

  throw new Error('无法识别的备份文件格式（请上传 .zip 或 .json 备份文件）');
}

/**
 * Restores physical SSL certificate files from a backup (`certFiles` map + `stateData.certificates` PEMs)
 * onto the filesystem so panel HTTPS and TLS nodes work immediately on a new Master VPS.
 */
function restoreBackupCertificatesToDisk(stateData, certFiles = new Map(), customCertRoot = '') {
  const targetRoot = customCertRoot || process.env.NG_CERT_DIR || '/etc/nexusgate/certs';
  const certs = Array.isArray(stateData.certificates) ? stateData.certificates : [];

  for (const cert of certs) {
    const safeDom = String(cert.domain || 'default').replace(/[^a-zA-Z0-9._-]/g, '_');
    const certPem = cert.certPem || certFiles.get(`certs/${safeDom}/fullchain.pem`) || '';
    const keyPem = cert.keyPem || certFiles.get(`certs/${safeDom}/privkey.pem`) || '';
    if (!certPem || !keyPem) continue;

    // 1. Write to original certPath/keyPath if writable, else write under targetRoot/<domain>/
    let finalCertPath = cert.certPath || path.join(targetRoot, safeDom, 'fullchain.pem');
    let finalKeyPath = cert.keyPath || path.join(targetRoot, safeDom, 'privkey.pem');

    const tryWritePair = (cPath, kPath) => {
      fs.mkdirSync(path.dirname(cPath), { recursive: true });
      fs.mkdirSync(path.dirname(kPath), { recursive: true });
      fs.writeFileSync(cPath, certPem, { mode: 0o644 });
      fs.writeFileSync(kPath, keyPem, { mode: 0o600 });
    };

    try {
      tryWritePair(finalCertPath, finalKeyPath);
    } catch {
      try {
        finalCertPath = path.join(targetRoot, safeDom, 'fullchain.pem');
        finalKeyPath = path.join(targetRoot, safeDom, 'privkey.pem');
        tryWritePair(finalCertPath, finalKeyPath);
      } catch { /* ignore in read-only sandbox */ }
    }

    const oldCertPath = cert.certPath;
    const oldKeyPath = cert.keyPath;
    cert.certPath = finalCertPath;
    cert.keyPath = finalKeyPath;
    cert.certPem = certPem;
    cert.keyPem = keyPem;

    if (stateData.settings) {
      if (stateData.settings.webCertFile === oldCertPath || stateData.settings.webDomain === cert.domain) {
        stateData.settings.webCertFile = finalCertPath;
        stateData.settings.webKeyFile = finalKeyPath;
      }
      if (stateData.settings.defaultCertFile === oldCertPath || stateData.settings.defaultTlsDomain === cert.domain) {
        stateData.settings.defaultCertFile = finalCertPath;
        stateData.settings.defaultKeyFile = finalKeyPath;
      }
    }
  }
}

module.exports = {
  crc32,
  createZipBuffer,
  parseZipBuffer,
  buildMasterBackupZip,
  extractMasterBackupPayload,
  restoreBackupCertificatesToDisk
};
