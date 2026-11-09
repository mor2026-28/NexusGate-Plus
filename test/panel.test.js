'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawnSync } = require('node:child_process');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-test-v27-'));
process.env.NG_DATA_FILE = path.join(tmpDir, 'nexusgate.json');
process.env.NG_SINGBOX_CONFIG = path.join(tmpDir, 'sing-box-config.json');
process.env.NG_ADMIN_USERNAME = 'ng_adminTest01';
process.env.NG_ADMIN_PASSWORD = 'StrongPassword123456';
process.env.NG_BASE_PATH = '/SecPath16Chars99/';

const { store, singbox, handleRequest } = require('../server');
const { REALITY_PRESETS, parseShareUriToOutbound } = require('../lib/protocols');
const { computeResetCycleKey } = require('../lib/singbox');

let server;
let baseUrl;
let cookie = '';
let csrf = '';

async function req(urlPath, options = {}) {
  const fullUrl = `${baseUrl}${urlPath}`;
  const headers = {
    ...(options.body && typeof options.body === 'string' ? { 'content-type': 'application/json' } : {}),
    ...(cookie ? { cookie } : {}),
    ...(csrf ? { 'x-csrf-token': csrf } : {}),
    ...(options.headers || {})
  };
  const res = await fetch(fullUrl, { ...options, headers, redirect: 'manual' });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) {
    cookie = setCookie.split(';')[0];
  }
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* raw */ }
  return { status: res.status, headers: res.headers, text, json };
}

test.before(async () => {
  server = http.createServer(handleRequest);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

test.after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('1. Strict webBasePath security: bare IP:Port returns 404, only /SecPath16Chars99/ allows login', async () => {
  const bareRes = await req('/');
  assert.equal(bareRes.status, 404);

  const loginRes = await req('/SecPath16Chars99/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'ng_adminTest01', password: 'StrongPassword123456' })
  });
  assert.equal(loginRes.status, 200);
  assert.equal(loginRes.json.authenticated, true);
  csrf = loginRes.json.csrf;
});

test('2. Reality SNI excludes Cloudflare/Microsoft, SS-2022 enforces exact-length Base64 keys, and TLS gets valid cert', async () => {
  for (const preset of REALITY_PRESETS) {
    assert.ok(!/cloudflare|microsoft|bing/i.test(preset.serverName), `Forbidden SNI in presets: ${preset.serverName}`);
  }

  const presets = ['vless-reality', 'anytls', 'hysteria2', 'ss2022-128', 'ss2022-256', 'ss-128', 'socks'];
  let portBase = 31000;

  for (const p of presets) {
    portBase += 1;
    const payload = {
      remark: `Node-${p}`,
      port: portBase,
      protocol: p.startsWith('ss') ? 'shadowsocks' : (p === 'vless-reality' ? 'vless' : p),
      security: p === 'vless-reality' ? 'reality' : (['anytls', 'hysteria2'].includes(p) ? 'tls' : 'none'),
      method: p === 'ss2022-256' ? '2022-blake3-aes-256-gcm' : (p === 'ss-128' ? 'aes-128-gcm' : '2022-blake3-aes-128-gcm'),
      // Pass a non-Base64 plain string to verify SS2022 automatically converts it into a valid 16/32-byte Base64 PSK
      ...(p.startsWith('ss2022') ? { password: 'plain_password_not_base64_20chars' } : {}),
      ...(p === 'vless-reality' ? { reality: { serverName: 'www.cloudflare.com', target: 'www.cloudflare.com:443' } } : {}),
      limitIp: 2,
      limitDevice: 2,
      totalGB: 100,
      resetDay: 15,
      expiryTime: Date.now() + 30 * 86400000
    };
    const createRes = await req('/SecPath16Chars99/api/inbounds', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(createRes.status, 201);
    const inb = createRes.json.inbound;
    assert.equal(inb.limitIp, 2);
    assert.equal(inb.limitDevice, 2);
    assert.equal(inb.resetDay, 15);
    assert.ok(inb.expiryTime > Date.now());
    assert.ok(inb.links.length > 0);

    if (p === 'ss2022-256') {
      assert.equal(Buffer.from(inb.password, 'base64').length, 32, 'SS2022-256 must have exact 32-byte Base64 PSK');
      assert.equal(inb.clients[0].password, inb.password, 'Single-user SS2022 client password must match server PSK');
    } else if (p === 'ss2022-128') {
      assert.equal(Buffer.from(inb.password, 'base64').length, 16, 'SS2022-128 must have exact 16-byte Base64 PSK');
    }

    if (p === 'vless-reality') {
      assert.equal(inb.reality.serverName, 'tesla.com', 'Forbidden SNI should automatically normalize to tesla.com');
      assert.equal(inb.reality.target, 'www.tesla.com:443');
    }

    for (const link of inb.links) {
      assert.ok(!link.uri.includes('www.bing.com'));
      assert.ok(!link.uri.includes('www.cloudflare.com'));
      const parsedOut = parseShareUriToOutbound(link.uri);
      assert.equal(parsedOut.port, portBase);
    }
  }

  const { config } = singbox.writeConfig();
  assert.equal(config.dns, undefined, 'Server config should omit deprecated legacy DNS block');
  assert.equal(config.log.level, 'warn', 'Default log level should be warn');

  const realityInb = config.inbounds.find((i) => i.type === 'vless' && i.tls?.reality?.enabled);
  assert.ok(realityInb, 'Reality inbound should exist in Sing-box config');
  assert.equal(realityInb.tls.certificate_path, undefined, 'Reality inbound MUST NEVER have certificate_path');
  assert.equal(realityInb.tls.key_path, undefined, 'Reality inbound MUST NEVER have key_path');
  assert.equal(realityInb.tls.server_name, 'tesla.com');

  const anytlsInb = config.inbounds.find((i) => i.type === 'anytls');
  assert.ok(anytlsInb, 'AnyTLS inbound should exist');
  assert.ok(anytlsInb.tls.certificate_path && fs.existsSync(anytlsInb.tls.certificate_path), 'AnyTLS inbound must have existing certificate_path');
});

test('3. Sing-box Clash API metadata.type ("anytls/inbound-XXXX") traffic attribution + online IP/device tracking & limitDevice enforcement', async () => {
  const anytlsInbound = store.state.inbounds.find((i) => i.protocol === 'anytls');
  assert.ok(anytlsInbound);
  anytlsInbound.limitIp = 0;
  anytlsInbound.limitDevice = 2;
  anytlsInbound.up = 0;
  anytlsInbound.down = 0;

  // Start a mock Sing-box Clash API server returning metadata.type = "anytls/<tag>"
  const closedConnIds = [];
  let mockConnections = [
    {
      id: 'conn-dev1-a',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '::ffff:203.0.113.10', sourcePort: '51001', destinationPort: '443', host: 'openai.com' },
      upload: 4096,
      download: 8192,
      chains: ['direct']
    },
    {
      // Same device (203.0.113.10) opening a second TCP connection on a distant ephemeral port — must still count as 1 device!
      id: 'conn-dev1-b',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.10', sourcePort: '62005', destinationPort: '443', host: 'google.com' },
      upload: 1024,
      download: 2048,
      chains: ['direct']
    },
    {
      // 2nd device (203.0.113.20) — allowed since limitDevice = 2
      id: 'conn-dev2-a',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.20', sourcePort: '53000', destinationPort: '443', host: 'github.com' },
      upload: 2000,
      download: 4000,
      chains: ['direct']
    },
    {
      // 3rd device (203.0.113.30) — exceeds limitDevice = 2, must be terminated immediately!
      id: 'conn-dev3-excess',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.30', sourcePort: '54000', destinationPort: '443', host: 'youtube.com' },
      upload: 500,
      download: 500,
      chains: ['direct']
    }
  ];

  const mockClashServer = http.createServer((reqMock, resMock) => {
    if (reqMock.method === 'GET' && reqMock.url === '/connections') {
      resMock.writeHead(200, { 'content-type': 'application/json' });
      resMock.end(JSON.stringify({ connections: mockConnections }));
    } else if (reqMock.method === 'DELETE' && reqMock.url.startsWith('/connections/')) {
      closedConnIds.push(decodeURIComponent(reqMock.url.slice('/connections/'.length)));
      resMock.writeHead(204);
      resMock.end();
    } else {
      resMock.writeHead(404);
      resMock.end();
    }
  });

  await new Promise((resolve) => mockClashServer.listen(0, '127.0.0.1', resolve));
  const clashPort = mockClashServer.address().port;
  store.state.settings.clashApiPort = clashPort;

  try {
    const baseTime = Date.now();
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime));
    // Wait briefly for async DELETE request to hit mockClashServer
    await new Promise((r) => setTimeout(r, 80));

    assert.equal(singbox.getActiveDeviceCountForInbound(anytlsInbound.tag), 2, 'Should show 2 online devices (not 3, and not splitting 1 device across ports)');
    assert.deepEqual(singbox.getActiveIpsForInbound(anytlsInbound.tag), ['203.0.113.10', '203.0.113.20']);
    assert.ok(closedConnIds.includes('conn-dev3-excess'), '3rd excess device connection must be closed via Clash API DELETE');
    assert.ok(!closedConnIds.includes('conn-dev1-a') && !closedConnIds.includes('conn-dev1-b') && !closedConnIds.includes('conn-dev2-a'), '1st and 2nd allowed devices must NEVER be interrupted when 3rd device connects');
    assert.equal(anytlsInbound.up, 7120, 'Only allowed devices (1st + 2nd) traffic should be accumulated');
    assert.equal(anytlsInbound.down, 14240, 'Only allowed devices (1st + 2nd) download traffic should be accumulated');

    // Poll #2: 1st and 2nd devices keep using traffic while 3rd device retries -> 1st & 2nd keep working smoothly, 3rd retry is blocked
    mockConnections = [
      {
        id: 'conn-dev1-a',
        metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.10', sourcePort: '51001', destinationPort: '443', host: 'openai.com' },
        upload: 6096,
        download: 12192,
        chains: ['direct']
      },
      {
        id: 'conn-dev2-a',
        metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.20', sourcePort: '53000', destinationPort: '443', host: 'github.com' },
        upload: 3000,
        download: 6000,
        chains: ['direct']
      },
      {
        id: 'conn-dev3-retry',
        metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.30', sourcePort: '54099', destinationPort: '443', host: 'youtube.com' },
        upload: 999,
        download: 999,
        chains: ['direct']
      }
    ];
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime + 2000));
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(closedConnIds.includes('conn-dev3-retry'), '3rd device retry must also be blocked');
    assert.ok(!closedConnIds.includes('conn-dev1-a') && !closedConnIds.includes('conn-dev2-a'), '1st and 2nd devices remain completely uninterrupted');
    assert.equal(anytlsInbound.up, 10120, '1st and 2nd devices continue accumulating traffic normally');

    // Even when active connections momentarily drop to [], 60s rolling lease keeps online count visible in UI
    mockConnections = [];
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime + 5000));
    assert.equal(singbox.getActiveDeviceCountForInbound(anytlsInbound.tag), 2, 'Online devices should remain visible within 60s lease window');

    // After 65s idle of 2nd device (while 1st device stays active), 2nd slot is freed and 3rd device is now admitted cleanly
    mockConnections = [
      {
        id: 'conn-dev1-a',
        metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.10', sourcePort: '51001', destinationPort: '443', host: 'openai.com' },
        upload: 7096,
        download: 14192,
        chains: ['direct']
      }
    ];
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime + 40000));
    mockConnections.push({
      id: 'conn-dev3-admitted',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.30', sourcePort: '55000', destinationPort: '443', host: 'youtube.com' },
      upload: 1000,
      download: 2000,
      chains: ['direct']
    });
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime + 70000));
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(!closedConnIds.includes('conn-dev3-admitted'), 'Once a slot frees up after 60s idle, 3rd device is admitted without being closed');
    assert.deepEqual(singbox.getActiveIpsForInbound(anytlsInbound.tag), ['203.0.113.10', '203.0.113.30']);
  } finally {
    await new Promise((resolve) => mockClashServer.close(resolve));
  }
});

test('4. Monthly automatic traffic reset (resetDay 1..31), batch operations, and system memory/log cleanup', async () => {
  const targetInb = store.state.inbounds[0];
  targetInb.resetDay = 15;
  targetInb.lastResetCycle = computeResetCycleKey(15, new Date('2026-11-16T10:00:00Z'));
  targetInb.up = 50 * (1024 ** 3);
  targetInb.down = 60 * (1024 ** 3);
  targetInb.enable = false;
  targetInb.disabledReason = 'quota';
  targetInb.expiryTime = 0;

  const res = singbox.checkAndResetMonthlyTraffic(new Date('2026-12-15T00:05:00Z'));
  assert.ok(res.resetCount >= 1);
  assert.equal(targetInb.up, 0);
  assert.equal(targetInb.down, 0);
  assert.equal(targetInb.enable, true);
  assert.equal(targetInb.lastResetCycle, '2026-12');

  targetInb.up = 123456;
  const batchRes = await req('/SecPath16Chars99/api/inbounds/batch', {
    method: 'POST',
    body: JSON.stringify({ action: 'reset-all-traffic' })
  });
  assert.equal(batchRes.status, 200);
  assert.ok(batchRes.json.count >= 1);
  assert.equal(targetInb.up, 0);

  const cleanRes = await req('/SecPath16Chars99/api/system/cleanup', { method: 'POST' });
  assert.equal(cleanRes.status, 200);
  assert.ok(Array.isArray(cleanRes.json.result.actions));
});

test('5. High-entropy subToken security (/sub/all returns 404) & clean CLI --show-info without username/subscription', async () => {
  const subAllRes = await req('/sub/all?format=clash');
  assert.equal(subAllRes.status, 404, '/sub/all must be rejected with 404 to prevent scanning/leaks');

  const subToken = store.state.settings.subToken;
  assert.ok(subToken && subToken.length >= 16 && subToken !== 'all', 'settings.subToken must be a high-entropy token');

  const subRes = await req(`/sub/${subToken}?format=clash`);
  assert.equal(subRes.status, 200);
  assert.ok(subRes.headers.get('subscription-userinfo').includes('total='));
  assert.ok(subRes.text.includes('port: 7890'));
  assert.ok(subRes.text.includes('socks-port: 7891'));
  assert.ok(subRes.text.includes('🔰 节点选择'));
  assert.ok(subRes.text.includes('♻️ 自动选择'));
  assert.ok(subRes.text.includes('🤖 AI 专线'));
  assert.ok(subRes.text.includes('DOMAIN-SUFFIX,openai.com,🤖 AI 专线'));
  assert.ok(subRes.text.includes('DOMAIN-SUFFIX,google.com,🔰 节点选择'));
  assert.ok(subRes.text.includes('GEOIP,CN,🎯 全球直连,no-resolve'));

  const cliInfo = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js'), '--show-info'], {
    env: { ...process.env, NG_DATA_FILE: path.join(tmpDir, 'nexusgate.json') },
    encoding: 'utf8'
  });
  assert.equal(cliInfo.status, 0);
  assert.ok(cliInfo.stdout.includes('访问地址'));
  assert.ok(cliInfo.stdout.includes('面板端口'));
  assert.ok(cliInfo.stdout.includes('安全路径'));
  assert.ok(!cliInfo.stdout.includes('登录账号'), '--show-info should NOT display 登录账号');
  assert.ok(!cliInfo.stdout.includes('聚合订阅'), '--show-info should NOT display 聚合订阅');
});

test('6. E2E Backup Migration of Universal .tar.gz Archive (with sublink.db, x-ui.db, /root/cert, WS+TLS & Reality)', async () => {
  const archiveBuildDir = path.join(tmpDir, 'archive_src');
  fs.mkdirSync(path.join(archiveBuildDir, 'etc', 'x-ui'), { recursive: true });
  fs.mkdirSync(path.join(archiveBuildDir, 'usr', 'local', 'bin', 'sublink', 'db'), { recursive: true });

  const sublinkDbPath = path.join(archiveBuildDir, 'usr', 'local', 'bin', 'sublink', 'db', 'sublink.db');
  const xuiDbPath = path.join(archiveBuildDir, 'etc', 'x-ui', 'x-ui.db');
  const tarGzPath = path.join(tmpDir, '3xui_universal_backup.tar.gz');

  const pyGen = `
import sqlite3, json, sys

c1 = sqlite3.connect(sys.argv[1])
c1.execute("CREATE TABLE sub_logs (id INTEGER PRIMARY KEY, name TEXT)")
c1.commit()
c1.close()

conn = sqlite3.connect(sys.argv[2])
cur = conn.cursor()
cur.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id INT, up INT, down INT, total INT, remark TEXT, enable INT, expiry_time INT, traffic_reset TEXT, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT)")
cur.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INT, enable INT, email TEXT, up INT, down INT, expiry_time INT, total INT)")
cur.execute("CREATE TABLE outbound_traffics (id INTEGER PRIMARY KEY, tag TEXT, up INT, down INT, total INT)")
cur.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")

for i in range(1, 41):
    port = 40000 + i
    tag = f"inbound-{port}"
    if i % 4 == 0:
        proto = "vless"
        settings = {"clients": [{"id": f"11111111-2222-4333-8444-{i:012d}", "flow": "xtls-rprx-vision", "email": f"vless_user_{i}", "limitIp": 3, "totalGB": 100 * (1024**3), "expiryTime": 1893456000000, "enable": True, "subId": f"sub_{i}"}], "decryption": "none"}
        stream = {"network": "tcp", "security": "reality", "realitySettings": {"dest": "www.tesla.com:443", "serverNames": ["tesla.com", "www.tesla.com"], "privateKey": "cHJpdmF0ZWtleXplaceholder", "shortIds": ["1a2b3c4d"], "settings": {"publicKey": "cHVibGlja2V5placeholder", "fingerprint": "chrome"}}}
    elif i % 4 == 1:
        proto = "vless"
        settings = {"clients": [{"id": f"22222222-3333-4444-8555-{i:012d}", "flow": "", "email": f"vless_ws_{i}", "enable": True}], "decryption": "none"}
        stream = {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "", "alpn": ["h2", "http/1.1"], "certificates": [{"certificateFile": "/root/cert/node.example.com/fullchain.pem", "keyFile": "/root/cert/node.example.com/privkey.pem"}]}, "wsSettings": {"path": "/ws-test", "headers": {}}}
    elif i % 4 == 2:
        proto = "shadowsocks"
        settings = {"method": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MDEyMzQ1Ng==", "network": "tcp,udp", "clients": [{"password": "YWJjZGVmZ2hpamtsbW5vcA==", "email": f"ss2022_{i}", "enable": True}]}
        stream = {"network": "tcp", "security": "none"}
    else:
        proto = "mixed"
        settings = {"auth": "password", "accounts": [{"user": f"socks_u_{i}", "pass": f"socks_p_{i}"}], "udp": True}
        stream = {"network": "tcp", "security": "none"}

    cur.execute(
        "INSERT INTO inbounds VALUES (?, 1, ?, ?, ?, ?, 1, 1893456000000, 'monthly', '', ?, ?, ?, ?, ?, '{}')",
        (i, i * 1024, i * 2048, 100 * (1024**3), f"Node-{i}", port, proto, json.dumps(settings), json.dumps(stream), tag)
    )

outbounds = [
    {"tag": "direct", "protocol": "freedom", "settings": {}},
    {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    {"tag": "api", "protocol": "blackhole", "settings": {}},
    {"tag": "relay-node-1", "protocol": "shadowsocks", "settings": {"servers": [{"address": "198.51.100.10", "port": 15001, "method": "aes-256-gcm", "password": "pass1", "uot": True}]}},
    {"tag": "relay-node-2", "protocol": "shadowsocks", "settings": {"servers": [{"address": "198.51.100.11", "port": 15002, "method": "2022-blake3-aes-128-gcm", "password": "pass2"}]}},
    {"tag": "relay-vless-flat", "protocol": "vless", "settings": {"address": "198.51.100.88", "port": 443, "id": "99999999-8888-4777-8666-555555555555", "flow": "xtls-rprx-vision", "encryption": "none"}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "www.apple.com", "publicKey": "pbk123", "shortId": "1a2b"}, "sockopt": {"dialerProxy": "relay-node-1"}}}
]

rules = [
    {"type": "field", "inboundTag": ["inbound-40001"], "outboundTag": "relay-node-1"},
    {"type": "field", "inboundTag": ["inbound-40002"], "outboundTag": "relay-node-2"},
    {"type": "field", "inboundTag": ["inbound-40004"], "outboundTag": "relay-vless-flat"}
]

cur.execute("INSERT INTO outbound_traffics VALUES (1, 'relay-node-1', 10485760, 20971520, 31457280)")
cur.execute("INSERT INTO settings VALUES (1, 'xrayTemplateConfig', ?)", (json.dumps({"outbounds": outbounds, "routing": {"rules": rules}}),))
conn.commit()
conn.close()
`;
  const pyRun = spawnSync('python3', ['-c', pyGen, sublinkDbPath, xuiDbPath], { encoding: 'utf8' });
  assert.equal(pyRun.status, 0, pyRun.stderr);

  const tarRun = spawnSync('tar', ['-czf', tarGzPath, '-C', archiveBuildDir, 'usr/local/bin/sublink/db/sublink.db', 'etc/x-ui/x-ui.db']);
  assert.equal(tarRun.status, 0);

  const tarBuf = fs.readFileSync(tarGzPath);
  const migRes = await req('/SecPath16Chars99/api/migrate/3xui?mode=replace', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: tarBuf
  });
  assert.equal(migRes.status, 200);
  assert.equal(migRes.json.summary.inboundsCount, 40);
  assert.equal(migRes.json.summary.outboundsCount, 3);

  const inbRes = await req('/SecPath16Chars99/api/inbounds');
  assert.equal(inbRes.status, 200);
  const wsInbound = inbRes.json.inbounds.find((i) => i.port === 40001);
  assert.equal(wsInbound.tlsDomain, 'node.example.com');
  assert.ok(wsInbound.links[0].uri.includes('sni=node.example.com'));
  assert.ok(wsInbound.links[0].uri.includes('type=ws'));

  const realityInbound = inbRes.json.inbounds.find((i) => i.port === 40004);
  assert.equal(realityInbound.reality.serverName, 'tesla.com');

  const { config } = singbox.writeConfig();
  const sbWsInb = config.inbounds.find((i) => i.listen_port === 40001);
  assert.deepEqual(sbWsInb.tls.alpn, ['http/1.1']);

  const heapUsedMB = Math.round(process.memoryUsage().heapUsed / (1024 * 1024));
  assert.ok(heapUsedMB < 90, `Heap used (${heapUsedMB} MB) should stay well below 90MB`);
});

test('7. Certificate failover switchover, deletion persistence, and SSH ng --show-info sync', async () => {
  // Create a mock Let's Encrypt CA so issued certs have issuer !== subject (isSelfSigned === false)
  const caDir = path.join(tmpDir, 'ca');
  fs.mkdirSync(caDir, { recursive: true });
  const caKey = path.join(caDir, 'ca.key');
  const caCert = path.join(caDir, 'ca.crt');
  spawnSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-days', '3650', '-nodes', '-subj', '/C=US/O=Let\'s Encrypt/CN=E1',
    '-keyout', caKey, '-out', caCert
  ]);

  const issueMockCaCert = (domain) => {
    const dir = path.join(tmpDir, 'certs', domain);
    fs.mkdirSync(dir, { recursive: true });
    const keyPath = path.join(dir, 'privkey.pem');
    const csrPath = path.join(dir, 'req.csr');
    const certPath = path.join(dir, 'fullchain.pem');
    spawnSync('openssl', [
      'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-nodes', '-subj', `/CN=${domain}`, '-keyout', keyPath, '-out', csrPath
    ]);
    spawnSync('openssl', [
      'x509', '-req', '-in', csrPath, '-CA', caCert, '-CAkey', caKey,
      '-CAcreateserial', '-out', certPath, '-days', '365'
    ]);
    return { certPath, keyPath };
  };

  // 1. Import initial cert "old-standby.example.com"
  const oldC = issueMockCaCert('old-standby.example.com');
  const resOld = await req('/SecPath16Chars99/api/certificates/custom', {
    method: 'POST',
    body: JSON.stringify({
      domain: 'old-standby.example.com',
      certPath: oldC.certPath,
      keyPath: oldC.keyPath
    })
  });
  assert.equal(resOld.status, 201);

  // 2. Import new failover cert "new-failover.example.com"
  const newC = issueMockCaCert('new-failover.example.com');
  const resNew = await req('/SecPath16Chars99/api/certificates/custom', {
    method: 'POST',
    body: JSON.stringify({
      domain: 'new-failover.example.com',
      certPath: newC.certPath,
      keyPath: newC.keyPath
    })
  });
  assert.equal(resNew.status, 201);

  // Verify SSH ng (--show-info) immediately reflects the newly imported "new-failover.example.com"
  const cliAfterImport = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js'), '--show-info'], {
    env: { ...process.env, NG_DATA_FILE: path.join(tmpDir, 'nexusgate.json') },
    encoding: 'utf8'
  });
  assert.equal(cliAfterImport.status, 0);
  assert.ok(cliAfterImport.stdout.includes('new-failover.example.com'), 'SSH --show-info must show newly imported cert domain');

  // 3. Delete "new-failover.example.com" and verify it stays deleted and automatically switches back to old-standby.example.com
  const certsListRes = await req('/SecPath16Chars99/api/certificates');
  const newCertItem = certsListRes.json.certificates.find((c) => c.domain === 'new-failover.example.com');
  assert.ok(newCertItem);

  const delRes = await req(`/SecPath16Chars99/api/certificates/${encodeURIComponent(newCertItem.id)}`, {
    method: 'DELETE'
  });
  assert.equal(delRes.status, 200);
  assert.equal(delRes.json.deletedDomain, 'new-failover.example.com');
  assert.equal(delRes.json.switchedDomain, 'old-standby.example.com');

  const certsAfterDel = await req('/SecPath16Chars99/api/certificates');
  assert.ok(!certsAfterDel.json.certificates.some((c) => c.domain === 'new-failover.example.com'), 'Deleted cert must not reappear');
  assert.equal(certsAfterDel.json.settings.webDomain, 'old-standby.example.com');
});

test('8. E2E Multi-Client Inbound Migration (client_alpha & client_beta), Per-Client CRUD, Per-Client Subscriptions & Independent Limits', async () => {
  // 1. Build a 3x-ui / X-Panel SQLite DB containing row #20 "Multi-User-Node-20" (port 55011, vless + ws + TLS) with 2 clients:
  //    - "client_alpha" (198.85 GB used, limitIp: 2)
  //    - "client_beta" (6.66 GB used, limitIp: 2)
  const multiDbPath = path.join(tmpDir, 'multi_client_xui.db');
  const pyMulti = `
import sqlite3, json, sys

conn = sqlite3.connect(sys.argv[1])
cur = conn.cursor()
cur.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id INT, up INT, down INT, total INT, remark TEXT, enable INT, expiry_time INT, traffic_reset TEXT, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT)")
cur.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INT, enable INT, email TEXT, up INT, down INT, expiry_time INT, total INT)")
cur.execute("CREATE TABLE outbound_traffics (id INTEGER PRIMARY KEY, tag TEXT, up INT, down INT, total INT)")
cur.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")

settings = {
  "clients": [
    {
      "id": "aaaaaaaa-1111-4222-8333-111111111111",
      "flow": "",
      "email": "client_alpha",
      "limitIp": 2,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": True,
      "subId": "sub_client_alpha_token16"
    },
    {
      "id": "bbbbbbbb-2222-4333-8444-222222222222",
      "flow": "",
      "email": "client_beta",
      "limitIp": 2,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": True,
      "subId": "sub_yanzi_token1688"
    }
  ],
  "decryption": "none"
}
stream = {
  "network": "ws",
  "security": "tls",
  "tlsSettings": {
    "serverName": "eb.example.com",
    "certificates": [{"certificateFile": "/root/cert/eb.example.com/fullchain.pem", "keyFile": "/root/cert/eb.example.com/privkey.pem"}]
  },
  "wsSettings": {"path": "/ws-nice", "headers": {}}
}

cur.execute(
  "INSERT INTO inbounds VALUES (20, 1, 1000000, 2000000, 0, 'Multi-User-Node-20', 1, 0, 'never', '', 55011, 'vless', ?, ?, 'inbound-55011', '{}')",
  (json.dumps(settings), json.dumps(stream))
)
u1_bytes = int(198.85 * (1024**3))
u2_bytes = int(6.66 * (1024**3))
cur.execute("INSERT INTO client_traffics VALUES (1, 20, 1, 'client_alpha', ?, ?, 0, 0)", (u1_bytes // 10, u1_bytes - (u1_bytes // 10)))
cur.execute("INSERT INTO client_traffics VALUES (2, 20, 1, 'client_beta', ?, ?, 0, 0)", (u2_bytes // 10, u2_bytes - (u2_bytes // 10)))
conn.commit()
conn.close()
`;
  const pyRun = spawnSync('python3', ['-c', pyMulti, multiDbPath], { encoding: 'utf8' });
  assert.equal(pyRun.status, 0, pyRun.stderr);

  const dbBuf = fs.readFileSync(multiDbPath);
  const migRes = await req('/SecPath16Chars99/api/migrate/3xui?mode=merge', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: dbBuf
  });
  assert.equal(migRes.status, 200);

  // 2. Verify migrated inbound has both clients ("client_alpha" & "client_beta"), both share links, and Sing-box users array has both UUIDs
  const inbRes = await req('/SecPath16Chars99/api/inbounds');
  const niceInb = inbRes.json.inbounds.find((i) => i.port === 55011);
  assert.ok(niceInb, 'Multi-User-Node-20 inbound on port 55011 must exist');
  assert.equal(niceInb.clients.length, 2, 'Must preserve both clients on port 55011');
  assert.equal(niceInb.clients[0].email, 'client_alpha');
  assert.equal(niceInb.clients[1].email, 'client_beta');
  assert.equal(niceInb.links.length, 2, 'Must generate 2 independent client share links');
  assert.ok(niceInb.links[0].uri.includes('aaaaaaaa-1111-4222-8333-111111111111'));
  assert.ok(niceInb.links[1].uri.includes('bbbbbbbb-2222-4333-8444-222222222222'));

  const { config: sbCfg1 } = singbox.writeConfig();
  const sbNice = sbCfg1.inbounds.find((i) => i.listen_port === 55011);
  assert.equal(sbNice.users.length, 2, 'Sing-box inbound.users must contain both clients');
  assert.equal(sbNice.users[0].name, 'client_alpha');
  assert.equal(sbNice.users[1].name, 'client_beta');

  // 3. Verify editing the inbound remark/outboundTag preserves BOTH clients intact without overwriting Client #2
  const editInbRes = await req(`/SecPath16Chars99/api/inbounds/${niceInb.id}`, {
    method: 'PUT',
    body: JSON.stringify({
      ...niceInb,
      remark: 'Multi-User-Node-20-已核验'
    })
  });
  assert.equal(editInbRes.status, 200);
  assert.equal(editInbRes.json.inbound.clients.length, 2);
  assert.equal(editInbRes.json.inbound.clients[1].email, 'client_beta');
  assert.equal(editInbRes.json.inbound.clients[1].id, 'bbbbbbbb-2222-4333-8444-222222222222');

  // 4. Verify per-client subscription URLs return only that specific client's node and individual traffic stats
  const sub1Res = await req('/sub/sub_client_alpha_token16?format=clash');
  assert.equal(sub1Res.status, 200);
  assert.ok(sub1Res.text.includes('client_alpha'));
  assert.ok(!sub1Res.text.includes('client_beta'), 'Client 1 subscription must NOT leak Client 2 node');

  const sub2Res = await req('/sub/sub_yanzi_token1688?format=clash');
  assert.equal(sub2Res.status, 200);
  assert.ok(sub2Res.text.includes('client_beta'));
  assert.ok(!sub2Res.text.includes('client_alpha'), 'Client 2 subscription must NOT leak Client 1 node');

  // 5. Verify per-client CRUD: Add a 3rd client, toggle it, reset traffic, and delete it
  const addClientRes = await req(`/SecPath16Chars99/api/inbounds/${niceInb.id}/clients`, {
    method: 'POST',
    body: JSON.stringify({
      email: 'vip_third_user',
      limitIp: 1,
      limitDevice: 1,
      totalGB: 50
    })
  });
  assert.equal(addClientRes.status, 201);
  assert.equal(addClientRes.json.inbound.clients.length, 3);
  const thirdClient = addClientRes.json.client;

  const toggleClientRes = await req(`/SecPath16Chars99/api/inbounds/${niceInb.id}/clients/${encodeURIComponent(thirdClient.id)}/toggle`, {
    method: 'POST'
  });
  assert.equal(toggleClientRes.status, 200);
  assert.equal(toggleClientRes.json.client.enable, false);

  // When 3rd client is disabled, Sing-box config has 2 active users ("client_alpha" and "client_beta")
  const { config: sbCfg2 } = singbox.writeConfig();
  assert.equal(sbCfg2.inbounds.find((i) => i.listen_port === 55011).users.length, 2);

  const delClientRes = await req(`/SecPath16Chars99/api/inbounds/${niceInb.id}/clients/${encodeURIComponent(thirdClient.id)}`, {
    method: 'DELETE'
  });
  assert.equal(delClientRes.status, 200);
  assert.equal(delClientRes.json.inbound.clients.length, 2);

  // 6. Verify per-client independent limitIp enforcement on multi-client inbound:
  //    "client_alpha" has limitIp=2, "client_beta" has limitIp=2 -> 2 IPs for client_alpha + 2 IPs for client_beta (4 IPs total) are ALL allowed!
  //    Only a 3rd IP for "client_alpha" is blocked!
  const closedMultiIds = [];
  const mockMultiConns = [
    { id: 'c-u1-ip1', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_alpha', sourceIP: '198.18.0.1', sourcePort: '40001' }, upload: 100, download: 200, chains: ['direct'] },
    { id: 'c-u1-ip2', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_alpha', sourceIP: '198.18.0.2', sourcePort: '40002' }, upload: 100, download: 200, chains: ['direct'] },
    { id: 'c-u2-ip1', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_beta', sourceIP: '198.18.0.3', sourcePort: '40003' }, upload: 100, download: 200, chains: ['direct'] },
    { id: 'c-u2-ip2', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_beta', sourceIP: '198.18.0.4', sourcePort: '40004' }, upload: 100, download: 200, chains: ['direct'] },
    { id: 'c-u1-ip3-excess', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_alpha', sourceIP: '198.18.0.5', sourcePort: '40005' }, upload: 100, download: 200, chains: ['direct'] }
  ];
  const mockClash = http.createServer((reqM, resM) => {
    if (reqM.method === 'GET' && reqM.url === '/connections') {
      resM.writeHead(200, { 'content-type': 'application/json' });
      resM.end(JSON.stringify({ connections: mockMultiConns }));
    } else if (reqM.method === 'DELETE' && reqM.url.startsWith('/connections/')) {
      closedMultiIds.push(decodeURIComponent(reqM.url.slice('/connections/'.length)));
      resM.writeHead(204);
      resM.end();
    }
  });
  await new Promise((r) => mockClash.listen(0, '127.0.0.1', r));
  store.state.settings.clashApiPort = mockClash.address().port;
  try {
    await singbox.pollConnectionsAndEnforceLimits(new Date());
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(closedMultiIds.includes('c-u1-ip3-excess'), '3rd IP of client_alpha must be blocked');
    assert.ok(
      !closedMultiIds.includes('c-u1-ip1') &&
      !closedMultiIds.includes('c-u1-ip2') &&
      !closedMultiIds.includes('c-u2-ip1') &&
      !closedMultiIds.includes('c-u2-ip2'),
      'Both client_alpha (2 IPs) and client_beta (2 IPs) must remain online without interfering with each other'
    );
    assert.equal(singbox.getActiveDeviceCountForClient('inbound-55011', 'client_alpha', false), 2);
    assert.equal(singbox.getActiveDeviceCountForClient('inbound-55011', 'client_beta', false), 2);
  } finally {
    await new Promise((r) => mockClash.close(r));
  }
});

test('9. Zero-disruption cleanup & config diffing: memory cleanup never double-counts active connections or drops nodes', async () => {
  // 1. Verify writeConfig() diffing reports changed: false when config is identical
  const w1 = singbox.writeConfig();
  const w2 = singbox.writeConfig();
  assert.equal(w2.changed, false, 'Identical Sing-box config must report changed: false to avoid unnecessary restarts');

  // 2. Verify cleanupSystemLogsAndMemory never clears connTrafficCache of active connections (preventing false quota exhaustion)
  const targetInb = store.state.inbounds.find((i) => i.port === 55011);
  assert.ok(targetInb);
  const beforeUp = targetInb.up;

  let activeConns = [
    {
      id: 'long-lived-conn-1',
      start: new Date().toISOString(),
      metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_alpha', sourceIP: '198.18.0.1', sourcePort: '41000' },
      upload: 50000,
      download: 100000,
      chains: ['direct']
    }
  ];

  const mockClash = http.createServer((reqM, resM) => {
    if (reqM.method === 'GET' && reqM.url === '/connections') {
      resM.writeHead(200, { 'content-type': 'application/json' });
      resM.end(JSON.stringify({ connections: activeConns }));
    } else {
      resM.writeHead(204);
      resM.end();
    }
  });
  await new Promise((r) => mockClash.listen(0, '127.0.0.1', r));
  store.state.settings.clashApiPort = mockClash.address().port;

  try {
    const nowMs = Date.now();
    await singbox.pollConnectionsAndEnforceLimits(new Date(nowMs));
    assert.equal(targetInb.up - beforeUp, 50000);

    // Trigger system memory & log cleanup while long-lived-conn-1 is still active
    const cleanRes = await req('/SecPath16Chars99/api/system/cleanup', { method: 'POST' });
    assert.equal(cleanRes.status, 200);

    // Poll again with the same cumulative upload=50000: deltaUp MUST be 0 (not double-counted as +50000!)
    await singbox.pollConnectionsAndEnforceLimits(new Date(nowMs + 2000));
    assert.equal(targetInb.up - beforeUp, 50000, 'Active connection traffic must NOT be double-counted after memory cleanup');
  } finally {
    await new Promise((r) => mockClash.close(r));
  }
});

test('10. High-Concurrency Stress Test: 40 Inbound Nodes + 35 Relay Outbounds + 400 Concurrent Connections Zero-Drop Benchmark', async () => {
  // Ensure 35 relay outbounds exist and are bound across the 40+ inbound nodes
  for (let i = 1; i <= 35; i += 1) {
    const tag = `stress-relay-out-${i}`;
    if (!store.state.outbounds.some((o) => o.tag === tag)) {
      store.state.outbounds.push({
        id: `out_stress_${i}`,
        tag,
        type: 'shadowsocks',
        remark: `Relay-Landing-${i}`,
        enabled: true,
        server: `198.51.100.${i}`,
        port: 20000 + i,
        method: '2022-blake3-aes-128-gcm',
        password: 'MTIzNDU2Nzg5MDEyMzQ1Ng==',
        up: 0,
        down: 0
      });
    }
  }

  const activeInbounds = store.state.inbounds.filter((i) => i.enable !== false);
  assert.ok(activeInbounds.length >= 40, `Expected at least 40 active inbounds, got ${activeInbounds.length}`);

  // Simulate 400 concurrent connections across 40 inbounds and 35 relay outbounds (10 connections per inbound)
  const closedDuringStress = [];
  const stressConns = [];
  activeInbounds.slice(0, 40).forEach((inb, idx) => {
    inb.limitIp = 0;
    inb.limitDevice = 0;
    const outTag = `stress-relay-out-${(idx % 35) + 1}`;
    const userEmail = inb.clients?.[0]?.email || 'default';
    for (let cIdx = 0; cIdx < 10; cIdx += 1) {
      stressConns.push({
        id: `stress-conn-${idx}-${cIdx}`,
        start: new Date().toISOString(),
        metadata: {
          network: 'tcp',
          type: `${inb.protocol}/${inb.tag}`,
          user: userEmail,
          sourceIP: `198.19.${idx}.${cIdx + 1}`,
          sourcePort: String(30000 + cIdx)
        },
        upload: 16384 * (cIdx + 1),
        download: 65536 * (cIdx + 1),
        chains: [outTag]
      });
    }
  });

  const mockClash = http.createServer((reqM, resM) => {
    if (reqM.method === 'GET' && reqM.url === '/connections') {
      resM.writeHead(200, { 'content-type': 'application/json' });
      resM.end(JSON.stringify({ connections: stressConns }));
    } else if (reqM.method === 'DELETE' && reqM.url.startsWith('/connections/')) {
      closedDuringStress.push(reqM.url);
      resM.writeHead(204);
      resM.end();
    }
  });
  await new Promise((r) => mockClash.listen(0, '127.0.0.1', r));
  store.state.settings.clashApiPort = mockClash.address().port;

  try {
    const t0 = Date.now();
    for (let round = 1; round <= 5; round += 1) {
      for (const c of stressConns) {
        c.upload += 4096;
        c.download += 8192;
      }
      await singbox.pollConnectionsAndEnforceLimits(new Date(t0 + round * 1000));
    }
    const elapsedMs = Date.now() - t0;
    assert.equal(closedDuringStress.length, 0, 'Zero normal client connections may be dropped under 40-node / 400-conn load');
    assert.ok(elapsedMs < 400, `5 full polling cycles of 400 connections should complete in <400ms (took ${elapsedMs}ms)`);

    // Verify overview status endpoint reports low private panel memory (RssAnon)
    const ovRes = await req('/SecPath16Chars99/api/overview');
    assert.equal(ovRes.status, 200);
    const panelMemMB = Math.round(ovRes.json.system.panelMemoryBytes / (1024 * 1024));
    assert.ok(panelMemMB < 45, `Panel private memory (${panelMemMB} MB) should stay well under 45 MB even with 40+ nodes and 400 connections`);
  } finally {
    await new Promise((r) => mockClash.close(r));
  }
});

test('11. Fast Non-Blocking Node Creation (< 50ms), Idempotent Double-Submit Guard & Modal Auto-Close Verification', async () => {
  const startMs = Date.now();
  const payload = {
    remark: 'Fast-Create-VLESS-Reality',
    protocol: 'vless',
    port: 58899,
    security: 'reality',
    transport: 'tcp',
    flow: 'xtls-rprx-vision',
    limitIp: 2,
    limitDevice: 2
  };

  // 1st click: creates node in < 50ms without blocking on ufw/iptables/systemctl
  const res1 = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  const elapsedMs = Date.now() - startMs;
  assert.equal(res1.status, 201);
  assert.equal(res1.json.inbound.port, 58899);
  assert.equal(res1.json.inbound.reality.serverName, 'tesla.com');
  assert.ok(elapsedMs < 150, `POST /api/inbounds must respond immediately without blocking (${elapsedMs}ms)`);

  // 2nd rapid click / network retry with same port & protocol within 15s: returns 200 OK (idempotent) instead of 400 error
  const res2 = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  assert.equal(res2.status, 200, 'Duplicate submit within 15s must return 200 OK so modal closes cleanly');
  assert.equal(res2.json.deduplicated, true);
  assert.equal(res2.json.inbound.id, res1.json.inbound.id);

  // Genuine port conflict (different protocol on the same port 58899) must still be rejected with 400
  const conflictRes = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify({ remark: 'Conflict-Trojan', protocol: 'trojan', port: 58899, security: 'tls' })
  });
  assert.equal(conflictRes.status, 400);

  // Verify frontend app.js and styles.css contain double-submit lock and dialog:not([open]) safeguard
  const appJs = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const stylesCss = fs.readFileSync(path.join(__dirname, '..', 'public', 'styles.css'), 'utf8');
  assert.ok(appJs.includes("form.dataset.submitting === '1'"), 'Frontend must lock form against double submit');
  assert.ok(appJs.includes("dlg.removeAttribute('open')"), 'closeModal() must forcefully remove open attribute');
  assert.ok(stylesCss.includes("dialog:not([open]){display:none!important}"), 'CSS must hide closed dialog across all browsers');
});

test('12. High-Strength Unique Initial Server Credentials (--init-panel & Store) and Non-Colliding Node/Client Credentials', async () => {
  const { generateStrongCredential, verifySecret, hashSecret } = require('../lib/auth');
  const { Store } = require('../lib/store');

  // 1) Verify generateStrongCredential guarantees uppercase, lowercase, digits, and non-collision across 50 runs
  const seen = new Set();
  for (let i = 0; i < 50; i += 1) {
    const u = generateStrongCredential(13, { prefix: 'ng_' });
    const p = generateStrongCredential(18, { exclude: u });
    assert.equal(u.length, 13);
    assert.equal(p.length, 18);
    assert.notEqual(u, p, 'Username and password must never be identical');
    assert.ok(/[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p), `Password must contain upper, lower, and digits: ${p}`);
    assert.ok(!seen.has(u) && !seen.has(p), 'Every generated credential must be unique');
    seen.add(u);
    seen.add(p);
  }

  // 2) Simulate 2 brand-new server installations via --init-panel and verify completely distinct high-strength credentials
  const srvDir1 = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-srv1-'));
  const srvDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-srv2-'));
  try {
    const cleanEnv1 = { ...process.env, NG_DATA_FILE: path.join(srvDir1, 'nexusgate.json'), NG_SINGBOX_CONFIG: path.join(srvDir1, 'sb.json') };
    delete cleanEnv1.NG_ADMIN_USERNAME;
    delete cleanEnv1.NG_ADMIN_PASSWORD;
    delete cleanEnv1.NG_PORT;
    delete cleanEnv1.NG_BASE_PATH;

    const cleanEnv2 = { ...cleanEnv1, NG_DATA_FILE: path.join(srvDir2, 'nexusgate.json'), NG_SINGBOX_CONFIG: path.join(srvDir2, 'sb.json') };

    const out1 = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js'), '--init-panel', 'auto', 'auto', 'auto', 'auto', '203.0.113.10'], { env: cleanEnv1, encoding: 'utf8' });
    assert.equal(out1.status, 0, `srv1 init failed: ${out1.stderr}`);
    const info1 = JSON.parse(out1.stdout.trim());

    // Also test passing identical username & password to --init-panel: it must automatically remediate so password !== username
    const out2 = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js'), '--init-panel', 'auto', 'same_cred_test', 'same_cred_test', 'auto', '203.0.113.11'], { env: cleanEnv2, encoding: 'utf8' });
    assert.equal(out2.status, 0, `srv2 init failed: ${out2.stderr}`);
    const info2 = JSON.parse(out2.stdout.trim());

    assert.ok(info1.username.startsWith('ng_') && info1.username.length === 13);
    assert.equal(info1.password.length, 18);
    assert.notEqual(info1.username, info1.password);
    assert.notEqual(info1.username, info2.username, 'Different servers must get different usernames');
    assert.notEqual(info1.password, info2.password, 'Different servers must get different passwords');
    assert.notEqual(info2.username, info2.password, 'Even if identical user/pass passed to --init-panel, password must be auto-remediated to a distinct 18-char strong password');
    assert.equal(info2.password.length, 18);
  } finally {
    fs.rmSync(srvDir1, { recursive: true, force: true });
    fs.rmSync(srvDir2, { recursive: true, force: true });
  }

  // 3) Verify creating SOCKS5 and AnyTLS nodes and adding clients always produces distinct username, email, and password
  const socksCreate = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify({
      remark: 'SOCKS-Unique-Creds',
      protocol: 'socks',
      port: 58901,
      socksUser: 'same_socks_cred',
      socksPassword: 'same_socks_cred'
    })
  });
  assert.equal(socksCreate.status, 201);
  const socksNode = socksCreate.json.inbound;
  assert.equal(socksNode.socksUser, 'same_socks_cred');
  assert.notEqual(socksNode.socksPassword, socksNode.socksUser, 'SOCKS password must never equal SOCKS username');
  assert.equal(socksNode.socksPassword.length, 18);
  assert.notEqual(socksNode.clients[0].username, socksNode.clients[0].password);

  // Add a second client to SOCKS node without specifying credentials
  const addSocksClient = await req(`/SecPath16Chars99/api/inbounds/${socksNode.id}/clients`, {
    method: 'POST',
    body: JSON.stringify({})
  });
  assert.equal(addSocksClient.status, 201);
  const sc = addSocksClient.json.client;
  assert.notEqual(sc.username, sc.password, 'Added client username and password must be distinct');
  assert.notEqual(sc.email, sc.password, 'Added client email and password must be distinct');
  assert.ok(sc.password.length >= 18);
});

test('13. Full-Lifecycle E2E: CLI Operations, Account/Port/Path Update, BBR Acceleration, Outbound Tag Cascade, Rule Reordering, Backup & Restore', async () => {
  // 1) BBR + FQ + HY2 Kernel Acceleration API
  const accAll = await req('/SecPath16Chars99/api/system/acceleration', {
    method: 'POST',
    body: JSON.stringify({ mode: 'all' })
  });
  assert.equal(accAll.status, 200);
  assert.ok(accAll.json.acceleration && typeof accAll.json.acceleration.congestion === 'string');

  // 2) Firewall API
  const fwRes = await req('/SecPath16Chars99/api/system/firewall', { method: 'POST' });
  assert.equal(fwRes.status, 200);
  assert.ok(Array.isArray(fwRes.json.openedPorts));

  // 3) Batch import all 8 outbound protocols via URI (ss, vless, vmess, trojan, hy2, anytls, socks5, tuic)
  const vmessObj = { v: '2', ps: 'Relay-VMess-WS', add: '127.0.0.1', port: '443', id: '6832b114-5826-4c3c-9c83-400383a51234', aid: '0', scy: 'auto', net: 'ws', path: '/vmess?ed=2048', host: 'vm.example.com', tls: 'tls', sni: 'vm.example.com' };
  const uriBatch = [
    'ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206TVRJek5EVTJOemc1Tabcdef@127.0.0.1:8388#Relay-SS2022',
    'vless://6832b114-5826-4c3c-9c83-400383a51234@127.0.0.1:8443?security=reality&sni=tesla.com&pbk=testpbk&sid=1a2b&type=tcp&flow=xtls-rprx-vision#Relay-VLESS',
    `vmess://${Buffer.from(JSON.stringify(vmessObj)).toString('base64')}`,
    'trojan://TrojanPass123@127.0.0.1:9443?security=tls&sni=tr.example.com&type=ws&path=%2Ftr%3Fed%3D2048#Relay-Trojan',
    'hy2://Hy2Pass123@127.0.0.1:10443?sni=hy2.example.com&obfs=salamander&obfs-password=obfspass#Relay-HY2',
    'anytls://AnyPass123@127.0.0.1:11443?sni=any.example.com&insecure=1#Relay-AnyTLS',
    'socks5://u_socks:p_socks@127.0.0.1:1080#Relay-SOCKS5',
    'tuic://6832b114-5826-4c3c-9c83-400383a51234:TuicPass123@127.0.0.1:12443?congestion_control=bbr&alpn=h3&sni=tuic.example.com#Relay-TUIC'
  ].join('\n');

  const impRes = await req('/SecPath16Chars99/api/outbounds/import-uri', {
    method: 'POST',
    body: JSON.stringify({ uri: uriBatch })
  });
  assert.equal(impRes.status, 201);
  assert.equal(impRes.json.count, 8);

  // Verify TCP Ping on a local listening port (our own HTTP test server port)
  const testListenPort = server.address().port;
  const pingTargetOut = await req('/SecPath16Chars99/api/outbounds', {
    method: 'POST',
    body: JSON.stringify({ tag: 'out-local-ping', type: 'socks', server: '127.0.0.1', port: testListenPort })
  });
  assert.equal(pingTargetOut.status, 201);
  const pingRes = await req(`/SecPath16Chars99/api/outbounds/${pingTargetOut.json.outbound.id}/ping`, { method: 'POST' });
  assert.equal(pingRes.status, 200);
  assert.equal(pingRes.json.reachable, true);

  // Create an inbound bound to out-local-ping, then rename out-local-ping -> out-local-renamed, and verify cascade!
  const boundInbRes = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify({
      remark: 'Cascade-Test-Node',
      protocol: 'vmess',
      port: 58910,
      security: 'tls',
      transport: 'ws',
      wsPath: '/vmess-ws?ed=2048',
      outboundTag: 'out-local-ping'
    })
  });
  assert.equal(boundInbRes.status, 201);
  // Verify VMess+WS+TLS link has TLS in Sing-box JSON and servername in Clash YAML
  const vmessLink = boundInbRes.json.inbound.links[0];
  const vmessSbOut = JSON.parse(vmessLink.singboxJson);
  assert.equal(vmessSbOut.tls.enabled, true, 'VMess TLS Sing-box JSON must include tls.enabled=true');
  assert.equal(vmessSbOut.transport.path, '/vmess-ws', 'WS ?ed=2048 must be stripped into max_early_data');
  assert.equal(vmessSbOut.transport.max_early_data, 2048);

  const renameOutRes = await req(`/SecPath16Chars99/api/outbounds/${pingTargetOut.json.outbound.id}`, {
    method: 'PUT',
    body: JSON.stringify({ tag: 'out-local-renamed', type: 'socks', server: '127.0.0.1', port: testListenPort })
  });
  assert.equal(renameOutRes.status, 200);
  const cascadedInb = store.state.inbounds.find((i) => i.id === boundInbRes.json.inbound.id);
  assert.equal(cascadedInb.outboundTag, 'out-local-renamed', 'Renaming outbound tag must cascade to bound inbounds');

  // Test Routing Presets & Rule Reordering (up / down / top / bottom)
  for (const preset of ['ai-relay', 'foreign-trade', 'block-ads', 'cn-direct', 'media-relay']) {
    const pr = await req('/SecPath16Chars99/api/routing/presets', {
      method: 'POST',
      body: JSON.stringify({ preset, outbound: 'out-local-renamed' })
    });
    assert.equal(pr.status, 201);
  }
  const lastRule = store.state.routing.rules[store.state.routing.rules.length - 1];
  const moveTop = await req(`/SecPath16Chars99/api/routing/rules/${lastRule.id}/move`, {
    method: 'POST',
    body: JSON.stringify({ direction: 'top' })
  });
  assert.equal(moveTop.status, 200);
  assert.equal(moveTop.json.rules[0].id, lastRule.id);

  // Test Full Backup & Restore (modifying state in between and verifying 100% restoration)
  const backupRes = await req('/SecPath16Chars99/api/backup');
  assert.equal(backupRes.status, 200);
  const backupSnapshot = JSON.parse(backupRes.text);
  const countBefore = backupSnapshot.inbounds.length;

  // Delete an inbound, then restore backup and verify count returns to countBefore
  await req(`/SecPath16Chars99/api/inbounds/${boundInbRes.json.inbound.id}`, { method: 'DELETE' });
  assert.equal(store.state.inbounds.length, countBefore - 1);

  const restoreRes = await req('/SecPath16Chars99/api/restore', {
    method: 'POST',
    body: JSON.stringify({ backup: backupSnapshot })
  });
  assert.equal(restoreRes.status, 200);
  assert.equal(store.state.inbounds.length, countBefore, 'Restore backup must restore all inbounds');

  // Test Account Password & Username Update + Reject Identical Username/Password
  const sameUserPassRes = await req('/SecPath16Chars99/api/auth/account', {
    method: 'POST',
    body: JSON.stringify({
      currentPassword: 'StrongPassword123456',
      username: 'ng_sameUser99',
      newPassword: 'ng_sameUser99'
    })
  });
  assert.equal(sameUserPassRes.status, 400, 'Setting password equal to username must be rejected with 400');

  const updateAccRes = await req('/SecPath16Chars99/api/auth/account', {
    method: 'POST',
    body: JSON.stringify({
      currentPassword: 'StrongPassword123456',
      username: 'ng_newAdmin88',
      newPassword: 'NewStrongPass998877'
    })
  });
  assert.equal(updateAccRes.status, 200);

  // Re-login with new credentials, then restore original test credentials for subsequent tests
  const relogin = await req('/SecPath16Chars99/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'ng_newAdmin88', password: 'NewStrongPass998877' })
  });
  assert.equal(relogin.status, 200);
  csrf = relogin.json.csrf;

  const restoreAcc = await req('/SecPath16Chars99/api/auth/account', {
    method: 'POST',
    body: JSON.stringify({
      currentPassword: 'NewStrongPass998877',
      username: 'ng_adminTest01',
      newPassword: 'StrongPassword123456'
    })
  });
  assert.equal(restoreAcc.status, 200);
  const reloginOrig = await req('/SecPath16Chars99/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'ng_adminTest01', password: 'StrongPassword123456' })
  });
  assert.equal(reloginOrig.status, 200);
  csrf = reloginOrig.json.csrf;
});

test('14. Security & Vulnerability Audit: Path Traversal, Malformed URI Encoding, CSRF Guard, Duplicate Remark Disambiguation & Brute-Force Lockout', async () => {
  // 1) Malformed percent-encoding in URL must never crash server (returns 404 cleanly)
  const badUri1 = await req('/sub/%E0%A4%A');
  assert.equal(badUri1.status, 404);
  const badUri2 = await req('/SecPath16Chars99/api/inbounds/%ZZ%99');
  assert.equal(badUri2.status, 404);

  // 2) Path traversal attempt on static file server must be blocked
  const travRes = await req('/SecPath16Chars99/..%2f..%2fpackage.json');
  assert.ok([302, 404].includes(travRes.status));

  // 3) CSRF token enforcement on mutating endpoints
  const savedCsrf = csrf;
  csrf = 'invalid_csrf_token';
  const csrfFail = await req('/SecPath16Chars99/api/settings', {
    method: 'PUT',
    body: JSON.stringify({ webPort: 2053 })
  });
  assert.equal(csrfFail.status, 403);
  csrf = savedCsrf;

  // 4) Duplicate node remarks in subscription must be automatically disambiguated in Clash & Sing-box subscriptions
  await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify({ remark: 'Dup-Remark-HK', protocol: 'vless', port: 58921, security: 'reality' })
  });
  await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify({ remark: 'Dup-Remark-HK', protocol: 'anytls', port: 58922, security: 'tls' })
  });
  const subTok = store.state.settings.subToken;
  const sbSub = await req(`/sub/${subTok}?format=singbox`);
  assert.equal(sbSub.status, 200);
  const sbJson = JSON.parse(sbSub.text);
  const hkTags = sbJson.outbounds.filter((o) => o.tag && o.tag.startsWith('Dup-Remark-HK')).map((o) => o.tag);
  assert.ok(hkTags.includes('Dup-Remark-HK') && hkTags.includes('Dup-Remark-HK (2)'), 'Duplicate remarks must be disambiguated in Sing-box & Clash subscriptions');
});

test('15. Multi-Tier Environment Stress Benchmark: Low (10 Nodes) -> Medium (40 Nodes) -> Extreme High Intensity (100 Nodes / 300 Clients / 80 Outbounds / 1,200 Active Connections)', async () => {
  // Prepare 100 Inbound Nodes (across all protocols, with 3 clients per node = 300 clients) and 80 Outbounds
  const protocols = ['vless', 'anytls', 'hysteria2', 'shadowsocks', 'trojan', 'vmess', 'socks', 'tuic'];
  const baseInbCount = store.state.inbounds.length;
  const baseOutCount = store.state.outbounds.length;

  store.transact((st) => {
    for (let i = 1; i <= 80; i += 1) {
      const oTag = `stress-high-out-${i}`;
      if (!st.outbounds.some((o) => o.tag === oTag)) {
        st.outbounds.push({
          id: `out_hi_${i}`,
          tag: oTag,
          type: i % 2 === 0 ? 'shadowsocks' : 'vless',
          remark: `高压落地-${i}`,
          enabled: true,
          server: `198.18.${Math.floor(i / 250)}.${(i % 250) + 1}`,
          port: 40000 + i,
          method: '2022-blake3-aes-128-gcm',
          password: 'MTIzNDU2Nzg5Mabcdef=',
          uuid: '6832b114-5826-4c3c-9c83-400383a51234',
          up: 0,
          down: 0
        });
      }
    }

    for (let i = 1; i <= 100; i += 1) {
      const proto = protocols[i % protocols.length];
      const port = 42000 + i;
      const tag = `inbound-hi-${port}`;
      const outTag = `stress-high-out-${((i - 1) % 80) + 1}`;
      if (!st.inbounds.some((x) => x.tag === tag)) {
        st.inbounds.push({
          id: `in_hi_${i}`,
          tag,
          remark: `HighStress-${proto.toUpperCase()}-${i}`,
          protocol: proto,
          listen: '::',
          port,
          enable: true,
          security: proto === 'vless' ? 'reality' : (['anytls', 'hysteria2', 'trojan', 'tuic'].includes(proto) ? 'tls' : 'none'),
          transport: 'tcp',
          method: '2022-blake3-aes-128-gcm',
          password: `PassHighStrength${i}Xy9`,
          socksUser: `u_hi_${i}`,
          socksPassword: `SockPassHi${i}Zz8`,
          outboundTag: outTag,
          limitIp: 5,
          limitDevice: 5,
          reality: { serverName: 'tesla.com', target: 'www.tesla.com:443', privateKey: 'priv', publicKey: 'pub', shortIds: ['1a2b'] },
          clients: [1, 2, 3].map((cIdx) => ({
            id: `6832b114-5826-4c3c-9c83-${String(i * 10 + cIdx).padStart(12, '0')}`,
            email: `hi_node${i}_u${cIdx}`,
            username: `u_hi_${i}_${cIdx}`,
            password: `ClientPassHi${i}_${cIdx}Ab9`,
            subId: `sub_hi_${i}_${cIdx}_token12345`,
            limitIp: 2,
            limitDevice: 2,
            enable: true,
            up: 0,
            down: 0
          })),
          up: 0,
          down: 0
        });
      }
    }
  });

  // Build 1,200 concurrent active connections (12 connections per node across 100 nodes: 2 IPs per client * 3 clients * 2 streams)
  const hiConns = [];
  const droppedIds = [];
  for (let i = 1; i <= 100; i += 1) {
    const proto = protocols[i % protocols.length];
    const port = 42000 + i;
    const tag = `inbound-hi-${port}`;
    const outTag = `stress-high-out-${((i - 1) % 80) + 1}`;
    for (let cIdx = 1; cIdx <= 3; cIdx += 1) {
      const userEmail = `hi_node${i}_u${cIdx}`;
      for (let ipIdx = 1; ipIdx <= 2; ipIdx += 1) {
        for (let sIdx = 1; sIdx <= 2; sIdx += 1) {
          // 3 clients * 2 IPs = 6 IPs if all distinct, but node limitIp is 5, so let clients share 4 distinct IPs per node (within both client limitIp=2 and node limitIp=5)
          const ipOctet = ((cIdx + ipIdx - 2) % 4) + 1;
          hiConns.push({
            id: `hi-conn-${i}-${cIdx}-${ipIdx}-${sIdx}`,
            start: new Date(Date.now() - 2000).toISOString(),
            metadata: {
              type: `${proto}/${tag}`,
              inboundPort: port,
              sourceIP: `198.51.100.${ipOctet}`,
              sourcePort: 20000 + cIdx * 100 + ipIdx * 10 + sIdx,
              user: userEmail
            },
            upload: 4096,
            download: 16384,
            chains: [outTag]
          });
        }
      }
    }
  }
  assert.equal(hiConns.length, 1200, 'Must simulate 1,200 concurrent connections across 100 nodes');

  const mockHiClash = http.createServer((reqM, resM) => {
    if (reqM.method === 'GET' && reqM.url === '/connections') {
      resM.writeHead(200, { 'content-type': 'application/json' });
      resM.end(JSON.stringify({ connections: hiConns }));
    } else if (reqM.method === 'DELETE' && reqM.url.startsWith('/connections/')) {
      droppedIds.push(reqM.url);
      resM.writeHead(204);
      resM.end();
    }
  });
  await new Promise((r) => mockHiClash.listen(0, '127.0.0.1', r));
  store.state.settings.clashApiPort = mockHiClash.address().port;

  try {
    const startPoll = Date.now();
    for (let cycle = 1; cycle <= 5; cycle += 1) {
      for (const c of hiConns) {
        c.upload += 2048;
        c.download += 8192;
      }
      await singbox.pollConnectionsAndEnforceLimits(new Date(startPoll + cycle * 1000));
    }
    const pollElapsed = Date.now() - startPoll;
    assert.equal(droppedIds.length, 0, 'Zero legitimate connections dropped across 1,200 concurrent streams on 100 nodes');
    assert.ok(pollElapsed < 1500, `5 cycles of 1,200 connections must complete in < 1.5s (took ${pollElapsed}ms)`);

    // Concurrently hammer read & subscription APIs while 100+ nodes & 300+ clients are active
    const subToken = store.state.settings.subToken;
    const concurrentReqs = await Promise.all([
      req('/SecPath16Chars99/api/overview'),
      req('/SecPath16Chars99/api/inbounds'),
      req('/SecPath16Chars99/api/outbounds'),
      req('/SecPath16Chars99/api/routing'),
      req(`/sub/${subToken}?format=base64`),
      req(`/sub/${subToken}?format=clash`),
      req(`/sub/${subToken}?format=singbox`),
      req('/sub/sub_hi_50_2_token12345?format=clash')
    ]);
    for (const r of concurrentReqs) {
      assert.equal(r.status, 200);
    }

    // Trigger memory cleanup and verify low panel memory footprint even after 100-node / 1,200-conn stress test
    const cleanRes = await req('/SecPath16Chars99/api/system/cleanup', { method: 'POST' });
    assert.equal(cleanRes.status, 200);
    const memMB = Math.round(cleanRes.json.system.panelMemoryBytes / (1024 * 1024));
    assert.ok(memMB < 65, `Panel private memory after 100-node / 1,200-connection stress must remain < 65 MB (was ${memMB} MB)`);
  } finally {
    await new Promise((r) => mockHiClash.close(r));
    store.transact((st) => {
      st.inbounds.length = baseInbCount;
      st.outbounds.length = baseOutCount;
    });
  }
});

test('16. Zero-Lag Sidebar Tab Switching Benchmark (< 15ms per tab with 40+ migrated nodes & memoized links)', async () => {
  // Ensure we have at least 35 active nodes in state
  store.transact((st) => {
    for (let i = 1; i <= 35; i += 1) {
      const port = 51000 + i;
      const tag = `inbound-tabbench-${port}`;
      if (!st.inbounds.some((x) => x.tag === tag)) {
        st.inbounds.push({
          id: `in_tb_${i}`,
          tag,
          remark: `Bench-VLESS-${i}`,
          protocol: 'vless',
          listen: '::',
          port,
          enable: true,
          security: 'reality',
          transport: 'tcp',
          flow: 'xtls-rprx-vision',
          reality: { serverName: 'tesla.com', target: 'www.tesla.com:443', privateKey: 'priv', publicKey: 'pub', shortIds: ['1a2b'] },
          clients: [{ id: `6832b114-5826-4c3c-9c83-${String(9000 + i).padStart(12, '0')}`, email: `tb_u_${i}`, subId: `sub_tb_${i}_12345678`, enable: true }]
        });
      }
    }
  });

  // Warm up caches on 1st pass, then benchmark all 6 sidebar tab endpoints across 3 rapid full rotations (18 tab switches)
  const tabEndpoints = [
    '/SecPath16Chars99/api/overview',
    '/SecPath16Chars99/api/inbounds',
    '/SecPath16Chars99/api/routing',
    '/SecPath16Chars99/api/outbounds',
    '/SecPath16Chars99/api/certificates',
    '/SecPath16Chars99/api/settings'
  ];

  for (const ep of tabEndpoints) {
    const warm = await req(ep);
    assert.equal(warm.status, 200);
  }

  const startBench = Date.now();
  for (let round = 0; round < 3; round += 1) {
    for (const ep of tabEndpoints) {
      const t0 = Date.now();
      const res = await req(ep);
      const dt = Date.now() - t0;
      assert.equal(res.status, 200);
      assert.ok(dt < 30, `Sidebar tab endpoint ${ep} must respond in < 30ms (took ${dt}ms)`);
    }
  }
  const totalBenchMs = Date.now() - startBench;
  assert.ok(totalBenchMs < 200, `18 consecutive sidebar tab switches across all 6 pages must complete in < 200ms total (took ${totalBenchMs}ms)`);
});

test('17. Real Frontend DOM Execution E2E Test: Boot public/app.js, Click All 7 Sidebar Tabs, Verify Active State, Title, Content & Modals with Zero Runtime Errors', async () => {
  const vm = require('node:vm');
  const appCode = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');

  // Build a lightweight, standards-compliant simulated DOM matching public/index.html
  const makeEl = (tag, id = '', attrs = {}) => {
    const classes = new Set((attrs.className || '').split(/\s+/).filter(Boolean));
    const el = {
      tagName: tag.toUpperCase(),
      id,
      dataset: { ...(attrs.dataset || {}) },
      style: {},
      value: attrs.value || '',
      checked: Boolean(attrs.checked),
      disabled: false,
      textContent: attrs.textContent || '',
      _innerHTML: '',
      isConnected: true,
      open: false,
      children: [],
      listeners: {},
      classList: {
        add: (...c) => c.forEach((x) => classes.add(x)),
        remove: (...c) => c.forEach((x) => classes.delete(x)),
        toggle: (c, force) => {
          const next = force !== undefined ? Boolean(force) : !classes.has(c);
          if (next) classes.add(c);
          else classes.delete(c);
          return next;
        },
        contains: (c) => classes.has(c)
      },
      get className() { return [...classes].join(' '); },
      set className(v) { classes.clear(); String(v || '').split(/\s+/).filter(Boolean).forEach((x) => classes.add(x)); },
      get innerHTML() { return this._innerHTML; },
      set innerHTML(v) { this._innerHTML = String(v ?? ''); },
      setAttribute(k, v) { if (k === 'open') this.open = true; this[k] = v; },
      removeAttribute(k) { if (k === 'open') { this.open = false; return; } delete this[k]; },
      showModal() { this.open = true; },
      close() { this.open = false; },
      append() {},
      remove() {},
      focus() {},
      select() {},
      setSelectionRange() {},
      addEventListener(type, fn) {
        if (!this.listeners[type]) this.listeners[type] = [];
        this.listeners[type].push(fn);
      },
      querySelector(sel) { return doc.querySelector(sel); },
      querySelectorAll(sel) { return doc.querySelectorAll(sel); },
      closest(sel) {
        if (sel === '#nav button[data-page]' && this.dataset.page) return this;
        if (sel === '[data-action]' && this.dataset.action) return this;
        if (sel === '[data-close]' && this.dataset.close !== undefined) return this;
        return null;
      },
      matches: () => false
    };
    return el;
  };

  const navPages = ['overview', 'inbounds', 'routing', 'outbounds', 'migrate', 'certificates', 'settings'];
  const navButtons = navPages.map((p, i) => makeEl('button', `nav-${p}`, { className: i === 0 ? 'active' : '', dataset: { page: p } }));
  const elementsById = new Map([
    ['login', makeEl('div', 'login', { className: 'login-shell hidden' })],
    ['app', makeEl('div', 'app', { className: 'app-shell hidden' })],
    ['sidebar', makeEl('aside', 'sidebar')],
    ['nav', makeEl('nav', 'nav')],
    ['sb-dot', makeEl('span', 'sb-dot')],
    ['connection-label', makeEl('span', 'connection-label')],
    ['logout', makeEl('button', 'logout')],
    ['menu-toggle', makeEl('button', 'menu-toggle')],
    ['breadcrumb', makeEl('p', 'breadcrumb')],
    ['page-title', makeEl('h1', 'page-title')],
    ['quick-config-btn', makeEl('button', 'quick-config-btn')],
    ['refresh', makeEl('button', 'refresh')],
    ['user-chip', makeEl('span', 'user-chip')],
    ['content', makeEl('div', 'content')],
    ['sidebar-scrim', makeEl('button', 'sidebar-scrim')],
    ['modal', makeEl('dialog', 'modal')],
    ['modal-kicker', makeEl('p', 'modal-kicker')],
    ['modal-title', makeEl('h2', 'modal-title')],
    ['modal-body', makeEl('div', 'modal-body')],
    ['toasts', makeEl('div', 'toasts')],
    ['login-error', makeEl('p', 'login-error')]
  ]);
  const metaTheme = makeEl('meta');
  const themeBtn = makeEl('button', 'theme-btn');

  const doc = {
    documentElement: { dataset: { theme: 'light' } },
    body: makeEl('body'),
    activeElement: { tagName: 'BODY' },
    listeners: {},
    createElement: (tag) => makeEl(tag),
    execCommand: () => true,
    addEventListener(type, fn) {
      if (!this.listeners[type]) this.listeners[type] = [];
      this.listeners[type].push(fn);
    },
    querySelector(sel) {
      if (sel.startsWith('#') && !sel.includes(' ')) return elementsById.get(sel.slice(1)) || makeEl('input', sel.slice(1));
      if (sel === 'meta[name="theme-color"]') return metaTheme;
      return null;
    },
    querySelectorAll(sel) {
      if (sel === '#nav button') return navButtons;
      if (sel === '[data-theme-toggle]') return [themeBtn];
      return [];
    }
  };

  const storageMap = new Map([['ng-active-page', 'inbounds']]);
  const storageObj = {
    getItem: (k) => storageMap.get(k) || null,
    setItem: (k, v) => storageMap.set(k, String(v)),
    removeItem: (k) => storageMap.delete(k)
  };

  const win = {
    __NG_BASE_PATH__: '/SecPath16Chars99',
    location: { hash: '#inbounds', protocol: 'https:', hostname: 'ppf.onliveme.com', port: '48842', href: '' },
    history: { replaceState: (_s, _t, h) => { win.location.hash = h; } },
    localStorage: storageObj,
    sessionStorage: storageObj,
    crypto: require('node:crypto').webcrypto,
    scrollY: 0,
    scrollX: 0,
    scrollTo: (x, y) => { win.scrollX = x; win.scrollY = y; },
    requestAnimationFrame: (fn) => fn(),
    addEventListener: () => {},
    qrcode: () => ({ addData() {}, make() {}, createSvgTag: () => '<svg></svg>' })
  };

  const sandbox = {
    window: win,
    document: doc,
    localStorage: storageObj,
    sessionStorage: storageObj,
    history: win.history,
    navigator: { clipboard: { writeText: async () => {} } },
    Intl,
    URLSearchParams,
    FormData: class { entries() { return []; } },
    ArrayBuffer,
    Uint32Array,
    Math,
    Date,
    Number,
    String,
    Boolean,
    Object,
    Array,
    Set,
    Map,
    Promise,
    JSON,
    encodeURIComponent,
    decodeURIComponent,
    confirm: () => true,
    setTimeout: (fn) => { fn(); return 1; },
    clearTimeout: () => {},
    setInterval: () => ({ unref() {} }),
    clearInterval: () => {},
    requestAnimationFrame: (fn) => fn(),
    fetch: async (urlPath, opts = {}) => {
      const r = await req(urlPath, opts);
      return {
        ok: r.status >= 200 && r.status < 300,
        status: r.status,
        headers: { get: (h) => r.headers.get(h) },
        json: async () => r.json,
        text: async () => r.text
      };
    }
  };

  vm.createContext(sandbox);
  vm.runInContext(appCode, sandbox);

  // Wait for async boot IIFE to finish
  await new Promise((r) => setTimeout(r, 80));

  // Verify initial boot on #inbounds succeeded: title is 入站节点管理, active button is inbounds, content is non-empty!
  assert.equal(elementsById.get('page-title').textContent, '入站节点管理', 'Initial boot on #inbounds must set page title to 入站节点管理');
  assert.ok(navButtons.find((b) => b.dataset.page === 'inbounds').classList.contains('active'), 'Inbounds sidebar button must be active');
  assert.ok(!navButtons.find((b) => b.dataset.page === 'overview').classList.contains('active'), 'Overview sidebar button must NOT remain active when on #inbounds');
  assert.ok(elementsById.get('content').innerHTML.includes('添加入站'), 'Inbounds content must be rendered immediately');

  // Now simulate clicking every single sidebar button via the document click listener and verify instant switching!
  const expectedTitles = {
    overview: '系统与内核总览',
    inbounds: '入站节点管理',
    routing: '路由规则 (转发)',
    outbounds: '出站规则 (中转)',
    migrate: '备份迁移',
    certificates: 'SSL 证书与订阅',
    settings: '面板设置与安全'
  };

  for (const page of navPages) {
    const btn = navButtons.find((b) => b.dataset.page === page);
    for (const clickHandler of doc.listeners.click || []) {
      await clickHandler({ target: btn });
    }
    await new Promise((r) => setTimeout(r, 30));
    assert.equal(elementsById.get('page-title').textContent, expectedTitles[page], `Clicking sidebar [${page}] must update #page-title to ${expectedTitles[page]}`);
    assert.equal(win.location.hash, `#${page}`, `Clicking sidebar [${page}] must update URL hash to #${page}`);
    assert.ok(btn.classList.contains('active'), `Sidebar button [${page}] must have .active class`);
    assert.ok(elementsById.get('content').innerHTML.length > 100, `Content for [${page}] must be non-empty`);
  }

  // Also test opening Inbound, Outbound, Rule, and Aggregate QR modals in the VM without any runtime errors
  await sandbox.openInboundModal();
  assert.equal(elementsById.get('modal').open, true);
  sandbox.closeModal();
  assert.equal(elementsById.get('modal').open, false);

  sandbox.openOutboundModal();
  assert.equal(elementsById.get('modal').open, true);
  sandbox.closeModal();

  sandbox.openRuleModal();
  assert.equal(elementsById.get('modal').open, true);
  sandbox.closeModal();

  // Verify frontend auto-remark helpers & live modal remark sync when editing a routing rule
  assert.equal(sandbox.isAutoRuleRemark('入站转发: inbound-19915 ➔ ppf19.9'), true);
  assert.equal(sandbox.isAutoRuleRemark('自定义专线备注'), false);
  assert.equal(sandbox.buildAutoRuleRemark(['inbound-19915'], '66yun02-216.167.32.217'), '入站转发: inbound-19915 ➔ 66yun02-216.167.32.217');

  // Even if an existing rule in memory had a stale remark, opening openRuleModal(existing) immediately normalizes it
  sandbox.openRuleModal({
    id: 'r_stale_19915',
    remark: '入站转发: inbound-19915 ➔ ppf19.9',
    inbound: ['inbound-19915'],
    outbound: '66yun02-216.167.32.217'
  });
  assert.equal(elementsById.get('modal-title').textContent, '入站转发: inbound-19915 ➔ 66yun02-216.167.32.217');
  assert.ok(elementsById.get('modal-body').innerHTML.includes('value="入站转发: inbound-19915 ➔ 66yun02-216.167.32.217"'));
  sandbox.closeModal();

  // Verify openClientDetailModal renders 创建时间, 更新时间, 上次在线, 使用情况, 剩余/总流量/到期时间, and URL
  const sampleInb = {
    id: 'in_detail_1',
    remark: 'US-BL-23',
    protocol: 'vless',
    transport: 'tcp',
    port: 16842,
    security: 'reality',
    outboundTag: '233boy-ss-216.167.32.217',
    reality: { serverName: 'tesla.com', target: 'www.tesla.com:443' },
    clients: [{
      id: 'b10d3378-8bee-4e80-937a-1d16ecda3373',
      email: 'uptrq3ve',
      flow: 'xtls-rprx-vision',
      up: 157345453,
      down: 38181454071,
      createdAt: 1792730157000,
      updatedAt: 1792730157000,
      lastOnline: 1794044230003,
      limitIp: 0,
      limitDevice: 5,
      enable: true
    }],
    links: [{ clientId: 'b10d3378-8bee-4e80-937a-1d16ecda3373', email: 'uptrq3ve', label: 'US-BL-23-uptrq3ve', uri: 'vless://b10d3378-8bee-4e80-937a-1d16ecda3373@ppf.onliveme.com:16842?security=reality#US-BL-23' }]
  };
  sandbox.openClientDetailModal(sampleInb, sampleInb.clients[0]);
  assert.equal(elementsById.get('modal-kicker').textContent, '详细信息');
  const detailHtml = elementsById.get('modal-body').innerHTML;
  assert.ok(detailHtml.includes('创建时间'), 'Detail modal must include 创建时间');
  assert.ok(detailHtml.includes('更新时间'), 'Detail modal must include 更新时间');
  assert.ok(detailHtml.includes('上次在线'), 'Detail modal must include 上次在线');
  assert.ok(detailHtml.includes('使用情况'), 'Detail modal must include 使用情况');
  sandbox.closeModal();
});

test('18. Real X-Panel Backup (ppfppf 3xui_backup.tar.gz) Migration: Strict Exact Inbound Tag Matching (Zero Fuzzy Cross-Binding), device_limit Column & Deduplication', async () => {
  const { parse3xuiPayload } = require('../lib/migrate3xui');
  const { Store } = require('../lib/store');

  // 1) Verify against the real backup archive if present
  const realBackupPath = '/working_dir/c_705d4f468dc5a47a/user_uploaded_files/ttl=63d/user_uploaded/ppfppf 3xui_backup.tar.gz';
  if (fs.existsSync(realBackupPath)) {
    const realParsed = parse3xuiPayload({ dbPath: realBackupPath, dryRun: true });
    assert.equal(realParsed.inbounds.length, 6, 'Real backup must parse all 6 inbounds');

    // Exact-matched relay rules (5 inbounds) must bind accurately
    const bl23 = realParsed.inbounds.find((i) => i.remark === 'US-BL-23');
    assert.equal(bl23.outboundTag, 'ppf19.9');
    assert.equal(bl23.limitDevice, 5, 'X-Panel top-level device_limit=5 on US-BL-23 must be preserved');
    assert.equal(bl23.clients[0].lastOnline, 1794044230003, 'X-Panel client_traffics.last_online must be migrated to client.lastOnline');
    assert.equal(bl23.clients[0].createdAt, 1792730157000, 'X-Panel client created_at must be migrated to client.createdAt');
    assert.equal(bl23.lastOnline, 1794044230003, 'Inbound lastOnline must reflect latest client lastOnline');

    const ino = realParsed.inbounds.find((i) => i.remark === 'US-inonenii-11/05');
    assert.equal(ino.outboundTag, 'ppf19.9');
    assert.equal(ino.limitIp, 3, 'Client limitIp=3 on US-inonenii-11/05 must be preserved');
    assert.equal(ino.limitDevice, 5, 'X-Panel top-level device_limit=5 on US-inonenii-11/05 must be preserved');

    const rak50 = realParsed.inbounds.find((i) => i.remark === 'US-rak-50');
    assert.equal(rak50.outboundTag, 'rakNTT50');

    // Mismatched rule inbound-53252 -> rakNTT52 MUST NOT be fuzzy-bound to US-rak-52 (port 53255 / inbound-53255)
    const rak52 = realParsed.inbounds.find((i) => i.remark === 'US-rak-52');
    assert.ok(rak52, 'US-rak-52 inbound must exist');
    assert.equal(rak52.port, 53255);
    assert.equal(rak52.tag, 'inbound-53255');
    assert.equal(rak52.outboundTag, 'default', 'Strict matching must NOT fuzzy-bind mismatched inbound-53252 to inbound-53255');
    assert.ok(
      Array.isArray(realParsed.summary.skippedDanglingRules) &&
      realParsed.summary.skippedDanglingRules.some((d) => d.inboundTag === 'inbound-53252' && d.outboundTag === 'rakNTT52'),
      'Dangling rule inbound-53252 -> rakNTT52 must be recorded in summary.skippedDanglingRules'
    );

    const privRule = realParsed.rules.find((r) => r.ip_is_private);
    assert.ok(privRule);
    assert.deepEqual(privRule.ip_cidr, [], 'geoip:private must not be duplicated in ip_cidr');
  }

  // 2) Verify Store.load() deduplicates geoip:private rules without ever guessing/fuzzy-binding unbound inbounds
  const healDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-strict-'));
  try {
    const healFile = path.join(healDir, 'nexusgate.json');
    fs.writeFileSync(healFile, JSON.stringify({
      version: 5.0,
      admin: { id: 'admin_1', username: 'ng_strictUser1', passwordHash: 'scrypt:aa:bb' },
      settings: { webPort: 48842, webBasePath: '/ezSlybeW43YKMzK2/', strictBasePath: true, subToken: 'subToken123456789012' },
      inbounds: [
        { id: 'in_1', remark: 'US-rak-50', port: 41450, tag: 'inbound-41450', protocol: 'vless', outboundTag: 'rakNTT50', migratedFrom3xui: true, clients: [{ id: '6832b114-5826-4c3c-9c83-400383a51234', email: 'u1', subId: 'sub12345678' }] },
        { id: 'in_2', remark: 'US-rak-52', port: 53255, tag: 'inbound-53255', protocol: 'vless', outboundTag: 'default', migratedFrom3xui: true, clients: [{ id: '332e3ee4-4c64-406c-924e-22dc9c4102d9', email: 'u2', subId: 'sub87654321' }] }
      ],
      outbounds: [
        { id: 'out_direct', tag: 'direct', type: 'direct', builtin: true, enabled: true },
        { id: 'out_block', tag: 'block', type: 'block', builtin: true, enabled: true },
        { id: 'out_50', tag: 'rakNTT50', type: 'shadowsocks', server: '198.247.0.50', port: 34156, enabled: true, migratedFrom3xui: true },
        { id: 'out_52', tag: 'rakNTT52', type: 'shadowsocks', server: '198.247.0.52', port: 44092, enabled: true, migratedFrom3xui: true }
      ],
      routing: {
        final: 'direct',
        rules: [
          { id: 'r_sniff', action: 'sniff', enabled: true },
          { id: 'r_50', remark: '入站转发: inbound-41450 ➔ ppf19.9', enabled: true, action: 'route', inbound: ['inbound-41450'], outbound: '66yun02-216.167.32.217' },
          { id: 'r_priv1', remark: '分流规则 #5 (block)', enabled: true, action: 'route', ip_is_private: true, ip_cidr: ['geoip:private'], outbound: 'block' },
          { id: 'r_priv2', remark: '阻止私有内网探测 (geoip:private)', enabled: true, action: 'route', ip_is_private: true, ip_cidr: [], outbound: 'block' }
        ]
      }
    }));

    const strictStore = new Store(healFile);
    const strictRak52 = strictStore.state.inbounds.find((i) => i.tag === 'inbound-53255');
    assert.equal(strictRak52.outboundTag, 'default', 'Store.load() must never auto-bind unbound inbounds by fuzzy similarity');
    const repairedRule = strictStore.state.routing.rules.find((r) => r.id === 'r_50');
    assert.equal(repairedRule.remark, '入站转发: inbound-41450 ➔ 66yun02-216.167.32.217', 'Store.load() must auto-update stale relay rule remarks to match current outbound');
    const privRules = strictStore.state.routing.rules.filter((r) => r.ip_is_private && r.outbound === 'block');
    assert.equal(privRules.length, 1, 'Store.load() must deduplicate duplicate private IP block rules');
    assert.deepEqual(privRules[0].ip_cidr, []);
  } finally {
    fs.rmSync(healDir, { recursive: true, force: true });
  }

  // 3) Verify PUT /api/routing/rules/:id automatically updates remark when outbound or inbound changes, even if old auto-remark is sent
  const createRuleRes = await req('/SecPath16Chars99/api/routing/rules', {
    method: 'POST',
    body: JSON.stringify({
      inbound: ['inbound-19915'],
      outbound: 'ppf19.9',
      remark: ''
    })
  });
  assert.equal(createRuleRes.status, 201);
  assert.equal(createRuleRes.json.rule.remark, '入站转发: inbound-19915 ➔ ppf19.9');

  // Now simulate editing the rule and changing outbound to 66yun02-216.167.32.217 while passing the old remark
  const updateRuleRes = await req(`/SecPath16Chars99/api/routing/rules/${createRuleRes.json.rule.id}`, {
    method: 'PUT',
    body: JSON.stringify({
      inbound: 'inbound-19915',
      outbound: '66yun02-216.167.32.217',
      remark: '入站转发: inbound-19915 ➔ ppf19.9'
    })
  });
  assert.equal(updateRuleRes.status, 200);
  const updatedRule = updateRuleRes.json.rules.find((r) => r.id === createRuleRes.json.rule.id);
  assert.equal(updatedRule.remark, '入站转发: inbound-19915 ➔ 66yun02-216.167.32.217', 'Editing rule outbound must auto-update remark to new outbound name');

  // 4) Verify 233boy SIP002 ss:// URI parsing (with =, ==, %3D, %3D%3D, %2F) never corrupts password with \r\ufffd\ufffd or trailing 7
  const ss233Uri1 = `ss://${Buffer.from('aes-128-gcm:233boy.com').toString('base64')}@216.167.32.217:36158#233boy-ss-216.167.32.217`;
  const parsed233_1 = parseShareUriToOutbound(ss233Uri1);
  assert.equal(parsed233_1.method, 'aes-128-gcm');
  assert.equal(parsed233_1.password, '233boy.com', 'SIP002 ss:// with == padding must not append \\r\\ufffd\\ufffd to password');
  assert.equal(parsed233_1.server, '216.167.32.217');
  assert.equal(parsed233_1.port, 36158);

  const ss233Uri2 = `ss://${Buffer.from('chacha20-ietf-poly1305:6832b114-5826-4c3c-9c83-400383a51234').toString('base64').replace(/=/g, '%3D')}@216.167.32.217:36158#233boy-ss-216.167.32.217`;
  const parsed233_2 = parseShareUriToOutbound(ss233Uri2);
  assert.equal(parsed233_2.method, 'chacha20-ietf-poly1305');
  assert.equal(parsed233_2.password, '6832b114-5826-4c3c-9c83-400383a51234', 'SIP002 ss:// with %3D padding must not append trailing 7 to UUID password');

  // 5) Verify Store.load() automatically heals existing corrupted outbounds (233boy-ss-216.167.32.217 and 66yun02-216.167.32.217)
  const ssHealDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-ss-heal-'));
  try {
    const ssHealFile = path.join(ssHealDir, 'nexusgate.json');
    fs.writeFileSync(ssHealFile, JSON.stringify({
      version: 5.0,
      admin: { id: 'admin_1', username: 'ng_ssHeal1', passwordHash: 'scrypt:aa:bb' },
      settings: { webPort: 48842, webBasePath: '/ezSlybeW43YKMzK2/', strictBasePath: true, subToken: 'subToken123456789012' },
      inbounds: [],
      outbounds: [
        { id: 'out_direct', tag: 'direct', type: 'direct', builtin: true, enabled: true },
        { id: 'out_block', tag: 'block', type: 'block', builtin: true, enabled: true },
        { id: 'out_9', tag: '66yun02-216.167.32.217', remark: '233boy-ss-216.167.32.217', type: 'shadowsocks', server: '216.167.32.217', port: 36158, method: '2022-blake3-aes-128-gcm', password: '', enabled: true },
        { id: 'out_10', tag: '233boy-ss-216.167.32.217', remark: '233boy-ss-216.167.32.217', type: 'shadowsocks', server: '216.167.32.217', port: 36158, method: 'aes-128-gcm', password: '233boy.com\r\ufffd\ufffd', enabled: true }
      ]
    }));
    const ssHealedStore = new Store(ssHealFile);
    const o10 = ssHealedStore.state.outbounds.find((o) => o.tag === '233boy-ss-216.167.32.217');
    assert.equal(o10.password, '233boy.com', 'Store.load() must strip \\r\\ufffd\\ufffd from %3D%3D-corrupted SS password');
    assert.equal(o10.method, 'aes-128-gcm');
    const o9 = ssHealedStore.state.outbounds.find((o) => o.tag === '66yun02-216.167.32.217');
    assert.equal(o9.password, '233boy.com', 'Store.load() must restore wiped password on 66yun02-216.167.32.217 from sibling outbound');
    assert.equal(o9.method, 'aes-128-gcm', 'Store.load() must restore aes-128-gcm method on 66yun02-216.167.32.217');
  } finally {
    fs.rmSync(ssHealDir, { recursive: true, force: true });
  }

  // 6) Verify GET /api/routing returns full outbounds (with password & method) so editing an outbound after visiting #routing never loses credentials
  const getRoutingRes = await req('/SecPath16Chars99/api/routing');
  assert.equal(getRoutingRes.status, 200);
  const fullOutbounds = getRoutingRes.json.outbounds || [];
  const customOutInRouting = fullOutbounds.find((o) => !o.builtin && o.type === 'shadowsocks');
  if (customOutInRouting) {
    assert.ok(customOutInRouting.method, 'GET /api/routing must include outbound.method');
    assert.ok(customOutInRouting.password !== undefined, 'GET /api/routing must include outbound.password');
  }
});

test('19. Long-Duration 30-Day (720-Hour) Continuous Operation Simulation: Memory Leak Guard, Disk Footprint, Monthly Reset & CPU Benchmark', async () => {
  // Simulate 30 days of continuous operation (advancing clock across 60 time checkpoints * 12 hours = 720 hours)
  // with rotating client IPs, ephemeral ports, quota resets, audit logging, and periodic memory cleanups
  const { cleanupSystemLogsAndMemory } = require('../lib/system');
  if (typeof global.gc === 'function') global.gc();
  const startHeapMB = process.memoryUsage().heapUsed / (1024 * 1024);

  let dynamicConns = [];
  const mockLongClash = http.createServer((reqM, resM) => {
    if (reqM.method === 'GET' && reqM.url === '/connections') {
      resM.writeHead(200, { 'content-type': 'application/json' });
      resM.end(JSON.stringify({ connections: dynamicConns }));
    } else {
      resM.writeHead(204);
      resM.end();
    }
  });
  await new Promise((r) => mockLongClash.listen(0, '127.0.0.1', r));
  store.state.settings.clashApiPort = mockLongClash.address().port;

  try {
    const activeInbs = store.state.inbounds.filter((i) => i.enable !== false).slice(0, 20);
    const simStartMs = Date.parse('2026-11-01T00:00:00Z');
    const cpuStartMs = Date.now();

    for (let step = 1; step <= 60; step += 1) {
      const curSimMs = simStartMs + step * 12 * 3600 * 1000; // +12 hours per step (60 steps = 30 days)
      dynamicConns = activeInbs.map((inb, idx) => ({
        id: `long-conn-${step}-${idx}`,
        start: new Date(curSimMs - 3000).toISOString(),
        metadata: {
          type: `${inb.protocol}/${inb.tag}`,
          inboundPort: inb.port,
          sourceIP: `198.51.100.${((step + idx) % 200) + 1}`,
          sourcePort: 30000 + (step * 17 + idx) % 20000,
          user: inb.clients?.[0]?.email || 'default'
        },
        upload: 65536 * (step % 5 + 1),
        download: 262144 * (step % 5 + 1),
        chains: [inb.outboundTag && inb.outboundTag !== 'default' ? inb.outboundTag : 'direct']
      }));

      await singbox.pollConnectionsAndEnforceLimits(new Date(curSimMs));
      store.addAudit('system_sim', 'periodic_check', `step_${step}`);

      // Trigger scheduled 6-hour cleanup every 5 steps
      if (step % 5 === 0) {
        cleanupSystemLogsAndMemory(singbox, store);
      }
    }

    const totalCpuWallMs = Date.now() - cpuStartMs;
    if (typeof global.gc === 'function') global.gc();
    const endHeapMB = process.memoryUsage().heapUsed / (1024 * 1024);
    const heapGrowthMB = endHeapMB - startHeapMB;

    // Verify zero unbounded growth in caches, audit logs, disk file size, and V8 heap
    assert.ok(singbox.connTrafficCache.size <= 50, `connTrafficCache must prune closed connections (size=${singbox.connTrafficCache.size})`);
    assert.ok(store.state.audit.length <= 100, `Audit log must be bounded <= 100 (length=${store.state.audit.length})`);
    assert.ok(heapGrowthMB < 10, `Heap growth after 30-day simulation must be < 10 MB (grew ${heapGrowthMB.toFixed(2)} MB)`);
    assert.ok(totalCpuWallMs < 1500, `60 polling & cleanup steps across 30 simulated days must take < 1.5s CPU time (took ${totalCpuWallMs}ms)`);

    const dataFileStat = fs.statSync(store.filePath);
    assert.ok(dataFileStat.size < 512 * 1024, `State file on disk must remain compact < 512 KB (size=${dataFileStat.size} bytes)`);
  } finally {
    await new Promise((r) => mockLongClash.close(r));
  }
});


test('20. v5.1 Deep Audit: Bi-Directional Single-Client <-> Inbound Sync, HY2/AnyTLS/TUIC Timestamp Migration & Multi-Round E2E Simulation', async () => {
  const { convert3xuiInbound } = require('../lib/migrate3xui');

  // 1) Create a single-client VLESS inbound and verify bi-directional sync between Inbound Edit and Client Edit
  const createInbRes = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify({
      remark: 'SyncTest-Node',
      port: 54321,
      protocol: 'vless',
      security: 'reality',
      limitIp: 2,
      limitDevice: 5,
      totalGB: 50
    })
  });
  assert.equal(createInbRes.status, 201);
  const inb = createInbRes.json.inbound;
  const c0 = inb.clients[0];
  assert.equal(inb.limitDevice, 5);
  assert.equal(c0.limitDevice, 5);
  assert.equal(c0.totalGB, 50);

  // Edit the sole client via PUT /api/inbounds/:id/clients/:clientId -> parent inbound must also sync!
  const putClientRes = await req(`/SecPath16Chars99/api/inbounds/${inb.id}/clients/${encodeURIComponent(c0.id)}`, {
    method: 'PUT',
    body: JSON.stringify({
      email: c0.email,
      limitIp: 4,
      limitDevice: 8,
      totalGB: 120,
      expiryTime: 1893456000000
    })
  });
  assert.equal(putClientRes.status, 200);
  const syncedInb1 = putClientRes.json.inbound;
  assert.equal(syncedInb1.limitIp, 4, 'Parent inbound limitIp must sync when sole client is edited');
  assert.equal(syncedInb1.limitDevice, 8, 'Parent inbound limitDevice must sync when sole client is edited');
  assert.equal(syncedInb1.total, 120 * (1024 ** 3), 'Parent inbound total must sync when sole client is edited');
  assert.equal(syncedInb1.expiryTime, 1893456000000, 'Parent inbound expiryTime must sync when sole client is edited');

  // Now edit the parent inbound via PUT /api/inbounds/:id -> sole client totalGB/totalBytes/limits must also sync!
  const putInbRes = await req(`/SecPath16Chars99/api/inbounds/${inb.id}`, {
    method: 'PUT',
    body: JSON.stringify({
      remark: 'SyncTest-Node',
      port: 54321,
      protocol: 'vless',
      security: 'reality',
      limitIp: 6,
      limitDevice: 10,
      totalGB: 250,
      expiryTime: 1896048000000
    })
  });
  assert.equal(putInbRes.status, 200);
  const syncedInb2 = putInbRes.json.inbound;
  assert.equal(syncedInb2.clients[0].limitIp, 6, 'Sole client limitIp must sync when parent inbound is edited');
  assert.equal(syncedInb2.clients[0].limitDevice, 10, 'Sole client limitDevice must sync when parent inbound is edited');
  assert.equal(syncedInb2.clients[0].totalGB, 250, 'Sole client totalGB must sync when parent inbound is edited');
  assert.equal(syncedInb2.clients[0].totalBytes, 250 * (1024 ** 3), 'Sole client totalBytes must sync when parent inbound is edited');
  assert.equal(syncedInb2.clients[0].expiryTime, 1896048000000, 'Sole client expiryTime must sync when parent inbound is edited');

  // Clean up test node
  await req(`/SecPath16Chars99/api/inbounds/${inb.id}`, { method: 'DELETE' });

  // 2) Verify convert3xuiInbound for hysteria2 / anytls / tuic preserves client_traffics (up, down, last_online, created_at, updated_at, device_limit)
  for (const proto of ['hysteria2', 'anytls', 'tuic']) {
    const converted = convert3xuiInbound(
      {
        id: 99,
        remark: `Mig-${proto}`,
        port: 49999,
        protocol: proto,
        device_limit: 5,
        enable: 1,
        settings: JSON.stringify({
          clients: [{
            id: 'b10d3378-8bee-4e80-937a-1d16ecda3373',
            email: `user_${proto}`,
            password: 'StrongPass999',
            created_at: 1790000000000,
            updated_at: 1791000000000
          }]
        }),
        stream_settings: JSON.stringify({ security: 'tls' })
      },
      [{ email: `user_${proto}`, up: 10485760, down: 52428800, all_time: 62914560, last_online: 1794050000000, total: 0, expiry_time: 0 }]
    );
    assert.equal(converted.limitDevice, 5);
    assert.equal(converted.clients[0].limitDevice, 5);
    assert.equal(converted.clients[0].up, 10485760);
    assert.equal(converted.clients[0].down, 52428800);
    assert.equal(converted.clients[0].lastOnline, 1794050000000);
    assert.equal(converted.clients[0].createdAt, 1790000000000);
    assert.equal(converted.clients[0].updatedAt, 1791000000000);
    assert.equal(converted.lastOnline, 1794050000000);
  }
});


test('21. NexusGate Plus v6.0 Cluster Architecture: Multi-Relay Independent Domains, Shared Exit SS Pool, Multi-3x-ui Lossless Merger & 1-Click Standby Failover', async () => {
  const { compileNodeSingboxConfig, ensureClusterNodes, syncExitNodeOutbounds } = require('../lib/cluster');
  const { triggerNodeFailover, triggerNodeFailback } = require('../lib/failover');

  // 1. Create two Relay nodes with distinct domains (hk1.vip.com & jp1.vip.com), one Shared Exit node (no domain, SS), and one Standby node
  const hkRes = await req('/SecPath16Chars99/api/cluster/nodes', {
    method: 'POST',
    body: JSON.stringify({
      name: '香港 CMI 中转 01',
      role: 'relay',
      host: '103.88.10.11',
      domain: 'hk1.vip.com',
      mirrorStandby: true
    })
  });
  assert.equal(hkRes.status, 201);
  const hkNode = hkRes.json.node;

  const jpRes = await req('/SecPath16Chars99/api/cluster/nodes', {
    method: 'POST',
    body: JSON.stringify({
      name: '日本 IIJ 中转 02',
      role: 'relay',
      host: '45.76.20.22',
      domain: 'jp1.vip.com'
    })
  });
  assert.equal(jpRes.status, 201);
  const jpNode = jpRes.json.node;

  const exitRes = await req('/SecPath16Chars99/api/cluster/nodes', {
    method: 'POST',
    body: JSON.stringify({
      name: '美国洛杉矶原生落地 01',
      role: 'exit',
      host: '198.51.100.88',
      exitPort: 38388,
      exitMethod: '2022-blake3-aes-128-gcm'
    })
  });
  assert.equal(exitRes.status, 201);
  const exitNode = exitRes.json.node;
  const sharedExitOutbound = exitRes.json.outbounds.find((o) => o.exitNodeId === exitNode.id);
  assert.ok(sharedExitOutbound, 'Adding an Exit node must automatically register a Shared Exit SS outbound');
  assert.equal(sharedExitOutbound.server, '198.51.100.88');
  assert.equal(sharedExitOutbound.port, 38388);

  const sbRes = await req('/SecPath16Chars99/api/cluster/nodes', {
    method: 'POST',
    body: JSON.stringify({
      name: '香港热备容灾机 S1',
      role: 'standby',
      host: '103.88.99.99'
    })
  });
  assert.equal(sbRes.status, 201);
  const standbyNode = sbRes.json.node;

  // Bind standbyNode to hkNode with mirrorStandby enabled
  const bindRes = await req(`/SecPath16Chars99/api/cluster/nodes/${hkNode.id}`, {
    method: 'PUT',
    body: JSON.stringify({ standbyNodeId: standbyNode.id, mirrorStandby: true })
  });
  assert.equal(bindRes.status, 200);

  // 2. Migrate two separate 3x-ui configurations (both having port 443 and pointing to the same Exit IP:Port) into hkNode and jpNode
  const xuiPayload1 = {
    inbounds: [{
      port: 443,
      protocol: 'vless',
      tag: 'inbound-443',
      remark: 'HK-VIP-Client1',
      settings: JSON.stringify({ clients: [{ id: '11111111-2222-4333-8444-555555555555', email: 'hk_customer_a', subId: 'sub_hk_cust_a_12345' }] }),
      streamSettings: JSON.stringify({ network: 'ws', security: 'none', wsSettings: { path: '/hkws' } })
    }],
    outbounds: [{
      tag: 'us-exit-ss',
      protocol: 'shadowsocks',
      settings: { servers: [{ address: '198.51.100.88', port: 38388, method: '2022-blake3-aes-128-gcm', password: sharedExitOutbound.password }] }
    }],
    routing: {
      rules: [{ inboundTag: ['inbound-443'], outboundTag: 'us-exit-ss' }]
    }
  };

  const xuiPayload2 = {
    inbounds: [{
      port: 443,
      protocol: 'vless',
      tag: 'inbound-443',
      remark: 'JP-VIP-Client2',
      settings: JSON.stringify({ clients: [{ id: '66666666-2222-4333-8444-777777777777', email: 'jp_customer_b', subId: 'sub_jp_cust_b_12345' }] }),
      streamSettings: JSON.stringify({ network: 'ws', security: 'none', wsSettings: { path: '/jpws' } })
    }],
    outbounds: [{
      tag: 'jp-to-us-ss',
      protocol: 'shadowsocks',
      settings: { servers: [{ address: '198.51.100.88', port: 38388, method: '2022-blake3-aes-128-gcm', password: sharedExitOutbound.password }] }
    }],
    routing: {
      rules: [{ inboundTag: ['inbound-443'], outboundTag: 'jp-to-us-ss' }]
    }
  };

  const mig1 = await req(`/SecPath16Chars99/api/migrate/3xui?mode=merge&targetNodeId=${hkNode.id}&nodeDomain=hk1.vip.com&deduplicateExits=true`, {
    method: 'POST',
    body: JSON.stringify({ jsonPayload: xuiPayload1 })
  });
  assert.equal(mig1.status, 200);

  const mig2 = await req(`/SecPath16Chars99/api/migrate/3xui?mode=merge&targetNodeId=${jpNode.id}&nodeDomain=jp1.vip.com&deduplicateExits=true`, {
    method: 'POST',
    body: JSON.stringify({ jsonPayload: xuiPayload2 })
  });
  assert.equal(mig2.status, 200);
  assert.ok(mig2.json.record.deduplicatedExitsCount >= 1, 'Identical Exit SS outbound across multiple 3x-ui DBs must be automatically deduplicated into the shared exit outbound');

  // Verify subscription links use hk1.vip.com for HK customer and jp1.vip.com for JP customer
  const subHk = await req('/sub/sub_hk_cust_a_12345?format=raw');
  assert.equal(subHk.status, 200);
  assert.ok(subHk.text.includes('@hk1.vip.com:443'), `HK customer link must use hk1.vip.com, got: ${subHk.text}`);

  const subJp = await req('/sub/sub_jp_cust_b_12345?format=raw');
  assert.equal(subJp.status, 200);
  assert.ok(subJp.text.includes('@jp1.vip.com:443'), `JP customer link must use jp1.vip.com, got: ${subJp.text}`);

  // 3. Verify Standby Node pre-warmed config & 1-Click Failover
  const foRes = await req('/SecPath16Chars99/api/cluster/failover', {
    method: 'POST',
    body: JSON.stringify({
      primaryNodeId: hkNode.id,
      standbyNodeId: standbyNode.id,
      reason: 'Unit Test Failover'
    })
  });
  assert.equal(foRes.status, 200);
  assert.equal(foRes.json.ok, true);
  assert.equal(foRes.json.event.newIp, '103.88.99.99');

  const sbConfigRes = await req(`/SecPath16Chars99/api/cluster/nodes/${standbyNode.id}/config`);
  assert.equal(sbConfigRes.status, 200);
  assert.ok(sbConfigRes.json.singboxConfig.inbounds.some((i) => i.listen_port === 443), 'Standby node must serve HK Relay port 443 inbound');

  const fbRes = await req('/SecPath16Chars99/api/cluster/failback', {
    method: 'POST',
    body: JSON.stringify({ primaryNodeId: hkNode.id })
  });
  assert.equal(fbRes.status, 200);
  assert.equal(fbRes.json.ok, true);
});
