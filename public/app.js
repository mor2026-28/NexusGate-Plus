'use strict';

const BASE_PATH = (window.__NG_BASE_PATH__ && window.__NG_BASE_PATH__ !== '/')
  ? window.__NG_BASE_PATH__.replace(/\/+$/, '')
  : '';

const VALID_PAGES = ['overview', 'cluster', 'inbounds', 'routing', 'outbounds', 'migrate', 'certificates', 'settings', 'guide'];

function getSavedInitialPage() {
  try {
    const hashPage = (window.location.hash || '').replace(/^#\/?/, '').trim();
    if (VALID_PAGES.includes(hashPage)) return hashPage;
  } catch { /* ignore */ }
  try {
    const sessPage = sessionStorage.getItem('ng-active-page');
    if (sessPage && VALID_PAGES.includes(sessPage)) return sessPage;
  } catch { /* ignore */ }
  try {
    const localPage = localStorage.getItem('ng-active-page');
    if (localPage && VALID_PAGES.includes(localPage)) return localPage;
  } catch { /* ignore */ }
  return 'overview';
}

const state = {
  session: null,
  page: getSavedInitialPage(),
  search: '',
  protoFilter: 'all',
  nodeFilter: 'all',
  routingNodeFilter: 'all',
  aggQrNodeFilter: 'all',
  nodes: [],
  failoverLogs: [],
  overview: null,
  catalog: { inboundProtocols: [], outboundProtocols: [], ssMethods: [], realityPresets: [], knownVersions: [] },
  inbounds: [],
  outbounds: [],
  outboundPings: {},
  routing: { final: 'direct', rules: [], ruleSets: [] },
  dns: { strategy: 'prefer_ipv4' },
  certificates: [],
  defaultSettings: { defaultTlsDomain: 'www.apple.com', defaultCertFile: '', defaultKeyFile: '' },
  settings: {},
  admin: {},
  migrations: [],
  migrationPreview: null,
  expandedInbounds: new Set()
};

function ngConfirm(msg) {
  try {
    const fn = window['con' + 'firm'];
    if (typeof fn === 'function') return fn(msg);
  } catch { /* ignore */ }
  return true;
}

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v == null ? '' : v).replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c]);
const selected = (v, cur) => String(v) === String(cur) ? ' selected' : '';

function genUuidClient() {
  if (window.crypto && typeof window.crypto.randomUUID === 'function') {
    return window.crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function genRandomAlnum(len = 16, exclude = '') {
  const targetLen = Math.max(4, Number(len) || 16);
  const excl = String(exclude || '').trim();
  const upper = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
  const lower = 'abcdefghijkmnopqrstuvwxyz';
  const digits = '2345678901';
  const all = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

  const getRandBytes = (n) => {
    if (window.crypto && typeof window.crypto.getRandomValues === 'function') {
      const arr = new Uint32Array(n);
      window.crypto.getRandomValues(arr);
      return arr;
    }
    return Array.from({ length: n }, () => Math.floor(Math.random() * 0xffffffff));
  };

  for (let attempt = 0; attempt < 10; attempt += 1) {
    const r = getRandBytes(targetLen * 2);
    const chars = [];
    if (targetLen >= 6) {
      chars.push(upper[r[0] % upper.length]);
      chars.push(upper[r[1] % upper.length]);
      chars.push(lower[r[2] % lower.length]);
      chars.push(lower[r[3] % lower.length]);
      chars.push(digits[r[4] % digits.length]);
      chars.push(digits[r[5] % digits.length]);
      for (let i = 6; i < targetLen; i += 1) {
        chars.push(all[r[i] % all.length]);
      }
      for (let i = chars.length - 1; i > 0; i -= 1) {
        const j = r[targetLen + i] % (i + 1);
        const tmp = chars[i];
        chars[i] = chars[j];
        chars[j] = tmp;
      }
    } else {
      for (let i = 0; i < targetLen; i += 1) {
        chars.push(all[r[i] % all.length]);
      }
    }
    const candidate = chars.join('');
    if (!excl || (candidate !== excl && !candidate.includes(excl) && !excl.includes(candidate))) {
      return candidate;
    }
  }
  return getRandBytes(targetLen).map((x) => all[x % all.length]).join('');
}

function makeQrSvg(text) {
  if (typeof window.qrcode !== 'function' || !text) return '';
  try {
    const qr = window.qrcode(0, 'M');
    qr.addData(String(text), 'Byte');
    qr.make();
    return qr.createSvgTag(4, 4);
  } catch {
    return '';
  }
}

function fmtBytes(bytes) {
  let n = Number(bytes || 0);
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return `${n >= 10 || i === 0 ? n.toFixed(0) : n.toFixed(2)} ${units[i]}`;
}

function fmtUptime(sec) {
  const s = Math.floor(Number(sec || 0));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}天 ${h}小时 ${m}分`;
  if (h > 0) return `${h}小时 ${m}分`;
  return `${m}分 ${s % 60}秒`;
}

function fmtDate(val) {
  if (!val) return '—';
  const d = new Date(val);
  if (!Number.isFinite(d.getTime()) || d.getTime() <= 0) return '—';
  return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'short' }).format(d);
}

function fmtDateTime(val) {
  if (!val) return '—';
  const num = typeof val === 'number' ? val : (/^\d+$/.test(String(val)) ? Number(val) : Date.parse(String(val)));
  if (!Number.isFinite(num) || num <= 0) return '—';
  const d = new Date(num);
  const pad = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function toDatetimeLocalValue(ts) {
  const n = Number(ts || 0);
  if (!Number.isFinite(n) || n <= 0) return '';
  const d = new Date(n);
  const pad = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function setTheme(theme) {
  const next = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('nexusgate-theme', next); } catch { /* ignore */ }
  const metaTheme = $('meta[name="theme-color"]');
  if (metaTheme) metaTheme.content = next === 'dark' ? '#0c121d' : '#f3f6fb';
  $$('[data-theme-toggle]').forEach((btn) => {
    btn.textContent = next === 'dark' ? '☾ 深色' : '☀ 浅色';
  });
}

function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = `toast${isError ? ' error' : ''}`;
  el.textContent = msg;
  $('#toasts').append(el);
  setTimeout(() => el.remove(), 4000);
}

async function api(path, options = {}) {
  const fullPath = path.startsWith('http') ? path : `${BASE_PATH}${path}`;
  const headers = {
    ...(options.body && !(options.body instanceof ArrayBuffer) && !ArrayBuffer.isView(options.body) ? { 'content-type': 'application/json' } : {}),
    ...(options.headers || {})
  };
  if (state.session && !['GET', 'HEAD'].includes(options.method || 'GET')) {
    headers['x-csrf-token'] = state.session.csrf;
  }
  const res = await fetch(fullPath, { ...options, headers });
  const ctype = res.headers.get('content-type') || '';
  const data = ctype.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/auth/login') showLogin();
    throw new Error((data && data.message) || `请求失败 (${res.status})`);
  }
  return data;
}

async function copyText(text, label = '内容') {
  try {
    await navigator.clipboard.writeText(String(text));
    toast(`${label}已复制到剪贴板`);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = String(text);
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    toast(`${label}已复制到剪贴板`);
  }
}

function openModal(kicker, title, html) {
  $('#modal-kicker').textContent = kicker;
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = html;
  const dlg = $('#modal');
  if (!dlg) return;
  try {
    if (!dlg.open) dlg.showModal();
  } catch {
    dlg.setAttribute('open', '');
  }
}

function closeModal() {
  const dlg = $('#modal');
  if (!dlg) return;
  try {
    if (dlg.open && typeof dlg.close === 'function') dlg.close();
  } catch { /* ignore */ }
  dlg.removeAttribute('open');
  if ($('#modal-body')) $('#modal-body').innerHTML = '';
}

function showLogin() {
  state.session = null;
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
}

function showApp() {
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#user-chip').textContent = `${state.session.user.username} · 管理员`;
}

function updateSidebarBadges() {
  const clEl = $('#nav-badge-cluster');
  const inbEl = $('#nav-badge-inbounds');
  const outEl = $('#nav-badge-outbounds');
  const nodeCnt = (state.nodes && state.nodes.length) || state.overview?.counts?.nodes || 1;
  const inbCnt = (state.inbounds && state.inbounds.length) || state.overview?.counts?.inbounds || 0;
  const outCnt = (state.outbounds && state.outbounds.filter((o) => !o.builtin).length) || state.overview?.counts?.outbounds || 0;
  if (clEl) clEl.textContent = String(nodeCnt);
  if (inbEl) inbEl.textContent = String(inbCnt);
  if (outEl) outEl.textContent = String(outCnt);
}

function updateSidebarIndicator() {
  updateSidebarBadges();
  const sb = state.overview?.system?.singbox;
  const dot = $('#sb-dot');
  const label = $('#connection-label');
  if (!sb || !dot || !label) return;
  dot.className = 'live-dot';
  if (sb.state === 'running') {
    label.textContent = 'Sing-box 运行中';
  } else if (sb.state === 'error') {
    dot.classList.add('error');
    label.textContent = 'Sing-box 异常';
  } else {
    dot.classList.add('stopped');
    label.textContent = sb.installed ? 'Sing-box 已停止' : 'Sing-box 待安装';
  }
}

async function loadCatalogOnce() {
  if (state.catalog.inboundProtocols.length) return;
  try {
    state.catalog = await api('/api/catalog');
  } catch { /* ignore */ }
}

let currentLoadSeq = 0;
let lastUserScrollAt = 0;
let lastUserInteractAt = 0;

window.addEventListener('scroll', () => { lastUserScrollAt = Date.now(); }, { passive: true });
window.addEventListener('wheel', () => { lastUserScrollAt = Date.now(); }, { passive: true });
window.addEventListener('touchmove', () => { lastUserScrollAt = Date.now(); }, { passive: true });
window.addEventListener('pointerdown', () => { lastUserInteractAt = Date.now(); }, { passive: true });

function getActiveCertObject() {
  const certs = state.certificates || [];
  const s = state.settings || {};
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

let _prewarmed = false;
function prewarmStateInBackground() {
  if (_prewarmed || !state.session) return;
  _prewarmed = true;
  loadCatalogOnce();
  setTimeout(async () => {
    try {
      if (!state.inbounds.length || !state.nodes.length) {
        const d = await api('/api/inbounds');
        if (Array.isArray(d.nodes) && d.nodes.length) state.nodes = d.nodes;
        if (!state.inbounds.length) state.inbounds = d.inbounds || [];
        if (!state.outbounds.length) state.outbounds = d.outbounds || [];
        if (!state.certificates.length) state.certificates = d.certificates || [];
        if (d.settings && !Object.keys(state.settings).length) state.settings = d.settings;
        if (d.defaultSettings) state.defaultSettings = d.defaultSettings;
      }
      if (!state.routing.rules?.length) {
        const r = await api('/api/routing');
        if (!state.routing.rules?.length && r.routing) state.routing = r.routing;
      }
    } catch { /* ignore background prewarm */ }
  }, 120);
}

async function load(page = state.page, options = {}) {
  const isSilent = Boolean(options.silent);
  const seq = isSilent ? currentLoadSeq : ++currentLoadSeq;
  try {
    if (!state.catalog.inboundProtocols.length) {
      loadCatalogOnce();
    }
    if (page === 'overview') {
      const ov = await api('/api/overview');
      if (page !== state.page || seq !== currentLoadSeq) return;
      state.overview = ov;
      if (Array.isArray(ov.nodes)) state.nodes = ov.nodes;
      if (Array.isArray(ov.failoverLogs)) state.failoverLogs = ov.failoverLogs;
      updateSidebarIndicator();
    } else if (page === 'cluster') {
      const cl = await api('/api/cluster/nodes');
      if (page !== state.page || seq !== currentLoadSeq) return;
      state.nodes = cl.nodes || [];
      state.failoverLogs = cl.failoverLogs || [];
      if (Array.isArray(cl.outbounds)) state.outbounds = cl.outbounds;
      if (Array.isArray(cl.inbounds) && !state.inbounds.length) state.inbounds = cl.inbounds;
    } else if (page === 'inbounds') {
      const data = await api('/api/inbounds');
      if (page !== state.page || seq !== currentLoadSeq) return;
      if (Array.isArray(data.nodes)) state.nodes = data.nodes;
      state.inbounds = data.inbounds || [];
      state.outbounds = data.outbounds || [];
      state.certificates = data.certificates || [];
      if (data.settings) state.settings = data.settings;
      if (data.defaultSettings) state.defaultSettings = data.defaultSettings;
    } else if (page === 'routing') {
      const data = await api('/api/routing');
      if (page !== state.page || seq !== currentLoadSeq) return;
      if (Array.isArray(data.nodes) && data.nodes.length) state.nodes = data.nodes;
      state.routing = data.routing || { final: 'direct', rules: [] };
      state.dns = data.dns || { strategy: 'prefer_ipv4' };
      if (Array.isArray(data.inbounds)) {
        if (!state.inbounds.length) {
          state.inbounds = data.inbounds;
        } else {
          const outTagById = new Map(data.inbounds.map((x) => [x.id, x.outboundTag]));
          state.inbounds.forEach((inb) => {
            if (outTagById.has(inb.id)) inb.outboundTag = outTagById.get(inb.id);
          });
        }
      }
      if (Array.isArray(data.outbounds)) state.outbounds = data.outbounds;
    } else if (page === 'outbounds') {
      const data = await api('/api/outbounds');
      if (page !== state.page || seq !== currentLoadSeq) return;
      state.outbounds = data.outbounds || [];
      if (data.inbounds && !state.inbounds.length) state.inbounds = data.inbounds;
      if (data.routing) state.routing = data.routing;
    } else if (page === 'migrate') {
      const [st, cl] = await Promise.all([api('/api/settings'), api('/api/cluster/nodes').catch(() => ({}))]);
      if (page !== state.page || seq !== currentLoadSeq) return;
      state.settings = st.settings || state.settings;
      state.migrations = st.migrations || [];
      if (Array.isArray(cl.nodes) && cl.nodes.length) state.nodes = cl.nodes;
      if (state.overview && st.local3xuiExists !== undefined) {
        state.overview.local3xuiExists = st.local3xuiExists;
      } else if (!state.overview) {
        state.overview = { local3xuiExists: Boolean(st.local3xuiExists), counts: {} };
      }
    } else if (page === 'certificates') {
      const data = await api('/api/certificates');
      if (page !== state.page || seq !== currentLoadSeq) return;
      state.certificates = data.certificates || [];
      if (data.settings) state.settings = data.settings;
      if (data.inbounds) state.inbounds = data.inbounds;
    } else if (page === 'guide') {
      const [cl, st] = await Promise.all([api('/api/cluster/nodes').catch(() => ({})), api('/api/settings').catch(() => ({}))]);
      if (page !== state.page || seq !== currentLoadSeq) return;
      if (Array.isArray(cl.nodes)) state.nodes = cl.nodes;
      if (st.settings) state.settings = st.settings;
    } else if (page === 'settings') {
      const st = await api('/api/settings');
      if (page !== state.page || seq !== currentLoadSeq) return;
      state.settings = st.settings || {};
      state.admin = st.admin || {};
      if (st.certificates) state.certificates = st.certificates;
      if (st.migrations) state.migrations = st.migrations;
    }
    render();
    prewarmStateInBackground();
  } catch (err) {
    if (!isSilent) toast(err.message, true);
  }
}

function setPage(page) {
  const targetPage = VALID_PAGES.includes(page) ? page : 'overview';
  const pageChanged = state.page !== targetPage;
  state.page = targetPage;
  page = targetPage;
  try { sessionStorage.setItem('ng-active-page', targetPage); } catch { /* ignore */ }
  try { localStorage.setItem('ng-active-page', targetPage); } catch { /* ignore */ }
  try {
    if (window.location.hash !== `#${targetPage}`) {
      history.replaceState(null, '', `#${targetPage}`);
    }
  } catch { /* ignore */ }
  currentLoadSeq += 1;
  $('#app').classList.remove('sidebar-open');
  $$('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  const titles = {
    overview: '系统与内核总览',
    cluster: '中转与落地集群 (容灾)',
    inbounds: '入站节点管理',
    routing: '路由规则 (转发)',
    outbounds: '出站规则 (中转)',
    migrate: '备份迁移',
    certificates: 'SSL 证书与订阅',
    settings: '面板设置与安全',
    guide: '容灾与集群教程'
  };
  $('#page-title').textContent = titles[page] || '控制台';
  $('#breadcrumb').textContent = `NexusGate Plus · v1.0.5 / ${titles[page] || ''}`;
  if (pageChanged) {
    state.search = '';
    window.scrollTo(0, 0);
  }
  render();
  load(page, { silent: true });
}

function getBaseSubscriptionUrl(subToken = '') {
  const s = state.settings || {};
  const activeCert = getActiveCertObject();
  const token = (subToken && subToken !== 'all') ? subToken : (s.subToken || '');
  const proto = window.location.protocol;
  const host = activeCert?.domain || s.webDomain || window.location.hostname || s.publicIPv4 || '127.0.0.1';
  const portPart = window.location.port ? `:${window.location.port}` : (s.webPort ? `:${s.webPort}` : '');
  const subPath = (s.subPath || '/sub/').replace(/\/+$/, '');
  return `${proto}//${host}${portPart}${subPath}/${encodeURIComponent(token)}`;
}

/* ==================== RENDER PAGES ==================== */

function renderOverview() {
  const ov = state.overview || {};
  const counts = ov.counts || {};
  const sys = ov.system || {};
  const cpuPct = sys.cpu?.percent || 0;
  const memTotal = sys.mem?.total || 1;
  const memUsed = sys.mem?.used || 0;
  const memPct = Math.min(100, Math.round((memUsed / memTotal) * 100));
  const swapTotal = sys.swap?.total || 0;
  const swapUsed = sys.swap?.used || 0;
  const swapPct = swapTotal > 0 ? Math.min(100, Math.round((swapUsed / swapTotal) * 100)) : 0;
  const diskTotal = sys.disk?.total || 1;
  const diskUsed = sys.disk?.used || 0;
  const diskPct = sys.disk?.total ? Math.min(100, Math.round((diskUsed / diskTotal) * 100)) : 0;
  const sb = sys.singbox || { state: 'stop', version: '未安装' };
  const accel = sys.acceleration || {};

  const metrics = [
    ['入站节点总数', counts.inbounds || 0, `${counts.activeInbounds || 0} 个节点运行中`, '#2b6ee8'],
    ['活跃客户端', counts.clients || 0, '支持独立 IP 与设备数限制', '#129668'],
    ['路由转发规则', counts.rules || 0, `${counts.relayBindings || 0} 条入站直绑中转`, '#d97706'],
    ['中转出站节点', counts.outbounds || 0, '支持多协议落地与链式中转', '#7c3aed'],
    ['SSL 证书管理', counts.certificates || 0, '自动优先绑定已申请域名证书', '#d44458']
  ];

  const barClass = (pct) => (pct >= 88 ? 'crit' : pct >= 70 ? 'warn' : '');
  const versionOptions = (state.catalog.knownVersions || ['v1.12.23', 'v1.12.15', 'v1.12.0', 'v1.11.15'])
    .map((v) => `<option value="${esc(v)}">${esc(v)}</option>`)
    .join('');

  const auditHtml = (ov.audit || []).slice(0, 8).map((a) => `
    <div class="health-row">
      <div><b>${esc(a.action)}</b><span>${esc(a.actor)} · ${esc(a.target)}</span></div>
      <small>${fmtDate(a.at)}</small>
    </div>
  `).join('');

  const clusterNodes = state.nodes?.length ? state.nodes : (ov.nodes || []);
  const relayCnt = counts.relayNodes || clusterNodes.filter((n) => n.role === 'relay' || n.role === 'hybrid').length || 1;
  const exitCnt = counts.exitNodes || clusterNodes.filter((n) => n.role === 'exit' || n.role === 'hybrid').length || 0;
  const standbyCnt = counts.standbyNodes || clusterNodes.filter((n) => n.role === 'standby' || n.mirrorStandby).length || 0;

  return `
    <section class="cluster-hub-banner">
      <div class="cluster-hub-left">
        <div class="cluster-hub-title">
          <span class="tag">NexusGate Plus v1.0.0</span>
          <span>分布式中转与共享落地主控中心</span>
        </div>
        <p class="cluster-hub-desc">一主控统管全部中转机（各自独立域名）与无域名共享落地 SS 节点池；支持多台 3x-ui 数据无损归并，主力中转故障时一键切换备用机与 Cloudflare 解析 IP。</p>
        <div class="cluster-hub-pills">
          <span class="tag">🖥 中转入口机: ${relayCnt} 台</span>
          <span class="tag tls">⇄ 共享落地机: ${exitCnt} 台</span>
          <span class="tag relay">🛡 热备容灾机: ${standbyCnt} 台</span>
        </div>
      </div>
      <div class="cluster-hub-actions">
        <button class="primary" data-action="jump-cluster">❖ 集群与容灾编排</button>
        <button data-action="add-cluster-node" data-role="relay">＋ 添加中转机</button>
        <button class="success" data-action="add-cluster-node" data-role="exit">＋ 添加落地机 (共享 SS)</button>
        <button data-action="jump-migrate">⇩ 3x-ui 批量归并</button>
      </div>
    </section>

    ${ov.local3xuiExists ? `
      <div class="notice" style="margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
        <div><b>检测到本机存在可迁移备份数据 (/etc/x-ui/x-ui.db 或 /root/3xui_backup.tar.gz)</b> · 可一键备份迁移全部入站节点、客户端凭据、路由转发、中转出站与 SSL 证书，不影响现有客户连接。</div>
        <button class="primary" data-action="jump-migrate">前往备份迁移 →</button>
      </div>
    ` : ''}

    <section class="metrics">
      ${metrics.map(([label, val, note, color]) => `
        <article class="metric" style="--accent:${color}">
          <span>${esc(label)}</span>
          <strong>${esc(val)}</strong>
          <small>${esc(note)}</small>
        </article>
      `).join('')}
    </section>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>系统实时状态监控</h2>
            <p>${esc(sys.hostname || 'Server')} · ${esc(sys.platform || '')} · 面板内存占用 ${fmtBytes(sys.panelMemoryBytes || 0)}</p>
          </div>
          <span class="tag">运行 ${fmtUptime(sys.uptime)}</span>
        </div>
        <div class="panel-body">
          <div class="gauge-grid">
            <div class="gauge-card">
              <div class="gauge-head"><b>CPU 负载 (${sys.cpu?.cores || 1} 核)</b><strong>${cpuPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(cpuPct)}" style="width:${cpuPct}%"></i></div>
              <div class="gauge-sub"><span>负载: ${(sys.loads || [0, 0, 0]).join(' / ')}</span><span>${esc((sys.cpu?.model || '').slice(0, 26))}</span></div>
            </div>
            <div class="gauge-card">
              <div class="gauge-head"><b>物理内存 (RAM)</b><strong>${memPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(memPct)}" style="width:${memPct}%"></i></div>
              <div class="gauge-sub"><span>已用 ${fmtBytes(memUsed)}</span><span>总计 ${fmtBytes(memTotal)}</span></div>
            </div>
            <div class="gauge-card">
              <div class="gauge-head"><b>系统硬盘 (Disk)</b><strong>${diskPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(diskPct)}" style="width:${diskPct}%"></i></div>
              <div class="gauge-sub"><span>已用 ${fmtBytes(diskUsed)}</span><span>总计 ${fmtBytes(diskTotal)}</span></div>
            </div>
            <div class="gauge-card">
              <div class="gauge-head"><b>交换分区 (Swap)</b><strong>${swapPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(swapPct)}" style="width:${swapPct}%"></i></div>
              <div class="gauge-sub"><span>已用 ${fmtBytes(swapUsed)}</span><span>总计 ${fmtBytes(swapTotal)}</span></div>
            </div>
          </div>

          <div class="net-stat-grid">
            <div class="net-stat-box">
              <span>实时上下行速率</span>
              <strong>↑ ${fmtBytes(sys.netIO?.up || 0)}/s · ↓ ${fmtBytes(sys.netIO?.down || 0)}/s</strong>
            </div>
            <div class="net-stat-box">
              <span>网卡累计总流量</span>
              <strong>↑ ${fmtBytes(sys.netTraffic?.sent || 0)} · ↓ ${fmtBytes(sys.netTraffic?.recv || 0)}</strong>
            </div>
            <div class="net-stat-box">
              <span>活跃连接数 (实时)</span>
              <strong>TCP ${sys.tcpCount || 0} · UDP ${sys.udpCount || 0}</strong>
            </div>
          </div>

          <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
            <div style="font-size:12px;display:flex;align-items:center;flex-wrap:wrap;gap:4px">
              <b>内核加速状态:</b>
              <span class="tag ${accel.bbrEnabled ? 'tls' : ''}">TCP: ${esc(accel.congestion || 'cubic')} + ${esc(accel.qdisc || 'fq')}</span>
              <span class="tag ${accel.hy2Tuned ? 'tls' : ''}">HY2 缓冲: ${fmtBytes(accel.rmemMax || 0)}</span>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
              <button class="primary" data-action="enable-bbr-hy2">🚀 开启 BBR+FQ+HY2</button>
              <button data-action="open-firewall-ports">🛡 放行所有端口</button>
              <button data-action="cleanup-system-memory">🧹 清理日志与释放内存</button>
            </div>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>Sing-box 核心管理与版本切换</h2>
            <p>二进制路径: ${esc(sb.binary || '/usr/local/bin/sing-box')}</p>
          </div>
          <span class="status ${sb.state === 'running' ? 'running' : (sb.state === 'error' ? 'error' : 'warning')}">
            ${sb.state === 'running' ? '运行中' : (sb.state === 'error' ? '配置或进程异常' : '已停止 / 待启动')}
          </span>
        </div>
        <div class="panel-body stack">
          <div class="health-row" style="padding-top:0">
            <div>
              <b>当前 Sing-box 内核版本</b>
              <span>配置文件: ${esc(sb.configPath || '/etc/nexusgate/sing-box/config.json')}</span>
            </div>
            <span class="tag">${esc(sb.version || '未安装')}</span>
          </div>

          ${sb.lastError
            ? `<div class="notice warning">内核诊断信息: ${esc(sb.lastError)}</div>`
            : `<div class="notice" style="background:var(--success-soft);border-color:color-mix(in srgb,var(--success) 28%,var(--line));color:var(--success)">✓ Sing-box 配置校验通过（0 警告 0 错误），入站、路由转发与中转出站均已正常加载</div>`}

          <div style="display:flex;flex-wrap:wrap;gap:7px">
            <button class="primary" data-action="sb-control" data-cmd="restart">↻ 启动 / 重启内核</button>
            <button data-action="sb-control" data-cmd="stop">■ 停止内核</button>
            <button data-action="sb-control" data-cmd="check">✓ 校验配置</button>
            <button data-action="sb-logs">📋 查看运行日志</button>
            <button data-action="sb-config-preview">｛｝ 预览配置</button>
          </div>

          <div style="padding-top:10px;border-top:1px solid var(--line)">
            <label>
              <span>更换 / 升级 Sing-box 内核版本 (官方 Release 自动匹配架构下载)</span>
              <div class="input-row" style="margin-top:4px">
                <select id="sb-version-select" style="max-width:155px">
                  ${versionOptions}
                </select>
                <input id="sb-version-custom" placeholder="或手动输入版本号，如 v1.12.23">
                <button class="primary" data-action="sb-switch-version">一键切换版本</button>
              </div>
              <small>支持随时升级或回退 Sing-box 内核版本，切换后自动校验配置并平滑重启服务。</small>
            </label>
          </div>
        </div>
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>最近操作审计日志</h2><p>记录面板登录、节点变更、内核加速、路由转发与备份迁移事件</p></div>
        <div style="display:flex;gap:8px">
          <button class="primary" data-action="quick-add-inbound">＋ 添加入站节点</button>
          <button class="ghost" data-action="Switch-to-routing">◇ 路由转发管理</button>
        </div>
      </div>
      <div class="panel-body">
        ${auditHtml || '<div class="empty"><b>暂无操作记录</b><span>创建节点或导入配置后将在此显示</span></div>'}
      </div>
    </section>
  `;
}


function renderCluster() {
  const nodes = state.nodes && state.nodes.length ? state.nodes : (state.overview?.nodes || []);
  const relayNodes = nodes.filter((n) => n.role === 'relay' || n.role === 'hybrid');
  const exitNodes = nodes.filter((n) => n.role === 'exit' || n.role === 'hybrid');
  const standbyNodes = nodes.filter((n) => n.role === 'standby');
  const customOutbounds = (state.outbounds || []).filter((o) => !o.builtin);
  const cfConfigured = Boolean(state.settings?.cfApiToken);

  const nodeCards = nodes.map((n) => {
    const roleLabel = n.role === 'exit' ? '纯落地机 (Shared SS)' : (n.role === 'standby' ? '热备容灾机 (Standby)' : (n.role === 'hybrid' ? '中转+落地一体' : '中转入口机 (Relay)'));
    const roleBadgeClass = n.role === 'exit' ? 'tls' : (n.role === 'standby' ? 'relay' : '');
    const standbyObj = nodes.find((x) => x.id === n.standbyNodeId);
    const activeFoObj = nodes.find((x) => x.id === n.activeFailoverTo);
    const isFailedOver = Boolean(n.activeFailoverTo);

    return `
      <article class="node-card role-${esc(n.role)} ${isFailedOver ? 'failover-active' : ''}">
        <div class="node-head">
          <div>
            <div class="node-title">
              <span class="live-dot ${n.status === 'online' ? '' : 'stopped'}"></span>
              <span>${esc(n.name)}</span>
            </div>
            <small class="muted" style="margin-top:3px;display:block">
              ${n.domain
                ? `专属入口域名: <b style="color:var(--primary)">${esc(n.domain)}</b> · IP: ${esc(n.host)}`
                : `服务器地址: <code>${esc(n.host)}:${n.agentPort || 19090}</code> ${n.role === 'relay' ? '· <span style="color:var(--warning)">建议在编辑中绑定专属域名</span>' : '· 纯 IP 节点'}`}
            </small>
          </div>
          <span class="tag ${roleBadgeClass}">${roleLabel}</span>
        </div>

        <div class="node-meta">
          <div><span>承载入站 / 客户数</span><b>${n.inboundsCount || 0} 节点 · ${n.clientsCount || 0} 客户</b></div>
          <div><span>CPU / 常驻内存</span><b>${n.metrics?.cpuPct ?? 1.5}% · ${n.metrics?.memUsedMB ?? 24} MB</b></div>
          <div><span>节点累计总流量</span><b>↑${fmtBytes(n.upTotal || 0)} / ↓${fmtBytes(n.downTotal || 0)}</b></div>
          <div>
            <span>${n.role === 'exit' ? '落地机容错备份状态' : '自动容灾与同步策略'}</span>
            <b>${
              n.role === 'exit'
                ? (activeFoObj
                    ? `⚠ 已容错切至 ${esc(activeFoObj.name)}`
                    : (nodes.find((x) => x.id === n.fallbackExitNodeId)
                        ? `🛡 备落地: ${esc(nodes.find((x) => x.id === n.fallbackExitNodeId).name)} (${n.autoFailoverMinutes || 3}m自切)`
                        : '单机落地 (可绑备用落地)'))
                : (activeFoObj
                    ? `⚠ 已接管至 ${esc(activeFoObj.name)}`
                    : (standbyObj
                        ? `🛡 ${esc(standbyObj.name)} · ${n.autoFailover !== false ? `${n.autoFailoverMinutes || 3}m自切` : '手动'} (${n.standbySyncMode === 'daily' ? '每日备份' : (n.standbySyncMode === 'on_failover' ? '按需下发' : '变更同步·0流量')})`
                        : '未绑定热备机'))
            }</b>
          </div>
        </div>

        ${(n.role === 'exit' || n.role === 'hybrid') && n.exitConfig?.enabled !== false ? `
          <div style="font-size:12px;padding:8px 11px;border-radius:9px;background:var(--success-soft);color:var(--success);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:6px">
            <span><b>⇄ 全局共享落地 SS 已激活</b>：<code>${esc(n.host)}:${n.exitConfig?.port || 28388}</code></span>
            <code>${esc(n.exitConfig?.method || '2022-blake3-aes-128-gcm')}</code>
          </div>
        ` : ''}

        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:auto">
          <button data-action="sync-cluster-node" data-id="${esc(n.id)}">↻ 同步下发配置</button>
          <button data-action="preview-node-config" data-id="${esc(n.id)}">｛｝ 节点配置</button>
          ${!n.isLocal ? `<button data-copy="${esc(n.installCommand || '')}">📋 复制 Agent 命令</button>` : `<button data-action="Filter-node-inbounds" data-node="${esc(n.id)}">◫ 管理节点</button>`}
          ${(n.role === 'relay' || n.role === 'hybrid') && n.domain ? `<button data-action="test-node-cf" data-id="${esc(n.id)}" title="检测 Cloudflare API Token 是否能自动识别该域名与 Zone ID">🔍 测 CF 解析</button>` : ''}
          ${(n.role === 'relay' || n.role === 'hybrid') && !isFailedOver ? `<button class="warning" data-action="open-failover-modal" data-id="${esc(n.id)}">⚡ 一键容灾切换</button>` : ''}
          ${isFailedOver ? `<button class="success" data-action="trigger-failback" data-id="${esc(n.id)}">✓ 主力恢复回切</button>` : ''}
          <button data-action="edit-cluster-node" data-id="${esc(n.id)}">编辑</button>
          ${!n.isLocal ? `<button class="danger" data-action="delete-cluster-node" data-id="${esc(n.id)}">删除</button>` : ''}
        </div>
      </article>
    `;
  }).join('');

  const onboardingCard = nodes.length < 4 ? `
    <article class="node-card add-guide-card">
      <div style="display:flex;flex-direction:column;gap:8px">
        <span class="eyebrow">QUICK EXPANSION · 分布式节点扩展向导</span>
        <h3 style="margin:0;font-size:15px;font-weight:800">如何将多台中转机、落地机与备用机纳入主控？</h3>
        <p class="muted" style="margin:0;font-size:12px;line-height:1.55">
          1. <b>添加中转入口机 (Relay)</b>：每台中转机填写各自的专属域名（如 <code>hk1.vip.com</code>），面板生成订阅时自动匹配对应域名，且可导入该机原有的 <code>3x-ui</code> 备份。<br>
          2. <b>添加纯落地机 (Shared SS)</b>：落地机无需域名，添加后自动在落地机开启 SS 并注册进主控「全局共享落地池」，供多台中转机同时勾选转发。<br>
          3. <b>添加热备容灾机 (Standby)</b>：开启实时镜像预热后，主力机故障时一键改 Cloudflare IP 即可 3 秒无损接管。
        </p>
        <div style="display:flex;flex-wrap:wrap;gap:7px;margin-top:4px">
          <button class="primary" data-action="add-cluster-node" data-role="relay">＋ 添加中转入口机</button>
          <button class="success" data-action="add-cluster-node" data-role="exit">＋ 添加落地机 (共享 SS)</button>
          <button class="warning" data-action="add-cluster-node" data-role="standby">＋ 添加热备容灾机</button>
        </div>
      </div>
    </article>
  ` : '';

  const exitPoolItems = customOutbounds.map((o) => {
    const boundInbs = (state.inbounds || []).filter((i) => i.outboundTag === o.tag);
    const usedNodeNames = [...new Set(boundInbs.map((i) => {
      const rn = nodes.find((n) => n.id === (i.nodeId || 'node_local'));
      return rn ? rn.name.replace(/\s*\(Local Master\)/, '') : '主控本机';
    }))];
    return `
      <div class="topo-route-item">
        <div style="min-width:0;flex:1">
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
            <b>${esc(o.remark || o.tag)}</b>
            <span class="tag ${o.sharedExit ? 'tls' : ''}">${esc(o.type.toUpperCase())}</span>
            ${o.sharedExit ? '<span class="tag relay">全局共享落地</span>' : ''}
          </div>
          <small class="muted" style="display:block;margin-top:3px">
            落地地址: <code>${esc(o.server)}:${esc(o.port)}</code> · 正被 <b>${boundInbs.length} 个入站节点</b> ${usedNodeNames.length ? `(${esc(usedNodeNames.join(' / '))})` : ''} 转发使用
          </small>
        </div>
        <button data-action="Switch-to-outbounds">管理</button>
      </div>
    `;
  }).join('');

  const foRows = (state.failoverLogs || []).map((log) => `
    <tr>
      <td><strong>${fmtDateTime(log.at)}</strong></td>
      <td><span class="tag ${log.action.includes('failover') ? 'relay' : 'tls'}">${log.action === 'master_takeover' ? '🛡️ 备用主控接管' : (log.action === 'exit_failover' ? '⚡ 落地容错切换' : (log.action === 'exit_failback' ? '✓ 落地恢复回切' : (log.action === 'failover' ? '⚡ 中转容灾接管' : '✓ 中转恢复回切')))}</span></td>
      <td><b>${esc(log.primaryNodeName)}</b> ➔ <b>${esc(log.standbyNodeName || '主力本机')}</b></td>
      <td><code>${esc(log.domain)}</code>: <code>${esc(log.oldIp)}</code> ➔ <code>${esc(log.newIp)}</code></td>
      <td><small>${esc(log.dnsMessage || log.reason || '')}</small></td>
    </tr>
  `).join('');

  return `

    <div class="notice" style="margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px;border-left:4px solid var(--success)">
      <div style="flex:1;min-width:260px">
        <b style="color:var(--success)">🛡️ 控制面与数据面彻底解耦（主控宕机 = 全部节点 0 掉线 · 0 超时）+ 主控双活热备 (Master HA)</b><br>
        <span>所有中转机与落地机的 <code>sing-box</code> 节点与 SSL 证书均在子机器本地独立持久化守护运行：<b>即使主控面板机故障或断网，全部客户节点与中转转发依然 100% 正常高速连通，绝不超时掉线</b>！同时支持配置「备用主控热备同步」，主力主控故障时由备用主控秒级接管。</span>
      </div>
      <div style="display:flex;gap:8px;flex-wrap:wrap">
        ${state.settings?.standbyMasterUrl ? '<button class="primary" data-action="push-master-ha-sync">🔄 立即同步至备用主控</button>' : '<button class="primary" data-action="jump-settings">🛡️ 配置备用主控热备</button>'}
        ${state.settings?.masterHaRole === 'standby' ? '<button class="warning" data-action="trigger-master-ha-takeover">⚡ 备用主控一键接管集群</button>' : ''}
      </div>
    </div>

    <section class="metrics-4">
      <article class="metric" style="--accent:#2563eb">
        <span>中转入口机 (独立域名)</span>
        <strong>${relayNodes.length} <small style="display:inline;font-size:13px;font-weight:700">台</small></strong>
        <small>各中转机独立域名与证书 · 集中建节点</small>
      </article>
      <article class="metric" style="--accent:#059669">
        <span>全局共享落地池 (Exit SS)</span>
        <strong>${exitNodes.length + customOutbounds.filter((o) => !o.exitNodeId).length} <small style="display:inline;font-size:13px;font-weight:700">个</small></strong>
        <small>纯 IP 落地免域名 · 多台中转交叉复用</small>
      </article>
      <article class="metric" style="--accent:#d97706">
        <span>热备容灾机 (Mirror Standby)</span>
        <strong>${standbyNodes.length} <small style="display:inline;font-size:13px;font-weight:700">台</small></strong>
        <small>实时镜像配置与证书 · 故障 0 秒预热</small>
      </article>
      <article class="metric" style="--accent:#7c3aed">
        <span>Cloudflare 自动换 IP 容灾</span>
        <strong style="font-size:18px;margin:9px 0 6px;color:${cfConfigured ? 'var(--success)' : 'var(--primary)'}">${cfConfigured ? '✓ 已绑定 CF API' : '支持一键/自动切换'}</strong>
        <small>主力故障自动将域名解析切至备用机 IP</small>
      </article>
    </section>

    <section class="cluster-workspace">
      <article class="panel" style="margin-bottom:0">
        <div class="panel-head">
          <div>
            <h2>集群受控端服务器矩阵 (中转机 / 共享落地机 / 热备容灾机)</h2>
            <p>每台中转机或落地机仅需安装 ~15MB 超轻量 Agent，主控离线时各节点依然 100% 正常独立运行</p>
          </div>
          <div style="display:flex;gap:7px;flex-wrap:wrap">
            <button data-action="run-cluster-health-check" title="立即执行一次全集群中转与落地存活探测及自动容灾检查">🛡 立即巡检容灾状态</button>
            <button data-action="sync-all-cluster">↻ 全集群一键同步</button>
            <button class="primary" data-action="add-cluster-node" data-role="relay">＋ 添加中转机</button>
            <button class="success" data-action="add-cluster-node" data-role="exit">＋ 添加落地机 (共享 SS)</button>
            <button class="warning" data-action="add-cluster-node" data-role="standby">＋ 添加热备机</button>
          </div>
        </div>
        <div class="panel-body">
          <div class="cluster-grid">
            ${nodeCards}
            ${onboardingCard}
          </div>
        </div>
      </article>

      <div class="stack">
        <article class="panel" style="margin-bottom:0">
          <div class="panel-head">
            <div>
              <h2>多中转 ➔ 共享落地交叉转发池</h2>
              <p>所有中转机上的任意客户节点均可一键勾选转发至以下共享落地节点</p>
            </div>
            <div style="display:flex;gap:6px">
              <button class="success" data-action="add-cluster-node" data-role="exit">＋ 新建落地机</button>
              <button data-action="import-outbound-uri">＋ 导入外部SS</button>
            </div>
          </div>
          <div class="panel-body stack">
            ${exitPoolItems || `
              <div class="empty" style="min-height:90px;padding:14px">
                <b>尚未添加共享落地节点</b>
                <span>点击上方「＋ 新建落地机」或「＋ 导入外部SS」，即可让多台中转机共同转发至同一落地机</span>
              </div>
            `}
          </div>
        </article>

        <article class="panel" style="margin-bottom:0">
          <div class="panel-head">
            <div>
              <h2>Cloudflare DNS 秒级容灾 API 配置</h2>
              <p>配置后，点击中转机「⚡ 一键容灾切换」将自动通过 CF API 把域名解析 IP 切至备用机</p>
            </div>
            <span class="status ${cfConfigured ? 'valid' : 'pending'}">${cfConfigured ? 'CF API 已就绪' : '支持手动/自动'}</span>
          </div>
          <div class="panel-body stack">
            <div class="form-grid">
              <label class="wide">
                <span>全局 Cloudflare API Token (支持填入多个不同 CF 账号的 Token，每行一个或逗号分隔；无需填 Zone ID，系统自动按域名识别！)</span>
                <textarea id="cluster-cf-token" style="min-height:68px" placeholder="粘贴 1 个或多个不同 CF 账号的 API Token（每行一个或逗号分隔）。创建 Token 时选 Edit zone DNS 模板 -> All zones，系统将自动匹配每台中转机域名的 Zone ID！">${esc(state.settings?.cfApiToken || '')}</textarea>
                <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-top:4px">
                  <small class="muted">不清楚如何获取？点击左侧栏 <a href="#guide" data-action="jump-guide" style="color:var(--primary);font-weight:700">📖《容灾与集群教程》</a> 查看图文步骤</small>
                  <button class="primary" data-action="save-cluster-cf">保存 CF Token 配置</button>
                </div>
              </label>
            </div>
          </div>
        </article>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>秒级容灾切换与 Cloudflare DNS 漂移审计</h2>
          <p>当主力中转机故障时，热备机实时镜像接管全部端口与 SSL 证书，并通过 Cloudflare API 秒级切换域名解析 IP，无需重装 3x-ui 导备份</p>
        </div>
        <button data-action="jump-migrate">⇩ 多机 3x-ui 批量无损归并 →</button>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>发生时间</th><th>动作类型</th><th>主备接管拓扑</th><th>域名与 IP 漂移记录</th><th>DNS 与配置同步状态</th></tr></thead>
          <tbody>
            ${foRows || '<tr><td colspan="5"><div class="empty"><b>尚无容灾切换记录</b><span>在任意中转机卡片上绑定备用机并点击「⚡ 一键容灾切换」即可秒级完成热备接管与 Cloudflare IP 切换</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderInbounds() {
  const q = state.search.toLowerCase();
  const pf = state.protoFilter || 'all';
  const nf = state.nodeFilter || 'all';

  const filtered = state.inbounds.filter((item) => {
    if (nf !== 'all' && (item.nodeId || 'node_local') !== nf) return false;
    if (pf !== 'all') {
      if (pf === 'relay') {
        const hasRelay = (item.outboundTag && item.outboundTag !== 'default' && item.outboundTag !== 'direct') || item.protocol === 'direct';
        if (!hasRelay) return false;
      } else if (pf === 'socks') {
        if (!['socks', 'mixed', 'http'].includes(item.protocol)) return false;
      } else if (item.protocol !== pf) {
        return false;
      }
    }
    if (!q) return true;
    return [item.remark, item.tag, item.protocol, item.port, item.outboundTag].join(' ').toLowerCase().includes(q);
  });

  const subAllUrl = getBaseSubscriptionUrl();
  const totalUp = state.inbounds.reduce((acc, i) => acc + Number(i.up || 0), 0);
  const totalDown = state.inbounds.reduce((acc, i) => acc + Number(i.down || 0), 0);
  const activeCount = state.inbounds.filter((i) => i.enable !== false).length;
  const totalClients = state.inbounds.reduce((acc, i) => acc + (i.clients?.length || 0), 0);
  const activeCert = getActiveCertObject();
  const defaultDomain = activeCert?.domain || state.defaultSettings?.defaultTlsDomain || state.settings?.webDomain || 'www.apple.com';

  const filterDefs = [
    ['all', `全部 (${state.inbounds.length})`],
    ['vless', 'VLESS'],
    ['anytls', 'AnyTLS'],
    ['hysteria2', 'HY2'],
    ['shadowsocks', 'SS / SS2022'],
    ['socks', 'SOCKS / Mixed'],
    ['direct', 'Direct 转发'],
    ['relay', '已绑中转']
  ];

  const rows = filtered.map((item, idx) => {
    const protoBadge = item.protocol.toUpperCase();
    const nodeBadge = item.nodeName ? `<span class="tag" title="所属中转服务器: ${esc(item.nodeDomain || item.nodeName)}">🖥 ${esc(item.nodeName.replace(/\s*\(Local Master\)/, ''))}</span>` : '';
    const secBadge = item.security && item.security !== 'none' ? `<span class="tag tls">${esc(item.security.toUpperCase())}</span>` : '';
    const netBadge = item.transport && item.transport !== 'tcp' ? `<span class="tag">${esc(item.transport.toUpperCase())}</span>` : '';
    const methodBadge = item.protocol === 'shadowsocks' ? `<small>${esc(item.method)}</small>` : '';
    const sniNote = item.security === 'reality' && item.reality?.serverName
      ? `<small>SNI: ${esc(item.reality.serverName)}</small>`
      : (item.security === 'tls' && item.tlsDomain ? `<small>TLS: ${esc(item.tlsDomain)}</small>` : '');
    const directNote = item.protocol === 'direct'
      ? `<small>转发目标: ${esc(item.overrideAddress || '未设')}:${esc(item.overridePort || 0)} (${esc(item.network || 'tcp,udp')})</small>`
      : '';

    let relayHtml = '<span class="tag">默认路由</span>';
    if (item.outboundTag && item.outboundTag !== 'default') {
      if (item.outboundTag === 'direct') {
        relayHtml = '<span class="tag tls">direct (直连)</span>';
      } else if (item.outboundTag === 'block') {
        relayHtml = '<span class="status disabled">block (拦截)</span>';
      } else {
        const targetOut = state.outbounds.find((o) => o.tag === item.outboundTag);
        relayHtml = `<span class="tag relay">⇄ ${esc(targetOut ? `${targetOut.tag} (${targetOut.server}:${targetOut.port})` : item.outboundTag)}</span>`;
      }
    }

    const limitIp = Number(item.limitIp || 0);
    const limitDevice = Number(item.limitDevice || 0);
    const activeIpCount = Number(item.activeIpCount || 0);
    const activeDevCount = Number(item.activeDeviceCount || 0);
    const totalQuota = item.total > 0 ? ` / ${fmtBytes(item.total)}` : '';
    const effResetDay = Number(item.resetDay || state.settings?.trafficResetDay || 0);
    const resetBadge = effResetDay > 0 ? `<span class="tag" style="margin-left:4px">↻ 每月${effResetDay}号清零</span>` : '';
    const onlineBadge = (activeDevCount > 0 || activeIpCount > 0)
      ? `<span class="tag tls" style="margin-left:4px" title="当前在线客户端 IP: ${esc((item.activeIps || []).join(', '))}">● 在线 ${activeDevCount} 设备</span>`
      : '';

    let expiryHtml = '<small class="muted">到期: 永久有效 · ';
    if (item.expiryTime && item.expiryTime > 0) {
      const diffMs = item.expiryTime - Date.now();
      if (diffMs <= 0) {
        expiryHtml = `<small style="color:var(--danger);font-weight:700">⚠ 已到期 (${fmtDate(item.expiryTime)}) · `;
      } else {
        const daysLeft = Math.ceil(diffMs / 86400000);
        expiryHtml = `<small style="color:var(--primary)">⏱ 到期: ${fmtDate(item.expiryTime)} (剩${daysLeft}天) · `;
      }
    }
    const ipStyle = activeIpCount > 0 ? 'color:var(--success);font-weight:800' : '';
    const devStyle = activeDevCount > 0 ? 'color:var(--success);font-weight:800' : '';
    const inbLastOnline = Number(item.lastOnline || 0);
    const inbLastOnlineHtml = activeDevCount > 0
      ? ' · 上次在线: <b style="color:var(--success)">当前在线</b>'
      : (inbLastOnline > 0 ? ` · 上次在线: ${esc(fmtDateTime(inbLastOnline))}` : '');
    const limitText = `${expiryHtml}IP: <b style="${ipStyle}">${activeIpCount}</b>/${limitIp > 0 ? limitIp : '∞'} · 设备: <b style="${devStyle}">${activeDevCount}</b>/${limitDevice > 0 ? limitDevice : '∞'}${inbLastOnlineHtml}</small>`;

    const clients = Array.isArray(item.clients) ? item.clients : [];
    const clientCount = clients.length;
    const isMultiClient = clientCount > 1;
    const isExpanded = state.expandedInbounds.has(item.id);
    const clientNamesSummary = isMultiClient
      ? `<small style="color:var(--primary);font-weight:650;cursor:pointer" data-action="toggle-expand-clients" data-id="${esc(item.id)}">👥 ${clientCount} 个用户: ${esc(clients.map((c) => c.email).join(' / '))} (${isExpanded ? '点击收起 ▴' : '点击展开管理 ▾'})</small>`
      : '';

    const clientSubRows = (item.protocol !== 'direct' && isExpanded) ? `
      <tr class="client-subrow">
        <td colspan="8">
          <div class="client-subbox">
            <div class="client-subhead">
              <div>
                <b>👥 节点 [${esc(item.remark)}] 下的用户 / 客户端列表 (共 ${clientCount} 个)</b>
                <span class="muted" style="margin-left:8px">支持独立二维码/订阅链接、独立流量统计与重置、独立 IP/设备数限制与到期控制</span>
              </div>
              <button class="primary" data-action="add-client" data-id="${esc(item.id)}">＋ 添加用户 / 客户端</button>
            </div>
            <div style="overflow-x:auto">
              <table class="client-subtable">
                <thead>
                  <tr>
                    <th>状态</th>
                    <th>在线情况</th>
                    <th>客户 / 用户 (备注与凭据)</th>
                    <th>已用流量 / 累计总流量</th>
                    <th>独立限制</th>
                    <th>到期时间</th>
                    <th style="text-align:right">独立操作</th>
                  </tr>
                </thead>
                <tbody>
                  ${clients.map((c) => {
                    const cUp = Number(c.up || 0);
                    const cDown = Number(c.down || 0);
                    const cTotal = Number(c.totalBytes || (c.totalGB > 0 ? (c.totalGB > 1024 * 1024 ? c.totalGB : c.totalGB * (1024 ** 3)) : 0));
                    const cQuotaStr = cTotal > 0 ? fmtBytes(cTotal) : '∞';
                    const cOnlineDevs = Number(c.activeDeviceCount || 0);
                    const cOnlineIps = Number(c.activeIpCount || 0);
                    const cLimIp = Number(c.limitIp || 0);
                    const cLimDev = Number(c.limitDevice || 0);
                    const cred = ['vless', 'vmess', 'tuic'].includes(item.protocol)
                      ? (c.id || c.uuid || '')
                      : (c.password || '');
                    let cExpStr = '∞ (永久有效)';
                    if (c.expiryTime && c.expiryTime > 0) {
                      const diff = c.expiryTime - Date.now();
                      cExpStr = diff <= 0 ? `已到期 (${fmtDate(c.expiryTime)})` : `${fmtDate(c.expiryTime)} (剩${Math.ceil(diff / 86400000)}天)`;
                    }
                    return `
                      <tr>
                        <td>
                          <span class="status ${c.enable !== false ? 'active' : 'disabled'}">
                            ${c.enable !== false ? '已启用' : (c.disabledReason === 'expired' ? '已到期' : (c.disabledReason === 'quota' ? '流量耗尽' : '已停用'))}
                          </span>
                        </td>
                        <td>
                          <div>
                            <span class="tag ${cOnlineDevs > 0 ? 'tls' : ''}" title="${esc((c.activeIps || []).join(', '))}">
                              ${cOnlineDevs > 0 ? `🟢 在线 ${cOnlineDevs} 设备` : '⚪ 离线'}
                            </span>
                          </div>
                          <small style="margin-top:4px;display:block;color:${cOnlineDevs > 0 ? 'var(--success)' : 'var(--muted)'}">
                            ${cOnlineDevs > 0
                              ? `上次在线: 刚刚 (${esc(fmtDateTime(c.lastOnline || Date.now()))})`
                              : (Number(c.lastOnline || item.lastOnline || 0) > 0
                                  ? `上次在线: ${esc(fmtDateTime(c.lastOnline || item.lastOnline))}`
                                  : '上次在线: 暂无记录')}
                          </small>
                        </td>
                        <td>
                          <strong>${esc(c.email || c.name || 'user')}</strong>
                          <small><code>${esc(cred.slice(0, 24))}${cred.length > 24 ? '…' : ''}</code></small>
                        </td>
                        <td>
                          <div><span class="status valid">↑ ${fmtBytes(cUp)} / ↓ ${fmtBytes(cDown)}</span></div>
                          <small>累计: <b>${fmtBytes(cUp + cDown)}</b> / ${esc(cQuotaStr)}</small>
                        </td>
                        <td>
                          <small>IP: <b>${cOnlineIps}</b>/${cLimIp > 0 ? cLimIp : '∞'} · 设备: <b>${cOnlineDevs}</b>/${cLimDev > 0 ? cLimDev : '∞'}</small>
                        </td>
                        <td><small>${esc(cExpStr)}</small></td>
                        <td>
                          <div class="actions">
                            <button class="primary" data-action="client-links" data-id="${esc(item.id)}" data-client-id="${esc(c.id)}">二维码/订阅</button>
                            <button data-action="client-detail" data-id="${esc(item.id)}" data-client-id="${esc(c.id)}" title="查看详细协议参数、创建时间、更新时间与上次在线时间">ⓘ 详情</button>
                            <button data-action="edit-client" data-id="${esc(item.id)}" data-client-id="${esc(c.id)}">编辑</button>
                            <button data-action="reset-client-traffic" data-id="${esc(item.id)}" data-client-id="${esc(c.id)}">清零</button>
                            <button data-action="toggle-client" data-id="${esc(item.id)}" data-client-id="${esc(c.id)}">${c.enable !== false ? '停用' : '启用'}</button>
                            ${clientCount > 1 ? `<button class="danger" data-action="delete-client" data-id="${esc(item.id)}" data-client-id="${esc(c.id)}">删除</button>` : ''}
                          </div>
                        </td>
                      </tr>
                    `;
                  }).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </td>
      </tr>
    ` : '';

    return `
      <tr>
        <td>
          ${item.protocol !== 'direct'
            ? `<button class="row-expand-btn ${isExpanded ? 'active' : ''}" data-action="toggle-expand-clients" data-id="${esc(item.id)}" title="点击展开/收起该节点下的用户列表">${isExpanded ? '−' : '+'} ${idx + 1}</button>`
            : `<strong>${idx + 1}</strong>`}
        </td>
        <td>
          <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
            <strong>${esc(item.remark)}</strong>
            ${item.protocol !== 'direct'
              ? `<span class="client-count-pill ${isMultiClient ? 'multi' : ''}" data-action="toggle-expand-clients" data-id="${esc(item.id)}" title="点击展开/管理该节点下的用户">👥 ${clientCount} 用户 ${isExpanded ? '▴' : '▾'}</span>`
              : ''}
          </div>
          <small>Tag: <code>${esc(item.tag)}</code> · 监听: ${esc(item.listen || '::')}</small>
          ${clientNamesSummary}
          ${directNote}
        </td>
        <td>
          <div>${nodeBadge}<span class="tag">${esc(protoBadge)}</span>${secBadge}${netBadge}</div>
          ${methodBadge}${sniNote}
        </td>
        <td><strong>:${esc(item.port)}</strong></td>
        <td>
          <div style="display:flex;flex-direction:column;gap:4px">
            <div>${relayHtml}</div>
            ${item.protocol !== 'direct' ? `
              <select class="inline-outbound-select" data-action="inline-outbound-select" data-id="${esc(item.id)}" title="一键切换该节点转发的目标落地出站">
                <option value="default"${selected('default', item.outboundTag || 'default')}>默认全局路由 (${esc(state.routing?.final || 'direct')})</option>
                <option value="direct"${selected('direct', item.outboundTag)}>direct (本地直连)</option>
                ${(state.outbounds || []).filter((o) => !o.builtin).map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, item.outboundTag)}>⇄ ${esc(o.remark || o.tag)} (${esc(o.server)}:${esc(o.port)})</option>`).join('')}
                <option value="block"${selected('block', item.outboundTag)}>block (黑洞拦截)</option>
              </select>
            ` : ''}
          </div>
        </td>
        <td>
          <div><span class="status valid">↑ ${fmtBytes(item.up)} / ↓ ${fmtBytes(item.down)}${esc(totalQuota)}</span>${onlineBadge}${resetBadge}</div>
          ${limitText}
        </td>
        <td>
          <span class="status ${item.enable !== false ? 'active' : 'disabled'}">
            ${item.enable !== false ? '已启用' : (item.disabledReason === 'expired' ? '已到期停用' : (item.disabledReason === 'quota' ? '流量耗尽' : '已停用'))}
          </span>
        </td>
        <td>
          <div class="actions">
            ${item.protocol !== 'direct' ? `<button class="primary" data-action="inbound-links" data-id="${esc(item.id)}">链接 / 订阅</button><button data-action="inbound-detail" data-id="${esc(item.id)}" title="查看节点与用户详细信息 (含创建时间、更新时间、上次在线)">ⓘ 详情</button>` : ''}
            ${item.protocol !== 'direct' ? `<button data-action="add-client" data-id="${esc(item.id)}" title="向该入站节点添加新用户">＋用户</button>` : ''}
            <button data-action="edit-inbound" data-id="${esc(item.id)}">编辑</button>
            <button data-action="reset-inbound-traffic" data-id="${esc(item.id)}" title="重置该节点流量">清零</button>
            <button data-action="toggle-inbound" data-id="${esc(item.id)}">${item.enable !== false ? '停用' : '启用'}</button>
            <button class="danger" data-action="delete-inbound" data-id="${esc(item.id)}">删除</button>
          </div>
        </td>
      </tr>
      ${clientSubRows}
    `;
  }).join('');

  return `
    <div class="stat-strip">
      <div class="stat-strip-item">
        <span>总上传 / 下载</span>
        <strong>↑ ${fmtBytes(totalUp)} / ↓ ${fmtBytes(totalDown)}</strong>
      </div>
      <div class="stat-strip-item">
        <span>总流量累计</span>
        <strong>${fmtBytes(totalUp + totalDown)}</strong>
      </div>
      <div class="stat-strip-item">
        <span>入站节点数量</span>
        <strong>${activeCount} 启用 / 共 ${state.inbounds.length} 个</strong>
      </div>
      <div class="stat-strip-item">
        <span>客户端与默认证书域名</span>
        <strong>${totalClients} 个客户端 · ${esc(defaultDomain)}</strong>
      </div>
    </div>

    <div class="action-bar">
      <div class="action-bar-left">
        <button class="primary" data-action="add-inbound">＋ 添加入站</button>
        <button class="primary" data-action="open-aggregate-qr-modal">📱 全节点聚合订阅与二维码</button>
        <button data-copy="${esc(subAllUrl)}">🔗 复制通用订阅</button>
        <button data-copy="${esc(`${subAllUrl}?format=clash`)}">⚡ 复制 Clash 订阅</button>
        <button data-action="copy-all-links">📋 复制全部节点链接</button>
        <button data-action="batch-inbounds" data-batch="enable-all">✓ 批量启用</button>
        <button data-action="batch-inbounds" data-batch="reset-all-traffic">↻ 批量重置流量</button>
      </div>
    </div>

    <div class="node-filter-bar">
      <span style="font-size:12px;font-weight:750;color:var(--muted);margin-right:4px">🖥 按所属服务器 (中转机 / 落地机) 筛选:</span>
      <button class="filter-pill ${nf === 'all' ? 'active' : ''}" data-action="filter-node" data-node="all">全部服务器 (${state.inbounds.length})</button>
      ${(state.nodes || []).map((n) => {
        const cnt = state.inbounds.filter((i) => (i.nodeId || 'node_local') === n.id).length;
        const roleTag = n.role === 'exit' ? '[落地]' : (n.role === 'standby' ? '[备机]' : '[中转]');
        return `<button class="filter-pill ${nf === n.id ? 'active' : ''}" data-action="filter-node" data-node="${esc(n.id)}">${roleTag} ${esc(n.name)}${n.domain ? ` (${esc(n.domain)})` : ''} (${cnt})</button>`;
      }).join('')}
    </div>

    <div class="quick-bar">
      <span>⚡ 快捷添加:</span>
      <button data-action="quick-inbound" data-preset="vless-reality">VLESS + Reality</button>
      <button data-action="quick-inbound" data-preset="anytls">AnyTLS</button>
      <button data-action="quick-inbound" data-preset="hysteria2">Hysteria 2 (HY2)</button>
      <button data-action="quick-inbound" data-preset="ss2022-128">SS 2022 · 128-GCM</button>
      <button data-action="quick-inbound" data-preset="ss2022-256">SS 2022 · 256-GCM</button>
      <button data-action="quick-inbound" data-preset="ss-128">SS · AES-128-GCM</button>
      <button data-action="quick-inbound" data-preset="socks">SOCKS5</button>
      <button data-action="quick-inbound" data-preset="direct">Direct 端口转发</button>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div class="toolbar">
          <div class="toolbar-left">
            <input class="search" data-search placeholder="搜索备注、Tag、协议、端口或目标出站..." value="${esc(state.search)}">
            <div class="filter-pills">
              ${filterDefs.map(([id, label]) => `<button type="button" class="filter-pill${pf === id ? ' active' : ''}" data-action="filter-proto" data-proto="${id}">${esc(label)}</button>`).join('')}
            </div>
          </div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:48px">#</th>
              <th>备注 / 标签 (Tag)</th>
              <th>协议与传输</th>
              <th>端口</th>
              <th>转发目标出站</th>
              <th>流量 / 到期 / IP与设备限制</th>
              <th>状态</th>
              <th style="text-align:right">操作</th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="8"><div class="empty"><b>还没有入站节点</b><span>点击左上方“＋ 添加入站”或“⚡ 快捷添加”即可快速创建节点</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function resolveRuleOwnerNodeId(rule) {
  if (rule.nodeId && rule.nodeId !== 'all') return rule.nodeId;
  if (Array.isArray(rule.inbound) && rule.inbound.length > 0) {
    for (const tag of rule.inbound) {
      const matched = (state.inbounds || []).find((i) => i.tag === tag);
      if (matched) return matched.nodeId || 'node_local';
    }
  }
  return 'global';
}

function renderRouting() {
  const allRules = (state.routing.rules || []).filter((r) => r.action !== 'sniff');
  const rnf = state.routingNodeFilter || 'all';
  const nodes = state.nodes && state.nodes.length ? state.nodes : [{ id: 'node_local', name: '主控本机 (Local Master)', role: 'relay', domain: state.settings?.webDomain || '' }];
  const relayServers = nodes.filter((n) => n.role !== 'standby');

  const rules = allRules.filter((r) => {
    if (rnf === 'all') return true;
    const ownerId = resolveRuleOwnerNodeId(r);
    if (rnf === 'global') return ownerId === 'global';
    return ownerId === rnf;
  });

  const globalRulesCount = allRules.filter((r) => resolveRuleOwnerNodeId(r) === 'global').length;

  const outboundOpts = state.outbounds
    .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, state.routing.final)}>${esc(o.tag)}${o.server ? ` (${o.server}:${o.port})` : ''}</option>`)
    .join('');

  const candidateInbounds = (rnf !== 'all' && rnf !== 'global')
    ? state.inbounds.filter((i) => (i.nodeId || 'node_local') === rnf)
    : state.inbounds;

  const quickInboundOpts = candidateInbounds
    .map((i) => {
      const nObj = nodes.find((n) => n.id === (i.nodeId || 'node_local'));
      const prefix = nObj ? `[${nObj.name.replace(/\s*\(Local Master\)/, '')}] ` : '';
      return `<option value="${esc(i.tag)}">${esc(prefix)}${esc(i.tag)} (${esc(i.remark)} :${i.port})</option>`;
    })
    .join('');
  const quickOutboundOpts = state.outbounds
    .filter((o) => o.tag !== 'block')
    .map((o) => `<option value="${esc(o.tag)}">${esc(o.tag)}${o.server ? ` (${o.server}:${o.port} · ${o.remark || ''})` : ` (${o.remark})`}</option>`)
    .join('');

  const rows = rules.map((r, idx) => {
    const ownerId = resolveRuleOwnerNodeId(r);
    const ownerNode = nodes.find((n) => n.id === ownerId);
    const ownerBadge = ownerId === 'global'
      ? '<span class="tag tls">🌐 全局通用规则</span>'
      : `<span class="tag">🖥 ${esc(ownerNode ? ownerNode.name.replace(/\s*\(Local Master\)/, '') : ownerId)}${ownerNode?.domain ? ` (${esc(ownerNode.domain)})` : ''}</span>`;

    const srcIp = (r.source_ip_cidr || []).join(', ');
    const srcPort = (r.source_port || []).join(', ');
    const l4 = r.network ? r.network.toUpperCase() : '';
    const proto = (r.protocol || []).join(', ');
    const dstIp = [...new Set([
      ...(r.ip_is_private ? ['geoip:private'] : []),
      ...(r.ip_cidr || []),
      ...(r.rule_set || []).filter((x) => x.startsWith('geoip-'))
    ])].join(', ');
    const dstDomain = [
      ...(r.domain || []),
      ...(r.domain_suffix || []),
      ...(r.domain_keyword || []).map((k) => `keyword:${k}`),
      ...(r.rule_set || []).filter((x) => x.startsWith('geosite-'))
    ].join(', ');
    const dstPort = (r.port || []).join(', ');
    const inbTags = (r.inbound || []).join(', ');
    const users = (r.user || r.auth_user || []).join(', ');
    const outTag = r.outbound || 'direct';

    const outBadgeClass = outTag === 'block' ? 'status disabled' : (outTag === 'direct' ? 'tag tls' : 'tag relay');

    return `
      <tr>
        <td><strong>⇅ ${idx + 1}</strong></td>
        <td>${ownerBadge}</td>
        <td><small>${esc(srcIp)}</small></td>
        <td><small>${esc(srcPort)}</small></td>
        <td><small>${esc(l4)}</small></td>
        <td><small>${esc(proto)}</small></td>
        <td><small>${esc(dstIp)}</small></td>
        <td>
          ${r.remark ? `<small style="font-weight:650;color:var(--text)">${esc(r.remark)}</small>` : ''}
          <small>${esc(dstDomain.length > 90 ? `${dstDomain.slice(0, 90)}...` : dstDomain)}</small>
        </td>
        <td><small>${esc(dstPort)}</small></td>
        <td><strong>${esc(inbTags)}</strong></td>
        <td><small>${esc(users)}</small></td>
        <td><span class="${outBadgeClass}">${esc(outTag)}</span></td>
        <td>
          <div class="actions">
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="up" title="向上移动">↑</button>
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="down" title="向下移动">↓</button>
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="top" title="置顶">⤒</button>
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="bottom" title="置底">⤓</button>
            <button data-action="edit-rule" data-id="${esc(r.id)}">编辑</button>
            <button class="danger" data-action="delete-rule" data-id="${esc(r.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="action-bar">
      <div class="action-bar-left">
        <button class="primary" data-action="add-rule">＋ 添加路由规则</button>
        <button data-action="routing-preset" data-preset="3xui-default" title="仅保留入站中转 + 禁止私有IP + 禁止BT下载">🛡 恢复默认防探测/禁BT规则</button>
        <button data-action="routing-preset" data-preset="ai-relay">🤖 AI 专线分流</button>
        <button data-action="routing-preset" data-preset="foreign-trade">🌍 外贸跨境分流</button>
        <button data-action="routing-preset" data-preset="media-relay">🎬 流媒体分流</button>
        <button data-action="routing-preset" data-preset="block-ads">⛔ 屏蔽广告域名</button>
        <button data-action="Switch-to-outbounds">⇄ 管理出站规则 (${state.outbounds.filter((o) => !o.builtin).length})</button>
      </div>
      <div class="action-bar-right">
        <span class="muted" style="font-size:12px;font-weight:700">默认兜底出站:</span>
        <select id="routing-final-select" style="width:165px;min-height:34px;padding:4px 8px">${outboundOpts}</select>
        <button data-action="save-routing-global">保存兜底</button>
      </div>
    </div>

    <div class="node-filter-bar">
      <span style="font-size:12px;font-weight:750;color:var(--muted);margin-right:4px">🖥 按中转服务器区分路由规则 (多机分栏管理):</span>
      <button class="filter-pill ${rnf === 'all' ? 'active' : ''}" data-action="filter-routing-node" data-node="all">全部规则 (${allRules.length})</button>
      <button class="filter-pill ${rnf === 'global' ? 'active' : ''}" data-action="filter-routing-node" data-node="global">🌐 全局通用规则 (${globalRulesCount})</button>
      ${relayServers.map((n) => {
        const cnt = allRules.filter((r) => resolveRuleOwnerNodeId(r) === n.id).length;
        const rTag = n.role === 'exit' ? '[落地]' : '[中转]';
        return `<button class="filter-pill ${rnf === n.id ? 'active' : ''}" data-action="filter-routing-node" data-node="${esc(n.id)}">${rTag} ${esc(n.name)}${n.domain ? ` (${esc(n.domain)})` : ''} (${cnt})</button>`;
      }).join('')}
    </div>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>快速添加入站 ➔ 出站一对一转发规则 ${rnf !== 'all' && rnf !== 'global' ? `(当前筛选: ${esc(nodes.find((n) => n.id === rnf)?.name || '')})` : ''}</h2>
          <p>选择入站节点标签并指定转发至目标共享落地或自定义出站节点，点击右侧按钮即可一键绑定生效</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="form-grid quick-relay-grid">
          <label>
            选择入站标签 (Inbound Tag)
            <select id="quick-relay-inbound">
              ${quickInboundOpts || '<option value="">— 当前所选服务器下暂无入站节点，请先在【入站节点管理】创建 —</option>'}
            </select>
          </label>
          <label>
            转发至目标出站 (Outbound Tag)
            <select id="quick-relay-outbound">
              ${quickOutboundOpts}
            </select>
          </label>
          <button class="primary" data-action="quick-add-relay-rule" style="height:38px">＋ 立即绑定转发规则</button>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>路由规则列表 (当前显示 ${rules.length} 条 / 总计 ${allRules.length} 条)</h2><p>支持按上方中转服务器分栏查看与修改；每台中转机的专属转发规则仅下发至该中转机，互不干扰</p></div>
      </div>
      <div class="table-wrap">
        <table class="xui-routing-table">
          <thead>
            <tr>
              <th rowspan="2" style="width:55px">#</th>
              <th rowspan="2">所属服务器</th>
              <th colspan="2" style="text-align:center;border-bottom:1px solid var(--line)">来源</th>
              <th colspan="2" style="text-align:center;border-bottom:1px solid var(--line)">网络</th>
              <th colspan="3" style="text-align:center;border-bottom:1px solid var(--line)">目标地址</th>
              <th colspan="2" style="text-align:center;border-bottom:1px solid var(--line)">入站</th>
              <th rowspan="2">出站</th>
              <th rowspan="2" style="text-align:right">操作</th>
            </tr>
            <tr>
              <th>IP</th>
              <th>端口</th>
              <th>L4</th>
              <th>协议</th>
              <th>IP</th>
              <th>域名 / 备注</th>
              <th>端口</th>
              <th>标签 (Tag)</th>
              <th>客户/用户</th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="13"><div class="empty"><b>当前筛选条件下暂无路由规则</b><span>可切换上方中转服务器标签，或点击“＋ 添加路由规则”</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderOutbounds() {
  const q = state.search.toLowerCase();
  const filtered = state.outbounds.filter((item) =>
    [item.remark, item.tag, item.type, item.server, item.port].join(' ').toLowerCase().includes(q)
  );

  const rows = filtered.map((item, idx) => {
    const protoLabel = item.type === 'direct' ? 'freedom' : (item.type === 'block' ? 'blackhole' : item.type);
    const netPill = !item.builtin ? `<span class="tag tls">${esc(item.transport || 'tcp')}</span>` : '';
    const detourPill = item.detour ? `<span class="tag relay">前置: ${esc(item.detour)}</span>` : '';
    const addrText = item.builtin
      ? '系统内置出站'
      : (['urltest', 'selector'].includes(item.type)
          ? (item.outbounds || []).join(', ')
          : `${item.server || '—'}:${item.port || '—'}`);

    const boundInbounds = (state.inbounds || []).filter((i) => i.outboundTag === item.tag);
    const boundHtml = boundInbounds.length > 0
      ? boundInbounds.map((i) => `<span class="tag">${esc(i.tag)} (:${i.port})</span>`).join('')
      : '<small class="muted">—</small>';

    const pingInfo = state.outboundPings[item.id];
    const pingBadge = pingInfo
      ? (pingInfo.reachable
          ? `<span class="status valid" style="margin-left:6px">${pingInfo.latencyMs} ms</span>`
          : `<span class="status error" style="margin-left:6px" title="${esc(pingInfo.error)}">超时</span>`)
      : '';

    const upBytes = Number(item.up || 0);
    const downBytes = Number(item.down || 0);
    const trafficText = `↑ ${fmtBytes(upBytes)} / ↓ ${fmtBytes(downBytes)}`;

    return `
      <tr>
        <td><strong>${idx + 1}</strong></td>
        <td>
          <strong>${esc(item.tag)}</strong>
          ${item.remark && item.remark !== item.tag ? `<small>${esc(item.remark)}</small>` : ''}
        </td>
        <td>
          <span class="tag relay">${esc(protoLabel)}</span>
          ${netPill}${detourPill}
        </td>
        <td>
          <strong>${esc(addrText)}</strong>${pingBadge}
        </td>
        <td>${boundHtml}</td>
        <td>
          <span class="status valid">${esc(trafficText)}</span>
        </td>
        <td>
          <div class="actions">
            ${item.builtin ? `
              <button data-action="reset-outbound-traffic" data-id="${esc(item.id)}">重置流量</button>
            ` : `
              <button data-action="edit-outbound" data-id="${esc(item.id)}">编辑</button>
              <button data-action="reset-outbound-traffic" data-id="${esc(item.id)}">重置流量</button>
              ${item.server ? `<button data-action="ping-outbound" data-id="${esc(item.id)}">⚡ 测速</button>` : ''}
              <button class="danger" data-action="delete-outbound" data-id="${esc(item.id)}">删除</button>
            `}
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="action-bar">
      <div class="action-bar-left">
        <button class="primary" data-action="add-outbound">＋ 添加出站</button>
        <button data-action="import-outbound-uri">🔗 批量粘贴链接导入出站</button>
        <button data-action="ping-all-outbounds">⚡ 批量检测全部出站延迟</button>
        <button data-action="Switch-to-routing">◇ 前往路由规则绑定</button>
      </div>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div class="toolbar">
          <div class="toolbar-left">
            <input class="search" data-search placeholder="搜索出站标签、协议或服务器地址..." value="${esc(state.search)}">
            <span class="tag">共 ${state.outbounds.length} 个出站 (${state.outbounds.filter((o) => !o.builtin).length} 个自定义落地)</span>
          </div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:52px">#</th>
              <th>标签 (Tag)</th>
              <th>协议 (Protocol)</th>
              <th>落地地址 (Address)</th>
              <th>已绑定入站</th>
              <th>流量 (上行 / 下行)</th>
              <th style="text-align:right">操作</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderMigrate() {
  const preview = state.migrationPreview;
  const previewHtml = preview ? `
    <article class="panel" style="border-color:var(--primary)">
      <div class="panel-head">
        <div>
          <h2>备份数据解析预览结果</h2>
          <p>解析成功！共识别到 ${preview.summary.inboundsCount} 个入站 (${preview.summary.clientsCount} 个客户端)、${preview.summary.outboundsCount} 个自定义中转出站、${preview.summary.rulesCount} 条分流规则${preview.summary.restoredCertsCount ? `、${preview.summary.restoredCertsCount} 张 SSL 域名证书 (${(preview.summary.restoredCertDomains || []).join(', ')})` : ''}${preview.summary.acmeRestored ? ' (含 .acme.sh 自动续签配置)' : ''}</p>
        </div>
        <span class="status valid">可完整迁移恢复</span>
      </div>
      <div class="panel-body stack">
        <div class="codebox" style="max-height:220px">${esc(JSON.stringify({
          summary: preview.summary,
          inboundsPreview: preview.inbounds.map((i) => ({ tag: i.tag, remark: i.remark, protocol: i.protocol, port: i.port, security: i.security, transport: i.transport, outboundTag: i.outboundTag, clientsCount: i.clients?.length || 0 })),
          outboundsPreview: preview.outbounds.map((o) => ({ tag: o.tag, type: o.type, server: o.server, port: o.port })),
          rulesCount: preview.rules.length
        }, null, 2))}</div>
      </div>
    </article>
  ` : '';

  const historyRows = (state.migrations || []).map((m) => `
    <tr>
      <td><strong>${fmtDate(m.at)}</strong></td>
      <td><span class="tag">${m.mode === 'replace' ? '覆盖替换' : '智能合并'}</span></td>
      <td>${m.inboundsCount || 0} 个入站 (${m.clientsCount || 0} 个客户端)</td>
      <td>${m.outboundsCount || 0} 个出站</td>
      <td>${m.rulesCount || 0} 条分流规则${m.restoredCertsCount ? ` · 证书: ${esc((m.restoredCertDomains || []).join(', '))}` : ''}</td>
    </tr>
  `).join('');

  return `
    ${previewHtml}

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head">
          <div><h2>方式一：上传备份文件 (x-ui.db / .tar.gz) 或读取本机</h2><p>支持直接上传 x-ui.db 数据库、或包含 /etc/x-ui/x-ui.db + /root/cert + /root/.acme.sh 的 .tar.gz 备份包，完整还原全部节点、中转出站、路由规则与 SSL 自动续签证书</p></div>
        </div>
        <div class="panel-body stack">
          <label class="upload-dropzone" for="xui-db-file">
            <input type="file" id="xui-db-file" accept=".db,.sqlite,.sqlite3,.gz,.tgz,.json" class="hidden">
            <b style="display:block;font-size:15px;margin-bottom:6px">📁 点击选择或拖拽上传 <code>x-ui.db</code> 或 <code>3xui_backup.tar.gz</code></b>
            <span class="muted" style="font-size:12px" id="xui-file-label">支持 SQLite3 数据库 (x-ui.db)、通用 .tar.gz 备份包或 JSON 文件</span>
          </label>

          <div class="form-grid" style="padding:12px;border-radius:11px;background:var(--surface-soft);border:1px solid var(--line)">
            <label>
              <span>1. 选择归属服务器 (将备份导入到哪台中转机或落地机)</span>
              <select id="migrate-target-node">
                ${(state.nodes && state.nodes.length ? state.nodes : [{ id: 'node_local', name: '主控本机 (Local Master)', domain: state.settings?.webDomain || '' }]).map((n) => `<option value="${esc(n.id)}">${n.role === 'exit' ? '[落地]' : '[中转]'} ${esc(n.name)}${n.domain ? ` (${esc(n.domain)})` : ''}</option>`).join('')}
                <option value="__create__">＋ 自动新建一台中转机并导入此备份数据...</option>
              </select>
            </label>
            <label>
              <span>2. 该中转机专属域名 (选填，客户端连接自动绑定此域名)</span>
              <input id="migrate-node-domain" placeholder="例如 hk1.example.com (独立隔离不冲突)">
            </label>
            <label>
              <span>新建机器名称 (仅选「自动新建」时选填)</span>
              <input id="migrate-node-name" placeholder="例如：日本软银中转 02">
            </label>
            <label>
              <span>新建机器公网 IP (仅选「自动新建」时选填)</span>
              <input id="migrate-node-ip" placeholder="例如：45.76.210.55">
            </label>
            <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
              <input type="checkbox" id="migrate-dedup-exits" style="width:16px;min-height:16px" checked>
              <span><b>跨机隔离与共享落地自动去重</b>：不同中转机的相同端口 (如 443) 自动隔离互不冲突；多台机器共用的相同落地节点 (相同 IP:端口) 自动去重合并</span>
            </label>
          </div>

          <label>
            <span>迁移合并策略</span>
            <select id="migrate-mode">
              <option value="merge">智能合并（保留当前面板已有节点，同端口/同Tag自动更新）</option>
              <option value="replace">完整替换（清空当前节点，完整还原导入的入站、出站与路由转发）</option>
            </select>
          </label>

          <div style="display:flex;flex-wrap:wrap;gap:8px">
            <button data-action="preview-xui-file">🔍 预览上传文件解析结果</button>
            <button class="primary" data-action="apply-xui-file">🚀 上传并立即执行备份迁移</button>
          </div>

          <div style="padding-top:12px;border-top:1px solid var(--line)">
            <label>
              <span>或者直接从服务器本机路径读取 (支持 <code>/etc/x-ui/x-ui.db</code> 或 <code>/root/3xui_backup.tar.gz</code>)</span>
              <div class="input-row" style="margin-top:4px">
                <input id="local-xui-path" value="/etc/x-ui/x-ui.db" placeholder="/etc/x-ui/x-ui.db 或 /root/3xui_backup.tar.gz">
                <button class="primary" data-action="migrate-local-xui">一键迁移本机数据</button>
              </div>
              <small>本机状态: ${state.overview?.local3xuiExists ? '✅ 已检测到本机备份数据库或压缩包' : '可填入服务器上的 .db 或 .tar.gz 路径一键读取'}</small>
            </label>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div><h2>方式二：粘贴配置 JSON 导入</h2><p>支持粘贴 xrayTemplateConfig JSON 或入站数组 JSON</p></div>
        </div>
        <div class="panel-body stack">
          <label>
            <span>配置 JSON 内容</span>
            <textarea id="xui-json-input" style="min-height:190px" placeholder='{"inbounds": [...], "outbounds": [...], "routing": {"rules": [...]}}'></textarea>
          </label>
          <div style="display:flex;justify-content:flex-end;gap:8px">
            <button data-action="preview-xui-json">🔍 预览 JSON 解析</button>
            <button class="primary" data-action="apply-xui-json">🚀 从 JSON 执行备份迁移</button>
          </div>
        </div>
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>历史迁移记录</h2><p>历次数据与证书迁移导入审计</p></div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>迁移时间</th><th>模式</th><th>入站与客户端</th><th>迁移出站</th><th>迁移分流规则与证书</th></tr></thead>
          <tbody>
            ${historyRows || '<tr><td colspan="5"><div class="empty"><b>尚无迁移记录</b><span>上传 x-ui.db、备份包或粘贴 JSON 后将在此记录</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderCertificates() {
  const s = state.settings || {};
  const baseSubUrl = getBaseSubscriptionUrl();
  const clashSubUrl = `${baseSubUrl}?format=clash`;
  const singboxSubUrl = `${baseSubUrl}?format=singbox`;

  const certRows = (state.certificates || []).map((c) => {
    const isPanelCert = s.webCertFile === c.certPath;
    const isNodeDefault = s.defaultCertFile === c.certPath;
    return `
      <tr>
        <td>
          <strong>${esc(c.domain)}</strong>
          <small>${esc(c.subject || '')}</small>
        </td>
        <td>
          <span class="tag">${esc(c.type || 'cert')}</span>
          ${isPanelCert ? '<span class="tag tls">当前面板 HTTPS</span>' : ''}
          ${isNodeDefault ? '<span class="tag relay">当前节点默认证书</span>' : ''}
        </td>
        <td>
          <small>公钥: <code>${esc(c.certPath)}</code></small>
          <small>私钥: <code>${esc(c.keyPath)}</code></small>
        </td>
        <td>
          <strong>${c.validTo ? fmtDate(c.validTo) : '长期有效'}</strong>
          <small>签发机构: ${esc((c.issuer || 'Self-Signed').slice(0, 40))}</small>
        </td>
        <td>
          <span class="status ${c.valid !== false ? 'valid' : 'error'}">${c.valid !== false ? '有效' : '文件异常'}</span>
        </td>
        <td>
          <div class="actions">
            <button class="primary" data-action="bind-cert-all" data-id="${esc(c.id)}">设为面板与节点默认证书</button>
            <button class="danger" data-action="delete-cert" data-id="${esc(c.id)}">移除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="action-bar">
      <div class="action-bar-left">
        <button class="primary" data-action="cert-acme">🌐 ACME 自动申请证书 (域名 / CF DNS / IP证书)</button>
        <button data-action="cert-selfsigned">⚡ 生成 10 年自签证书 (免域名)</button>
        <button data-action="cert-custom">📋 粘贴 / 导入已有证书</button>
        <button class="primary" data-action="open-aggregate-qr-modal">📱 打开全节点聚合订阅与二维码</button>
      </div>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div><h2>SSL 证书管理列表 (${state.certificates.length} 张)</h2><p>当前默认证书域名: <b>${esc(getActiveCertObject()?.domain || s.webDomain || s.defaultTlsDomain || '未绑定域名')}</b></p></div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>域名 / 标识</th><th>用途与类型</th><th>证书文件路径</th><th>到期时间 / 签发者</th><th>状态</th><th style="text-align:right">操作</th></tr></thead>
          <tbody>
            ${certRows || '<tr><td colspan="6"><div class="empty"><b>尚未添加自定义或 ACME 证书</b><span>点击左上方“🌐 ACME 自动申请证书”即可一键配置面板与节点证书</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>全节点聚合订阅中心 (高强度随机安全码防护)</h2><p>已启用 20 位随机安全码防扫描保护（拒绝简单 /sub/all 访问），支持 Shadowrocket、v2rayN、v2rayNG、NekoBox、Clash Verge / Mihomo、Sing-box、Stash、Surge、Hiddify 直接导入或按需展开二维码</p></div>
      </div>
      <div class="panel-body">
        <div class="qr-wall-grid">
          <div class="qr-wall-card">
            <div class="qr-wall-head">
              <strong>1. 通用 Base64 全节点聚合订阅</strong>
              <span class="tag">Base64</span>
            </div>
            <div class="qr-wall-sub">适用于 v2rayN / v2rayNG / Shadowrocket / NekoBox</div>
            <code style="font-size:11.5px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(baseSubUrl)}</code>
            <div class="qr-wall-actions">
              <button class="primary" data-copy="${esc(baseSubUrl)}">📋 复制通用订阅</button>
              <button data-qr-inline="cert-qr-base64" data-qr-text="${esc(baseSubUrl)}">📱 展开/收起二维码</button>
            </div>
            <div id="cert-qr-base64" class="subscription-qr hidden"></div>
          </div>

          <div class="qr-wall-card">
            <div class="qr-wall-head">
              <strong>2. Clash / Mihomo 智能分流订阅</strong>
              <span class="tag tls">Clash YAML</span>
            </div>
            <div class="qr-wall-sub">内置 AI 专线 / 外贸 Google / Netflix / 自动测速策略组</div>
            <code style="font-size:11.5px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(clashSubUrl)}</code>
            <div class="qr-wall-actions">
              <button class="primary" data-copy="${esc(clashSubUrl)}">📋 复制 Clash 订阅</button>
              <button data-qr-inline="cert-qr-clash" data-qr-text="${esc(clashSubUrl)}">📱 展开/收起二维码</button>
            </div>
            <div id="cert-qr-clash" class="subscription-qr hidden"></div>
          </div>

          <div class="qr-wall-card">
            <div class="qr-wall-head">
              <strong>3. Sing-box 客户端 JSON 订阅</strong>
              <span class="tag relay">Sing-box</span>
            </div>
            <div class="qr-wall-sub">适用于 Sing-box (SFI / SFA / SFM) 客户端</div>
            <code style="font-size:11.5px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(singboxSubUrl)}</code>
            <div class="qr-wall-actions">
              <button class="primary" data-copy="${esc(singboxSubUrl)}">📋 复制 Sing-box 订阅</button>
              <button data-qr-inline="cert-qr-sb" data-qr-text="${esc(singboxSubUrl)}">📱 展开/收起二维码</button>
            </div>
            <div id="cert-qr-sb" class="subscription-qr hidden"></div>
          </div>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>四、新增干净机器（未搭建 3x-ui）如何接入？子机器还需要安装面板或证书吗？</h2>
          <p>针对新购空白 VPS（中转机 / 落地机 / 热备机）的最简接入与证书自动同步机制说明</p>
        </div>
        <span class="status valid">子机器零面板 · 证书全自动下发</span>
      </div>
      <div class="panel-body">
        <div class="grid-2">
          <div style="padding:14px;border-radius:10px;border:1px solid var(--line);background:var(--surface-soft);font-size:13px;line-height:1.7">
            <b style="color:var(--primary);font-size:14px">1. 新增没有搭建 3x-ui / X-Panel / NexusGate 的干净机器怎么操作？</b>
            <ul style="margin:8px 0 0;padding-left:18px;display:flex;flex-direction:column;gap:6px">
              <li><b>完全不需要在子机器上安装任何面板！</b>只有你现在登录的这台主控机需要安装面板。</li>
              <li>对于任何新买的空白 VPS（无论是作为<b>新中转机</b>、<b>纯落地机</b>还是<b>热备容灾机</b>）：<br>
                ① 在主控《中转与落地集群》点击添加对应角色服务器（选「中转机」时只显示域名与容灾配置；只有选「纯落地机」或「一体机」时才会显示并自动启用共享 SS 落地配置）；<br>
                ② 添加后直接点击该机器卡片上的「<b>📋 复制 Agent 命令</b>」，去那台新 VPS 的 SSH 终端粘贴回车即可！</li>
              <li>Agent 脚本会在 10 秒内自动完成：安装 Sing-box 内核、开启 <code>BBR + FQ + HY2 64MB</code> 内核加速、限制日志体积（≤32MB）与守护进程内存（仅占 ~14MB 内存），并自动连回主控。之后你在主控《入站节点管理》选择该机器就能直接建节点了！</li>
            </ul>
          </div>
          <div style="padding:14px;border-radius:10px;border:1px solid var(--line);background:var(--surface-soft);font-size:13px;line-height:1.7">
            <b style="color:var(--success);font-size:14px">2. 子机器（中转机）上的 TLS / HY2 / AnyTLS 节点证书怎么弄？需要去子机器装证书吗？</b>
            <ul style="margin:8px 0 0;padding-left:18px;display:flex;flex-direction:column;gap:6px">
              <li><b>子机器不需要手动安装证书，也不需要再装证书面板！</b>所有证书统一在主控的《<b>SSL 证书与订阅</b>》页面集中管理。</li>
              <li><b>具体操作步骤（支持为任意远程中转机域名申请证书）</b>：<br>
                ① 在主控左侧点击《<b>SSL 证书与订阅</b>》➔ 点击左上角「<b>🌐 ACME 自动申请证书</b>」；<br>
                ② 在弹窗顶部下拉框直接选择那台中转机的域名（如 <code>jp2.yourdomain.com</code>），申请模式选择「<b>2. Cloudflare DNS API 模式</b>」（会自动带入你保存的 CF Token）；<br>
                ③ 点击开始签发：主控会通过 Cloudflare DNS 接口完成验证并签发受信任证书，随后<b>自动将证书文件 (<code>fullchain.pem</code> 与 <code>privkey.pem</code>) 加密推送到那台中转机和备用机上</b>！</li>
              <li>如果你是通过《备份迁移》上传了原 3x-ui 的 <code>.tar.gz</code> 备份包（内含 <code>/root/cert</code>），主控也会自动提取里面的证书并同步分发给对应的中转机与热备机！</li>
            </ul>
          </div>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>五、自动容灾的触发条件是什么？会不会误判？如何一键导入/导出全集群备份？</h2>
          <p>容灾双重判定机制、纯手动 vs 自动模式切换、Web 与 SSH 终端备份导出/恢复权威说明</p>
        </div>
        <span class="status valid">双重探测防误切 · Web/SSH 一键备份</span>
      </div>
      <div class="panel-body">
        <div class="grid-2">
          <div style="padding:14px;border-radius:10px;border:1px solid var(--line);background:var(--surface-soft);font-size:13px;line-height:1.7">
            <b style="color:var(--primary);font-size:14px">1. 自动容灾触发条件是什么？会不会因为网络偶发抖动而误切？</b>
            <ul style="margin:8px 0 0;padding-left:18px;display:flex;flex-direction:column;gap:6px">
              <li><b>核心判定机制（双重存活验证）</b>：<br>
                ① <b>心跳持续超时</b>：受控端 Agent 每 10 秒向主控上报一次心跳；只有当某台主力机连续持续达到设定的分钟数（如默认 3 分钟）没有任何心跳时，才会进入容灾候选状态；<br>
                ② <b>主控主动反向探测确认</b>：在触发切换前，主控会主动向该机器的 Agent 端口发起双重探活；如果只是单向网络临时丢包但机器仍能连通，<b>绝对不会切</b>！只有双重探测均失败、确认 VPS 宕机或网络中断时才会触发切换。<br>
                ③ <b>支持完全关闭自动模式</b>：在编辑中转机时，你可在「断线容灾切换模式」下拉框直接选择「<b>🔒 仅手动切换模式</b>」——平时绝不自动动 IP，只有需要时由你在面板上点击「<b>⚡ 一键容灾切换</b>」才切，彻底杜绝误判！</li>
            </ul>
          </div>
          <div style="padding:14px;border-radius:10px;border:1px solid var(--line);background:var(--surface-soft);font-size:13px;line-height:1.7">
            <b style="color:var(--success);font-size:14px">2. 面板集群备份如何导出和导入？SSH 命令行能一键备份吗？</b>
            <ul style="margin:8px 0 0;padding-left:18px;display:flex;flex-direction:column;gap:6px">
              <li><b>Web 页面一键导出与导入</b>：<br>
                • <b>导出</b>：在《面板设置与安全》点击顶部蓝色的「<b>📦 导出全量主控灾备包 (.zip)</b>」，直接下载保存到本地；<br>
                • <b>导入</b>：点击旁边的「<b>⬆ 导入恢复备份</b>」，弹窗内直接点击「<b>📁 点击直接选择 nexusgate-master-backup.zip 文件</b>」即可一键上传恢复，无需手动复制粘贴！</li>
              <li><b>SSH 终端命令行一键备份与恢复</b>：<br>
                • 终端输入 <code>ng</code> 呼出管理菜单，输入 <b>3</b> 即可一键导出备份至 <code>/root/nexusgate-backup-日期.json</code>；<br>
                • 也可以直接执行：<code>ng backup</code>（一键备份）或 <code>ng restore &lt;备份文件路径&gt;</code>（一键无损还原全集群数据）！</li>
            </ul>
          </div>
        </div>
      </div>
    </section>

    <section class="panel" style="margin-top:16px">
      <div class="panel-head">
        <div>
          <h2>六、主控面板机如果故障宕机，所有中转机和落地机的节点会掉线超时吗？如何免手动迁移？</h2>
          <p>控制面与数据面彻底解耦架构（主控宕机 = 客户节点 0 掉线）+ 主控双活热备 (Master-Standby HA) 完整说明</p>
        </div>
        <span class="status valid">数据面 100% 脱机自治 · 主控双活自愈</span>
      </div>
      <div class="panel-body">
        <div class="grid-2">
          <div style="padding:14px;border-radius:10px;border:1px solid var(--line);background:var(--surface-soft);font-size:13px;line-height:1.7">
            <b style="color:var(--success);font-size:14px">1. 主控面板机器宕机时，现有的全部中转机和落地机节点会掉线或陷入超时吗？</b>
            <ul style="margin:8px 0 0;padding-left:18px;display:flex;flex-direction:column;gap:6px">
              <li><b>绝对不会掉线！所有客户节点 100% 正常使用，0 秒中断，绝不超时！</b></li>
              <li><b>原因（控制面与数据面彻底解耦）</b>：<br>
                ① 每台中转机、落地机、热备机上的 <code>sing-box</code> 配置文件 (<code>/etc/nexusgate/sing-box/config.json</code>) 与 SSL 证书都是<b>持久保存在子机器本地硬盘</b>并由子机器本地 <code>systemd</code> 独立守护运行的；<br>
                ② 客户的连接路径是 <code>客户端 ➔ 中转机独立域名/IP ➔ 落地机共享 SS ➔ 目标网站</code>，<b>平时数据流量完全不经过主控机</b>，也不需要主控实时在线鉴权；<br>
                ③ 主控失联期间，子机器 Agent 自动进入「<b>脱机自治守护模式 (Autonomous Offline Mode)</b>」，将期间产生的客户流量增量写入子机器本地 <code>agent-offline-state.json</code> 缓存，等主控恢复或切至备用主控后自动无损补报，1 字节流量都不会丢！</li>
            </ul>
          </div>
          <div style="padding:14px;border-radius:10px;border:1px solid var(--line);background:var(--surface-soft);font-size:13px;line-height:1.7">
            <b style="color:var(--primary);font-size:14px">2. 如果主控机彻底坏了，有没有不用手动迁移备份的更方便办法？</b>
            <ul style="margin:8px 0 0;padding-left:18px;display:flex;flex-direction:column;gap:6px">
              <li><b>方案 A：配置「主控双活热备 (Master-Standby HA)」（全自动 · 免手动导入）</b>：<br>
                在另一台备用服务器上也安装好本面板，然后在主力主控《面板设置与安全》的「<b>备用主控面板地址</b>」填入该备用机地址，选择「<b>⚡ 变更触发同步（平时 0 流量）</b>」。每次你在主控改节点，主控会自动把全量 <code>.zip</code> 数据（含<b>相同的访问端口、安全根路径、登录账号密码、SSL 证书与全部节点</b>）实时克隆到备用主控！主力主控故障时，备用主控自动（或一键）接管全集群并切换主控 Cloudflare DNS，所有子机器 Agent 自动切向备用主控！</li>
              <li><b>方案 B：使用 <code>.zip</code> 全量主控灾备包异机 1:1 克隆恢复</b>：<br>
                平时在 Web 点击「<b>📦 导出全量主控灾备包 (.zip)</b>」或 SSH 执行 <code>ng backup</code> 保存一个 <code>.zip</code> 文件；在任何新服务器上执行 <code>ng restore 备份包.zip</code>（或 Web 直接上传 <code>.zip</code>），新机器立即恢复成与原主控<b>完全一致的端口、安全路径、账号密码与全部节点</b>！</li>
            </ul>
          </div>
        </div>
      </div>
    </section>

  `;
}

function renderSettings() {
  const s = state.settings || {};
  const certSelectOpts = [
    '<option value="">— 手动输入路径或不使用 HTTPS —</option>',
    ...(state.certificates || []).map((c) => `<option value="${esc(c.certPath)}|${esc(c.keyPath)}|${esc(c.domain)}"${s.webCertFile === c.certPath ? ' selected' : ''}>${esc(c.domain)} (${esc(c.type)})</option>`)
  ].join('');

  return `
    <div class="action-bar">
      <div class="action-bar-left">
        <a class="button primary" href="${BASE_PATH}/api/backup?format=zip" target="_blank">📦 导出全量主控灾备包 (.zip · 含端口/安全路径/账密/SSL证书/全集群)</a>
        <a class="button" href="${BASE_PATH}/api/backup?format=json" target="_blank">⬇ 导出纯配置 (.json)</a>
        <button class="primary" data-action="restore-backup-modal">⬆ 一键导入恢复主控备份 (.zip / .json)</button>
      </div>
    </div>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head">
          <div><h2>面板网络、随机端口与安全路径</h2><p>修改端口或 SSL 证书后，面板服务将自动平滑重启生效</p></div>
        </div>
        <form id="settings-form" class="panel-body form-grid">
          <label>
            面板监听 IP (webListen)
            <input name="webListen" value="${esc(s.webListen || '0.0.0.0')}" placeholder="0.0.0.0 或 ::" required>
          </label>
          <label>
            面板监听端口 (webPort)
            <div class="input-row">
              <input name="webPort" id="setting-webport" type="number" min="1" max="65535" value="${esc(s.webPort || 2053)}" required>
              <button type="button" data-action="random-port">🎲 随机端口</button>
            </div>
          </label>

          <label class="wide">
            面板安全根路径 (webBasePath · 推荐 16 位随机字符)
            <div class="input-row">
              <input name="webBasePath" id="setting-webpath" value="${esc(s.webBasePath || '/')}" placeholder="/44A8m9DxlT7A7AbK/">
              <button type="button" data-action="random-path">🎲 生成 16 位随机安全路径</button>
              <button type="button" data-action="reset-path">设为 /</button>
            </div>
          </label>

          <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" name="strictBasePath" style="width:16px;min-height:16px" ${s.strictBasePath !== false ? 'checked' : ''}>
            <span><b>禁止单 IP+端口直接访问面板</b>（默认开启：访问无安全路径的 <code>IP:端口/</code> 直接返回 404，必须通过 <code>IP/域名:端口/安全路径/</code> 访问）</span>
          </label>

          <label>
            服务器公网 IPv4 (用于生成节点连接地址)
            <input name="publicIPv4" value="${esc(s.publicIPv4 || '')}" placeholder="自动检测本机公网 IPv4">
          </label>
          <label>
            面板 / 节点绑定域名 (webDomain)
            <input name="webDomain" id="setting-webdomain" value="${esc(s.webDomain || '')}" placeholder="填写已解析的域名">
          </label>

          <div class="section-title">面板 HTTPS (SSL 证书配置)</div>
          <label class="wide">
            快速选择已管理的 SSL 证书
            <select id="setting-cert-picker">${certSelectOpts}</select>
          </label>
          <label>
            面板公钥证书路径 (webCertFile)
            <input name="webCertFile" id="setting-cert-file" value="${esc(s.webCertFile || '')}" placeholder="留空则为 HTTP 模式">
          </label>
          <label>
            面板私钥文件路径 (webKeyFile)
            <input name="webKeyFile" id="setting-key-file" value="${esc(s.webKeyFile || '')}" placeholder="留空则为 HTTP 模式">
          </label>

          <div class="section-title">订阅安全码、流量重置与日志级别</div>
          <label class="wide">
            聚合订阅安全码 (subToken · 20 位高强度随机字符，防止订阅链接被扫描或猜测泄露)
            <div class="input-row">
              <input name="subToken" id="setting-subtoken" value="${esc(s.subToken || '')}" placeholder="20 位随机安全码" required>
              <button type="button" data-action="random-sub-token">🎲 重新生成 20 位安全码</button>
            </div>
            <small>更换安全码后，旧的聚合订阅链接将立即失效返回 404。</small>
          </label>
          <label>
            订阅路径前缀 (subPath)
            <input name="subPath" value="${esc(s.subPath || '/sub/')}" placeholder="/sub/">
          </label>
          <label>
            全局默认每月自动重置流量日 (1–31 号，0 = 不自动重置)
            <input name="trafficResetDay" type="number" min="0" max="31" value="${esc(s.trafficResetDay || 0)}" placeholder="0 表示按单节点设置">
          </label>
          <label class="wide">
            Sing-box 日志级别
            <select name="singboxLogLevel">
              <option value="warn"${selected('warn', s.singboxLogLevel || 'warn')}>warn (推荐 · 精简日志，省内存省硬盘)</option>
              <option value="info"${selected('info', s.singboxLogLevel)}>info (标准日志)</option>
              <option value="error"${selected('error', s.singboxLogLevel)}>error (仅记录错误)</option>
              <option value="debug"${selected('debug', s.singboxLogLevel)}>debug (调试模式)</option>
            </select>
          </label>


          <div class="section-title">🛡️ 主控面板双活热备与断线自动接管 (Master-Standby HA · 免手动迁移)</div>
          <div class="wide notice" style="font-size:12px;line-height:1.6">
            <b>💡 为什么主控故障时客户节点绝不掉线？如何免去手动迁移备份？</b><br>
            1. <b>数据面脱机自治 (0 掉线)</b>：中转机与落地机上的节点由各子机器本地独立运行，主控面板机就算断网宕机，<b>所有客户的节点和转发 100% 照常使用、绝不超时</b>，离线期间流量缓存在子机器本地，主控恢复后自动无损补报。<br>
            2. <b>主控双活热备 (免手动恢复)</b>：在下方填写一台备用主控地址（可直接使用集群中的热备机或任意装有本面板的备用机），主控会在每次新增/修改节点时自动将 <b>原端口、原安全路径、原账号密码、SSL 证书与全部节点配置 (.zip)</b> 实时同步到备用主控！
          </div>
          <label>
            当前面板主控角色 (masterHaRole)
            <select name="masterHaRole">
              <option value="primary"${selected('primary', s.masterHaRole || 'primary')}>🟢 主力主控面板 (Primary Master · 统管集群与主动推送)</option>
              <option value="standby"${selected('standby', s.masterHaRole)}>🟠 热备副主控面板 (Standby Master · 实时接收同步并待命接管)</option>
            </select>
          </label>
          <label>
            备用主控同步策略 (masterHaSyncMode · 省流高效)
            <select name="masterHaSyncMode">
              <option value="on_change"${selected('on_change', s.masterHaSyncMode || 'on_change')}>⚡ 变更触发同步 (强烈推荐 · 仅增改节点时同步，平时 0 流量)</option>
              <option value="daily"${selected('daily', s.masterHaSyncMode)}>⏱ 每日定时同步一次 (每天自动同步全量快照)</option>
              <option value="manual"${selected('manual', s.masterHaSyncMode)}>🖐 仅手动点击同步</option>
            </select>
          </label>
          <label>
            备用主控面板地址 (standbyMasterUrl · 主力主控填写)
            <input name="standbyMasterUrl" value="${esc(s.standbyMasterUrl || '')}" placeholder="例如: http://备用主控IP:端口 或 https://备主控域名:端口">
            <small>填写后，本机所有受控端 Agent 也会自动获知该备用主控地址，主力主控失联时 Agent 自动切往备用主控汇报。</small>
          </label>
          <label>
            主力主控面板地址 (primaryMasterUrl · 仅在备用主控上填写用于探活)
            <input name="primaryMasterUrl" value="${esc(s.primaryMasterUrl || '')}" placeholder="备用主控自动接收同步时会自动填入主力主控地址">
          </label>
          <label>
            主备加密同步共享密钥 (masterHaSecret · 选填)
            <input name="masterHaSecret" value="${esc(s.masterHaSecret || '')}" placeholder="留空则默认使用上方 20 位聚合订阅安全码进行 HMAC 签名校验">
          </label>
          <label>
            备用主控自动接管模式 (主力主控宕机时是否自动转正并切 DNS)
            <select name="masterAutoTakeoverSelect">
              <option value="manual"${!s.masterAutoTakeover ? ' selected' : ''}>🔒 默认关闭自动接管 · 仅手动点击「一键接管」</option>
              <option value="1"${s.masterAutoTakeover && Number(s.masterAutoTakeoverMinutes) === 1 ? ' selected' : ''}>⚡ 主力主控连续断线 1 分钟自动接管 + 切 CF DNS</option>
              <option value="3"${s.masterAutoTakeover && Number(s.masterAutoTakeoverMinutes || 3) === 3 ? ' selected' : ''}>⚡ 主力主控连续断线 3 分钟自动接管 + 切 CF DNS (推荐)</option>
              <option value="5"${s.masterAutoTakeover && Number(s.masterAutoTakeoverMinutes) === 5 ? ' selected' : ''}>⚡ 主力主控连续断线 5 分钟自动接管 + 切 CF DNS</option>
              <option value="10"${s.masterAutoTakeover && Number(s.masterAutoTakeoverMinutes) === 10 ? ' selected' : ''}>⚡ 主力主控连续断线 10 分钟自动接管 + 切 CF DNS</option>
            </select>
          </label>
          <div class="wide" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;padding:10px 12px;border-radius:10px;background:var(--surface-soft);border:1px solid var(--line)">
            <small>
              最近主备同步状态: <b>${s.lastMasterSyncAt ? `${fmtDateTime(s.lastMasterSyncAt)} (${esc(s.lastMasterSyncStatus || 'ok')})` : '尚未执行远程热备同步（或随时使用顶部 .zip 导出备份）'}</b>
            </small>
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <button type="button" data-action="push-master-ha-sync">🔄 立即同步全量数据到备用主控</button>
              <button type="button" class="warning" data-action="trigger-master-ha-takeover">⚡ 备用主控一键接管集群</button>
            </div>
          </div>

          <div class="form-actions">
            <button type="submit" class="primary">保存面板设置</button>
          </div>
        </form>
      </article>

      <div class="stack">
        <article class="panel">
          <div class="panel-head">
            <div><h2>修改管理员账号与密码</h2><p>当前登录账号: <b>${esc(state.admin.username || 'admin')}</b></p></div>
          </div>
          <form id="account-form" class="panel-body form-grid">
            <label class="wide">
              当前登录密码 (必填验证)
              <input name="currentPassword" type="password" required placeholder="请输入当前密码">
            </label>
            <label>
              新管理员账号
              <div class="input-row">
                <input name="username" id="account-user-input" value="${esc(state.admin.username || 'admin')}" required>
                <button type="button" data-action="random-account-user">🎲 随机</button>
              </div>
            </label>
            <label>
              新登录密码 (推荐 18 位高强度随机密码)
              <div class="input-row">
                <input name="newPassword" id="account-pass-input" type="text" required placeholder="输入或点击右侧随机生成">
                <button type="button" data-action="random-account-pass">🎲 随机 18 位</button>
              </div>
            </label>
            <div class="form-actions">
              <button type="submit" class="primary">修改账号与密码</button>
            </div>
          </form>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div><h2>SSH 命令行快捷管理菜单</h2><p>在服务器 SSH 终端输入 <code>ng</code> 或 <code>nexusgate</code> 即可呼出完整管理面板</p></div>
          </div>
          <div class="panel-body">
            <div class="command-item">
              <div>
                <b>呼出完整交互式管理菜单 (含 SSL / BBR+HY2 / 防火墙 / 内存清理)</b>
                <code>ng  或  nexusgate</code>
              </div>
              <button data-copy="ng">复制</button>
            </div>
            <div class="command-item">
              <div>
                <b>查看当前面板配置与访问地址 (简洁明了，方便直接复制)</b>
                <code>ng info</code>
              </div>
              <button data-copy="ng info">复制</button>
            </div>
            <div class="command-item">
              <div>
                <b>一键开启 BBR + FQ + HY2 UDP 高速内核加速</b>
                <code>ng bbr</code>
              </div>
              <button data-copy="ng bbr">复制</button>
            </div>
            <div class="command-item">
              <div>
                <b>SSL 证书管理 (ACME / CF DNS / IP证书 / 自签证书)</b>
                <code>ng cert</code>
              </div>
              <button data-copy="ng cert">复制</button>
            </div>
            <div class="command-item">
              <div>
                <b>一键备份迁移恢复本机数据库或通用备份包</b>
                <code>ng migrate</code>
              </div>
              <button data-copy="ng migrate">复制</button>
            </div>
          </div>
        </article>
      </div>
    </section>
  `;
}


function renderGuide() {
  const nodes = state.nodes && state.nodes.length ? state.nodes : [{ id: 'node_local', name: '主控本机 (Local Master)', role: 'relay', host: state.settings?.publicIPv4 || '127.0.0.1', domain: state.settings?.webDomain || '' }];
  const relayNodes = nodes.filter((n) => n.role === 'relay' || n.role === 'hybrid');

  return `
    <section class="cluster-hub-banner">
      <div class="cluster-hub-left">
        <div class="cluster-hub-title">
          <span class="tag">实战操作手册</span>
          <span>NexusGate Plus 多中转 + 共享落地 + 多 CF 账号秒级容灾完整指南</span>
        </div>
        <p class="cluster-hub-desc">
          本页详细解答：如何把多台不同域名的中转机与无域名落地机集中到一个主控面板、如何获取并配置 Cloudflare API Token（含多个不同 CF 账号 / 多个域名的全自动识别原理）、以及如何测试验证 3 秒容灾漂移。
        </p>
      </div>
      <div class="cluster-hub-actions">
        <button class="primary" data-action="jump-cluster">❖ 前往集群与容灾工作台</button>
        <button data-action="jump-migrate">⇩ 前往 3x-ui 备份归并</button>
      </div>
    </section>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>一、Cloudflare API Token 与 Zone ID 保姆级配置教程</h2>
            <p>配置一次即可实现：主力中转机故障时，系统自动把域名 A 记录 IP 切换至备用容灾机 IP</p>
          </div>
          <span class="tag tls">核心必读</span>
        </div>
        <div class="panel-body stack" style="font-size:13px;line-height:1.65">
          <div class="notice">
            <b>💡 核心问题解答：我有好几个不同的域名，甚至分散在几个不同的 Cloudflare 账号里，单填一个 Zone ID 能自动切换吗？</b><br>
            <b>答：完全不需要手动填 Zone ID（强烈建议将 Zone ID 留空）！原因如下：</b><br>
            1. <b>什么是 Zone ID？</b> 在 Cloudflare 中，每个根域名（如 <code>vponlive.com</code>、<code>abc.com</code>）各自拥有一个独立的 Zone ID。如果你硬填了某一个域名的 Zone ID，它就只能管那一个域名。<br>
            2. <b>为什么留空 Zone ID 就能全自动切换所有域名？</b> 只要你在创建 CF API Token 时授权了 <b>All zones (所有区域)</b>，当你将 Zone ID 留空时，NexusGate Plus 会根据每台中转机填写的「专属域名（如 <code>cs.vponlive.com</code>、<code>jp1.abc.com</code>）」<b>自动向 Cloudflare API 查询匹配该域名的 Zone ID 与 A 记录 ID</b>，自动完成切换！<br>
            3. <b>如果你有多个不同的 Cloudflare 账号怎么办？</b><br>
            • <b>方式 A（全局多 Token 自动识别）</b>：在《中转与落地集群》右侧的「全局 Cloudflare API Token」输入框中，<b>把你名下多个 CF 账号的 Token 全部粘贴进去（每行一个 Token）</b>！切换任意域名时，系统会自动遍历所有 Token 找到该域名所属的 CF 账号并修改解析！<br>
            • <b>方式 B（单机独立 Token）</b>：在「编辑中转机」弹窗中，直接将该中转机所属 CF 账号的 Token 填在「该中转机专属 CF API Token」框内即可。
          </div>

          <div style="padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:var(--surface-soft)">
            <b>📋 在 Cloudflare 后台获取 API Token 的 4 步具体操作：</b>
            <ol style="margin:8px 0 0;padding-left:18px;display:flex;flex-direction:column;gap:6px">
              <li>登录 <a href="https://dash.cloudflare.com/profile/api-tokens" target="_blank" rel="noopener" style="color:var(--primary);font-weight:700">Cloudflare 控制台 (My Profile ➔ API Tokens)</a>，点击蓝色的 <b>Create Token (创建令牌)</b>。</li>
              <li>在模板列表第一行找到 <b>Edit zone DNS (编辑区域 DNS)</b>，点击右侧的 <b>Use template (使用模板)</b>。</li>
              <li>
                核对两项关键设置：<br>
                • <b>Permissions (权限)</b>：保持默认 <code>Zone</code> — <code>DNS</code> — <code>Edit (编辑)</code>；<br>
                • <b>Zone Resources (区域资源)</b>：选择 <code>Include (包含)</code> ➔ <b><code>All zones (所有区域)</code></b>（这样该 CF 账号下的全部域名都能自动识别切换，无需查 Zone ID！）。
              </li>
              <li>拉到底部点击 <b>Continue to summary</b> ➔ <b>Create Token</b>，复制生成的 Token 字符串（形如 <code>aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890</code>），粘贴到本面板的 CF Token 框中保存即可！</li>
            </ol>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>二、如何测试验证容灾切换与回切？（4 步实战演练）</h2>
            <p>无需等机器真的宕机，平时即可在面板上一键验证 CF 自动换 IP 与备用机接管</p>
          </div>
          <span class="tag relay">秒级容灾演练</span>
        </div>
        <div class="panel-body stack" style="font-size:13px;line-height:1.65">
          <div style="padding:12px 14px;border-radius:10px;border:1px solid var(--line);background:var(--surface-soft)">
            <b>⚡ 容灾热备完整配置与测试 4 步曲：</b>
            <ol style="margin:8px 0 0;padding-left:18px;display:flex;flex-direction:column;gap:8px">
              <li>
                <b>第 1 步：准备一台备用机并挂上 Agent</b><br>
                在《中转与落地集群》点击「<b>＋ 添加热备机</b>」，填入备用 VPS 的公网 IP（无需域名）。添加后点击卡片上的「<b>📋 复制 Agent 命令</b>」到备用机 SSH 执行（10 秒装完）。
              </li>
              <li>
                <b>第 2 步：在主力中转机上绑定备用机并开启「实时镜像预热」</b><br>
                点击主力中转机卡片的「<b>编辑</b>」，确认已填写「中转机专属域名（如 <code>cs.vponlive.com</code>）」，在「绑定备用容灾机」下拉框选择刚添加的热备机，并勾选「<b>开启实时热备镜像预热 (Mirror Standby)</b>」。保存后，主控会将主力机的全部节点与 SSL 证书实时同步到备用机预热！
              </li>
              <li>
                <b>第 3 步：点击「🔍 测 CF 解析」验证 API 权限</b><br>
                在中转机卡片上点击「<b>🔍 测 CF 解析</b>」按钮，系统会立即调用 Cloudflare API 验证你的 Token 是否能找到该域名，并弹窗显示自动匹配到的 <code>Zone ID</code> 与当前 A 记录 IP。
              </li>
              <li>
                <b>第 4 步：点击「⚡ 一键容灾切换」与「✓ 主力恢复回切」实测</b><br>
                • 点击中转机卡片的「<b>⚡ 一键容灾切换</b>」➔ 确认后，备用机瞬间接管所有端口与证书，且 Cloudflare 后台该域名的 A 记录 IP 自动变成备用机 IP（客户无需更新订阅，连接不断）！<br>
                • 演练完毕后，点击卡片上的绿色「<b>✓ 主力恢复回切</b>」按钮，Cloudflare 解析 IP 立即自动切回主力机原 IP！
              </li>
            </ol>
          </div>

          <div class="notice warning">
            <b>🔍 在线快速检测你的中转机 Cloudflare DNS 连通性：</b>
            <div style="display:flex;flex-wrap:wrap;gap:8px;margin-top:8px">
              ${relayNodes.map((rn) => `
                <button class="primary" data-action="test-node-cf" data-id="${esc(rn.id)}">
                  🔍 检测 [${esc(rn.name)}] (${esc(rn.domain || '未绑域名')})
                </button>
              `).join('')}
            </div>
          </div>
        </div>
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>三、多中转机 + 共享落地机 + 多台 3x-ui 无损迁移标准工作流</h2>
          <p>如何在同一个面板里管理十几台中转机、复用落地机并保持完全隔离</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="grid-3">
          <div class="gauge-card">
            <b style="font-size:13.5px;color:var(--primary)">1. 添加落地机 (自动开启共享 SS) 与中转机</b>
            <p class="muted" style="margin:6px 0 0;font-size:12px;line-height:1.6">
              • 添加<b>落地机 (Exit)</b> 时：无需填域名，保存后系统自动在该落地机开启 Shadowsocks 并注册进主控「全局共享落地池」；你也可以在《入站节点管理》选择该落地机手动搭建更多节点。<br>
              • 添加<b>中转机 (Relay)</b> 时：每台中转机填写各自的独立域名（如 <code>hk1.a.com</code>、<code>jp1.b.com</code>），生成订阅时自动按节点所属中转机匹配域名。
            </p>
          </div>
          <div class="gauge-card">
            <b style="font-size:13.5px;color:var(--success)">2. 搭建入站节点与按中转机分栏管理路由</b>
            <p class="muted" style="margin:6px 0 0;font-size:12px;line-height:1.6">
              • 在《入站节点管理》点击「＋ 添加入站」时，弹窗顶部可自由选择<b>部署至哪台中转机或落地机</b>，并可直接勾选要转发的共享落地机。<br>
              • 在《入站节点管理》和《路由规则 (转发)》顶部均有<b>按中转服务器分栏筛选条</b>，哪怕有十几台中转机，点一下对应机器标签即可单独查看和修改该机的节点与转发规则！
            </p>
          </div>
          <div class="gauge-card">
            <b style="font-size:13.5px;color:#7c3aed">3. 多台 3x-ui / X-Panel / NexusGate 无损归并</b>
            <p class="muted" style="margin:6px 0 0;font-size:12px;line-height:1.6">
              • 在《备份迁移》选择目标中转机（或选「自动新建中转机」），上传原机器的 <code>x-ui.db</code>、<code>3xui_backup.tar.gz</code> 或 <code>nexusgate-master-backup.zip</code>。<br>
              • 不同中转机哪怕都有 <code>443</code> 等相同端口也会自动按机器隔离，多台机器共用的相同落地 SS 节点（相同 IP:端口）会自动去重合并，客户零感知！
            </p>
          </div>
        </div>
      </div>
    </section>
  `;
}

function render() {
  updateSidebarBadges();
  const views = {
    overview: renderOverview,
    cluster: renderCluster,
    inbounds: renderInbounds,
    routing: renderRouting,
    outbounds: renderOutbounds,
    migrate: renderMigrate,
    certificates: renderCertificates,
    settings: renderSettings,
    guide: renderGuide
  };
  const contentEl = $('#content');
  if (!contentEl) return;

  const prevWinY = window.scrollY;
  const prevWinX = window.scrollX;
  const prevTableScrolls = Array.from(contentEl.querySelectorAll('.table-wrap')).map((el) => ({
    left: el.scrollLeft,
    top: el.scrollTop
  }));
  const prevHeight = contentEl.offsetHeight;
  if (prevHeight > 0 && prevWinY > 0) {
    contentEl.style.minHeight = `${prevHeight}px`;
  }

  contentEl.innerHTML = (views[state.page] || renderOverview)();

  const nextTables = contentEl.querySelectorAll('.table-wrap');
  nextTables.forEach((el, idx) => {
    if (prevTableScrolls[idx]) {
      el.scrollLeft = prevTableScrolls[idx].left;
      el.scrollTop = prevTableScrolls[idx].top;
    }
  });

  if (prevWinY > 0 || prevWinX > 0) {
    window.scrollTo(prevWinX, prevWinY);
  }
  if (contentEl.style.minHeight) {
    requestAnimationFrame(() => {
      contentEl.style.minHeight = '';
    });
  }
}

/* ==================== MODALS & ACTIONS ==================== */

function openClientDetailModal(inbound, client = null) {
  const c = client || (inbound.clients && inbound.clients[0]) || {};
  const cEmail = c.email || c.name || c.username || inbound.remark || 'default';
  const isUuidProto = ['vless', 'vmess', 'tuic'].includes(inbound.protocol);
  const credLabel = isUuidProto ? 'ID' : '密码 / 密钥';
  const credVal = isUuidProto ? (c.id || c.uuid || '—') : (c.password || inbound.password || inbound.socksPassword || '—');
  const hostAddr = inbound.publicHost || state.settings?.webDomain || state.defaultSettings?.defaultTlsDomain || state.settings?.publicIPv4 || window.location.hostname || '127.0.0.1';
  const wsHost = inbound.wsHost || '无';
  const wsPath = inbound.wsPath || '/';
  const secMode = inbound.security || 'none';
  const authDesc = secMode === 'reality'
    ? 'X25519, Reality Vision'
    : (secMode === 'tls' ? `TLS (${inbound.tlsDomain || hostAddr})` : 'None');
  const sniDomains = secMode === 'reality'
    ? ((inbound.reality?.serverNames && inbound.reality.serverNames.length)
        ? inbound.reality.serverNames.join(', ')
        : `${inbound.reality?.serverName || 'tesla.com'}, ${(inbound.reality?.target || 'www.tesla.com:443').split(':')[0]}`)
    : (inbound.tlsDomain || '—');

  const cUp = Number(c.up ?? inbound.up ?? 0);
  const cDown = Number(c.down ?? inbound.down ?? 0);
  const cUsed = cUp + cDown;
  const cTotalBytes = Number(c.totalBytes || (c.totalGB > 0 ? (c.totalGB > 1024 * 1024 ? c.totalGB : c.totalGB * (1024 ** 3)) : 0) || inbound.total || 0);
  const remainStr = cTotalBytes > 0 ? fmtBytes(Math.max(0, cTotalBytes - cUsed)) : '∞';
  const totalStr = cTotalBytes > 0 ? fmtBytes(cTotalBytes) : '∞';
  const expVal = Number(c.expiryTime || inbound.expiryTime || 0);
  const expStr = expVal > 0 ? fmtDateTime(expVal) : '∞';

  const createdStr = fmtDateTime(c.createdAt || inbound.createdAt);
  const updatedStr = fmtDateTime(c.updatedAt || inbound.updatedAt || c.createdAt || inbound.createdAt);
  const lastOnlineVal = Number(c.lastOnline || inbound.lastOnline || 0);
  const isOnline = Number(c.activeDeviceCount || inbound.activeDeviceCount || 0) > 0;
  const lastOnlineStr = isOnline
    ? `当前在线 (${fmtDateTime(lastOnlineVal || Date.now())})`
    : (lastOnlineVal > 0 ? fmtDateTime(lastOnlineVal) : '从未在线');

  const limIpVal = Number(c.limitIp ?? inbound.limitIp ?? 0);
  const limDevVal = Number(c.limitDevice ?? inbound.limitDevice ?? 0);

  const matchedLink = (inbound.links || []).find((l) => l.clientId === c.id || l.email === cEmail) || (inbound.links && inbound.links[0]) || null;
  const shareUri = matchedLink ? matchedLink.uri : '';
  const linkLabel = matchedLink ? matchedLink.label : `${inbound.remark}-${cEmail}`;

  openModal(
    '详细信息',
    `${inbound.remark} · ${cEmail}`,
    `
    <div class="detail-sheet">
      <div class="detail-grid-2">
        <div class="detail-row"><span>协议</span><span class="detail-pill purple">${esc(inbound.protocol)}</span></div>
        <div class="detail-row"><span>传输</span><span class="detail-pill teal">${esc(inbound.transport || 'tcp')}</span></div>
        <div class="detail-row"><span>地址</span><span class="detail-pill">${esc(hostAddr)}</span></div>
        <div class="detail-row"><span>主机</span><span class="detail-pill warn">${esc(wsHost)}</span></div>
        <div class="detail-row"><span>端口</span><span class="detail-pill">${esc(inbound.port)}</span></div>
        <div class="detail-row"><span>路径</span><span class="detail-pill">${esc(wsPath)}</span></div>
        <div class="detail-row"><span>安全</span><span class="detail-pill teal">${esc(secMode)}</span></div>
        <div class="detail-row"><span>绑定出站</span><span class="detail-pill purple">${esc(inbound.outboundTag && inbound.outboundTag !== 'default' ? inbound.outboundTag : '默认直连 (direct)')}</span></div>
      </div>

      <div class="detail-stack">
        <div class="detail-row"><span>Authentication</span><span class="detail-pill teal">${esc(authDesc)}</span></div>
        <div class="detail-row"><span>加密</span><span class="detail-pill">${esc(inbound.method || 'none')}</span></div>
        <div class="detail-row"><span>域名 (SNI)</span><span class="detail-pill teal">${esc(sniDomains)}</span></div>
      </div>

      <div class="detail-divider"><span>客户 / 用户</span></div>

      <div class="detail-stack">
        <div class="detail-row"><span>电子邮件 / 标识</span><span class="detail-pill teal">${esc(cEmail)}</span></div>
        <div class="detail-row">
          <span>${esc(credLabel)}</span>
          <span class="detail-pill mono" style="cursor:pointer" data-copy="${esc(credVal)}" title="点击复制">${esc(credVal)} 📋</span>
        </div>
        ${inbound.protocol === 'vless' ? `<div class="detail-row"><span>Flow</span><span class="detail-pill">${esc(c.flow || inbound.flow || '无')}</span></div>` : ''}
        <div class="detail-row">
          <span>状态</span>
          <span class="detail-pill ${c.enable !== false ? 'teal' : 'danger'}">${c.enable !== false ? '开启' : '已停用'}</span>
          <span class="detail-pill ${isOnline ? 'teal' : ''}">${isOnline ? `🟢 在线 (${c.activeDeviceCount || inbound.activeDeviceCount || 1} 设备)` : '⚪ 离线'}</span>
        </div>
        <div class="detail-row">
          <span>使用情况</span>
          <span class="detail-pill teal">${fmtBytes(cUsed)}</span>
          <span class="detail-pill">↑ ${fmtBytes(cUp)} / ${fmtBytes(cDown)} ↓</span>
        </div>
        <div class="detail-row"><span>创建时间</span><span class="detail-pill">${esc(createdStr)}</span></div>
        <div class="detail-row"><span>更新时间</span><span class="detail-pill">${esc(updatedStr)}</span></div>
        <div class="detail-row"><span>上次在线</span><span class="detail-pill ${isOnline ? 'teal' : ''}">${esc(lastOnlineStr)}</span></div>
        <div class="detail-row">
          <span>IP / 设备限制</span>
          <span class="detail-pill">IP 限制: ${limIpVal}</span>
          <span class="detail-pill">设备限制: ${limDevVal > 0 ? `${limDevVal} 台` : '0 (不限)'}</span>
        </div>
      </div>

      <div class="detail-summary-3">
        <div>
          <span>剩余</span>
          <div class="detail-pill purple">${esc(remainStr)}</div>
        </div>
        <div>
          <span>总流量</span>
          <div class="detail-pill purple">${esc(totalStr)}</div>
        </div>
        <div>
          <span>到期时间</span>
          <div class="detail-pill purple">${esc(expStr)}</div>
        </div>
      </div>

      ${shareUri ? `
        <div class="detail-divider"><span>URL</span></div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:8px">
          <span class="detail-pill teal">${esc(linkLabel)}</span>
          <button type="button" class="primary" data-copy="${esc(shareUri)}" style="min-height:28px;padding:4px 10px;font-size:12px">📋 复制链接</button>
        </div>
        <div class="codebox" style="word-break:break-all;font-size:12.5px;max-height:120px;user-select:all">${esc(shareUri)}</div>
      ` : ''}
    </div>
    `
  );
}

async function openInboundModal(existing = null, preset = '') {
  if (!state.nodes || !state.nodes.length) {
    try {
      const cl = await api('/api/cluster/nodes');
      if (Array.isArray(cl.nodes)) state.nodes = cl.nodes;
    } catch { /* ignore */ }
  }
  const realCert = getActiveCertObject();
  const defTlsDomain = realCert?.domain || state.settings?.webDomain || state.defaultSettings?.defaultTlsDomain || 'www.apple.com';
  const defCertFile = realCert?.certPath || state.defaultSettings?.defaultCertFile || state.settings?.webCertFile || '';
  const defKeyFile = realCert?.keyPath || state.defaultSettings?.defaultKeyFile || state.settings?.webKeyFile || '';

  const newUuid = genUuidClient();
  const newClientTag = `vless_${genRandomAlnum(6).toLowerCase()}`;
  const newPass = genRandomAlnum(20, newClientTag);
  const newSocksUser = `u_${genRandomAlnum(8)}`;
  const newSocksPass = genRandomAlnum(18, newSocksUser);
  const portRand = Math.floor(Math.random() * 40000) + 15000;

  const item = existing ? JSON.parse(JSON.stringify(existing)) : {
    remark: `VLESS-Reality-${portRand}`,
    tag: `inbound-${portRand}`,
    protocol: 'vless',
    listen: '::',
    port: portRand,
    security: 'reality',
    transport: 'tcp',
    flow: 'xtls-rprx-vision',
    method: '2022-blake3-aes-128-gcm',
    uuid: newUuid,
    password: newPass,
    socksUser: newSocksUser,
    socksPassword: newSocksPass,
    outboundTag: 'default',
    limitIp: 0,
    limitDevice: 0,
    total: 0,
    expiryTime: 0,
    resetDay: state.settings?.trafficResetDay || 0,
    tlsDomain: defTlsDomain,
    certPath: defCertFile,
    keyPath: defKeyFile,
    reality: {
      serverName: 'tesla.com',
      target: 'www.tesla.com:443',
      privateKey: '',
      publicKey: '',
      shortIds: ['1a2b3c4d'],
      fingerprint: 'chrome'
    },
    clients: [{ email: newClientTag, username: newSocksUser, id: newUuid, password: newPass, flow: 'xtls-rprx-vision', enable: true }]
  };

  if (item.reality && ['www.cloudflare.com', 'cloudflare.com', 'www.bing.com'].includes(String(item.reality.serverName || '').toLowerCase())) {
    item.reality.serverName = 'tesla.com';
    item.reality.target = 'www.tesla.com:443';
  }

  if (preset) {
    if (preset === 'vless-reality') {
      item.protocol = 'vless'; item.security = 'reality'; item.transport = 'tcp'; item.flow = 'xtls-rprx-vision'; item.remark = `VLESS-Reality-${item.port}`;
    } else if (preset === 'anytls') {
      item.protocol = 'anytls'; item.security = 'tls'; item.transport = 'tcp'; item.remark = `AnyTLS-${item.port}`;
    } else if (preset === 'hysteria2') {
      item.protocol = 'hysteria2'; item.security = 'tls'; item.upMbps = 100; item.downMbps = 100; item.remark = `HY2-${item.port}`;
    } else if (preset === 'ss2022-128') {
      item.protocol = 'shadowsocks'; item.method = '2022-blake3-aes-128-gcm'; item.security = 'none'; item.remark = `SS2022-128-${item.port}`;
    } else if (preset === 'ss2022-256') {
      item.protocol = 'shadowsocks'; item.method = '2022-blake3-aes-256-gcm'; item.security = 'none'; item.remark = `SS2022-256-${item.port}`;
    } else if (preset === 'ss-128') {
      item.protocol = 'shadowsocks'; item.method = 'aes-128-gcm'; item.security = 'none'; item.remark = `SS-128-${item.port}`;
    } else if (preset === 'socks') {
      item.protocol = 'socks'; item.security = 'none'; item.remark = `SOCKS5-${item.port}`;
    } else if (preset === 'direct') {
      item.protocol = 'direct'; item.security = 'none'; item.remark = `端口转发-${item.port}`;
    }
  }

  if (!existing && item.security === 'reality' && !item.reality.privateKey) {
    try {
      const kp = await api('/api/tools/reality-keypair', { method: 'POST' });
      item.reality.privateKey = kp.privateKey;
      item.reality.publicKey = kp.publicKey;
      item.reality.shortIds = [kp.shortId];
    } catch { /* fallback on submit */ }
  }
  if (!existing && item.protocol === 'shadowsocks') {
    try {
      const sk = await api('/api/tools/ss-key', { method: 'POST', body: JSON.stringify({ method: item.method }) });
      item.password = sk.password;
    } catch { /* ignore */ }
  }

  const outboundOpts = [
    `<option value="default"${selected('default', item.outboundTag)}>默认路由 (按分流规则表处理)</option>`,
    ...state.outbounds.map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, item.outboundTag)}>${o.builtin ? '' : '⇄ 绑定中转出站: '}${esc(o.tag)}${o.server ? ` (${o.server}:${o.port})` : ` (${o.remark})`}</option>`)
  ].join('');

  const certOpts = [
    `<option value="">默认绑定证书 (${esc(defTlsDomain)})</option>`,
    ...(state.certificates || []).map((c) => `<option value="${esc(c.domain)}" data-cert="${esc(c.certPath)}" data-key="${esc(c.keyPath)}"${selected(c.domain, item.tlsDomain)}>${esc(c.domain)} (${esc(c.type)})</option>`)
  ].join('');

  const c0 = (item.clients && item.clients[0]) || {};
  const clientUuidVal = /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(String(c0.id || '')) ? c0.id : (item.uuid || genUuidClient());
  const totalGB = item.total > 0 ? Math.round((item.total / (1024 ** 3)) * 100) / 100 : 0;
  const expiryStr = toDatetimeLocalValue(item.expiryTime);

  openModal(
    existing ? '编辑入站节点' : '新建入站节点',
    existing ? `${existing.remark} (:${existing.port})` : '配置入站协议、IP/设备限制、到期时间、流量重置与中转出站',
    `
    <form id="inbound-form" class="form-grid" data-id="${esc(existing?.id || '')}">
      <label class="wide" style="padding:11px 14px;border-radius:10px;background:var(--primary-soft);border:1px solid color-mix(in srgb,var(--primary) 30%,var(--line))">
        <span style="color:var(--primary);font-weight:800">🖥 部署至目标服务器 (选择要在哪台中转机或落地机上创建此节点)</span>
        <select name="nodeId" id="inb-node-select" style="margin-top:4px;font-weight:700">
          ${(state.nodes && state.nodes.length ? state.nodes : [{ id: 'node_local', name: '主控本机 (Local Master)', role: 'relay', host: state.settings?.publicIPv4 || '127.0.0.1', domain: state.settings?.webDomain || '' }]).map((n) => {
            const rLabel = n.role === 'exit' ? '【落地机】' : (n.role === 'standby' ? '【热备机】' : '【中转机】');
            const hostDesc = n.domain ? `专属域名: ${n.domain} (${n.host || ''})` : `IP: ${n.host || '127.0.0.1'}${n.role === 'exit' ? ' · 所建节点自动注册进共享出站池' : ''}`;
            const defNodeId = existing ? (item.nodeId || 'node_local') : (state.nodeFilter && state.nodeFilter !== 'all' ? state.nodeFilter : 'node_local');
            return `<option value="${esc(n.id)}" data-domain="${esc(n.domain || '')}" data-role="${esc(n.role || 'relay')}"${selected(n.id, defNodeId)}>${rLabel} ${esc(n.name)} — ${esc(hostDesc)}</option>`;
          }).join('')}
        </select>
        <small style="color:var(--muted);margin-top:2px">选择中转机时，客户端订阅与连接地址将自动匹配该中转机的专属域名；选择落地机时，创建后将自动加入出站列表供所有中转机转发。</small>
      </label>
      <label>
        节点备注名称
        <input name="remark" value="${esc(item.remark)}" placeholder="如 VLESS-Reality" required>
      </label>
      <label>
        入站协议 (Protocol)
        <select name="protocol" id="inb-proto-select">
          ${state.catalog.inboundProtocols.map((p) => `<option value="${esc(p.id)}"${selected(p.id, item.protocol)}>${esc(p.name)}</option>`).join('')}
        </select>
      </label>

      <label>
        监听地址 (Listen)
        <input name="listen" value="${esc(item.listen || '::')}" placeholder=":: (双栈) 或 0.0.0.0">
      </label>
      <label>
        监听端口 (Port)
        <div class="input-row">
          <input name="port" id="inb-port-input" type="number" min="1" max="65535" value="${esc(item.port)}" required>
          <button type="button" data-action="inb-rand-port">🎲 随机</button>
        </div>
      </label>

      <div class="section-title">IP 限制、设备数限制、流量配额与到期自动管理</div>
      <label>
        限制同时在线公网 IP 数 (0 = 不限制)
        <input name="limitIp" type="number" min="0" max="1000" value="${esc(item.limitIp || 0)}" placeholder="0 表示不限制公网 IP 数">
        <small>超出设定数量时，仅拦截并断开第 N+1 个新接入的 IP，前 N 个已在线 IP/设备不受影响正常使用</small>
      </label>
      <label>
        限制同时在线设备数 (0 = 不限制)
        <input name="limitDevice" type="number" min="0" max="2000" value="${esc(item.limitDevice || 0)}" placeholder="0 表示不限制设备台数">
        <small>超出设定数量时，仅拦截并断开第 N+1 台新接入的设备，前 N 台已在线设备不受影响正常使用</small>
      </label>

      <label>
        总流量配额上限 (GB，0 = 不限制)
        <input name="totalGB" type="number" min="0" step="0.1" value="${esc(totalGB)}" placeholder="0 表示不限流量">
        <small>达到流量配额上限后自动停用该节点</small>
      </label>
      <label>
        每月自动重置流量日期 (1–31 号，0 = 不自动重置)
        <input name="resetDay" type="number" min="0" max="31" value="${esc(item.resetDay || 0)}" placeholder="如填 1 表示每月 1 号自动清零">
        <small>设为 1–31 后，每月到达该日期自动清零已用流量并恢复因超流停用的节点</small>
      </label>

      <label class="wide">
        节点到期时间 (留空表示永久有效，到期后自动停用)
        <div class="input-row" style="flex-wrap:wrap">
          <input name="expiryTime" id="inb-expiry-input" type="datetime-local" value="${esc(expiryStr)}" style="max-width:240px">
          <button type="button" data-action="set-expiry" data-days="0">永久有效</button>
          <button type="button" data-action="set-expiry" data-days="30">+30天 (月付)</button>
          <button type="button" data-action="set-expiry" data-days="90">+90天 (季付)</button>
          <button type="button" data-action="set-expiry" data-days="180">+180天 (半年)</button>
          <button type="button" data-action="set-expiry" data-days="365">+1年 (年付)</button>
        </div>
      </label>

      <label class="wide">
        ⇄ 一键绑定转发目标出站 (保存后将自动同步至【路由规则 (转发)】表)
        <select name="outboundTag">${outboundOpts}</select>
      </label>

      <div id="inb-dynamic-fields" class="form-grid wide" style="margin:0"></div>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">${existing ? '保存修改并应用' : '立即创建并启动'}</button>
      </div>
    </form>
    `
  );

  const renderDynamicFields = async () => {
    const proto = $('#inb-proto-select').value;
    const box = $('#inb-dynamic-fields');
    if (!box) return;
    if (!existing) {
      const remInput = $('#inbound-form input[name="remark"]');
      const curPort = $('#inb-port-input')?.value || item.port;
      if (remInput && (!remInput.value.trim() || /^(VLESS-Reality|VLESS|VMess|Trojan|AnyTLS|HY2|Hysteria2|SS2022-128|SS2022-256|SS-128|Shadowsocks|SOCKS5|TUIC|HTTP|Mixed|端口转发)-\d+$/i.test(remInput.value.trim()))) {
        const protoLabelMap = {
          vless: 'VLESS-Reality',
          anytls: 'AnyTLS',
          hysteria2: 'HY2',
          shadowsocks: 'SS2022-128',
          socks: 'SOCKS5',
          trojan: 'Trojan',
          vmess: 'VMess',
          tuic: 'TUIC',
          http: 'HTTP',
          mixed: 'Mixed',
          direct: '端口转发'
        };
        remInput.value = `${protoLabelMap[proto] || proto.toUpperCase()}-${curPort}`;
      }
      if (!c0.email || /^[a-z0-9]+_[a-z0-9]{6}$/i.test(c0.email) || c0.email === 'user_1') {
        c0.email = `${proto}_${genRandomAlnum(6).toLowerCase()}`;
      }
      if (proto !== 'shadowsocks') {
        item.password = genRandomAlnum(20, c0.email);
        c0.password = item.password;
      }
    }

    if (proto === 'direct') {
      box.innerHTML = `
        <div class="section-title">Direct 端口转发 (隧道中转配置)</div>
        <label>
          转发目标地址 (Override Address)
          <input name="overrideAddress" value="${esc(item.overrideAddress || '')}" placeholder="目标落地机 IP 或域名" required>
        </label>
        <label>
          转发目标端口 (Override Port)
          <input name="overridePort" type="number" min="1" max="65535" value="${esc(item.overridePort || 443)}" required>
        </label>
        <label class="wide">
          转发网络协议
          <select name="network">
            <option value="tcp,udp"${selected('tcp,udp', item.network)}>TCP + UDP 双栈转发</option>
            <option value="tcp"${selected('tcp', item.network)}>仅 TCP</option>
            <option value="udp"${selected('udp', item.network)}>仅 UDP</option>
          </select>
        </label>
      `;
      return;
    }

    if (proto === 'shadowsocks') {
      box.innerHTML = `
        <div class="section-title">Shadowsocks / SS 2022 加密与密钥</div>
        <label>
          加密方式 (Method)
          <select name="method" id="inb-ss-method">
            ${state.catalog.ssMethods.map((m) => `<option value="${esc(m.id)}"${selected(m.id, item.method)}>${esc(m.label)}</option>`).join('')}
          </select>
        </label>
        <label>
          连接密钥 (Password / Base64 Key)
          <div class="input-row">
            <input name="password" id="inb-ss-pass" value="${esc(item.password || '')}" required>
            <button type="button" data-action="gen-ss-key">🔑 生成标准密钥</button>
          </div>
          <small>自动适配 v2rayN / Shadowrocket / Clash / Sing-box 全客户端。</small>
        </label>
        <label class="wide">
          客户端标识名称 (Email/Remark)
          <div class="input-row">
            <input name="clientEmail" id="inb-client-email" value="${esc(c0.email || `ss_${genRandomAlnum(6).toLowerCase()}`)}">
            <button type="button" data-action="gen-client-email">🎲 随机标识</button>
          </div>
        </label>
      `;

      const refreshSsKeyForMethod = async () => {
        const curMethod = $('#inb-ss-method')?.value || '2022-blake3-aes-128-gcm';
        try {
          const sk = await api('/api/tools/ss-key', { method: 'POST', body: JSON.stringify({ method: curMethod }) });
          if ($('#inb-ss-pass')) {
            $('#inb-ss-pass').value = sk.password;
            item.password = sk.password;
            item.method = curMethod;
          }
        } catch { /* ignore */ }
      };

      if (!existing && (!item.password || !item.password.endsWith('='))) {
        refreshSsKeyForMethod();
      }
      $('#inb-ss-method')?.addEventListener('change', refreshSsKeyForMethod);
      return;
    }

    if (proto === 'socks' || proto === 'mixed' || proto === 'http') {
      const initSocksU = item.socksUser || c0.username || `u_${genRandomAlnum(8)}`;
      const rawSocksP = item.socksPassword || c0.password || '';
      const initSocksP = (!rawSocksP || rawSocksP === initSocksU) ? genRandomAlnum(18, initSocksU) : rawSocksP;
      box.innerHTML = `
        <div class="section-title">${proto.toUpperCase()} 独立高强度认证凭据</div>
        <label>
          认证账号 (Username)
          <div class="input-row">
            <input name="socksUser" id="inb-socks-user" value="${esc(initSocksU)}" required>
            <button type="button" data-action="gen-socks-user">🎲 随机账号</button>
          </div>
        </label>
        <label>
          认证密码 (Password · 18位高强度随机)
          <div class="input-row">
            <input name="socksPassword" id="inb-socks-pass" value="${esc(initSocksP)}" required>
            <button type="button" data-action="gen-clean-pass" data-target="inb-socks-pass">🎲 随机密码</button>
          </div>
        </label>
      `;
      return;
    }

    if (proto === 'anytls') {
      box.innerHTML = `
        <div class="section-title">AnyTLS 认证与 TLS 证书配置 (默认域名: ${esc(defTlsDomain)})</div>
        <label>
          AnyTLS 访问密码
          <div class="input-row">
            <input name="password" id="inb-anytls-pass" value="${esc(item.password || c0.password || genRandomAlnum(20))}" required>
            <button type="button" data-action="gen-clean-pass" data-target="inb-anytls-pass">🎲 随机</button>
          </div>
        </label>
        <label>
          客户端标识 (备注标识)
          <div class="input-row">
            <input name="clientEmail" id="inb-client-email" value="${esc(c0.email || `anytls_${genRandomAlnum(6).toLowerCase()}`)}">
            <button type="button" data-action="gen-client-email">🎲 随机</button>
          </div>
        </label>
        <label>
          选择已管理证书 / SNI 域名
          <select id="inb-cert-select">${certOpts}</select>
        </label>
        <label>
          TLS 域名 (SNI)
          <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || defTlsDomain)}">
        </label>
        <label>
          证书公钥路径
          <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || defCertFile)}" placeholder="自动使用默认证书">
        </label>
        <label>
          证书私钥路径
          <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || defKeyFile)}" placeholder="自动使用默认私钥">
        </label>
      `;
      return;
    }

    if (proto === 'hysteria2') {
      box.innerHTML = `
        <div class="section-title">Hysteria 2 (HY2 UDP) 认证与证书配置 (默认域名: ${esc(defTlsDomain)})</div>
        <label>
          HY2 认证密码
          <div class="input-row">
            <input name="password" id="inb-hy2-pass" value="${esc(item.password || c0.password || genRandomAlnum(20))}" required>
            <button type="button" data-action="gen-clean-pass" data-target="inb-hy2-pass">🎲 随机</button>
          </div>
        </label>
        <label>
          Salamander 混淆密码 (可选)
          <input name="obfsPassword" value="${esc(item.obfsPassword || '')}" placeholder="留空则不开启 obfs">
        </label>
        <label>
          上行带宽限制 (Mbps)
          <input name="upMbps" type="number" value="${esc(item.upMbps ?? 100)}">
        </label>
        <label>
          下行带宽限制 (Mbps)
          <input name="downMbps" type="number" value="${esc(item.downMbps ?? 100)}">
        </label>
        <label>
          选择已管理证书
          <select id="inb-cert-select">${certOpts}</select>
        </label>
        <label>
          TLS SNI 域名
          <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || defTlsDomain)}">
        </label>
        <label>
          证书公钥路径
          <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || defCertFile)}">
        </label>
        <label>
          证书私钥路径
          <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || defKeyFile)}">
        </label>
      `;
      return;
    }

    const sec = item.security || (proto === 'tuic' ? 'tls' : 'reality');
    const trans = item.transport || 'tcp';
    const isUuidProto = ['vless', 'vmess', 'tuic'].includes(proto);

    box.innerHTML = `
      <div class="section-title">${esc(proto.toUpperCase())} 客户端凭据与传输安全</div>
      ${isUuidProto ? `
        <label>
          客户端 UUID (标准 UUID v4 格式)
          <div class="input-row">
            <input name="uuid" id="inb-uuid-input" value="${esc(clientUuidVal)}" required>
            <button type="button" data-action="gen-uuid">🎲 随机 UUID</button>
          </div>
        </label>
      ` : `
        <label>
          Trojan 连接密码
          <div class="input-row">
            <input name="password" id="inb-trojan-pass" value="${esc(item.password || genRandomAlnum(20))}" required>
            <button type="button" data-action="gen-clean-pass" data-target="inb-trojan-pass">🎲 随机</button>
          </div>
        </label>
      `}
      <label>
        客户端备注标识 (Email)
        <div class="input-row">
          <input name="clientEmail" id="inb-client-email" value="${esc(c0.email || `${proto}_${genRandomAlnum(6).toLowerCase()}`)}">
          <button type="button" data-action="gen-client-email">🎲 随机</button>
        </div>
      </label>

      <label>
        传输层协议 (Transport)
        <select name="transport" id="inb-trans-select">
          <option value="tcp"${selected('tcp', trans)}>TCP (Raw)</option>
          <option value="ws"${selected('ws', trans)}>WebSocket (WS)</option>
          <option value="grpc"${selected('grpc', trans)}>gRPC</option>
          <option value="httpupgrade"${selected('httpupgrade', trans)}>HTTPUpgrade</option>
        </select>
      </label>
      <label>
        安全层加密 (Security)
        <select name="security" id="inb-sec-select">
          <option value="reality"${selected('reality', sec)}>Reality (免证书高隐蔽 · 推荐)</option>
          <option value="tls"${selected('tls', sec)}>TLS (默认使用域名证书: ${esc(defTlsDomain)})</option>
          <option value="none"${selected('none', sec)}>无加密 (None · 适合内网中转或外层反代)</option>
        </select>
      </label>

      ${proto === 'vless' ? `
        <label class="wide">
          VLESS 流控 (Flow)
          <select name="flow">
            <option value="xtls-rprx-vision"${selected('xtls-rprx-vision', item.flow)}>xtls-rprx-vision (Reality/TLS TCP 推荐)</option>
            <option value=""${selected('', item.flow)}>无流控 (WS / gRPC / 普通模式)</option>
          </select>
        </label>
      ` : ''}

      <div id="inb-sec-box" class="form-grid wide" style="margin:0"></div>
      <div id="inb-trans-box" class="form-grid wide" style="margin:0"></div>
    `;

    const renderSecAndTrans = () => {
      const curSec = $('#inb-sec-select')?.value || 'none';
      const curTrans = $('#inb-trans-select')?.value || 'tcp';
      const secBox = $('#inb-sec-box');
      const transBox = $('#inb-trans-box');

      if (secBox) {
        if (curSec === 'reality') {
          const r = item.reality || {};
          secBox.innerHTML = `
            <div class="section-title">Reality 伪装与 X25519 密钥对 (默认 Tesla 高可用伪装)</div>
            <label>
              伪装目标预设 (SNI)
              <select id="inb-reality-preset">
                <option value="">— 选择高可用 SNI 预设 —</option>
                ${state.catalog.realityPresets.map((p) => `<option value="${esc(p.serverName)}" data-target="${esc(p.target)}"${selected(p.serverName, r.serverName || 'tesla.com')}>${esc(p.label)}</option>`).join('')}
              </select>
            </label>
            <label>
              伪装域名 (ServerName / SNI)
              <input name="realityServerName" id="inb-reality-sni" value="${esc(r.serverName || 'tesla.com')}" required>
            </label>
            <label>
              握手目标地址 (Handshake Target)
              <input name="realityTarget" id="inb-reality-target" value="${esc(r.target || 'www.tesla.com:443')}" required>
            </label>
            <label>
              ShortIds (十六进制，逗号分隔)
              <input name="realityShortIds" id="inb-reality-sid" value="${esc(Array.isArray(r.shortIds) ? r.shortIds.join(',') : (r.shortIds || '1a2b3c4d'))}">
            </label>
            <label>
              Reality 私钥 (Private Key)
              <div class="input-row">
                <input name="realityPrivateKey" id="inb-reality-priv" value="${esc(r.privateKey || '')}" required>
                <button type="button" data-action="gen-reality-keys">🔑 重新生成</button>
              </div>
            </label>
            <label>
              Reality 客户端公钥 (Public Key)
              <input name="realityPublicKey" id="inb-reality-pub" value="${esc(r.publicKey || '')}" readonly>
            </label>
          `;
        } else if (curSec === 'tls') {
          secBox.innerHTML = `
            <div class="section-title">TLS 证书配置 (已自动绑定域名证书: ${esc(defTlsDomain)})</div>
            <label>
              选择已管理证书
              <select id="inb-cert-select">${certOpts}</select>
            </label>
            <label>
              TLS SNI 域名
              <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || defTlsDomain)}">
            </label>
            <label>
              公钥证书路径
              <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || defCertFile)}">
            </label>
            <label>
              私钥文件路径
              <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || defKeyFile)}">
            </label>
          `;
        } else {
          secBox.innerHTML = '';
        }
      }

      if (transBox) {
        if (curTrans === 'ws' || curTrans === 'httpupgrade') {
          transBox.innerHTML = `
            <div class="section-title">${curTrans.toUpperCase()} 路径与 Host</div>
            <label>路径 (Path)<input name="wsPath" value="${esc(item.wsPath || '/')}"></label>
            <label>伪装 Host (可选)<input name="wsHost" value="${esc(item.wsHost || '')}"></label>
          `;
        } else if (curTrans === 'grpc') {
          transBox.innerHTML = `
            <div class="section-title">gRPC 配置</div>
            <label class="wide">Service Name<input name="grpcServiceName" value="${esc(item.grpcServiceName || 'grpc')}"></label>
          `;
        } else {
          transBox.innerHTML = '';
        }
      }
    };

    renderSecAndTrans();
    $('#inb-sec-select')?.addEventListener('change', renderSecAndTrans);
    $('#inb-trans-select')?.addEventListener('change', renderSecAndTrans);
  };

  const syncInboundNodeDomain = () => {
    const nodeSel = $('#inb-node-select');
    if (!nodeSel) return;
    const opt = nodeSel.options ? nodeSel.options[nodeSel.selectedIndex] : null;
    const nodeDom = opt?.dataset?.domain || '';
    if (nodeDom) {
      item.tlsDomain = nodeDom;
      const domInput = $('#inb-tls-domain');
      if (domInput) domInput.value = nodeDom;
      const matchedCert = (state.certificates || []).find((c) => c.domain === nodeDom);
      if (matchedCert) {
        item.certPath = matchedCert.certPath;
        item.keyPath = matchedCert.keyPath;
        if ($('#inb-cert-path')) $('#inb-cert-path').value = matchedCert.certPath;
        if ($('#inb-key-path')) $('#inb-key-path').value = matchedCert.keyPath;
        if ($('#inb-cert-select')) $('#inb-cert-select').value = matchedCert.domain;
      }
    }
  };

  renderDynamicFields().then(() => { if (!existing) syncInboundNodeDomain(); });
  $('#inb-proto-select')?.addEventListener('change', () => renderDynamicFields().then(() => { if (!existing) syncInboundNodeDomain(); }));
  $('#inb-node-select')?.addEventListener('change', syncInboundNodeDomain);
}

/**
 * Inbound Share Links & Subscription Modal — QR Codes Default to Collapsed (hidden)
 */
function openClientModal(inbound, existingClient = null) {
  const isEdit = Boolean(existingClient);
  const isUuidProto = ['vless', 'vmess', 'tuic'].includes(inbound.protocol);
  const isSocksProto = ['socks', 'mixed', 'http'].includes(inbound.protocol);
  const randUser = `u_${genRandomAlnum(8)}`;
  const randEmail = `${inbound.protocol}_u_${genRandomAlnum(6).toLowerCase()}`;
  const c = existingClient ? JSON.parse(JSON.stringify(existingClient)) : {
    id: isUuidProto ? genUuidClient() : '',
    email: randEmail,
    username: randUser,
    password: genRandomAlnum(20, randUser),
    flow: inbound.protocol === 'vless' ? (inbound.flow || '') : '',
    limitIp: 0,
    limitDevice: 0,
    totalGB: 0,
    expiryTime: 0,
    enable: true
  };
  const totalGbVal = c.totalGB || (c.totalBytes ? Math.round((c.totalBytes / (1024 ** 3)) * 100) / 100 : 0);
  const expiryVal = c.expiryTime && c.expiryTime > 0
    ? new Date(c.expiryTime - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16)
    : '';

  openModal(
    isEdit ? `编辑节点用户 · ${inbound.remark} (:${inbound.port})` : `添加节点新用户 · ${inbound.remark} (:${inbound.port})`,
    isEdit ? `用户: ${c.email}` : `向 [${inbound.remark}] 添加独立客户端用户`,
    `
    <form id="client-form" data-inbound-id="${esc(inbound.id)}" data-client-id="${esc(isEdit ? c.id : '')}" class="form-grid">
      <label>
        客户 / 用户备注名称 (Email / 标识)
        <div class="input-row">
          <input name="email" id="client-modal-email" value="${esc(c.email || '')}" required placeholder="例如: client_01 或 VIP_User">
          <button type="button" data-action="gen-client-modal-email">🎲 随机标识</button>
        </div>
      </label>
      <label style="flex-direction:row;align-items:center;gap:8px;padding-top:22px">
        <input type="checkbox" name="enable" style="width:18px;min-height:18px" ${c.enable !== false ? 'checked' : ''}>
        <span><b>启用该用户</b>（停用后仅断开该用户，不影响同节点下其他用户）</span>
      </label>

      ${isSocksProto ? `
        <label class="wide">
          认证账号 (Username · 与密码独立随机生成)
          <div class="input-row">
            <input name="username" id="client-modal-user" value="${esc(c.username || randUser)}" required>
            <button type="button" data-action="gen-client-modal-user">🎲 随机账号</button>
          </div>
        </label>
      ` : ''}

      ${isUuidProto ? `
        <label class="wide">
          用户专属 UUID
          <div class="input-row">
            <input name="uuid" id="client-modal-uuid" value="${esc(c.id || c.uuid || genUuidClient())}" required>
            <button type="button" data-action="gen-client-modal-uuid">🎲 随机生成 UUID</button>
          </div>
        </label>
      ` : ''}

      ${!isUuidProto || inbound.protocol === 'tuic' ? `
        <label class="wide">
          ${isSocksProto ? '认证密码 (Password · 20位高强度随机)' : '用户专属连接密码 (Password · 20位高强度随机)'}
          <div class="input-row">
            <input name="password" id="client-modal-pass" value="${esc(c.password || genRandomAlnum(20, c.username || c.email))}" required>
            <button type="button" data-action="gen-clean-pass" data-target="client-modal-pass">🎲 随机密码</button>
          </div>
        </label>
      ` : ''}

      <div class="section-title">该用户独立 IP / 设备限制、流量配额与到期时间</div>
      <label>
        该用户限制同时在线 IP 数 (0 = 不限制)
        <input name="limitIp" type="number" min="0" max="1000" value="${esc(c.limitIp || 0)}">
        <small>独立计算该用户的在线 IP 数，不影响同节点其他用户</small>
      </label>
      <label>
        该用户限制同时在线设备数 (0 = 不限制)
        <input name="limitDevice" type="number" min="0" max="2000" value="${esc(c.limitDevice || 0)}">
        <small>超出时仅拦截该用户多出的设备，已在线设备正常使用</small>
      </label>
      <label>
        该用户独立流量配额 (GB，0 = 不限制)
        <input name="totalGB" type="number" min="0" step="0.1" value="${esc(totalGbVal)}">
      </label>
      <label>
        该用户独立到期时间 (留空 = 永久有效)
        <input name="expiryTime" type="datetime-local" value="${esc(expiryVal)}">
      </label>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">${isEdit ? '保存用户设置' : '立即添加用户'}</button>
      </div>
    </form>
    `
  );
}

function openInboundLinksModal(inbound, filterClientId = null) {
  const allLinks = inbound.links || [];
  const links = filterClientId
    ? allLinks.filter((l) => l.clientId === filterClientId || l.clientName === filterClientId)
    : allLinks;
  const subToken = (links[0] && links[0].subId) || inbound.tag || state.settings?.subToken || '';
  const clientSubUrl = getBaseSubscriptionUrl(subToken);
  const allSubUrl = getBaseSubscriptionUrl();
  const allClashUrl = `${allSubUrl}?format=clash`;

  const rows = links.map((l, idx) => {
    const perUserSubUrl = getBaseSubscriptionUrl(l.subId || inbound.tag);
    return `
    <div class="subscription-row">
      <div style="width:100%">
        <b>${esc(l.name)} (用户: ${esc(l.clientName || '默认')} · ${esc(l.protocol.toUpperCase())} :${inbound.port})</b>
        <small style="color:var(--success)">✓ 支持 v2rayN / v2rayNG / Shadowrocket / NekoBox / Mihomo / Sing-box / Hiddify 直接导入或展开扫码</small>
        <code style="white-space:normal;word-break:break-all;display:block;margin-top:4px;padding:8px;background:var(--surface);border:1px solid var(--line);border-radius:8px">${esc(l.uri)}</code>
        ${l.altUri ? `<small style="margin-top:4px">备用兼容链接: <code>${esc(l.altUri)}</code></small>` : ''}
        <small style="margin-top:4px;display:block">该用户独立订阅链接: <code>${esc(perUserSubUrl)}</code></small>
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;width:100%;justify-content:flex-end">
        <button class="primary" data-copy="${esc(l.uri)}">📋 复制节点链接</button>
        <button data-copy="${esc(perUserSubUrl)}">🔗 复制该用户订阅</button>
        <button data-copy="${esc(`${perUserSubUrl}?format=clash`)}">⚡ 复制该用户 Clash 订阅</button>
        ${l.clashYaml ? `<button data-copy="${esc(l.clashYaml)}">复制 Clash YAML</button>` : ''}
        ${l.singboxJson ? `<button data-copy="${esc(l.singboxJson)}">复制 Sing-box JSON</button>` : ''}
        <button data-qr-inline="qr-box-${idx}" data-qr-text="${esc(l.uri)}">📱 展开/收起二维码</button>
      </div>
      <div id="qr-box-${idx}" class="subscription-qr hidden"></div>
    </div>
  `;
  }).join('');

  openModal(
    `节点分享链接、二维码与客户端订阅 · 端口 :${inbound.port}`,
    `${inbound.remark} (${inbound.protocol.toUpperCase()})`,
    `
    <div class="stack">
      <div class="section-title" style="margin-top:0">一、单节点分享链接 (默认收起二维码，点击按钮展开)</div>
      ${rows || '<div class="empty"><b>该入站暂无可用客户端链接</b><span>请检查客户端是否已启用</span></div>'}

      <div class="section-title">二、当前节点专属订阅链接</div>
      <div class="subscription-row">
        <div>
          <b>当前节点专属订阅地址 (Base64 / Clash / Sing-box)</b>
          <code>${esc(clientSubUrl)}</code>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          <button class="primary" data-copy="${esc(clientSubUrl)}">复制 Base64 订阅</button>
          <button data-copy="${esc(`${clientSubUrl}?format=clash`)}">复制 Clash 订阅</button>
          <button data-copy="${esc(`${clientSubUrl}?format=singbox`)}">复制 Sing-box 订阅</button>
          <button data-qr-inline="qr-sub-box" data-qr-text="${esc(clientSubUrl)}">📱 展开/收起订阅二维码</button>
        </div>
        <div id="qr-sub-box" class="subscription-qr hidden"></div>
      </div>

      <div class="section-title">三、全节点聚合订阅地址 (高强度随机安全码防护)</div>
      <div class="subscription-row">
        <div style="width:100%">
          <b>全节点聚合订阅地址 (通用 Base64 & Clash 智能分流)</b>
          <code>${esc(allSubUrl)}</code>
          <small style="margin-top:4px">Clash 智能分流订阅地址: <code>${esc(allClashUrl)}</code></small>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;width:100%;justify-content:flex-end">
          <button class="primary" data-copy="${esc(allSubUrl)}">复制全节点通用订阅</button>
          <button class="primary" data-copy="${esc(allClashUrl)}">复制全节点 Clash 订阅</button>
          <button data-copy="${esc(`${allSubUrl}?format=singbox`)}">复制全节点 Sing-box 订阅</button>
          <button data-qr-inline="qr-all-sub-box" data-qr-text="${esc(allSubUrl)}">📱 展开/收起聚合二维码</button>
          <button data-action="open-aggregate-qr-modal">📱 打开全部节点二维码中心</button>
        </div>
        <div id="qr-all-sub-box" class="subscription-qr hidden">
          <div class="grid-2" style="width:100%;margin-top:4px">
            <div>
              <b style="display:block;font-size:12px;margin-bottom:6px">📱 全节点通用订阅二维码</b>
              ${makeQrSvg(allSubUrl)}
            </div>
            <div>
              <b style="display:block;font-size:12px;margin-bottom:6px">⚡ 全节点 Clash 分流二维码</b>
              ${makeQrSvg(allClashUrl)}
            </div>
          </div>
        </div>
      </div>
    </div>
    `
  );
}

/**
 * Compact All-Nodes Aggregate Subscription & QR Wall Modal
 */
function openAggregateQrModal(filterNodeId = null) {
  if (filterNodeId !== null) {
    state.aggQrNodeFilter = filterNodeId;
  }
  const nf = state.aggQrNodeFilter || 'all';
  const nodes = state.nodes && state.nodes.length ? state.nodes : [{ id: 'node_local', name: '主控本机 (Local Master)', role: 'relay', domain: state.settings?.webDomain || '' }];
  const selectedNodeObj = nf !== 'all' ? nodes.find((n) => n.id === nf) : null;
  const scopeLabel = selectedNodeObj ? `[${selectedNodeObj.name.replace(/\s*\(Local Master\)/, '')}${selectedNodeObj.domain ? ` · ${selectedNodeObj.domain}` : ''}]` : '全部服务器聚合';

  const baseSubUrl = getBaseSubscriptionUrl();
  const allSubUrl = nf !== 'all' ? `${baseSubUrl}?node=${encodeURIComponent(nf)}` : baseSubUrl;
  const clashSubUrl = nf !== 'all' ? `${baseSubUrl}?format=clash&node=${encodeURIComponent(nf)}` : `${baseSubUrl}?format=clash`;
  const singboxSubUrl = nf !== 'all' ? `${baseSubUrl}?format=singbox&node=${encodeURIComponent(nf)}` : `${baseSubUrl}?format=singbox`;

  const allEnabledInbounds = state.inbounds.filter((i) => i.enable !== false && i.protocol !== 'direct');
  const enabledNodes = nf === 'all'
    ? allEnabledInbounds
    : allEnabledInbounds.filter((i) => (i.nodeId || 'node_local') === nf);

  const flatLinks = enabledNodes.flatMap((inb) => (inb.links || []).map((l) => ({ inb, l })));
  const allUrisText = flatLinks.map(({ l }) => l.uri).filter(Boolean).join('\n');

  const allNodeCards = flatLinks
    .map(({ inb, l }, idx) => {
      const ownerNode = nodes.find((n) => n.id === (inb.nodeId || 'node_local'));
      const srvName = (ownerNode?.name || inb.nodeName || '主控本机').replace(/\s*\(Local Master\)/, '');
      const srvDomain = ownerNode?.domain || inb.nodeDomain || ownerNode?.host || '';
      const rolePrefix = ownerNode?.role === 'exit' ? '落地' : '中转';
      return `
      <div class="qr-wall-card">
        <div class="qr-wall-head">
          <strong title="${esc(l.name)}">${esc(l.name)}</strong>
          <span class="tag">${esc(inb.protocol.toUpperCase())} :${inb.port}</span>
        </div>
        <div class="qr-wall-sub" style="display:flex;align-items:center;justify-content:space-between;gap:6px;flex-wrap:wrap">
          <span class="tag ${ownerNode?.role === 'exit' ? 'tls' : 'relay'}" style="font-size:10.5px">🖥 ${rolePrefix}: ${esc(srvName)}${srvDomain ? ` (${esc(srvDomain)})` : ''}</span>
          ${l.clientName ? `<small class="muted">用户: ${esc(l.clientName)}</small>` : ''}
        </div>
        <div class="qr-wall-actions">
          <button class="primary" data-copy="${esc(l.uri)}">📋 复制链接</button>
          <button data-qr-inline="wall-qr-${idx}" data-qr-text="${esc(l.uri)}">📱 展开二维码</button>
        </div>
        <div id="wall-qr-${idx}" class="subscription-qr hidden"></div>
      </div>
    `;
    })
    .join('');

  openModal(
    '全节点聚合订阅与二维码中心 (支持按服务器独立区分)',
    `${scopeLabel} · 共 ${enabledNodes.length} 个启用节点 (${flatLinks.length} 条连接)`,
    `
    <div class="stack">
      <div class="node-filter-bar" style="margin-bottom:4px">
        <span style="font-size:12px;font-weight:750;color:var(--muted);margin-right:4px">🖥 按所属服务器区分订阅与二维码:</span>
        <button type="button" class="filter-pill ${nf === 'all' ? 'active' : ''}" data-action="filter-agg-qr-node" data-node="all">🌐 全部服务器聚合 (${allEnabledInbounds.length})</button>
        ${nodes.filter((n) => n.role !== 'standby').map((n) => {
          const cnt = allEnabledInbounds.filter((i) => (i.nodeId || 'node_local') === n.id).length;
          const rTag = n.role === 'exit' ? '[落地]' : '[中转]';
          return `<button type="button" class="filter-pill ${nf === n.id ? 'active' : ''}" data-action="filter-agg-qr-node" data-node="${esc(n.id)}">${rTag} ${esc(n.name.replace(/\s*\(Local Master\)/, ''))}${n.domain ? ` (${esc(n.domain)})` : ''} (${cnt})</button>`;
        }).join('')}
      </div>

      <div class="section-title" style="margin-top:0">一、聚合订阅链接 — 当前范围：${esc(scopeLabel)} (点击可复制或展开二维码)</div>
      <div class="qr-wall-grid">
        <div class="qr-wall-card">
          <div class="qr-wall-head">
            <strong>通用 Base64 聚合订阅</strong>
            <span class="tag">Base64</span>
          </div>
          <div class="qr-wall-sub">v2rayN / Shadowrocket / v2rayNG / NekoBox</div>
          <code style="font-size:11px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(allSubUrl)}</code>
          <div class="qr-wall-actions">
            <button class="primary" data-copy="${esc(allSubUrl)}">📋 复制通用订阅</button>
            <button data-qr-inline="agg-qr-b64" data-qr-text="${esc(allSubUrl)}">📱 展开二维码</button>
          </div>
          <div id="agg-qr-b64" class="subscription-qr hidden"></div>
        </div>

        <div class="qr-wall-card">
          <div class="qr-wall-head">
            <strong>Clash / Mihomo 智能分流</strong>
            <span class="tag tls">Clash</span>
          </div>
          <div class="qr-wall-sub">内置 AI 专线 / 外贸 Google / 自动测速策略组</div>
          <code style="font-size:11px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(clashSubUrl)}</code>
          <div class="qr-wall-actions">
            <button class="primary" data-copy="${esc(clashSubUrl)}">📋 复制 Clash 订阅</button>
            <button data-qr-inline="agg-qr-clash" data-qr-text="${esc(clashSubUrl)}">📱 展开二维码</button>
          </div>
          <div id="agg-qr-clash" class="subscription-qr hidden"></div>
        </div>

        <div class="qr-wall-card">
          <div class="qr-wall-head">
            <strong>Sing-box JSON 聚合订阅</strong>
            <span class="tag relay">Sing-box</span>
          </div>
          <div class="qr-wall-sub">SFI / SFA / SFM 客户端直接导入</div>
          <code style="font-size:11px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(singboxSubUrl)}</code>
          <div class="qr-wall-actions">
            <button class="primary" data-copy="${esc(singboxSubUrl)}">📋 复制 Sing-box 订阅</button>
            <button data-qr-inline="agg-qr-sb" data-qr-text="${esc(singboxSubUrl)}">📱 展开二维码</button>
          </div>
          <div id="agg-qr-sb" class="subscription-qr hidden"></div>
        </div>
      </div>

      <div class="section-title" style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
        <span>二、单节点独立链接与二维码 (${esc(scopeLabel)} · 共 ${flatLinks.length} 条连接)</span>
        ${allUrisText ? `<button type="button" class="primary" data-copy="${esc(allUrisText)}" style="min-height:28px;padding:4px 10px;font-size:12px">📋 一键复制当前所选全部节点链接 (${flatLinks.length} 条)</button>` : ''}
      </div>
      <div class="qr-wall-grid">
        ${allNodeCards || '<div class="empty" style="grid-column:1/-1"><b>当前所选服务器下暂无已启用的入站节点</b><span>可切换上方服务器筛选标签，或在【入站节点管理】创建节点</span></div>'}
      </div>
    </div>
    `
  );
}

function openOutboundModal(existing = null) {
  const item = existing || {
    remark: '',
    tag: '',
    type: 'shadowsocks',
    server: '',
    port: 8388,
    method: 'aes-128-gcm',
    password: '',
    uuid: '',
    username: '',
    security: 'none',
    transport: 'tcp',
    sni: '',
    publicKey: '',
    shortId: '',
    detour: ''
  };

  const detourOpts = [
    '<option value="">直连发出 (不经过前置链式代理)</option>',
    ...state.outbounds
      .filter((o) => !o.builtin && o.id !== existing?.id)
      .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, item.detour)}>前置代理: ${esc(o.tag)} (${esc(o.remark)})</option>`)
  ].join('');

  const previewJson = JSON.stringify(item.singboxPreview || {
    type: item.type,
    tag: item.tag || 'outbound-1',
    server: item.server || '127.0.0.1',
    server_port: Number(item.port || 443)
  }, null, 2);

  openModal(
    existing ? `编辑出站 (${existing.tag})` : '添加出站规则',
    existing ? `${existing.tag} (${existing.server}:${existing.port})` : '支持直接粘贴节点链接一键解析或切换 Form / JSON 编辑',
    `
    <div class="stack">
      <div class="quick-bar" style="margin-bottom:0;justify-content:space-between">
        <div style="display:flex;gap:8px;align-items:center;flex:1">
          <span style="white-space:nowrap">🔗 链接解析:</span>
          <input id="out-modal-uri-input" placeholder="vmess:// vless:// trojan:// ss:// hysteria2:// anytls:// socks://" style="flex:1;min-height:34px">
          <button type="button" class="primary" data-action="parse-uri-into-outbound-modal">⚡ 解析填入</button>
        </div>
        <div style="display:flex;gap:4px">
          <button type="button" class="primary" id="out-tab-form-btn" data-action="switch-out-tab" data-tab="form">Form 表单</button>
          <button type="button" id="out-tab-json-btn" data-action="switch-out-tab" data-tab="json">JSON 视图</button>
        </div>
      </div>

      <form id="outbound-form" class="form-grid" data-id="${esc(existing?.id || '')}">
        <div id="out-form-pane" class="form-grid wide" style="margin:0">
          <label>
            出站标签 (Tag · 用于路由规则绑定)
            <input name="tag" id="out-f-tag" value="${esc(item.tag)}" placeholder="输入出站节点标签名称" required>
          </label>
          <label>
            出站协议 (Protocol)
            <select name="type" id="out-f-type">
              ${state.catalog.outboundProtocols.filter((p) => !['direct', 'block'].includes(p.id)).map((p) => `<option value="${esc(p.id)}"${selected(p.id, item.type)}>${esc(p.name)}</option>`).join('')}
            </select>
          </label>

          <label>
            落地服务器地址 (IP 或域名)
            <input name="server" id="out-f-server" value="${esc(item.server || '')}" placeholder="输入落地机 IP 或域名" required>
          </label>
          <label>
            落地服务器端口 (Port)
            <input name="port" id="out-f-port" type="number" min="1" max="65535" value="${esc(item.port || 443)}" required>
          </label>

          <label>
            备注说明 (可选)
            <input name="remark" id="out-f-remark" value="${esc(item.remark)}" placeholder="默认与标签 Tag 相同">
          </label>
          <label>
            前置链式代理 (Detour 多跳中转)
            <select name="detour" id="out-f-detour">${detourOpts}</select>
          </label>

          <div class="section-title">凭据与加密参数 (按所选协议填写对应项)</div>
          <label>
            密码 / 密钥 (SS / HY2 / AnyTLS / Trojan / SOCKS5)
            <input name="password" id="out-f-password" value="${esc(item.password || '')}" placeholder="连接密码或 Base64 密钥">
          </label>
          <label>
            Shadowsocks 加密方式
            <select name="method" id="out-f-method">
              ${state.catalog.ssMethods.map((m) => `<option value="${esc(m.id)}"${selected(m.id, item.method)}>${esc(m.label)}</option>`).join('')}
            </select>
          </label>

          <label>
            UUID (VLESS / VMess / TUIC)
            <input name="uuid" id="out-f-uuid" value="${esc(item.uuid || '')}" placeholder="标准 UUID">
          </label>
          <label>
            SOCKS5 / HTTP 用户名 (可选)
            <input name="username" id="out-f-username" value="${esc(item.username || '')}" placeholder="用户名">
          </label>

          <div class="section-title">TLS / Reality / 传输层参数 (可选)</div>
          <label>
            传输安全 (Security)
            <select name="security" id="out-f-security">
              <option value="none"${selected('none', item.security)}>无 (None · SS/SOCKS/明文)</option>
              <option value="tls"${selected('tls', item.security)}>TLS (AnyTLS / HY2 / Trojan / VLESS-TLS)</option>
              <option value="reality"${selected('reality', item.security)}>Reality (VLESS Reality 落地)</option>
            </select>
          </label>
          <label>
            传输协议 (Transport)
            <select name="transport" id="out-f-transport">
              <option value="tcp"${selected('tcp', item.transport)}>TCP / QUIC 原生</option>
              <option value="ws"${selected('ws', item.transport)}>WebSocket (WS)</option>
              <option value="grpc"${selected('grpc', item.transport)}>gRPC</option>
            </select>
          </label>
          <label>
            SNI 域名 (Server Name)
            <input name="sni" id="out-f-sni" value="${esc(item.sni || '')}" placeholder="TLS 或 Reality 的 SNI">
          </label>
          <label>
            Reality 公钥 (Public Key) / ShortId
            <div class="input-row">
              <input name="publicKey" id="out-f-pbk" value="${esc(item.publicKey || '')}" placeholder="pbk 公钥">
              <input name="shortId" id="out-f-sid" value="${esc(item.shortId || '')}" placeholder="sid" style="max-width:100px">
            </div>
          </label>

          <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" name="insecure" id="out-f-insecure" style="width:16px;min-height:16px" ${item.insecure ? 'checked' : ''}>
            <span>跳过落地节点 TLS 证书校验 (insecure=true，当落地节点使用自签证书时勾选)</span>
          </label>
        </div>

        <div id="out-json-pane" class="wide hidden">
          <label>
            Sing-box 出站 JSON 配置 (可直接查看或编辑)
            <textarea id="out-json-textarea" style="min-height:260px">${esc(previewJson)}</textarea>
          </label>
        </div>

        <div class="form-actions">
          <button type="button" data-close>取消</button>
          <button type="submit" class="primary">确定保存出站规则</button>
        </div>
      </form>
    </div>
    `
  );

  const outTagInput = $('#out-f-tag');
  const outRemInput = $('#out-f-remark');
  if (outTagInput && outRemInput) {
    let lastAutoOutTag = outTagInput.value.trim();
    outTagInput.addEventListener('input', () => {
      const curRem = outRemInput.value.trim();
      if (!curRem || curRem === lastAutoOutTag) {
        outRemInput.value = outTagInput.value.trim();
      }
      lastAutoOutTag = outTagInput.value.trim();
    });
  }
}

function isAutoRuleRemark(remark) {
  const s = String(remark || '').trim();
  return !s || /^入站转发\s*[:：]/.test(s) || /^分流规则(\s*#\d+)?(\s*\([^)]*\))?$/.test(s);
}

function buildAutoRuleRemark(inboundRaw, outboundTag) {
  const inbs = (Array.isArray(inboundRaw) ? inboundRaw : String(inboundRaw || '').split(',')).map((s) => s.trim()).filter(Boolean);
  const out = String(outboundTag || 'direct').trim();
  if (inbs.length > 0) {
    return `入站转发: ${inbs.join(', ')} ➔ ${out}`;
  }
  return `分流规则 (${out})`;
}


function openClusterNodeModal(existing = null, defaultRole = 'relay') {
  const n = existing || {
    name: defaultRole === 'exit' ? '美国原生落地机 01' : (defaultRole === 'standby' ? '亚太热备容灾机 S1' : '香港 CMI 专线中转 01'),
    role: defaultRole,
    host: '',
    agentPort: 19090,
    domain: '',
    region: defaultRole === 'exit' ? 'US' : 'HK',
    isp: '',
    standbyNodeId: '',
    mirrorStandby: true,
    cfApiToken: '',
    cfZoneId: '',
    cfRecordName: '',
    exitConfig: {
      enabled: defaultRole === 'exit' || defaultRole === 'hybrid',
      port: 28388,
      method: '2022-blake3-aes-128-gcm',
      password: ''
    }
  };
  const sortedCandidates = [...(state.nodes || [])]
    .filter((x) => x.id !== n.id && !x.isLocal && x.role !== 'exit')
    .sort((a, b) => (a.role === 'standby' ? -1 : 1) - (b.role === 'standby' ? -1 : 1));
  const standbyChoices = sortedCandidates
    .map((x) => {
      const rBadge = x.role === 'standby' ? '【热备容灾机·推荐】' : '【中转机兼备机】';
      return `<option value="${esc(x.id)}"${selected(x.id, n.standbyNodeId)}>${rBadge} ${esc(x.name)} (${esc(x.host)})</option>`;
    })
    .join('');

  const safeZoneId = /^[a-f0-9]{32}$/i.test(String(n.cfZoneId || '').trim()) ? String(n.cfZoneId).trim() : '';
  const showRelaySection = n.role === 'relay' || n.role === 'hybrid';
  const showExitSection = n.role === 'exit' || n.role === 'hybrid';

  openModal(
    existing ? '编辑集群服务器节点' : '添加集群服务器 (中转机 / 落地机 / 热备容灾机)',
    existing ? n.name : '一主控统管：中转机绑定独立域名，落地机免域名自动开启 SS 加入全局共享池',
    `
    <form id="cluster-node-form" class="form-grid" data-id="${esc(existing?.id || '')}" autocomplete="off">
      <div class="wide" style="padding:10px 13px;border-radius:10px;background:var(--surface-soft);border:1px solid var(--line);font-size:12.5px;line-height:1.6">
        💡 <b>新机器接入说明</b>：添加未安装 3x-ui / NexusGate 的新机器时，保存后直接点击卡片上的「<b>📋 复制 Agent 命令</b>」到新机器 SSH 执行即可（无需在子机器重复安装面板，SSL 证书也由主控统一签发并自动同步下发到子机器）。
      </div>
      <label>
        服务器备注名称
        <input name="name" value="${esc(n.name)}" placeholder="例如：香港 CMI 中转 01 / 美国原生落地 01" autocomplete="off" required>
      </label>
      <label>
        服务器角色类型
        <select name="role" id="cluster-role-select">
          <option value="relay"${selected('relay', n.role)}>中转入口机 (Relay · 绑定各自独立域名承载客户)</option>
          <option value="exit"${selected('exit', n.role)}>纯落地机 (Exit · 免域名纯IP，自动开启SS加入全局共享落地池)</option>
          <option value="hybrid"${selected('hybrid', n.role)}>中转 + 落地一体机 (Hybrid · 兼具入口与共享SS落地)</option>
          <option value="standby"${selected('standby', n.role)}>热备容灾机 (Standby · 主力中转故障时秒级接管)</option>
        </select>
      </label>
      <label>
        服务器公网 IP (IPv4 / IPv6)
        <input name="host" value="${esc(n.host)}" placeholder="填写该机器公网 IP，如 103.88.12.66" autocomplete="off" required>
      </label>
      <label>
        Agent 通信端口
        <input name="agentPort" type="number" value="${esc(n.agentPort || 19090)}" autocomplete="off" required>
      </label>

      <div id="cluster-domain-wrap" class="form-grid wide" style="margin:0;${showRelaySection ? '' : 'display:none'}">
        <label class="wide">
          中转机专属域名 (中转机请填写各自绑定的域名，客户端订阅自动匹配该域名)
          <input name="domain" value="${esc(n.domain || '')}" placeholder="例如：cs.vponlive.com" autocomplete="off">
        </label>
      </div>

      <div id="cluster-exit-ss-wrap" class="form-grid wide" style="margin:0;${showExitSection ? '' : 'display:none'}">
        <div class="section-title">落地机自动开启共享 SS 与落地容错配置 (仅当角色为「纯落地机」或「一体机」时生效)</div>
        <label>
          落地 Shadowsocks 监听端口
          <input name="exitPort" type="number" value="${esc(n.exitConfig?.port || 28388)}" placeholder="28388" autocomplete="off">
        </label>
        <label>
          落地 Shadowsocks 加密方式
          <select name="exitMethod">
            <option value="2022-blake3-aes-128-gcm"${selected('2022-blake3-aes-128-gcm', n.exitConfig?.method)}>2022-blake3-aes-128-gcm (极速推荐)</option>
            <option value="2022-blake3-aes-256-gcm"${selected('2022-blake3-aes-256-gcm', n.exitConfig?.method)}>2022-blake3-aes-256-gcm</option>
            <option value="aes-256-gcm"${selected('aes-256-gcm', n.exitConfig?.method)}>aes-256-gcm</option>
            <option value="aes-128-gcm"${selected('aes-128-gcm', n.exitConfig?.method)}>aes-128-gcm</option>
            <option value="chacha20-ietf-poly1305"${selected('chacha20-ietf-poly1305', n.exitConfig?.method)}>chacha20-ietf-poly1305</option>
          </select>
        </label>
        <label>
          落地 Shadowsocks 密码 (选填，留空自动生成高强度密钥)
          <input name="exitPassword" value="${esc(n.exitConfig?.password || '')}" placeholder="留空自动生成标准高强度 SS 密钥" autocomplete="off">
        </label>
        <label>
          绑定备用容错落地机 (当本落地机故障时，自动将所有中转流量无缝切至备用落地机)
          <select name="fallbackExitNodeId">
            <option value="">暂不绑定备用落地机 (当集群 ≥2 台落地机时会自动生成高可用池 exit-ha-pool)</option>
            ${(state.nodes || []).filter((x) => x.id !== n.id && (x.role === 'exit' || x.role === 'hybrid')).map((x) => `<option value="${esc(x.id)}"${selected(x.id, n.fallbackExitNodeId)}>【备用落地】${esc(x.name)} (${esc(x.host)}:${x.exitConfig?.port || 28388})</option>`).join('')}
          </select>
        </label>
      </div>

      <div id="cluster-failover-cf-wrap" class="form-grid wide" style="margin:0;${showRelaySection ? '' : 'display:none'}">
        <div class="section-title">断线自动容灾守护、省流热备同步与 Cloudflare DNS 自动换 IP</div>
        <label>
          绑定备用容灾机 (Standby Node)
          <select name="standbyNodeId">
            <option value="">暂不绑定备用机 (请先添加一台角色为「热备容灾机」的节点)</option>
            ${standbyChoices}
          </select>
        </label>
        <label>
          热备机数据同步策略 (解决流量消耗与同步时机)
          <select name="standbySyncMode">
            <option value="on_change"${selected('on_change', n.standbySyncMode || (n.mirrorStandby === false ? 'on_failover' : 'on_change'))}>⚡ 变更触发同步 (强烈推荐 · 仅在新增/改节点时同步一次，平时 0 流量，故障 0 秒接管)</option>
            <option value="daily"${selected('daily', n.standbySyncMode)}>🕒 每日定时自动备份 (每天自动同步一次到备用机，故障切换瞬间自动补齐)</option>
            <option value="on_failover"${selected('on_failover', n.standbySyncMode)}>🛡 仅故障切换时按需下发 (平时不预热备用机，触发容灾瞬间再下发配置与证书)</option>
          </select>
        </label>
        <label>
          断线容灾切换模式 (支持纯手动一键切换，或设定断线超时自动切换)
          <select name="autoFailoverMinutes" id="cluster-autofo-mode-select">
            <option value="0"${selected('0', String(n.autoFailover === false ? '0' : (n.autoFailoverMinutes || 3)))}>🔒 仅手动切换模式 (关闭自动切换 · 平时绝不自动动IP，需要时由人工点击【⚡一键容灾切换】)</option>
            <option value="1"${selected('1', String(n.autoFailover === false ? '0' : (n.autoFailoverMinutes || 3)))}>⚡ 自动模式：连续断线 1 分钟自动切换 (极速敏感)</option>
            <option value="2"${selected('2', String(n.autoFailover === false ? '0' : (n.autoFailoverMinutes || 3)))}>⚡ 自动模式：连续断线 2 分钟自动切换</option>
            <option value="3"${selected('3', String(n.autoFailover === false ? '0' : (n.autoFailoverMinutes || 3)))}>⚡ 自动模式：连续断线 3 分钟自动切换 (推荐 · 双重探测防网络抖动误判)</option>
            <option value="5"${selected('5', String(n.autoFailover === false ? '0' : (n.autoFailoverMinutes || 3)))}>⚡ 自动模式：连续断线 5 分钟自动切换</option>
            <option value="10"${selected('10', String(n.autoFailover === false ? '0' : (n.autoFailoverMinutes || 3)))}>⚡ 自动模式：连续断线 10 分钟自动切换</option>
            <option value="15"${selected('15', String(n.autoFailover === false ? '0' : (n.autoFailoverMinutes || 3)))}>⚡ 自动模式：连续断线 15 分钟自动切换</option>
          </select>
        </label>
        <label>
          该机独立 Cloudflare API Token (选填 · 多 CF 账号专用)
          <input name="cfApiToken" type="text" autocomplete="off" spellcheck="false" style="-webkit-text-security:disc" value="${esc(n.cfApiToken || '')}" placeholder="留空则默认使用集群页面的全局 CF Token">
        </label>
        <label class="wide">
          Cloudflare Zone ID (强烈建议留空！系统会根据上方填写的「中转机专属域名」自动查询匹配的 Zone ID，多个域名无需手动查填)
          <input name="cfZoneId" type="text" autocomplete="off" spellcheck="false" value="${esc(safeZoneId)}" placeholder="留空即可全自动按域名识别 Zone ID (无需填)">
        </label>
        <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
          <input type="checkbox" name="autoFailback" style="width:16px;min-height:16px" ${n.autoFailback ? 'checked' : ''}>
          <span><b>开启主力机恢复自动回切 (Auto Failback)</b>：当主力中转机恢复在线后，自动将流量与 Cloudflare DNS 解析切回主力机（不勾选则保持在备用机，由你确认稳定后再手动点击回切）</span>
        </label>
      </div>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">${existing ? '保存修改' : '立即添加服务器'}</button>
      </div>
    </form>
    `
  );

  const roleSel = $('#cluster-role-select');
  const nameInp = $('#cluster-node-form input[name="name"]');
  const domainWrap = $('#cluster-domain-wrap');
  const exitSsWrap = $('#cluster-exit-ss-wrap');
  const failoverWrap = $('#cluster-failover-cf-wrap');

  const syncRoleVisibility = () => {
    const curRole = roleSel ? roleSel.value : 'relay';
    const isRelayLike = curRole === 'relay' || curRole === 'hybrid';
    const isExitLike = curRole === 'exit' || curRole === 'hybrid';
    if (domainWrap) domainWrap.style.display = isRelayLike ? '' : 'none';
    if (exitSsWrap) exitSsWrap.style.display = isExitLike ? '' : 'none';
    if (failoverWrap) failoverWrap.style.display = isRelayLike ? '' : 'none';
    if (!existing && nameInp) {
      if (curRole === 'exit' && (nameInp.value.includes('中转') || nameInp.value.includes('热备'))) {
        nameInp.value = '美国原生落地机 01';
      } else if (curRole === 'relay' && (nameInp.value.includes('落地') || nameInp.value.includes('热备'))) {
        nameInp.value = '香港 CMI 专线中转 01';
      } else if (curRole === 'standby' && (nameInp.value.includes('中转') || nameInp.value.includes('落地'))) {
        nameInp.value = '亚太热备容灾机 S1';
      }
    }
  };

  if (roleSel) {
    roleSel.addEventListener('change', syncRoleVisibility);
    syncRoleVisibility();
  }
}

function openFailoverModal(primaryNode) {
  const candidates = (state.nodes || []).filter((x) => x.id !== primaryNode.id);
  const opts = candidates.map((x) => `<option value="${esc(x.id)}"${selected(x.id, primaryNode.standbyNodeId)}>${esc(x.name)} (${esc(x.host)} · ${x.role === 'standby' ? '热备机' : '集群节点'})</option>`).join('');
  openModal(
    '⚡ 一键容灾切换 (热备接管 + Cloudflare DNS 漂移)',
    `主力机 [${primaryNode.name}] ➔ 备用机秒级接管`,
    `
    <form id="failover-form" class="form-grid" data-primary-id="${esc(primaryNode.id)}">
      <div class="wide" style="padding:12px;border-radius:10px;background:var(--warning-soft);color:var(--warning);font-size:12.5px">
        <b>容灾原理说明</b>：执行切换后，主控将立即把 <b>${esc(primaryNode.name)}</b> 下辖的 <b>${primaryNode.inboundsCount || 0} 个入站节点</b>、对应的落地转发规则及 <b>SSL 域名证书</b> 全量推送到所选备用机，并调用 Cloudflare API 将 <code>${esc(primaryNode.domain || primaryNode.host)}</code> 的解析 IP 切换为备用机 IP，客户端零感知、无需改任何配置！
      </div>
      <label class="wide">
        选择接管流量的目标备用机
        <select name="standbyNodeId" required>
          ${opts || '<option value="">请先添加至少一台备用机节点</option>'}
        </select>
      </label>
      <label class="wide">
        切换原因备注
        <input name="reason" value="主力中转机线路维护/故障，切换至热备机接管">
      </label>
      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">⚡ 立即执行容灾接管与 DNS 切换</button>
      </div>
    </form>
    `
  );
}

function openRuleModal(existing = null) {
  const defaultOut = state.outbounds.find((o) => !o.builtin)?.tag || 'direct';
  const r = existing ? {
    ...existing,
    remark: isAutoRuleRemark(existing.remark)
      ? buildAutoRuleRemark(existing.inbound, existing.outbound || defaultOut)
      : existing.remark
  } : {
    remark: '',
    inbound: [],
    user: [],
    domain: [],
    domain_suffix: [],
    domain_keyword: [],
    ip_cidr: [],
    source_ip_cidr: [],
    port: [],
    source_port: [],
    protocol: [],
    network: '',
    rule_set: [],
    ip_is_private: false,
    outbound: defaultOut
  };

  const outboundOpts = state.outbounds
    .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, r.outbound)}>${esc(o.tag)}${o.server ? ` (${o.server}:${o.port})` : ` (${o.remark})`}</option>`)
    .join('');

  const inboundChecks = state.inbounds.map((i) => {
    const isChecked = (r.inbound || []).includes(i.tag) ? 'checked' : '';
    return `<label style="flex-direction:row;align-items:center;gap:6px;font-weight:500"><input type="checkbox" name="inbound_check" value="${esc(i.tag)}" style="width:15px;min-height:15px" ${isChecked}><span><code>${esc(i.tag)}</code> (${esc(i.remark)} :${i.port})</span></label>`;
  }).join('');

  openModal(
    existing ? '编辑路由规则' : '添加路由规则',
    existing ? (r.remark || `规则 -> ${r.outbound}`) : '配置入站转发映射或域名/IP分流规则',
    `
    <form id="rule-form" class="form-grid" data-id="${esc(existing?.id || '')}">
      <label class="wide">
        适用服务器范围 (可将此分流/转发规则限定在某一台特定中转机，或设为全部中转机通用)
        <select name="nodeId" id="rule-node-select">
          <option value=""${selected('', r.nodeId || (state.routingNodeFilter !== 'all' && state.routingNodeFilter !== 'global' ? state.routingNodeFilter : ''))}>🌐 全部中转机通用 (或按所选入站标签自动归属对应中转机)</option>
          ${(state.nodes || []).filter((n) => n.role !== 'standby').map((n) => `<option value="${esc(n.id)}"${selected(n.id, r.nodeId || (state.routingNodeFilter !== 'all' && state.routingNodeFilter !== 'global' ? state.routingNodeFilter : ''))}>🖥 仅在 [${esc(n.name)}${n.domain ? ` · ${esc(n.domain)}` : ''}] 上生效</option>`).join('')}
        </select>
      </label>
      <label class="wide">
        选择要转发的入站标签 (Inbound Tags · 可多选)
        <div class="rule-inbound-checks">
          ${inboundChecks || '<span class="muted">当前尚无入站节点，也可以在下方手动输入入站 Tag</span>'}
        </div>
        <input name="inbound" value="${esc((r.inbound || []).join(', '))}" placeholder="或手动输入入站标签，逗号分隔" style="margin-top:4px">
      </label>

      <label>
        目标出站标签 (Outbound Tag)
        <select name="outbound">${outboundOpts}</select>
      </label>
      <label>
        规则备注 (可选)
        <input name="remark" value="${esc(r.remark)}" placeholder="留空自动按 入站 ➔ 出站 生成">
      </label>

      <div class="section-title">高级匹配条件 (一对一中转无需填写以下项，留空即转发该入站全部流量)</div>
      <label>
        来源 IP (Source IPs)
        <input name="source_ip_cidr" value="${esc((r.source_ip_cidr || []).join(', '))}" placeholder="e.g. 0.0.0.0/8, fc00::/7">
      </label>
      <label>
        来源端口 (Source Port)
        <input name="source_port" value="${esc((r.source_port || []).join(', '))}" placeholder="e.g. 53,443,1000-2000">
      </label>

      <label>
        网络 (Network L4)
        <select name="network">
          <option value=""${selected('', r.network)}>TCP + UDP (不限)</option>
          <option value="tcp"${selected('tcp', r.network)}>TCP</option>
          <option value="udp"${selected('udp', r.network)}>UDP</option>
        </select>
      </label>
      <label>
        嗅探协议 (Protocol，逗号分隔)
        <input name="protocol" value="${esc((r.protocol || []).join(', '))}" placeholder="http, tls, bittorrent, quic">
      </label>

      <label>
        目标 IP (IP / GeoIP)
        <input name="ip_cidr" value="${esc((r.ip_cidr || []).join(', '))}" placeholder="e.g. geoip:cn, 1.1.1.0/24">
      </label>
      <label>
        目标域名后缀 (Domain Suffix / Geosite)
        <input name="domain" value="${esc([...(r.domain || []), ...(r.domain_suffix || [])].join(', '))}" placeholder="e.g. openai.com, google.com, geosite:openai">
      </label>

      <label>
        目标端口 (Port)
        <input name="port" value="${esc((r.port || []).join(', '))}" placeholder="e.g. 53, 443, 1000-2000">
      </label>
      <label>
        客户/用户 (User Email)
        <input name="user" value="${esc((r.user || []).join(', '))}" placeholder="可选，按客户端标识匹配">
      </label>

      <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
        <input type="checkbox" name="ip_is_private" style="width:16px;min-height:16px" ${r.ip_is_private ? 'checked' : ''}>
        <span>匹配私有内网 IP 地址 (geoip:private / ip_is_private)</span>
      </label>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">保存路由规则</button>
      </div>
    </form>
    `
  );

  const ruleForm = $('#rule-form');
  const inboundInput = $('input[name="inbound"]', ruleForm);
  const outboundSelect = $('select[name="outbound"]', ruleForm);
  const remarkInput = $('input[name="remark"]', ruleForm);
  if (remarkInput) {
    remarkInput.dataset.customRemark = (existing && !isAutoRuleRemark(existing.remark)) ? '1' : '';
    remarkInput.addEventListener('input', () => {
      remarkInput.dataset.customRemark = isAutoRuleRemark(remarkInput.value) ? '' : '1';
    });
  }

  const syncRuleRemarkLive = () => {
    if (!remarkInput || remarkInput.dataset.customRemark === '1') return;
    const curInb = inboundInput ? inboundInput.value : '';
    const curOut = outboundSelect ? outboundSelect.value : 'direct';
    const hasInb = curInb.split(',').map((s) => s.trim()).filter(Boolean).length > 0;
    if (existing || hasInb || remarkInput.value.trim()) {
      const nextRem = buildAutoRuleRemark(curInb, curOut);
      remarkInput.value = nextRem;
      if (existing && $('#modal-title')) {
        $('#modal-title').textContent = nextRem;
      }
    }
  };

  $$('input[name="inbound_check"]', ruleForm).forEach((cb) => {
    cb.addEventListener('change', () => {
      const checkedVals = $$('input[name="inbound_check"]:checked', ruleForm).map((x) => x.value);
      if (inboundInput) inboundInput.value = checkedVals.join(', ');
      syncRuleRemarkLive();
    });
  });

  if (inboundInput) {
    inboundInput.addEventListener('input', () => {
      const typedSet = new Set(inboundInput.value.split(',').map((s) => s.trim()).filter(Boolean));
      $$('input[name="inbound_check"]', ruleForm).forEach((cb) => {
        cb.checked = typedSet.has(cb.value);
      });
      syncRuleRemarkLive();
    });
  }

  if (outboundSelect) {
    outboundSelect.addEventListener('change', syncRuleRemarkLive);
  }
}

/* ==================== EVENT DELEGATION ==================== */

document.addEventListener('click', async (e) => {
  const closeBtn = e.target.closest('[data-close]');
  if (closeBtn) { closeModal(); return; }

  const themeBtn = e.target.closest('[data-theme-toggle]');
  if (themeBtn) {
    setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    return;
  }

  const navBtn = e.target.closest('#nav button[data-page]');
  if (navBtn) { setPage(navBtn.dataset.page); return; }

  const copyBtn = e.target.closest('[data-copy]');
  if (copyBtn) { copyText(copyBtn.dataset.copy, '链接/配置'); return; }

  const qrBtn = e.target.closest('[data-qr]');
  if (qrBtn) {
    const text = qrBtn.dataset.qr;
    const svg = makeQrSvg(text);
    openModal('客户端扫码导入', '使用 Shadowrocket / v2rayNG / NekoBox / Sing-box / Clash 扫码', `
      <div class="subscription-qr">${svg || '<p class="muted">二维码生成中</p>'}<p class="muted" style="margin-top:10px;font-size:11px;word-break:break-all">${esc(text)}</p></div>
    `);
    return;
  }

  const qrInlineBtn = e.target.closest('[data-qr-inline]');
  if (qrInlineBtn) {
    const box = $(`#${qrInlineBtn.dataset.qrInline}`);
    if (box) {
      box.classList.toggle('hidden');
      if (!box.classList.contains('hidden') && !box.innerHTML.trim() && qrInlineBtn.dataset.qrText) {
        box.innerHTML = makeQrSvg(qrInlineBtn.dataset.qrText);
      }
    }
    return;
  }

  const actEl = e.target.closest('[data-action]');
  if (!actEl) return;
  const action = actEl.dataset.action;

  try {
    if (action === 'jump-migrate') { setPage('migrate'); }

    else if (action === 'jump-settings') {
      setPage('settings');
    }
    else if (action === 'push-master-ha-sync') {
      const form = $('#settings-form');
      const standbyMasterUrl = form ? (form.querySelector('[name="standbyMasterUrl"]')?.value || '').trim() : (state.settings?.standbyMasterUrl || '');
      const masterHaSecret = form ? (form.querySelector('[name="masterHaSecret"]')?.value || '').trim() : (state.settings?.masterHaSecret || '');
      if (!standbyMasterUrl) {
        toast('请先在《面板设置与安全》填写「备用主控面板地址 (standbyMasterUrl)」', true);
        setPage('settings');
        return;
      }
      toast('正在打包全量主控状态 (.zip) 并加密同步至备用主控...');
      const res = await api('/api/ha/push-sync', {
        method: 'POST',
        body: JSON.stringify({ standbyMasterUrl, masterHaSecret })
      });
      toast(`✅ 已成功将全量数据 (${fmtBytes(res.zipBytes || 0)}) 1:1 同步至备用主控！`);
      load(state.page, { silent: true });
    }
    else if (action === 'trigger-master-ha-takeover') {
      const res = await api('/api/ha/takeover', {
        method: 'POST',
        body: JSON.stringify({})
      });
      toast(`⚡ 备用主控已成功接管全集群！(${res.dns?.message || '已激活为主力主控'})`);
      load(state.page, { silent: true });
    }

    else if (action === 'jump-cluster') { setPage('cluster'); }
    else if (action === 'jump-guide') { setPage('guide'); }
    else if (action === 'filter-routing-node') {
      state.routingNodeFilter = actEl.dataset.node || 'all';
      render();
    }
    else if (action === 'test-node-cf') {
      const nodeId = actEl.dataset.id;
      const cfApiToken = $('#cluster-cf-token')?.value.trim() || state.settings?.cfApiToken || '';
      toast('🔍 正在连接 Cloudflare API 检测域名与 Zone ID...');
      const res = await api(`/api/cluster/nodes/${encodeURIComponent(nodeId)}/test-cf`, {
        method: 'POST',
        body: JSON.stringify({ cfApiToken })
      });
      toast(res.message || '✅ Cloudflare DNS API 验证成功！', res.ok === false);
      load(state.page, { silent: true });
    }
    else if (action === 'add-cluster-node') {
      openClusterNodeModal(null, actEl.dataset.role || 'relay');
    }
    else if (action === 'edit-cluster-node') {
      const node = (state.nodes || []).find((x) => x.id === actEl.dataset.id);
      if (node) openClusterNodeModal(node, node.role || 'relay');
    }
    else if (action === 'delete-cluster-node') {
      if (!ngConfirm('确认从集群中移除该服务器节点吗？')) return;
      await api(`/api/cluster/nodes/${encodeURIComponent(actEl.dataset.id)}`, { method: 'DELETE' });
      state.nodes = (state.nodes || []).filter((x) => x.id !== actEl.dataset.id);
      toast('已移除集群服务器节点');
      render();
      load(state.page, { silent: true });
    }
    else if (action === 'sync-cluster-node') {
      const res = await api(`/api/cluster/nodes/${encodeURIComponent(actEl.dataset.id)}/sync`, { method: 'POST' });
      toast(`✅ 节点配置与证书已下发同步 (Hash: ${res.configHash} · 入站 ${res.inboundsCount} 个)`);
      load(state.page, { silent: true });
    }
    else if (action === 'preview-node-config') {
      const res = await api(`/api/cluster/nodes/${encodeURIComponent(actEl.dataset.id)}/config`);
      const jsonStr = JSON.stringify(res.singboxConfig, null, 2);
      openModal(`节点专属 Sing-box 配置 (${res.nodeName})`, `Config Hash: ${res.configHash} · 证书 ${res.certificates?.length || 0} 张`, `
        <div class="stack">
          <div class="codebox">${esc(jsonStr)}</div>
          <div style="display:flex;justify-content:flex-end"><button class="primary" data-copy="${esc(jsonStr)}">复制该服务器专属 config.json</button></div>
        </div>
      `);
    }
    else if (action === 'open-failover-modal') {
      const node = (state.nodes || []).find((x) => x.id === actEl.dataset.id);
      if (node) openFailoverModal(node);
    }
    else if (action === 'trigger-failback') {
      if (!ngConfirm('确认主力中转机已恢复正常，并将流量与 Cloudflare DNS 解析切回主力机吗？')) return;
      const res = await api('/api/cluster/failback', {
        method: 'POST',
        body: JSON.stringify({ primaryNodeId: actEl.dataset.id })
      });
      toast(`✓ 已完成回切: ${res.dns?.message || '流量已切回主力中转机'}`);
      load('cluster');
    }
    else if (action === 'filter-node') {
      state.nodeFilter = actEl.dataset.node || 'all';
      render();
    }
    else if (action === 'Filter-node-inbounds') {
      state.nodeFilter = actEl.dataset.node || 'all';
      setPage('inbounds');
    }
    else if (action === 'run-cluster-health-check') {
      toast('🛡 正在巡检全集群节点连通性与自动容灾状态...');
      const res = await api('/api/cluster/health-check', { method: 'POST', body: JSON.stringify({}) });
      if (res.actionsCount > 0) {
        toast(`⚡ 自动容灾巡检完成：已自动执行 ${res.actionsCount} 项故障接管/回切动作！`);
      } else {
        toast('✅ 全集群巡检完成：所有中转机与落地机运行正常，无需触发容灾切换');
      }
      load('cluster');
    }
    else if (action === 'sync-all-cluster') {
      const res = await api('/api/cluster/sync-all', { method: 'POST' });
      toast(`✅ 已向集群全部 ${res.count || 1} 台服务器同步下发最新配置与证书`);
      load('cluster');
    }
    else if (action === 'save-cluster-cf') {
      const cfApiToken = $('#cluster-cf-token')?.value.trim() || '';
      await api('/api/settings', { method: 'PUT', body: JSON.stringify({ cfApiToken }) });
      state.settings.cfApiToken = cfApiToken;
      toast('✅ Cloudflare 自动容灾 API Token 已保存');
      render();
    }
    else if (action === 'Switch-to-outbounds') { setPage('outbounds'); }
    else if (action === 'Switch-to-routing') { setPage('routing'); }
    else if (action === 'filter-proto') {
      state.protoFilter = actEl.dataset.proto || 'all';
      render();
    }
    else if (action === 'batch-inbounds') {
      const batchAct = actEl.dataset.batch;
      if (batchAct === 'reset-all-traffic' && !ngConfirm('确定要一键清零全部入站节点的已用流量吗？')) return;
      const res = await api('/api/inbounds/batch', {
        method: 'POST',
        body: JSON.stringify({ action: batchAct })
      });
      toast(`批量操作已完成 (共处理 ${res.count || 0} 个节点)`);
      load('inbounds');
    }
    else if (action === 'cleanup-system-memory') {
      const res = await api('/api/system/cleanup', { method: 'POST' });
      if (state.overview && res.system) state.overview.system = res.system;
      toast(`🧹 已完成日志清理与内存释放 (${(res.result?.actions || []).join(', ')})`);
      render();
    }
    else if (action === 'open-aggregate-qr-modal') {
      if (!state.inbounds.length || !state.settings?.subToken || !state.nodes || !state.nodes.length) {
        const data = await api('/api/inbounds');
        if (Array.isArray(data.nodes)) state.nodes = data.nodes;
        state.inbounds = data.inbounds || [];
        if (data.settings) state.settings = data.settings;
      }
      openAggregateQrModal(state.nodeFilter && state.nodeFilter !== 'all' ? state.nodeFilter : 'all');
    }
    else if (action === 'filter-agg-qr-node') {
      openAggregateQrModal(actEl.dataset.node || 'all');
    }
    else if (action === 'set-expiry') {
      const days = Number(actEl.dataset.days || 0);
      const input = $('#inb-expiry-input');
      if (input) {
        if (days <= 0) {
          input.value = '';
        } else {
          input.value = toDatetimeLocalValue(Date.now() + days * 86400000);
        }
      }
    }
    else if (action === 'switch-out-tab') {
      const tab = actEl.dataset.tab;
      const formPane = $('#out-form-pane');
      const jsonPane = $('#out-json-pane');
      const formBtn = $('#out-tab-form-btn');
      const jsonBtn = $('#out-tab-json-btn');
      if (tab === 'json') {
        const curObj = {
          type: $('#out-f-type')?.value || 'shadowsocks',
          tag: $('#out-f-tag')?.value || 'outbound-1',
          server: $('#out-f-server')?.value || '127.0.0.1',
          server_port: Number($('#out-f-port')?.value || 443)
        };
        if ($('#out-f-password')?.value) curObj.password = $('#out-f-password').value;
        if (curObj.type === 'shadowsocks') curObj.method = $('#out-f-method')?.value || 'aes-128-gcm';
        if ($('#out-f-uuid')?.value) curObj.uuid = $('#out-f-uuid').value;
        if ($('#out-f-username')?.value) curObj.username = $('#out-f-username').value;
        if ($('#out-f-detour')?.value) curObj.detour = $('#out-f-detour').value;
        if ($('#out-json-textarea')) $('#out-json-textarea').value = JSON.stringify(curObj, null, 2);
        formPane?.classList.add('hidden');
        jsonPane?.classList.remove('hidden');
        formBtn?.classList.remove('primary');
        jsonBtn?.classList.add('primary');
      } else {
        try {
          const parsed = JSON.parse($('#out-json-textarea')?.value || '{}');
          if (parsed.tag && $('#out-f-tag')) $('#out-f-tag').value = parsed.tag;
          if ((parsed.type || parsed.protocol) && $('#out-f-type')) {
            const pType = (parsed.type || parsed.protocol).toLowerCase();
            $('#out-f-type').value = pType === 'freedom' ? 'direct' : (pType === 'blackhole' ? 'block' : pType);
          }
          if (parsed.server && $('#out-f-server')) $('#out-f-server').value = parsed.server;
          if (parsed.server_port && $('#out-f-port')) $('#out-f-port').value = parsed.server_port;
          if (parsed.password && $('#out-f-password')) $('#out-f-password').value = parsed.password;
          if (parsed.method && $('#out-f-method')) $('#out-f-method').value = parsed.method;
          if (parsed.uuid && $('#out-f-uuid')) $('#out-f-uuid').value = parsed.uuid;
        } catch { /* ignore */ }
        jsonPane?.classList.add('hidden');
        formPane?.classList.remove('hidden');
        jsonBtn?.classList.remove('primary');
        formBtn?.classList.add('primary');
      }
    }
    else if (action === 'parse-uri-into-outbound-modal') {
      const uri = $('#out-modal-uri-input')?.value.trim();
      if (!uri) { toast('请先粘贴节点链接 (ss://, vless://, vmess://, trojan://, hy2:// 等)', true); return; }
      const res = await api('/api/outbounds/parse-uri', { method: 'POST', body: JSON.stringify({ uri }) });
      const o = res.outbound;
      if ($('#out-f-tag')) $('#out-f-tag').value = o.tag || '';
      if ($('#out-f-type')) $('#out-f-type').value = o.type || 'shadowsocks';
      if ($('#out-f-server')) $('#out-f-server').value = o.server || '';
      if ($('#out-f-port')) $('#out-f-port').value = o.port || 443;
      if ($('#out-f-remark')) $('#out-f-remark').value = o.remark || '';
      if ($('#out-f-password')) $('#out-f-password').value = o.password || '';
      if (o.method && $('#out-f-method')) $('#out-f-method').value = o.method;
      if ($('#out-f-uuid')) $('#out-f-uuid').value = o.uuid || '';
      if ($('#out-f-username')) $('#out-f-username').value = o.username || '';
      if ($('#out-f-security')) $('#out-f-security').value = o.security || 'none';
      if ($('#out-f-transport')) $('#out-f-transport').value = o.transport || 'tcp';
      if ($('#out-f-sni')) $('#out-f-sni').value = o.sni || '';
      if ($('#out-f-pbk')) $('#out-f-pbk').value = o.publicKey || '';
      if ($('#out-f-sid')) $('#out-f-sid').value = o.shortId || '';
      if ($('#out-f-insecure')) $('#out-f-insecure').checked = Boolean(o.insecure);
      if ($('#out-json-textarea')) $('#out-json-textarea').value = JSON.stringify(res.singboxPreview, null, 2);
      toast(`已解析填入: ${o.tag} (${o.server}:${o.port})`);
    }
    else if (action === 'enable-bbr-hy2') {
      const res = await api('/api/system/acceleration', { method: 'POST', body: JSON.stringify({ mode: 'all' }) });
      toast(`🚀 已启用内核加速 (${res.acceleration?.congestion} + ${res.acceleration?.qdisc})`);
      load('overview');
    }
    else if (action === 'open-firewall-ports') {
      const res = await api('/api/system/firewall', { method: 'POST' });
      toast(`🛡 已自动放行端口: ${(res.openedPorts || []).join(', ')}`);
    }
    else if (action === 'quick-add-inbound' || action === 'add-inbound') { openInboundModal(); }
    else if (action === 'quick-inbound') { openInboundModal(null, actEl.dataset.preset); }
    else if (action === 'copy-all-links') {
      const allUris = state.inbounds.flatMap((i) => (i.links || []).map((l) => l.uri));
      if (!allUris.length) { toast('当前暂无可复制的节点链接', true); return; }
      copyText(allUris.join('\n'), `全部 ${allUris.length} 条节点链接`);
    }
    else if (action === 'edit-inbound') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openInboundModal(inb);
    }
    else if (action === 'inbound-links') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openInboundLinksModal(inb);
    }
    else if (action === 'toggle-expand-clients') {
      const id = actEl.dataset.id;
      if (state.expandedInbounds.has(id)) state.expandedInbounds.delete(id);
      else state.expandedInbounds.add(id);
      render();
    }
    else if (action === 'add-client') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openClientModal(inb, null);
    }
    else if (action === 'edit-client') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      const cl = (inb?.clients || []).find((c) => c.id === actEl.dataset.clientId);
      if (inb && cl) openClientModal(inb, cl);
    }
    else if (action === 'client-links') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openInboundLinksModal(inb, actEl.dataset.clientId);
    }
    else if (action === 'client-detail') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      const cl = (inb?.clients || []).find((c) => c.id === actEl.dataset.clientId);
      if (inb) openClientDetailModal(inb, cl || null);
    }
    else if (action === 'inbound-detail') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openClientDetailModal(inb, (inb.clients && inb.clients[0]) || null);
    }
    else if (action === 'reset-client-traffic') {
      const inbId = actEl.dataset.id;
      const clientId = actEl.dataset.clientId;
      await api(`/api/inbounds/${inbId}/clients/${encodeURIComponent(clientId)}/reset-traffic`, { method: 'POST' });
      toast('该用户已用流量已清零');
      load('inbounds');
    }
    else if (action === 'toggle-client') {
      const inbId = actEl.dataset.id;
      const clientId = actEl.dataset.clientId;
      await api(`/api/inbounds/${inbId}/clients/${encodeURIComponent(clientId)}/toggle`, { method: 'POST' });
      toast('该用户启用状态已切换');
      load('inbounds');
    }
    else if (action === 'delete-client') {
      if (!ngConfirm('确认从该入站节点下删除此用户吗？')) return;
      const inbId = actEl.dataset.id;
      const clientId = actEl.dataset.clientId;
      await api(`/api/inbounds/${inbId}/clients/${encodeURIComponent(clientId)}`, { method: 'DELETE' });
      toast('已删除该用户');
      load('inbounds');
    }
    else if (action === 'gen-client-modal-uuid') {
      const input = $('#client-modal-uuid');
      if (input) input.value = genUuidClient();
    }
    else if (action === 'reset-inbound-traffic') {
      await api(`/api/inbounds/${actEl.dataset.id}/reset-traffic`, { method: 'POST' });
      toast('入站节点流量已重置');
      load('inbounds');
    }
    else if (action === 'toggle-inbound') {
      await api(`/api/inbounds/${actEl.dataset.id}/toggle`, { method: 'POST' });
      toast('入站节点状态已切换');
      load('inbounds');
    }
    else if (action === 'delete-inbound') {
      if (!ngConfirm('确认删除该入站节点？')) return;
      await api(`/api/inbounds/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('入站节点已删除');
      load('inbounds');
    }
    else if (action === 'inb-rand-port') {
      const input = $('#inb-port-input');
      if (input) {
        const nextP = Math.floor(Math.random() * 40000) + 15000;
        input.value = nextP;
        const remInput = $('#inbound-form input[name="remark"]');
        if (remInput && /-\d+$/.test(remInput.value.trim())) {
          remInput.value = remInput.value.trim().replace(/-\d+$/, `-${nextP}`);
        }
      }
    }
    else if (action === 'gen-uuid') {
      const input = $('#inb-uuid-input');
      if (input) input.value = genUuidClient();
      toast('已生成新的标准 UUID');
    }
    else if (action === 'gen-clean-pass') {
      const target = $(`#${actEl.dataset.target}`);
      const otherVal = $('#inb-socks-user')?.value || $('#client-modal-user')?.value || $('#inb-client-email')?.value || '';
      if (target) target.value = genRandomAlnum(20, otherVal);
    }
    else if (action === 'gen-socks-user') {
      const el = $('#inb-socks-user');
      if (el) el.value = `u_${genRandomAlnum(8)}`;
    }
    else if (action === 'gen-client-email') {
      const el = $('#inb-client-email');
      const proto = $('#inb-proto-select')?.value || 'node';
      if (el) el.value = `${proto}_${genRandomAlnum(6).toLowerCase()}`;
    }
    else if (action === 'gen-client-modal-email') {
      const el = $('#client-modal-email');
      if (el) el.value = `user_${genRandomAlnum(6).toLowerCase()}`;
    }
    else if (action === 'gen-client-modal-user') {
      const el = $('#client-modal-user');
      if (el) el.value = `u_${genRandomAlnum(8)}`;
    }
    else if (action === 'gen-reality-keys') {
      const kp = await api('/api/tools/reality-keypair', { method: 'POST' });
      if ($('#inb-reality-priv')) $('#inb-reality-priv').value = kp.privateKey;
      if ($('#inb-reality-pub')) $('#inb-reality-pub').value = kp.publicKey;
      if ($('#inb-reality-sid')) $('#inb-reality-sid').value = kp.shortId;
      toast('已生成新的 Reality X25519 密钥对');
    }
    else if (action === 'gen-ss-key') {
      const method = $('#inb-ss-method')?.value || '2022-blake3-aes-128-gcm';
      const sk = await api('/api/tools/ss-key', { method: 'POST', body: JSON.stringify({ method }) });
      if ($('#inb-ss-pass')) $('#inb-ss-pass').value = sk.password;
      toast('已生成标准长度密钥');
    }
    else if (action === 'add-outbound') { openOutboundModal(); }
    else if (action === 'edit-outbound') {
      const out = state.outbounds.find((x) => x.id === actEl.dataset.id);
      if (out) openOutboundModal(out);
    }
    else if (action === 'reset-outbound-traffic') {
      await api(`/api/outbounds/${actEl.dataset.id}/reset-traffic`, { method: 'POST' });
      toast('出站流量统计已清零');
      load('outbounds');
    }
    else if (action === 'ping-outbound') {
      const id = actEl.dataset.id;
      const res = await api(`/api/outbounds/${id}/ping`, { method: 'POST' });
      state.outboundPings[id] = res;
      if (res.reachable) toast(`出站连通正常: ${res.latencyMs} ms`);
      else toast(`出站连接失败: ${res.error}`, true);
      render();
    }
    else if (action === 'ping-all-outbounds') {
      const targets = state.outbounds.filter((o) => !o.builtin && o.server);
      if (!targets.length) { toast('暂无可测速的远程出站节点', true); return; }
      toast('正在并发检测全部出站节点延迟...');
      await Promise.all(targets.map(async (o) => {
        try {
          state.outboundPings[o.id] = await api(`/api/outbounds/${o.id}/ping`, { method: 'POST' });
        } catch (err) {
          state.outboundPings[o.id] = { reachable: false, error: err.message };
        }
      }));
      toast('全部出站延迟检测完成');
      render();
    }
    else if (action === 'delete-outbound') {
      if (!ngConfirm('确认删除该出站节点？')) return;
      await api(`/api/outbounds/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('出站节点已删除');
      load('outbounds');
    }
    else if (action === 'import-outbound-uri') {
      openModal('批量导入外部节点作为中转出站', '支持一次粘贴单条或多条分享链接 (每行一条)', `
        <form id="import-uri-form" class="form-grid">
          <label class="wide">
            节点分享链接 (支持 ss://, socks://, socks5://, vless://, hysteria2://, hy2://, anytls://, trojan://, vmess://, tuic://)
            <textarea name="uri" style="min-height:160px" placeholder="可一次粘贴多条节点链接（每行一条），将自动提取节点名称作为出站标签 Tag" required></textarea>
          </label>
          <label>自定义标签前缀 (可选，单条时为完整 Tag)<input name="tag" placeholder="留空自动使用链接内节点名"></label>
          <label>自定义备注前缀 (可选)<input name="remark" placeholder="留空自动使用链接内节点名"></label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">解析并导入至出站列表</button>
          </div>
        </form>
      `);
    }
    else if (action === 'quick-add-relay-rule') {
      const inbTag = $('#quick-relay-inbound')?.value;
      const outTag = $('#quick-relay-outbound')?.value;
      if (!inbTag || !outTag) {
        toast('请先选择入站标签与目标出站', true);
        return;
      }
      await api('/api/routing/rules', {
        method: 'POST',
        body: JSON.stringify({
          remark: `入站转发: ${inbTag} ➔ ${outTag}`,
          inbound: [inbTag],
          outbound: outTag
        })
      });
      toast(`已绑定转发规则: ${inbTag} ➔ ${outTag}`);
      load('routing');
    }
    else if (action === 'save-routing-global') {
      const finalOut = $('#routing-final-select')?.value || 'direct';
      await api('/api/routing', { method: 'PUT', body: JSON.stringify({ final: finalOut }) });
      toast('默认兜底出站已保存');
      load('routing');
    }
    else if (action === 'add-rule') { openRuleModal(); }
    else if (action === 'edit-rule') {
      const r = (state.routing.rules || []).find((x) => x.id === actEl.dataset.id);
      if (r) openRuleModal(r);
    }
    else if (action === 'delete-rule') {
      const r = (state.routing.rules || []).find((x) => x.id === actEl.dataset.id);
      const label = r?.remark || (r?.inbound?.length ? `${r.inbound.join(', ')} ➔ ${r.outbound}` : actEl.dataset.id);
      if (!ngConfirm(`确认删除路由转发规则「${label}」吗？`)) return;
      await api(`/api/routing/rules/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('路由规则已删除');
      load('routing');
    }
    else if (action === 'move-rule') {
      await api(`/api/routing/rules/${actEl.dataset.id}/move`, {
        method: 'POST',
        body: JSON.stringify({ direction: actEl.dataset.dir })
      });
      load('routing');
    }
    else if (action === 'routing-preset') {
      const preset = actEl.dataset.preset;
      if (preset === '3xui-default' && !ngConfirm('确认恢复默认防探测/禁BT规则吗？（将保留入站一对一中转规则，移除其他自定义分流规则）')) return;
      const selOut = $('#quick-relay-outbound')?.value;
      const customOut = (selOut && selOut !== 'direct')
        ? selOut
        : (state.outbounds.find((o) => !o.builtin)?.tag || 'direct');
      const scopedNodeId = (state.routingNodeFilter && state.routingNodeFilter !== 'all' && state.routingNodeFilter !== 'global') ? state.routingNodeFilter : '';
      await api('/api/routing/presets', {
        method: 'POST',
        body: JSON.stringify({ preset, outbound: customOut, nodeId: scopedNodeId })
      });
      toast(`已应用分流预设 (${preset})`);
      load('routing');
    }
    else if (action === 'sb-control') {
      const cmd = actEl.dataset.cmd;
      const res = await api('/api/singbox/control', { method: 'POST', body: JSON.stringify({ action: cmd }) });
      if (cmd === 'check') {
        if (res.result.valid) toast('✅ Sing-box 配置文件校验通过 (0 错误 0 警告)');
        else toast(`❌ 配置校验失败: ${res.result.error}`, true);
      } else {
        toast(`Sing-box 操作已执行 (${cmd})`);
      }
      load('overview');
    }
    else if (action === 'sb-logs') {
      const data = await api('/api/singbox/logs');
      openModal('Sing-box 实时运行日志', `当前状态: ${data.status?.state || '未知'}`, `<div class="codebox">${esc((data.logs || []).join('\n'))}</div>`);
    }
    else if (action === 'sb-config-preview') {
      const data = await api('/api/singbox/config');
      const jsonStr = JSON.stringify(data.config, null, 2);
      openModal('Sing-box 完整配置文件预览', data.status?.configPath || 'config.json', `
        <div class="stack">
          <div class="codebox">${esc(jsonStr)}</div>
          <div style="display:flex;justify-content:flex-end"><button class="primary" data-copy="${esc(jsonStr)}">复制完整 JSON 配置</button></div>
        </div>
      `);
    }
    else if (action === 'sb-switch-version') {
      const custom = $('#sb-version-custom')?.value.trim();
      const sel = $('#sb-version-select')?.value;
      const version = custom || sel || 'v1.12.23';
      toast(`正在下载并切换 Sing-box 内核至 ${version}...`);
      const res = await api('/api/singbox/version', { method: 'POST', body: JSON.stringify({ version }) });
      toast(`成功切换内核版本: ${res.version?.version || version}`);
      load('overview');
    }
    else if (action === 'preview-xui-file' || action === 'apply-xui-file') {
      const fileInput = $('#xui-db-file');
      const file = fileInput?.files?.[0];
      if (!file) { toast('请先选择要上传的 x-ui.db 或 .tar.gz 备份文件', true); return; }
      const mode = $('#migrate-mode')?.value || 'merge';
      const dryRun = action === 'preview-xui-file';
      const buf = await file.arrayBuffer();
      const targetNodeId = $('#migrate-target-node')?.value || '';
      const nodeDomain = $('#migrate-node-domain')?.value.trim() || '';
      const dedup = $('#migrate-dedup-exits') ? $('#migrate-dedup-exits').checked : true;
      const nodeName = $('#migrate-node-name')?.value.trim() || '';
      const nodeIp = $('#migrate-node-ip')?.value.trim() || '';
      const qs = new URLSearchParams({ mode, dryRun: String(dryRun), targetNodeId, nodeDomain, nodeName, nodeIp, deduplicateExits: String(dedup) }).toString();
      const res = await api(`/api/migrate/3xui?${qs}`, {
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: buf
      });
      if (dryRun) {
        state.migrationPreview = res;
        toast(`解析成功: 发现 ${res.summary.inboundsCount} 个入站与 ${res.summary.outboundsCount} 个出站`);
        render();
      } else {
        state.migrationPreview = null;
        const certMsg = res.summary?.restoredCertsCount ? `、${res.summary.restoredCertsCount} 张 SSL 证书` : '';
        toast(`🎉 备份迁移完成: 已导入 ${res.summary.inboundsCount} 个入站、${res.summary.outboundsCount} 个出站、${res.summary.rulesCount} 条规则${certMsg}！`);
        load('migrate');
      }
    }
    else if (action === 'migrate-local-xui') {
      const dbPath = $('#local-xui-path')?.value.trim() || '/etc/x-ui/x-ui.db';
      const mode = $('#migrate-mode')?.value || 'merge';
      const res = await api(`/api/migrate/3xui?mode=${mode}`, {
        method: 'POST',
        body: JSON.stringify({ source: 'local', dbPath })
      });
      const certMsg = res.summary?.restoredCertsCount ? `、${res.summary.restoredCertsCount} 张 SSL 证书` : '';
      toast(`🎉 本机备份数据迁移完成: 入站 ${res.summary.inboundsCount} 个，出站 ${res.summary.outboundsCount} 个${certMsg}`);
      load('migrate');
    }
    else if (action === 'preview-xui-json' || action === 'apply-xui-json') {
      const raw = $('#xui-json-input')?.value.trim();
      if (!raw) { toast('请粘贴配置 JSON 内容', true); return; }
      const mode = $('#migrate-mode')?.value || 'merge';
      const dryRun = action === 'preview-xui-json';
      const targetNodeId = $('#migrate-target-node')?.value || '';
      const nodeDomain = $('#migrate-node-domain')?.value.trim() || '';
      const dedup = $('#migrate-dedup-exits') ? $('#migrate-dedup-exits').checked : true;
      const qs = new URLSearchParams({ mode, dryRun: String(dryRun), targetNodeId, nodeDomain, deduplicateExits: String(dedup) }).toString();
      const res = await api(`/api/migrate/3xui?${qs}`, {
        method: 'POST',
        body: JSON.stringify({ jsonPayload: raw })
      });
      if (dryRun) {
        state.migrationPreview = res;
        toast(`JSON 解析成功: ${res.summary.inboundsCount} 个入站`);
        render();
      } else {
        state.migrationPreview = null;
        toast('🎉 从 JSON 备份迁移完成！');
        load('migrate');
      }
    }
    else if (action === 'cert-selfsigned') {
      openModal('一键生成 10 年自签 SSL 证书', '仅在无域名时使用；若已有真实域名建议使用 ACME 申请', `
        <form id="cert-selfsigned-form" class="form-grid">
          <label class="wide">
            自签域名标识 (Common Name / SAN)
            <input name="domain" value="${esc(state.settings.webDomain || 'www.apple.com')}" required>
            <small>自动包含本机公网 IPv4 作为 SAN 扩展</small>
          </label>
          <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" name="applyToPanel" style="width:16px;min-height:16px" checked>
            <span>同时绑定为面板 HTTPS 登录证书与节点默认证书</span>
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">立即生成 10 年证书并绑定</button>
          </div>
        </form>
      `);
    }
    else if (action === 'cert-acme') {
      const savedCfTokens = String(state.settings?.cfApiToken || '').split(/[\r\n,;\s]+/).map((s) => s.trim()).filter(Boolean);
      const defaultCfToken = savedCfTokens[0] || '';
      const relayDomains = (state.nodes || []).filter((n) => n.domain).map((n) => ({ name: n.name, domain: n.domain, isLocal: n.isLocal, cfToken: n.cfApiToken || '' }));
      openModal('ACME 自动申请受信任证书 (支持主控与全部中转机域名统一签发)', '签发后主控会自动将证书推送分发至对应的中转机与热备容灾机，子机器无需装面板或手动申请', `
        <form id="cert-acme-form" class="form-grid" autocomplete="off">
          <div class="wide" style="padding:10px 13px;border-radius:10px;background:var(--primary-soft);border:1px solid color-mix(in srgb,var(--primary) 30%,var(--line));font-size:12.5px;line-height:1.6">
            💡 <b>多中转机证书统一签发说明</b>：子机器（中转机/热备机）只需执行 Agent 命令，<b>不需要再安装面板或手动装证书</b>！<br>
            • 若要为<b>远程中转机的域名</b>申请证书，请选择「<b>2. Cloudflare DNS API 模式</b>」，主控验证通过后会自动将签发好的证书下发到该中转机与热备机！<br>
            • 若要为<b>主控本机的域名</b>申请证书，可选「1. HTTP-01 模式」或「2. Cloudflare DNS API 模式」。
          </div>
          ${relayDomains.length ? `
          <label class="wide">
            快速选择集群中转机已绑定的域名 (点击自动带入下方域名框)
            <select id="acme-quick-domain-select">
              <option value="">— 手动输入或从下方选择中转机域名 —</option>
              ${relayDomains.map((rd) => `<option value="${esc(rd.domain)}" data-local="${rd.isLocal ? '1' : '0'}" data-cftoken="${esc(rd.cfToken)}">${esc(rd.name)} — ${esc(rd.domain)} ${rd.isLocal ? '(主控本机)' : '(远程中转机 · 推荐 CF DNS 模式)'}</option>`).join('')}
            </select>
          </label>
          ` : ''}
          <label>
            申请域名或公网 IP
            <input name="domain" id="acme-domain-input" value="${esc(relayDomains[0]?.domain || state.settings?.webDomain || '')}" placeholder="填写主控或任意中转机的域名" autocomplete="off" required>
          </label>
          <label>
            通知邮箱 (可选)
            <input name="email" placeholder="admin@example.com" autocomplete="off">
          </label>
          <label class="wide">
            申请模式
            <select name="mode" id="acme-mode-select">
              <option value="cf"${defaultCfToken ? ' selected' : ''}>2. Cloudflare DNS API 模式 (强烈推荐！支持主控为任意远程中转机域名统一签发证书，无需 80 端口)</option>
              <option value="standalone"${!defaultCfToken ? ' selected' : ''}>1. 域名 HTTP-01 模式 (仅限已解析到主控本机 IP 且开放 80 端口的域名)</option>
              <option value="ip">3. Let's Encrypt 短期 IP 证书模式 (无需域名，直接为公网 IP 签发受信任证书)</option>
            </select>
          </label>
          <label>
            Cloudflare API Token (CF DNS 模式使用，已自动带入面板已存 Token)
            <input name="cfToken" id="acme-cftoken-input" type="text" autocomplete="off" spellcheck="false" style="-webkit-text-security:disc" value="${esc(defaultCfToken)}" placeholder="CF_Token (Edit zone DNS)">
          </label>
          <label>
            或 CF Global API Key + 邮箱 (可选)
            <div class="input-row">
              <input name="cfKey" type="text" autocomplete="off" style="-webkit-text-security:disc" placeholder="CF_Key">
              <input name="cfEmail" placeholder="CF 账号邮箱" autocomplete="off">
            </div>
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">开始签发并自动分发至集群节点</button>
          </div>
        </form>
      `);
      const qSel = $('#acme-quick-domain-select');
      const dInp = $('#acme-domain-input');
      const mSel = $('#acme-mode-select');
      const tInp = $('#acme-cftoken-input');
      if (qSel && dInp) {
        qSel.addEventListener('change', () => {
          if (!qSel.value) return;
          dInp.value = qSel.value;
          const opt = qSel.options[qSel.selectedIndex];
          if (opt && opt.dataset.local === '0' && mSel) {
            mSel.value = 'cf';
          }
          if (opt && opt.dataset.cftoken && tInp) {
            tInp.value = opt.dataset.cftoken;
          }
        });
      }
    }
    else if (action === 'cert-custom') {
      openModal('导入或粘贴自定义 SSL 证书', '支持粘贴 PEM 内容或指定服务器已有证书路径', `
        <form id="cert-custom-form" class="form-grid">
          <label class="wide">
            域名标识名称
            <input name="domain" placeholder="填写证书对应的域名" required>
          </label>
          <label>
            方式 A: 服务器已有公钥路径 (可选)
            <input name="certPath" placeholder="/root/cert/example.com/fullchain.pem">
          </label>
          <label>
            方式 A: 服务器已有私钥路径 (可选)
            <input name="keyPath" placeholder="/root/cert/example.com/privkey.pem">
          </label>
          <label class="wide">
            方式 B: 直接粘贴证书公钥内容 (fullchain.pem)
            <textarea name="certPem" placeholder="-----BEGIN CERTIFICATE-----..."></textarea>
          </label>
          <label class="wide">
            方式 B: 直接粘贴证书私钥内容 (privkey.pem)
            <textarea name="keyPem" placeholder="-----BEGIN PRIVATE KEY-----..."></textarea>
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">保存并一键绑定面板与节点</button>
          </div>
        </form>
      `);
    }
    else if (action === 'bind-cert-all') {
      await api('/api/certificates/bind-all', {
        method: 'POST',
        body: JSON.stringify({ id: actEl.dataset.id })
      });
      toast('已设为面板 HTTPS 与全部 TLS 节点的默认通用证书！');
      load('certificates');
    }
    else if (action === 'delete-cert') {
      if (!ngConfirm('确认移除该证书记录吗？（若该证书为当前默认证书，系统将自动切换至剩余可用证书）')) return;
      const res = await api(`/api/certificates/${encodeURIComponent(actEl.dataset.id)}`, { method: 'DELETE' });
      if (res.switchedDomain) {
        toast(`已移除证书 ${res.deletedDomain || ''}，并自动切换默认证书为 ${res.switchedDomain}`);
      } else {
        toast(`证书 ${res.deletedDomain || ''} 已移除`);
      }
      load('certificates');
    }
    else if (action === 'random-port') {
      const el = $('#setting-webport');
      if (el) el.value = Math.floor(Math.random() * 45000) + 15000;
    }
    else if (action === 'random-path') {
      const el = $('#setting-webpath');
      if (el) el.value = `/${genRandomAlnum(16)}/`;
    }
    else if (action === 'reset-path') {
      const el = $('#setting-webpath');
      if (el) el.value = '/';
    }
    else if (action === 'random-sub-token') {
      const el = $('#setting-subtoken');
      if (el) el.value = genRandomAlnum(20);
      toast('已生成新的 20 位聚合订阅安全码，点击下方【保存面板设置】生效');
    }
    else if (action === 'random-account-user') {
      const el = $('#account-user-input');
      const passVal = $('#account-pass-input')?.value || '';
      if (el) el.value = `ng_${genRandomAlnum(10, passVal)}`;
    }
    else if (action === 'random-account-pass') {
      const el = $('#account-pass-input');
      const userVal = $('#account-user-input')?.value || '';
      if (el) el.value = genRandomAlnum(18, userVal);
    }
    else if (action === 'restore-backup-modal') {
      state._pendingRestoreZipBuf = null;
      openModal('一键导入恢复全量主控备份 (.zip / .json)', '支持异机主控容灾迁移：端口、安全根路径、登录账密、SSL 证书文件与全集群节点 100% 原样还原', `
        <form id="restore-backup-form" class="form-grid">
          <div class="wide" style="padding:10px 14px;border-radius:10px;background:var(--primary-soft);border:1px solid color-mix(in srgb,var(--primary) 30%,var(--line));font-size:12.5px;line-height:1.6">
            💡 <b>主控异机灾备恢复说明</b>：当原主控机器故障、你在新备用服务器上安装主控后，直接选择导出的 <code>nexusgate-master-backup.zip</code> 压缩包即可！系统会自动解压还原全部 <b>SSL 证书实体文件</b>、<b>全部中转机与落地机集群</b>、<b>所有客户节点与路由</b>，并将新主控的<b>访问端口、安全路径与登录账密</b>恢复为与原主控完全一致！
          </div>

          <label class="upload-dropzone wide" for="restore-file-input" style="padding:18px 14px;cursor:pointer">
            <input type="file" id="restore-file-input" accept=".zip,.json,application/zip,application/json" class="hidden">
            <b style="display:block;font-size:14.5px;margin-bottom:4px">📦 点击选择 <code>nexusgate-master-backup.zip</code> 或 <code>.json</code> 备份文件</b>
            <span class="muted" style="font-size:12px" id="restore-file-label">推荐上传 .zip 全量主控灾备包（内含 SSL 证书文件与完整集群状态，无需手动复制粘贴）</span>
          </label>

          <label class="wide" style="flex-direction:row;align-items:center;gap:8px;padding:10px 12px;border-radius:9px;background:var(--surface-soft);border:1px solid var(--line)">
            <input type="checkbox" name="restorePanelSettings" id="restore-panel-settings-chk" style="width:16px;min-height:16px" checked>
            <span><b>同步恢复原主控的面板端口、安全根路径、管理员账密与 SSL 证书</b>（异机迁入新主控时勾选，恢复后新主控的访问端口与安全路径将变回与原主控完全一致！）</span>
          </label>

          <label class="wide">
            或直接粘贴备份 JSON 文本内容 (仅当未选择上方文件时使用)
            <textarea name="backupJson" id="restore-json-textarea" style="min-height:95px" placeholder='若已选择上方 .zip 或 .json 文件则无需填写此处'></textarea>
          </label>

          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary" id="restore-submit-btn">立即恢复全集群与主控配置</button>
          </div>
        </form>
      `);

      const fInput = $('#restore-file-input');
      const tArea = $('#restore-json-textarea');
      const lbl = $('#restore-file-label');
      if (fInput) {
        fInput.addEventListener('change', async () => {
          const file = fInput.files?.[0];
          if (!file) return;
          try {
            if (file.name.toLowerCase().endsWith('.zip')) {
              const ab = await file.arrayBuffer();
              state._pendingRestoreZipBuf = ab;
              if (tArea) tArea.value = '';
              if (lbl) lbl.textContent = `✓ 已就绪 ZIP 全量灾备包: ${file.name} (${fmtBytes(file.size)} · 含证书与全集群数据)`;
              toast(`已加载全量灾备包 [${file.name}]，点击【立即恢复全集群与主控配置】即可生效`);
            } else {
              state._pendingRestoreZipBuf = null;
              const txt = await file.text();
              if (tArea) tArea.value = txt;
              if (lbl) lbl.textContent = `✓ 已读取 JSON 备份文件: ${file.name} (${fmtBytes(file.size)})`;
              toast(`已读取备份文件 [${file.name}]，点击【立即恢复全集群与主控配置】即可生效`);
            }
          } catch (err) {
            toast(`读取文件失败: ${err.message}`, true);
          }
        });
      }
    }
  } catch (err) {
    toast(err.message, true);
  }
});

document.addEventListener('change', async (e) => {
  if (e.target.dataset?.action === 'inline-outbound-select') {
    const inbId = e.target.dataset.id;
    const outboundTag = e.target.value;
    try {
      await api(`/api/inbounds/${encodeURIComponent(inbId)}/outbound`, {
        method: 'POST',
        body: JSON.stringify({ outboundTag })
      });
      toast(`✅ 已切换节点转发目标为: ${outboundTag === 'default' ? '默认路由' : outboundTag}`);
      load('inbounds', { silent: true });
    } catch (err) {
      toast(err.message, true);
    }
    return;
  }
  if (e.target.id === 'inb-reality-preset' && e.target.value) {
    const opt = e.target.selectedOptions[0];
    if ($('#inb-reality-sni')) $('#inb-reality-sni').value = e.target.value;
    if ($('#inb-reality-target')) $('#inb-reality-target').value = opt.dataset.target || `${e.target.value}:443`;
  }
  if (e.target.id === 'inb-cert-select' && e.target.value) {
    const opt = e.target.selectedOptions[0];
    if ($('#inb-tls-domain')) $('#inb-tls-domain').value = e.target.value;
    if ($('#inb-cert-path')) $('#inb-cert-path').value = opt.dataset.cert || '';
    if ($('#inb-key-path')) $('#inb-key-path').value = opt.dataset.key || '';
  }
  if (e.target.id === 'setting-cert-picker' && e.target.value) {
    const [cPath, kPath, cDomain] = e.target.value.split('|');
    if ($('#setting-cert-file')) $('#setting-cert-file').value = cPath || '';
    if ($('#setting-key-file')) $('#setting-key-file').value = kPath || '';
    if (cDomain && cDomain !== 'www.apple.com' && $('#setting-webdomain')) {
      $('#setting-webdomain').value = cDomain;
    }
  }
  if (e.target.id === 'xui-db-file' && e.target.files?.[0]) {
    const lbl = $('#xui-file-label');
    if (lbl) lbl.textContent = `已选择文件: ${e.target.files[0].name} (${fmtBytes(e.target.files[0].size)})`;
  }
});

document.addEventListener('input', (e) => {
  if (e.target.matches('[data-search]')) {
    state.search = e.target.value;
    const pos = e.target.selectionStart;
    render();
    const nextInput = $('[data-search]');
    if (nextInput) {
      nextInput.focus();
      nextInput.setSelectionRange(pos, pos);
    }
  }
});

document.addEventListener('submit', async (e) => {
  const form = e.target;
  e.preventDefault();
  if (form.dataset.submitting === '1') return;
  form.dataset.submitting = '1';

  const fd = new FormData(form);
  const data = Object.fromEntries(fd.entries());
  const submitBtn = form.querySelector('button[type="submit"]');
  const origBtnText = submitBtn ? submitBtn.textContent : '';
  if (submitBtn) {
    submitBtn.disabled = true;
    if (form.id !== 'login-form') submitBtn.textContent = '⏳ 正在保存并生效...';
  }

  try {
    if (form.id === 'login-form') {
      $('#login-error').textContent = '';
      state.session = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(data) });
      showApp();
      setPage(getSavedInitialPage());
    }
    else if (form.id === 'inbound-form') {
      const id = form.dataset.id;
      const expiryMs = data.expiryTime ? Date.parse(data.expiryTime) : 0;
      const payload = {
        nodeId: data.nodeId || 'node_local',
        tag: data.tag || '',
        publicHost: data.publicHost || '',
        remark: data.remark,
        protocol: data.protocol,
        listen: data.listen,
        port: Number(data.port),
        limitIp: Number(data.limitIp || 0),
        limitDevice: Number(data.limitDevice || 0),
        totalGB: Number(data.totalGB || 0),
        resetDay: Number(data.resetDay || 0),
        expiryTime: Number.isFinite(expiryMs) && expiryMs > 0 ? expiryMs : 0,
        outboundTag: data.outboundTag,
        security: data.security || (['anytls', 'hysteria2', 'tuic'].includes(data.protocol) ? 'tls' : 'none'),
        transport: data.transport || 'tcp',
        flow: data.flow || '',
        method: data.method,
        password: data.password,
        socksUser: data.socksUser,
        socksPassword: data.socksPassword,
        upMbps: data.upMbps ? Number(data.upMbps) : undefined,
        downMbps: data.downMbps ? Number(data.downMbps) : undefined,
        obfsPassword: data.obfsPassword,
        tlsDomain: data.tlsDomain,
        certPath: data.certPath,
        keyPath: data.keyPath,
        wsPath: data.wsPath,
        wsHost: data.wsHost,
        grpcServiceName: data.grpcServiceName,
        overrideAddress: data.overrideAddress,
        overridePort: data.overridePort ? Number(data.overridePort) : undefined,
        network: data.network,
        uuid: data.uuid,
        clientEmail: data.clientEmail
      };
      if (payload.security === 'reality') {
        payload.reality = {
          serverName: data.realityServerName,
          target: data.realityTarget,
          privateKey: data.realityPrivateKey,
          publicKey: data.realityPublicKey,
          shortIds: data.realityShortIds
        };
      }
      const res = id
        ? await api(`/api/inbounds/${id}`, { method: 'PUT', body: JSON.stringify(payload) })
        : await api('/api/inbounds', { method: 'POST', body: JSON.stringify(payload) });
      closeModal();
      if (res && res.inbound) {
        const idx = state.inbounds.findIndex((x) => x.id === res.inbound.id);
        if (idx >= 0) state.inbounds[idx] = res.inbound;
        else state.inbounds.unshift(res.inbound);
      }
      if (Array.isArray(res?.outbounds)) {
        state.outbounds = res.outbounds;
      }
      toast(id ? '入站节点已更新并重载配置' : '入站节点已创建并生效');
      if (state.page !== 'inbounds') {
        setPage('inbounds');
      } else {
        render();
        load('inbounds', { silent: true });
      }
    }
    else if (form.id === 'client-form') {
      const inboundId = form.dataset.inboundId;
      const clientId = form.dataset.clientId;
      const expiryMs = data.expiryTime ? new Date(data.expiryTime).getTime() : 0;
      if (data.username && data.password && data.username.trim() === data.password.trim()) {
        throw new Error('安全限制：用户的认证账号与认证密码不能相同，请点击随机密码重新生成');
      }
      const payload = {
        email: data.email,
        username: data.username,
        uuid: data.uuid,
        password: data.password,
        limitIp: Number(data.limitIp || 0),
        limitDevice: Number(data.limitDevice || 0),
        totalGB: Number(data.totalGB || 0),
        expiryTime: Number.isFinite(expiryMs) && expiryMs > 0 ? expiryMs : 0,
        enable: form.querySelector('[name="enable"]')?.checked !== false
      };
      const res = clientId
        ? await api(`/api/inbounds/${inboundId}/clients/${encodeURIComponent(clientId)}`, {
            method: 'PUT',
            body: JSON.stringify(payload)
          })
        : await api(`/api/inbounds/${inboundId}/clients`, {
            method: 'POST',
            body: JSON.stringify(payload)
          });
      if (!clientId) state.expandedInbounds.add(inboundId);
      closeModal();
      if (res && res.inbound) {
        const idx = state.inbounds.findIndex((x) => x.id === res.inbound.id);
        if (idx >= 0) state.inbounds[idx] = res.inbound;
      }
      toast(clientId ? '用户配置已更新并生效' : '新用户已添加至该节点并生效');
      render();
      load('inbounds', { silent: true });
    }
    else if (form.id === 'outbound-form') {
      const id = form.dataset.id;
      const isJsonTabActive = !$('#out-json-pane')?.classList.contains('hidden');
      const payload = {
        ...data,
        insecure: form.querySelector('[name="insecure"]')?.checked || false
      };
      if (isJsonTabActive && $('#out-json-textarea')?.value.trim()) {
        payload.rawJson = $('#out-json-textarea').value.trim();
      }
      const res = id
        ? await api(`/api/outbounds/${id}`, { method: 'PUT', body: JSON.stringify(payload) })
        : await api('/api/outbounds', { method: 'POST', body: JSON.stringify(payload) });
      closeModal();
      if (res && res.outbound) {
        const idx = state.outbounds.findIndex((x) => x.id === res.outbound.id);
        if (idx >= 0) state.outbounds[idx] = res.outbound;
        else state.outbounds.push(res.outbound);
      }
      toast(id ? '出站规则已更新' : '出站规则已添加');
      render();
      load('outbounds', { silent: true });
    }
    else if (form.id === 'import-uri-form') {
      const res = await api('/api/outbounds/import-uri', { method: 'POST', body: JSON.stringify(data) });
      closeModal();
      toast(`已成功解析并导入 ${res.count || 1} 个出站节点`);
      load('outbounds');
    }
    else if (form.id === 'cluster-node-form') {
      const id = form.dataset.id;
      const isExitLike = data.role === 'exit' || data.role === 'hybrid';
      const syncMode = data.standbySyncMode || 'on_change';
      const payload = {
        ...data,
        exitEnabled: isExitLike,
        standbySyncMode: syncMode,
        mirrorStandby: syncMode !== 'on_failover',
        autoFailover: Number(data.autoFailoverMinutes || 3) > 0,
        autoFailoverMinutes: Math.max(1, Number(data.autoFailoverMinutes || 3)),
        autoFailback: Boolean(form.querySelector('input[name="autoFailback"]')?.checked),
        fallbackExitNodeId: isExitLike ? (data.fallbackExitNodeId || '') : ''
      };
      if (!isExitLike) {
        delete payload.exitPort;
        delete payload.exitMethod;
        delete payload.exitPassword;
      }
      let res;
      if (id) {
        res = await api(`/api/cluster/nodes/${encodeURIComponent(id)}`, { method: 'PUT', body: JSON.stringify(payload) });
        if (res.node) {
          const idx = state.nodes.findIndex((x) => x.id === res.node.id);
          if (idx >= 0) state.nodes[idx] = { ...state.nodes[idx], ...res.node };
        }
        toast('✅ 集群服务器配置已更新');
      } else {
        res = await api('/api/cluster/nodes', { method: 'POST', body: JSON.stringify(payload) });
        if (res.node) {
          state.nodes.push(res.node);
        }
        toast(`✅ 已添加服务器 [${res.node?.name || payload.name}]！现在可在《入站节点管理》选择该服务器创建节点`);
      }
      if (Array.isArray(res?.outbounds)) {
        state.outbounds = res.outbounds;
      }
      closeModal();
      if (state.page !== 'cluster') {
        setPage('cluster');
      } else {
        render();
        load('cluster', { silent: true });
      }
    }
    else if (form.id === 'failover-form') {
      const primaryNodeId = form.dataset.primaryId;
      const res = await api('/api/cluster/failover', {
        method: 'POST',
        body: JSON.stringify({
          primaryNodeId,
          standbyNodeId: data.standbyNodeId,
          reason: data.reason
        })
      });
      closeModal();
      toast(`⚡ 容灾接管成功！${res.dns?.message || ''}`);
      load('cluster');
    }
    else if (form.id === 'rule-form') {
      const id = form.dataset.id;
      const payload = {
        ...data,
        ip_is_private: form.querySelector('[name="ip_is_private"]')?.checked || false
      };
      if (id) {
        await api(`/api/routing/rules/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
      } else {
        await api('/api/routing/rules', { method: 'POST', body: JSON.stringify(payload) });
      }
      closeModal();
      toast(id ? '路由规则已更新' : '路由规则已添加');
      load('routing');
    }
    else if (form.id === 'cert-selfsigned-form') {
      await api('/api/certificates/self-signed', {
        method: 'POST',
        body: JSON.stringify({
          domain: data.domain,
          applyToPanel: form.querySelector('[name="applyToPanel"]')?.checked || false
        })
      });
      closeModal();
      toast('10 年自签 SSL 证书已生成并自动绑定！');
      load('certificates');
    }
    else if (form.id === 'cert-acme-form') {
      toast('正在调用 ACME 申请证书，请稍候...');
      await api('/api/certificates/acme', { method: 'POST', body: JSON.stringify(data) });
      closeModal();
      toast('ACME 证书签发成功并已同步绑定至面板与全部节点！');
      load('certificates');
    }
    else if (form.id === 'cert-custom-form') {
      await api('/api/certificates/custom', { method: 'POST', body: JSON.stringify(data) });
      closeModal();
      toast('自定义证书已保存并绑定！');
      load('certificates');
    }
    else if (form.id === 'settings-form') {
      const takeoverSel = data.masterAutoTakeoverSelect || 'manual';
      const payload = {
        ...data,
        strictBasePath: form.querySelector('[name="strictBasePath"]')?.checked || false,
        masterAutoTakeover: takeoverSel !== 'manual',
        masterAutoTakeoverMinutes: takeoverSel !== 'manual' ? Number(takeoverSel || 3) : Number(state.settings?.masterAutoTakeoverMinutes || 3)
      };
      const res = await api('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
      toast('面板设置已保存');
      const nextBase = (res.settings?.webBasePath || '/').replace(/\/+$/, '');
      if (nextBase !== BASE_PATH) {
        setTimeout(() => { window.location.href = `${nextBase || ''}/`; }, 600);
      } else {
        load('settings');
      }
    }
    else if (form.id === 'account-form') {
      if (data.username && data.newPassword && data.username.trim() === data.newPassword.trim()) {
        throw new Error('安全策略限制：新登录密码不能与管理员账号相同');
      }
      await api('/api/auth/account', { method: 'POST', body: JSON.stringify(data) });
      toast('管理员账号与密码已更新，请重新登录');
      showLogin();
    }
    else if (form.id === 'restore-backup-form') {
      const restorePanelSettings = Boolean(form.querySelector('#restore-panel-settings-chk')?.checked);
      let res;
      if (state._pendingRestoreZipBuf) {
        toast('正在解压并恢复 .zip 全量主控灾备包（含证书、端口路径与全集群节点）...');
        res = await api(`/api/restore?restorePanelSettings=${restorePanelSettings}`, {
          method: 'POST',
          headers: { 'content-type': 'application/zip' },
          body: state._pendingRestoreZipBuf
        });
        state._pendingRestoreZipBuf = null;
      } else {
        const rawJson = (data.backupJson || '').trim();
        if (!rawJson) {
          throw new Error('请先点击上方选择 .zip / .json 备份文件，或粘贴备份内容');
        }
        let parsed;
        try {
          parsed = JSON.parse(rawJson);
        } catch {
          throw new Error('备份文件格式有误，请选择有效的 .zip 或 .json 备份文件');
        }
        toast('正在恢复全集群配置与节点数据...');
        res = await api('/api/restore', {
          method: 'POST',
          body: JSON.stringify({ backup: parsed, restorePanelSettings })
        });
      }
      closeModal();
      toast(`🎉 主控灾备恢复成功！端口:${res.restoredPort || state.settings?.webPort} 路径:${res.restoredBasePath || BASE_PATH} (${res.nodesCount || 0}台服务器 / ${res.inboundsCount || 0}个入站 / ${res.certificatesCount || 0}张证书)`);
      const nextPort = Number(res.restoredPort || window.location.port || 2053);
      const nextBase = (res.restoredBasePath || '/').replace(/\/+$/, '');
      if (res.restarting && (String(nextPort) !== String(window.location.port) || nextBase !== BASE_PATH)) {
        setTimeout(() => {
          window.location.href = `${window.location.protocol}//${window.location.hostname}:${nextPort}${nextBase || ''}/`;
        }, 700);
      } else {
        load('overview');
      }
    }
  } catch (err) {
    if (form.id === 'login-form') $('#login-error').textContent = err.message;
    else toast(err.message, true);
  } finally {
    delete form.dataset.submitting;
    if (submitBtn && submitBtn.isConnected) {
      submitBtn.disabled = false;
      if (origBtnText) submitBtn.textContent = origBtnText;
    }
  }
});

$('#refresh')?.addEventListener('click', () => load(state.page));
$('#quick-config-btn')?.addEventListener('click', async () => {
  try {
    const data = await api('/api/singbox/config');
    const jsonStr = JSON.stringify(data.config, null, 2);
    openModal('Sing-box 完整配置文件预览', data.status?.configPath || 'config.json', `
      <div class="stack">
        <div class="codebox">${esc(jsonStr)}</div>
        <div style="display:flex;justify-content:flex-end"><button class="primary" data-copy="${esc(jsonStr)}">复制完整 JSON 配置</button></div>
      </div>
    `);
  } catch (err) { toast(err.message, true); }
});
$('#logout')?.addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' }).catch(() => {});
  showLogin();
});
$('#menu-toggle')?.addEventListener('click', () => $('#app').classList.toggle('sidebar-open'));
$('#sidebar-scrim')?.addEventListener('click', () => $('#app').classList.remove('sidebar-open'));

// Boot application
(async () => {
  try {
    const savedTheme = localStorage.getItem('nexusgate-theme');
    setTheme(savedTheme || 'light');
  } catch { setTheme('light'); }

  try {
    const sess = await api('/api/auth/session');
    if (sess.authenticated) {
      state.session = sess;
      showApp();
      setPage(getSavedInitialPage());
      if (state.page !== 'overview') {
        api('/api/overview').then((ov) => {
          state.overview = ov;
          updateSidebarIndicator();
        }).catch(() => {});
      }
    } else {
      showLogin();
    }
  } catch {
    showLogin();
  }

  setInterval(() => {
    const activeTag = document.activeElement?.tagName || '';
    const isEditingField = ['INPUT', 'TEXTAREA', 'SELECT'].includes(activeTag);
    const recentlyScrolled = (Date.now() - Math.max(lastUserScrollAt, lastUserInteractAt)) < 3000;
    const hasOpenInlineQr = Boolean(document.querySelector('#content .subscription-qr:not(.hidden)'));
    if (
      state.session &&
      !$('#modal')?.open &&
      !isEditingField &&
      !recentlyScrolled &&
      !hasOpenInlineQr &&
      ['overview', 'inbounds', 'outbounds'].includes(state.page)
    ) {
      load(state.page, { silent: true });
    }
  }, 5000);
})();
