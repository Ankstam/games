// sub.js - 面板与订阅生成（纯直连低延迟版：同时输出原始 IP8~IP13 与新增 EXTRA_IPS 节点）
import { safeBase64Encode } from "./protocol.js";

const XHTTP_EXTRA_CONFIG = JSON.stringify({
  xPaddingBytes: "100-1000",
  noGRPCHeader: false,
  xmux: {
    maxConcurrency: "16-32",
    maxConnections: 0,
    cMaxReuseTimes: 0,
    hMaxRequestTimes: "600-900",
    hMaxReusableSecs: "1800-3000",
    hKeepAlivePeriod: 0,
  },
});

function getAllEndpoints(cfg) {
  const { IP8, IP9, IP10, IP11, IP12, IP13, PT8, PT9, PT10, PT11, PT12, PT13, EXTRA_IPS = [] } = cfg;
  const originalEndpoints = [
    { ip: IP8, pt: PT8, id: "V8" },
    { ip: IP9, pt: PT9, id: "V9" },
    { ip: IP10, pt: PT10, id: "V10" },
    { ip: IP11, pt: PT11, id: "V11" },
    { ip: IP12, pt: PT12, id: "V12" },
    { ip: IP13, pt: PT13, id: "V13" },
  ];
  return [...originalEndpoints, ...EXTRA_IPS];
}

function buildWSNodeList(cfg, hostName) {
  const { userID, IP8, IP9, IP10 } = cfg;
  const endpoints = getAllEndpoints(cfg);

  const domainNodes = [
    `vless://${userID}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=chrome&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}_VLESS_WS`,
    `trojan://${userID}@${hostName}:443?security=tls&sni=${hostName}&fp=chrome&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#${hostName}_Trojan_WS`
  ];

  const vlessLines = endpoints.map(
    (e) =>
      `vless://${userID}@${e.ip}:${e.pt}?encryption=none&security=tls&sni=${hostName}&fp=chrome&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_WS_${e.id}_${e.ip}_${e.pt}`
  );

  const trojanLines = [IP8, IP9, IP10].map(
    (ip, idx) =>
      `trojan://${userID}@${ip}:443?security=tls&sni=${hostName}&fp=chrome&type=ws&host=${hostName}&path=%2F%3Fed%3D2560#CF_Trojan_WS${idx + 1}_${ip}_443`
  );

  return [...domainNodes, ...vlessLines, ...trojanLines];
}

function buildXHTTPNodeList(cfg, hostName) {
  const { userID, IP8, IP9, IP10 } = cfg;
  const endpoints = getAllEndpoints(cfg);
  const extraParam = encodeURIComponent(XHTTP_EXTRA_CONFIG);

  const domainNodes = [
    `vless://${userID}@${hostName}:443?encryption=none&security=tls&sni=${hostName}&fp=chrome&alpn=h2&type=xhttp&host=${hostName}&path=%2Fxhttp&mode=stream-one&extra=${extraParam}#${hostName}_VLESS_XHTTP`,
    `trojan://${userID}@${hostName}:443?security=tls&sni=${hostName}&fp=chrome&alpn=h2&type=xhttp&host=${hostName}&path=%2Fxhttp&mode=stream-one&extra=${extraParam}#${hostName}_Trojan_XHTTP`
  ];

  const xhttpVlessLines = endpoints.map(
    (e) =>
      `vless://${userID}@${e.ip}:${e.pt}?encryption=none&security=tls&sni=${hostName}&fp=chrome&alpn=h2&type=xhttp&host=${hostName}&path=%2Fxhttp&mode=stream-one&extra=${extraParam}#CF_XHTTP_${e.id}_${e.ip}_${e.pt}`
  );

  const xhttpTrojanLines = [IP8, IP9, IP10].map(
    (ip, idx) =>
      `trojan://${userID}@${ip}:443?security=tls&sni=${hostName}&fp=chrome&alpn=h2&type=xhttp&host=${hostName}&path=%2Fxhttp&mode=stream-one&extra=${extraParam}#CF_Trojan_XHTTP${idx + 1}_${ip}_443`
  );

  return [...domainNodes, ...xhttpVlessLines, ...xhttpTrojanLines];
}

function buildNodeList(cfg, hostName) {
  return [...buildWSNodeList(cfg, hostName), ...buildXHTTPNodeList(cfg, hostName)].join("\n");
}

export function gettyConfig(cfg, hostName) {
  return safeBase64Encode(buildNodeList(cfg, hostName));
}

export function getxhttpConfig(cfg, hostName) {
  return safeBase64Encode(buildXHTTPNodeList(cfg, hostName).join("\n"));
}

function escapeAttr(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

export function getvlessConfig(cfg, hostName) {
  const { userID, SECRET_TOKEN } = cfg;
  const tokenParam = SECRET_TOKEN ? `?token=${SECRET_TOKEN}` : "";
  const extraParam = encodeURIComponent(XHTTP_EXTRA_CONFIG);

  const pvlesswstls = `vless://${userID}@${hostName}:443?encryption=none&security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=chrome&path=%2F%3Fed%3D2560#${hostName}_VLESS_WS`;
  const ptrojanwstls = `trojan://${userID}@${hostName}:443?security=tls&type=ws&host=${hostName}&sni=${hostName}&fp=chrome&path=%2F%3Fed%3D2560#${hostName}_Trojan_WS`;

  const pvlessxhttp = `vless://${userID}@${hostName}:443?encryption=none&security=tls&type=xhttp&host=${hostName}&sni=${hostName}&fp=chrome&alpn=h2&path=%2Fxhttp&mode=stream-one&extra=${extraParam}#${hostName}_VLESS_XHTTP`;
  const ptrojanxhttp = `trojan://${userID}@${hostName}:443?security=tls&type=xhttp&host=${hostName}&sni=${hostName}&fp=chrome&alpn=h2&path=%2Fxhttp&mode=stream-one&extra=${extraParam}#${hostName}_Trojan_XHTTP`;

  const ty = `https://${hostName}/${userID}/ty${tokenParam}`;
  const xhttpSub = `https://${hostName}/${userID}/xhttp${tokenParam}`;
  const cl = `https://${hostName}/${userID}/cl${tokenParam}`;
  const sb = `https://${hostName}/${userID}/sb${tokenParam}`;
  const allNodes = gettyConfig(cfg, hostName);
  const onlyXhttpNodes = getxhttpConfig(cfg, hostName);

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cloudflare 节点管理面板</title>
<link href="[https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css](https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css)" rel="stylesheet">
<style>
  body { background-color: #f8f9fa; }
  .card { border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); margin-bottom: 1.5rem; }
  .code-box {
    max-width: 100%;
    word-break: break-all;
    background: #f1f3f5;
    padding: 6px 10px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 0.85rem;
    max-height: 68px;
    overflow-y: auto;
  }
  .btn-copy { min-width: 82px; transition: all 0.2s ease; }
</style>
<script>
function handleCopy(btn) {
  const text = btn.getAttribute('data-clip') || '';
  if (!text) return;

  const originalHtml = btn.getAttribute('data-orig') || btn.innerHTML;
  if (!btn.getAttribute('data-orig')) {
    btn.setAttribute('data-orig', originalHtml);
  }

  const showSuccess = () => {
    btn.innerHTML = '✅ 已复制';
    btn.classList.add('btn-dark');
    if (btn._timer) clearTimeout(btn._timer);
    btn._timer = setTimeout(() => {
      btn.innerHTML = originalHtml;
      btn.classList.remove('btn-dark');
    }, 1500);
  };

  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(showSuccess).catch(() => fallbackCopy(text, showSuccess));
  } else {
    fallbackCopy(text, showSuccess);
  }
}

function fallbackCopy(text, callback) {
  const textarea = document.createElement('textarea');
  textarea.value = text;
  textarea.style.position = 'fixed';
  textarea.style.opacity = '0';
  document.body.appendChild(textarea);
  textarea.select();
  try { document.execCommand('copy'); callback(); } catch (e) {}
  document.body.removeChild(textarea);
}
</script>
</head>
<body>
<div class="container py-4">
  <div class="d-flex justify-content-between align-items-center flex-wrap mb-3">
    <h3 class="mb-0 fw-bold">Cloudflare 纯 TLS 节点面板（WS + XHTTP 双引擎）</h3>
    <span class="badge bg-success mt-2 mt-sm-0 p-2">
      当前模式：纯直连低延迟（已禁用 ProxyIP）
    </span>
  </div>

  <!-- 1. WebSocket 节点区 -->
  <div class="card">
    <div class="card-header bg-white d-flex justify-content-between align-items-center">
      <h5 class="mb-0">1. WebSocket (WS) 推荐单节点</h5>
      <span class="badge bg-primary">全客户端通用（v2rayN / Clash / Sing-box / 小火箭）</span>
    </div>
    <div class="card-body p-0">
      <table class="table table-bordered align-middle mb-0">
        <tr>
          <td style="width: 140px;"><strong>VLESS-WS</strong></td>
          <td><div class="code-box">${escapeAttr(pvlesswstls)}</div></td>
          <td style="width: 100px;" class="text-center">
            <button class="btn btn-primary btn-sm btn-copy" data-clip="${escapeAttr(pvlesswstls)}" onclick="handleCopy(this)">复制</button>
          </td>
        </tr>
        <tr>
          <td><strong>Trojan-WS</strong></td>
          <td><div class="code-box">${escapeAttr(ptrojanwstls)}</div></td>
          <td class="text-center">
            <button class="btn btn-success btn-sm btn-copy" data-clip="${escapeAttr(ptrojanwstls)}" onclick="handleCopy(this)">复制</button>
          </td>
        </tr>
      </table>
    </div>
  </div>

  <!-- 2. XHTTP 节点区 -->
  <div class="card">
    <div class="card-header bg-white d-flex justify-content-between align-items-center">
      <h5 class="mb-0">2. XHTTP (stream-one) 推荐单节点</h5>
      <span class="badge bg-warning text-dark">已内置 XMUX 与 Padding 优化（v2rayN / v2rayNG / 小火箭）</span>
    </div>
    <div class="card-body p-0">
      <table class="table table-bordered align-middle mb-0">
        <tr>
          <td style="width: 140px;"><strong>VLESS-XHTTP</strong></td>
          <td><div class="code-box">${escapeAttr(pvlessxhttp)}</div></td>
          <td style="width: 100px;" class="text-center">
            <button class="btn btn-warning btn-sm btn-copy" data-clip="${escapeAttr(pvlessxhttp)}" onclick="handleCopy(this)">复制</button>
          </td>
        </tr>
        <tr>
          <td><strong>Trojan-XHTTP</strong></td>
          <td><div class="code-box">${escapeAttr(ptrojanxhttp)}</div></td>
          <td class="text-center">
            <button class="btn btn-warning btn-sm btn-copy" data-clip="${escapeAttr(ptrojanxhttp)}" onclick="handleCopy(this)">复制</button>
          </td>
        </tr>
      </table>
    </div>
  </div>

  <!-- 3. 订阅链接区 -->
  <div class="card">
    <div class="card-header bg-white">
      <h5 class="mb-0">3. 聚合订阅链接（含原始 V8~V13 + 新增 V14~V22 优选节点）</h5>
    </div>
    <div class="card-body p-0">
      <table class="table table-bordered align-middle mb-0">
        <tr>
          <th style="width: 200px;">批量复制 Base64 节点</th>
          <td>
            <button class="btn btn-outline-primary btn-sm btn-copy me-2" data-clip="${escapeAttr(allNodes)}" onclick="handleCopy(this)">复制全部 (WS + XHTTP)</button>
            <button class="btn btn-outline-warning btn-sm btn-copy text-dark" data-clip="${escapeAttr(onlyXhttpNodes)}" onclick="handleCopy(this)">仅复制 XHTTP 节点</button>
          </td>
          <td style="width: 100px;" class="text-center text-muted small">剪贴板导入</td>
        </tr>
        <tr>
          <th>通用订阅（WS + XHTTP）</th>
          <td><div class="code-box">${escapeAttr(ty)}</div></td>
          <td class="text-center">
            <button class="btn btn-primary btn-sm btn-copy" data-clip="${escapeAttr(ty)}" onclick="handleCopy(this)">复制</button>
          </td>
        </tr>
        <tr>
          <th>XHTTP 独立订阅</th>
          <td><div class="code-box">${escapeAttr(xhttpSub)}</div></td>
          <td class="text-center">
            <button class="btn btn-warning btn-sm btn-copy" data-clip="${escapeAttr(xhttpSub)}" onclick="handleCopy(this)">复制</button>
          </td>
        </tr>
        <tr>
          <th>Clash 订阅（纯 WS）</th>
          <td><div class="code-box">${escapeAttr(cl)}</div></td>
          <td class="text-center">
            <button class="btn btn-primary btn-sm btn-copy" data-clip="${escapeAttr(cl)}" onclick="handleCopy(this)">复制</button>
          </td>
        </tr>
        <tr>
          <th>Sing-box 订阅（纯 WS）</th>
          <td><div class="code-box">${escapeAttr(sb)}</div></td>
          <td class="text-center">
            <button class="btn btn-primary btn-sm btn-copy" data-clip="${escapeAttr(sb)}" onclick="handleCopy(this)">复制</button>
          </td>
        </tr>
      </table>
    </div>
  </div>
</div>
</body>
</html>`;
}

export function getclConfig(cfg, hostName) {
  const { userID } = cfg;
  const clean = (ip) => String(ip).replace(/[\[\]]/g, "");
  const endpoints = getAllEndpoints(cfg);

  const proxyBlocks = endpoints
    .map(
      (e) => `- name: CF_${e.id}_${e.ip}_${e.pt}
  type: vless
  server: ${clean(e.ip)}
  port: ${e.pt}
  uuid: ${userID}
  udp: true
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}`
    )
    .join("\n\n");

  const proxyNames = endpoints
    .map((e) => `    - CF_${e.id}_${e.ip}_${e.pt}`)
    .join("\n");

  return `port: 7890
allow-lan: true
mode: rule
log-level: info
unified-delay: true
global-client-fingerprint: chrome
dns:
  enable: false
proxies:
- name: ${hostName}_VLESS
  type: vless
  server: ${hostName}
  port: 443
  uuid: ${userID}
  udp: true
  tls: true
  network: ws
  servername: ${hostName}
  ws-opts:
    path: "/?ed=2560"
    headers:
      Host: ${hostName}

${proxyBlocks}

proxy-groups:
- name: 自动选择
  type: url-test
  url: [https://www.gstatic.com/generate_204](https://www.gstatic.com/generate_204)
  interval: 300
  tolerance: 50
  proxies:
    - ${hostName}_VLESS
${proxyNames}

- name: 🌍选择代理
  type: select
  proxies:
    - 自动选择
    - DIRECT
    - ${hostName}_VLESS
${proxyNames}

rules:
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,🌍选择代理`;
}

export function getsbConfig(cfg, hostName) {
  const { userID } = cfg;
  const endpoints = getAllEndpoints(cfg);

  const outbounds = [
    {
      server: hostName,
      server_port: 443,
      tag: `${hostName}_VLESS`,
      type: "vless",
      uuid: userID,
      tls: {
        enabled: true,
        server_name: hostName,
        insecure: false,
        utls: { enabled: true, fingerprint: "chrome" },
      },
      transport: {
        type: "ws",
        path: "/?ed=2560",
        headers: { Host: [hostName] },
      },
    },
    ...endpoints.map((item) => ({
      server: item.ip,
      server_port: Number(item.pt),
      tag: `CF_${item.id}_${item.ip}_${item.pt}`,
      type: "vless",
      uuid: userID,
      tls: {
        enabled: true,
        server_name: hostName,
        insecure: false,
        utls: { enabled: true, fingerprint: "chrome" },
      },
      transport: {
        type: "ws",
        path: "/?ed=2560",
        headers: { Host: [hostName] },
      },
    })),
  ];

  const tags = outbounds.map((o) => o.tag);

  return JSON.stringify({
    log: { level: "info", timestamp: true },
    inbounds: [
      {
        type: "tun",
        tag: "tun-in",
        address: ["172.19.0.1/30", "fd00::1/126"],
        auto_route: true,
        strict_route: true,
        sniff: true,
      },
    ],
    outbounds: [
      {
        tag: "select",
        type: "selector",
        default: "auto",
        outbounds: ["auto", ...tags],
      },
      ...outbounds,
      { tag: "direct", type: "direct" },
      {
        tag: "auto",
        type: "urltest",
        outbounds: tags,
        url: "[https://www.gstatic.com/generate_204](https://www.gstatic.com/generate_204)",
        interval: "1m",
        tolerance: 50,
      },
    ],
  }, null, 2);
}
