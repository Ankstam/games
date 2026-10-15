// config.js - 核心配置（纯直连低延迟版：完整保留原始优选 IP + 追加新测速 IP，禁用 ProxyIP）

export const DEFAULT_CONFIG = {
  // 你的 UUID（同时作为 VLESS UUID 和 Trojan 密码）
  userID: "55882903-c416-4c9b-b33e-2f561cacb077",

  // 面板访问密码
  SECRET_TOKEN: "fuckyou888999",

  // 伪装站点
  DISGUISE_URL: "https://developer.mozilla.org",

  // 【100% 原样保留】你原始的面板展示及优选节点地址
  CDNIP: "104.18.222.236",
  IP8: "104.18.222.236",
  IP9: "104.16.4.14",
  IP10: "172.66.3.135",
  IP11: "104.18.222.236",
  IP12: "104.16.4.14",
  IP13: "172.66.3.135",

  // 【100% 原样保留】你原始的端口配置
  PT8: "443",
  PT9: "8443",
  PT10: "2053",
  PT11: "2083",
  PT12: "2087",
  PT13: "2096",

  // 【完整保留】你测速截图中测出的 0% 丢包优质优选 IP（追加在原始节点之后）
  EXTRA_IPS: [
    { ip: "104.18.42.1", pt: "443", id: "V14_14MBs" },
    { ip: "104.18.43.1", pt: "443", id: "V15_15MBs" },
    { ip: "104.18.40.1", pt: "443", id: "V16_10MBs" },
    { ip: "162.159.38.1", pt: "443", id: "V17_6MBs" },
    { ip: "162.159.39.1", pt: "443", id: "V18_7MBs" },
    { ip: "104.17.35.1", pt: "443", id: "V19_4MBs" },
    { ip: "104.16.24.1", pt: "443", id: "V20_4MBs" },
    { ip: "104.18.41.1", pt: "443", id: "V21_4MBs" },
    { ip: "104.17.33.1", pt: "443", id: "V22_4MBs" },
  ],

  dohURL: "https://cloudflare-dns.com/dns-query",
};

/**
 * 0ms 纯同步构建运行配置（不使用任何 ProxyIP）
 */
export function loadRuntimeConfig(env = {}) {
  const cfg = {
    ...DEFAULT_CONFIG,
    EXTRA_IPS: [...(DEFAULT_CONFIG.EXTRA_IPS || [])],
  };

  cfg.userID = String(env.uuid || env.UUID || cfg.userID).trim();
  cfg.SECRET_TOKEN = String(env.token || env.TOKEN || cfg.SECRET_TOKEN);

  // 彻底禁用 ProxyIP，保持纯直连
  cfg.proxyIP = "";
  cfg.proxyPort = "";

  cfg.CDNIP = env.cdnip || cfg.CDNIP;

  for (const key of ["IP8", "IP9", "IP10", "IP11", "IP12", "IP13"]) {
    const envKey = key.toLowerCase();
    cfg[key] = env[envKey] || cfg[key];
  }

  for (const key of ["PT8", "PT9", "PT10", "PT11", "PT12", "PT13"]) {
    const envKey = key.toLowerCase();
    cfg[key] = env[envKey] || cfg[key];
  }

  return cfg;
}