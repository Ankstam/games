// protocol.js - VLESS / Trojan 协议解析

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}

export function isValidUUID(uuid) {
  // 宽松验证，兼容非标准 UUID
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

export function stringifyUUID(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

export function safeBase64Encode(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

export function processProtocolHeader(buffer, userID) {
  const bytes = new Uint8Array(buffer);

  // Trojan 检测
  if (buffer.byteLength >= 62 && bytes[56] === 0x0d && bytes[57] === 0x0a) {
    const uuids = userID.includes(",") ? userID.split(",") : [userID];
    const incomingHash = new TextDecoder().decode(buffer.slice(0, 56)).toLowerCase();
    const isTrojanUser = uuids.some((u) => sha224(u.trim()) === incomingHash);
    if (isTrojanUser) {
      return parseTrojanBuffer(buffer, bytes);
    }
  }

  return parseVlessBuffer(buffer, userID);
}

function parseVlessBuffer(cloudflareBuffer, userID) {
  if (cloudflareBuffer.byteLength < 24) {
    return { hasError: true, message: "invalid data" };
  }
  const version = new Uint8Array(cloudflareBuffer.slice(0, 1));
  const slicedBuffer = new Uint8Array(cloudflareBuffer.slice(1, 17));
  const slicedBufferString = stringifyUUID(slicedBuffer);

  const uuids = userID.includes(",") ? userID.split(",") : [userID];
  const isValidUser = uuids.some((userUuid) => slicedBufferString === userUuid.trim().toLowerCase());

  if (!isValidUser) {
    return { hasError: true, message: "invalid user" };
  }

  const optLength = new Uint8Array(cloudflareBuffer.slice(17, 18))[0];
  const command = new Uint8Array(cloudflareBuffer.slice(18 + optLength, 18 + optLength + 1))[0];

  let isUDP = false;
  if (command === 1) {
    isUDP = false;
  } else if (command === 2) {
    isUDP = true;
  } else {
    return { hasError: true, message: `command ${command} is not supported` };
  }

  const portIndex = 18 + optLength + 1;
  const portRemote = new DataView(cloudflareBuffer.slice(portIndex, portIndex + 2)).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressType = new Uint8Array(cloudflareBuffer.slice(addressIndex, addressIndex + 1))[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(cloudflareBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(cloudflareBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(cloudflareBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(cloudflareBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: `invalid addressType is ${addressType}` };
  }

  if (!addressValue) {
    return { hasError: true, message: `addressValue is empty` };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    cloudflareResponseHeader: new Uint8Array([version[0], 0]),
    isUDP,
  };
}

function parseTrojanBuffer(buffer, bytes) {
  const command = bytes[58];
  let isUDP = false;
  if (command === 1) {
    isUDP = false;
  } else if (command === 3) {
    isUDP = true;
  } else {
    return { hasError: true, message: `Trojan command ${command} not supported` };
  }

  const addressType = bytes[59];
  let offset = 60;
  let addressValue = "";
  const view = new DataView(buffer);

  switch (addressType) {
    case 1:
      addressValue = `${bytes[offset]}.${bytes[offset + 1]}.${bytes[offset + 2]}.${bytes[offset + 3]}`;
      offset += 4;
      break;
    case 3:
      const domainLen = bytes[offset];
      offset += 1;
      addressValue = new TextDecoder().decode(buffer.slice(offset, offset + domainLen));
      offset += domainLen;
      break;
    case 4:
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(view.getUint16(offset + i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      offset += 16;
      break;
    default:
      return { hasError: true, message: `invalid Trojan addressType ${addressType}` };
  }

  const portRemote = view.getUint16(offset);
  offset += 2;
  if (bytes[offset] === 0x0d && bytes[offset + 1] === 0x0a) {
    offset += 2;
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: offset,
    cloudflareResponseHeader: null,
    isUDP,
  };
}

export function sha224(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ];
  const H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const words = [];
  const asciiBitLength = ascii.length * 8;
  for (let i = 0; i < ascii.length; i++) {
    words[i >> 2] |= (ascii.charCodeAt(i) & 0xff) << (24 - (i % 4) * 8);
  }
  words[ascii.length >> 2] |= 0x80 << (24 - (ascii.length % 4) * 8);
  words[(((ascii.length + 8) >> 6) << 4) + 15] = asciiBitLength;

  const w = new Array(64);
  for (let j = 0; j < words.length; j += 16) {
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      if (i < 16) {
        w[i] = words[j + i] | 0;
      } else {
        const gamma0x = w[i - 15];
        const gamma0 = rightRotate(gamma0x, 7) ^ rightRotate(gamma0x, 18) ^ (gamma0x >>> 3);
        const gamma1x = w[i - 2];
        const gamma1 = rightRotate(gamma1x, 17) ^ rightRotate(gamma1x, 19) ^ (gamma1x >>> 10);
        w[i] = (w[i - 16] + gamma0 + w[i - 7] + gamma1) | 0;
      }
      const ch = (e & f) ^ (~e & g);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const sigma0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const sigma1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const t1 = (h + sigma1 + ch + K[i] + w[i]) | 0;
      const t2 = (sigma0 + maj) | 0;
      h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
    }
    H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
    H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
  }
  let hex = "";
  for (let i = 0; i < 7; i++) {
    for (let j = 3; j >= 0; j--) {
      const b = (H[i] >> (j * 8)) & 0xff;
      hex += (b < 16 ? "0" : "") + b.toString(16);
    }
  }
  return hex;
}
