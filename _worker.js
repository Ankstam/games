// _worker.js - 主入口（WS + XHTTP 双引擎 · C++ 零拷贝流管道防 CPU 超限版）
import { connect } from "cloudflare:sockets";
import { loadRuntimeConfig } from "./config.js";
import { isValidUUID, base64ToArrayBuffer, processProtocolHeader } from "./protocol.js";
import { getvlessConfig, gettyConfig, getxhttpConfig, getclConfig, getsbConfig } from "./sub.js";

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      // 0ms 纯同步加载配置
      const cfg = loadRuntimeConfig(env, url);

      if (!isValidUUID(cfg.userID)) {
        throw new Error("uuid is not valid");
      }

      const upgradeHeader = request.headers.get("Upgrade");
      const hostName = request.headers.get("Host") || url.hostname;

      // 非 WebSocket 请求
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== "websocket") {
        // 1. 拦截 XHTTP (stream-one) 代理流量
        if (request.method === "POST" && url.pathname.startsWith("/xhttp") && request.body) {
          return await vlessOverXHTTPHandler(request, cfg);
        }

        const token = url.searchParams.get("token");

        if (url.pathname.startsWith(`/${cfg.userID}`)) {
          if (token !== cfg.SECRET_TOKEN) {
            return await proxyDisguise(request, cfg.DISGUISE_URL);
          }
        }

        switch (url.pathname) {
          case `/${cfg.userID}`: {
            return new Response(getvlessConfig(cfg, hostName), {
              status: 200,
              headers: { "Content-Type": "text/html;charset=utf-8" },
            });
          }
          case `/${cfg.userID}/ty`:
          case `/${cfg.userID}/pty`: {
            return new Response(gettyConfig(cfg, hostName), {
              status: 200,
              headers: { "Content-Type": "text/plain;charset=utf-8" },
            });
          }
          case `/${cfg.userID}/xhttp`: {
            return new Response(getxhttpConfig(cfg, hostName), {
              status: 200,
              headers: { "Content-Type": "text/plain;charset=utf-8" },
            });
          }
          case `/${cfg.userID}/cl`:
          case `/${cfg.userID}/pcl`: {
            return new Response(getclConfig(cfg, hostName), {
              status: 200,
              headers: { "Content-Type": "text/plain;charset=utf-8" },
            });
          }
          case `/${cfg.userID}/sb`:
          case `/${cfg.userID}/psb`: {
            return new Response(getsbConfig(cfg, hostName), {
              status: 200,
              headers: { "Content-Type": "application/json;charset=utf-8" },
            });
          }
          default: {
            return await proxyDisguise(request, cfg.DISGUISE_URL);
          }
        }
      }

      // WebSocket 代理
      return await vlessOverWSHandler(request, cfg);
    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

async function proxyDisguise(request, disguiseUrl) {
  const url = new URL(request.url);
  const targetUrl = new URL(url.pathname + url.search, disguiseUrl);
  const headers = new Headers(request.headers);
  headers.set("Host", targetUrl.host);
  headers.set("Referer", targetUrl.origin);
  headers.delete("cf-connecting-ip");
  headers.delete("x-forwarded-for");
  headers.delete("x-real-ip");

  return await fetch(targetUrl.toString(), {
    method: request.method,
    headers,
    body: request.body,
    redirect: "follow",
  });
}

async function vlessOverWSHandler(request, cfg) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader);

  let remoteSocketWapper = { value: null, writer: null };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
          }
          if (remoteSocketWapper.writer) {
            await remoteSocketWapper.writer.write(chunk);
            return;
          }

          const {
            hasError,
            message,
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            cloudflareResponseHeader,
            isUDP,
          } = processProtocolHeader(chunk, cfg.userID);

          if (hasError) {
            throw new Error(message);
          }

          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              throw new Error("UDP proxy only enable for DNS which is port 53");
            }
          }

          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            const { write } = await handleUDPOutBound(webSocket, cloudflareResponseHeader, cfg.dohURL);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }

          await handleTCPOutBound(
            remoteSocketWapper,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            cloudflareResponseHeader
          );
        },
      })
    )
    .catch(() => {
      safeCloseWebSocket(webSocket);
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, cloudflareResponseHeader) {
  try {
    const tcpSocket = connect({ hostname: addressRemote, port: Number(portRemote) });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    remoteSocket.writer = writer;
    if (rawClientData.byteLength > 0) {
      await writer.write(rawClientData);
    }
    remoteSocketToWS(tcpSocket, webSocket, cloudflareResponseHeader);
  } catch {
    safeCloseWebSocket(webSocket);
  }
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (!readableStreamCancel) controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (!readableStreamCancel) controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },
    cancel() {
      if (readableStreamCancel) return;
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function remoteSocketToWS(remoteSocket, webSocket, cloudflareResponseHeader) {
  let cloudflareHeader = cloudflareResponseHeader;

  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            throw new Error("webSocket.readyState is not open");
          }
          if (cloudflareHeader) {
            const combined = new Uint8Array(cloudflareHeader.byteLength + chunk.byteLength);
            combined.set(new Uint8Array(cloudflareHeader), 0);
            combined.set(new Uint8Array(chunk), cloudflareHeader.byteLength);
            webSocket.send(combined.buffer);
            cloudflareHeader = null;
          } else {
            webSocket.send(chunk);
          }
        },
      })
    )
    .catch(() => {
      safeCloseWebSocket(webSocket);
    });
}

async function handleUDPOutBound(webSocket, cloudflareResponseHeader, dohURL) {
  let iscloudflareHeaderSent = !cloudflareResponseHeader;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const resp = await fetch(dohURL, {
            method: "POST",
            headers: { "content-type": "application/dns-message" },
            body: chunk,
          });
          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (iscloudflareHeaderSent) {
              const out = new Uint8Array(2 + udpSize);
              out.set(udpSizeBuffer, 0);
              out.set(new Uint8Array(dnsQueryResult), 2);
              webSocket.send(out.buffer);
            } else {
              const out = new Uint8Array(cloudflareResponseHeader.byteLength + 2 + udpSize);
              out.set(new Uint8Array(cloudflareResponseHeader), 0);
              out.set(udpSizeBuffer, cloudflareResponseHeader.byteLength);
              out.set(new Uint8Array(dnsQueryResult), cloudflareResponseHeader.byteLength + 2);
              webSocket.send(out.buffer);
              iscloudflareHeaderSent = true;
            }
          }
        },
      })
    )
    .catch(() => {});

  const writer = transformStream.writable.getWriter();
  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch {}
}

// ============================================================================
// XHTTP (SplitHTTP stream-one) 零拷贝引擎（消除 while 循环 CPU 超限与 waitUntil 警告）
// ============================================================================
async function vlessOverXHTTPHandler(request, cfg) {
  const reader = request.body.getReader();

  // 1. 仅在读取首包协议头（>= 24 字节）时使用 JS
  let firstChunk = new Uint8Array(0);
  try {
    while (firstChunk.byteLength < 24) {
      const { value, done } = await reader.read();
      if (done) break;
      if (value && value.byteLength > 0) {
        const merged = new Uint8Array(firstChunk.byteLength + value.byteLength);
        merged.set(firstChunk, 0);
        merged.set(value, firstChunk.byteLength);
        firstChunk = merged;
      }
    }
  } catch {
    try { reader.releaseLock(); } catch {}
    return new Response("Bad Request", { status: 400 });
  }

  const headerBuffer = firstChunk.buffer.slice(
    firstChunk.byteOffset,
    firstChunk.byteOffset + firstChunk.byteLength
  );

  const {
    hasError,
    message,
    portRemote = 443,
    addressRemote = "",
    rawDataIndex,
    cloudflareResponseHeader,
    isUDP,
  } = processProtocolHeader(headerBuffer, cfg.userID);

  if (hasError) {
    try { reader.releaseLock(); } catch {}
    return new Response(message, { status: 400 });
  }

  if (isUDP && portRemote !== 53) {
    try { reader.releaseLock(); } catch {}
    return new Response("UDP proxy only enabled for DNS port 53", { status: 400 });
  }

  const rawClientData = firstChunk.slice(rawDataIndex);

  // 原样匹配客户端发来的 Content-Type（如 application/grpc-web 或 application/grpc）
  const reqContentType = request.headers.get("content-type") || "";
  const respContentType = reqContentType.includes("grpc")
    ? reqContentType
    : "application/octet-stream";

  // 2. DNS (UDP 53) 请求处理
  if (isUDP && portRemote === 53) {
    const { readable, writable } = new TransformStream();
    const responseWriter = writable.getWriter();
    let cloudflareHeader = cloudflareResponseHeader;

    (async () => {
      try {
        const sendDnsQuery = async (chunkData) => {
          for (let index = 0; index + 2 <= chunkData.byteLength; ) {
            const udpPacketLength = new DataView(
              chunkData.buffer,
              chunkData.byteOffset + index,
              2
            ).getUint16(0);
            if (index + 2 + udpPacketLength > chunkData.byteLength) break;
            const udpData = chunkData.subarray(index + 2, index + 2 + udpPacketLength);
            index += 2 + udpPacketLength;

            const resp = await fetch(cfg.dohURL, {
              method: "POST",
              headers: { "content-type": "application/dns-message" },
              body: udpData,
            });
            const dnsResult = new Uint8Array(await resp.arrayBuffer());
            const udpSize = dnsResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (cloudflareHeader) {
              const out = new Uint8Array(cloudflareHeader.byteLength + 2 + udpSize);
              out.set(new Uint8Array(cloudflareHeader), 0);
              out.set(udpSizeBuffer, cloudflareHeader.byteLength);
              out.set(dnsResult, cloudflareHeader.byteLength + 2);
              await responseWriter.write(out);
              cloudflareHeader = null;
            } else {
              const out = new Uint8Array(2 + udpSize);
              out.set(udpSizeBuffer, 0);
              out.set(dnsResult, 2);
              await responseWriter.write(out);
            }
          }
        };

        if (rawClientData.byteLength > 0) {
          await sendDnsQuery(rawClientData);
        }
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          if (value && value.byteLength > 0) {
            await sendDnsQuery(value);
          }
        }
      } catch {} finally {
        try { reader.releaseLock(); } catch {}
        try { await responseWriter.close(); } catch {}
      }
    })();

    return new Response(readable, {
      status: 200,
      headers: {
        "Content-Type": respContentType,
        "X-Accel-Buffering": "no",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
      },
    });
  }

  // 3. 标准 TCP 流量：使用 C++ 原生 IdentityTransformStream + pipeTo 零拷贝转发（0 JS 循环开销）
  let tcpSocket;
  try {
    tcpSocket = connect({ hostname: addressRemote, port: Number(portRemote) });
  } catch {
    try { reader.releaseLock(); } catch {}
    return new Response("Connect Failed", { status: 502 });
  }

  // 客户端取消请求（outcome: "canceled"）时立即关闭底层 TCP Socket，杜绝后台悬挂
  if (request.signal) {
    request.signal.addEventListener(
      "abort",
      () => {
        try { tcpSocket.close(); } catch {}
      },
      { once: true }
    );
  }

  // 上行管道：写入首包剩余载荷后立即释放 JS 锁，交由底层 C++ pipeTo 直通转发
  (async () => {
    try {
      if (rawClientData.byteLength > 0) {
        const socketWriter = tcpSocket.writable.getWriter();
        await socketWriter.write(rawClientData);
        socketWriter.releaseLock();
      }
      reader.releaseLock();
      await request.body.pipeTo(tcpSocket.writable);
    } catch {
      try { tcpSocket.close(); } catch {}
    }
  })();

  // 下行管道：若无 VLESS 响应头（如 Trojan）直接返回底层 Socket 流；若有则写入 2 字节头后 C++ pipeTo 直通
  if (!cloudflareResponseHeader || cloudflareResponseHeader.byteLength === 0) {
    return new Response(tcpSocket.readable, {
      status: 200,
      headers: {
        "Content-Type": respContentType,
        "X-Accel-Buffering": "no",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Pragma": "no-cache",
      },
    });
  }

  const { readable, writable } =
    typeof IdentityTransformStream !== "undefined"
      ? new IdentityTransformStream()
      : new TransformStream();

  (async () => {
    try {
      const respWriter = writable.getWriter();
      await respWriter.write(new Uint8Array(cloudflareResponseHeader));
      respWriter.releaseLock();
      await tcpSocket.readable.pipeTo(writable);
    } catch {
      try { tcpSocket.close(); } catch {}
    }
  })();

  return new Response(readable, {
    status: 200,
    headers: {
      "Content-Type": respContentType,
      "X-Accel-Buffering": "no",
      "Cache-Control": "no-store, no-cache, must-revalidate",
      "Pragma": "no-cache",
    },
  });
}