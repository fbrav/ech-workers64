// ========== 基础常量 ==========
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const DEFAULT_FALLBACK_IP = '[2a00:1098:2b::1:6815:5881]'; // 可修改为你的默认兜底
const encoder = new TextEncoder();

import { connect } from 'cloudflare:sockets';

// ========== 静态配置（可选）==========
// 若希望静态设置，可在此处直接赋值：
// 例如：STATIC_ENABLE_SOCKS = 'socks5' 或 'http'，不设置请置为 null
const STATIC_ENABLE_SOCKS = null; // 'socks5' | 'http' | null
const STATIC_SOCKS_ADDRESS = null; // 示例: 'user:pass@proxy.example.com:1080' 或 '[2001:db8::1]:1080'
// 例如：STATIC_GLOBE_PROXY = ture 或 false
const STATIC_GLOBE_PROXY = false;

// ========== 运行时参数 ==========
let enableSocks = null;        // 'socks5' 或 'http'
let parsedSocksAddress = {};
let globeProxy = 0;            // 0 或 1

export default {
  async fetch(request, env, ctx) {
    try {
      const token = ''; // 可选：子协议 token 简易鉴权
      const upgradeHeader = request.headers.get('Upgrade');

      // 非 WebSocket 请求的响应
      if (!upgradeHeader || upgradeHeader.toLowerCase() !== 'websocket') {
        return new URL(request.url).pathname === '/' 
          ? new Response('WebSocket Proxy Server', { status: 200 })
          : new Response('Expected WebSocket', { status: 426 });
      }

      // 简易 token 校验
      if (token && request.headers.get('Sec-WebSocket-Protocol') !== token) {
        return new Response('Unauthorized', { status: 401 });
      }

      // 解析代理参数（优先级：静态配置 > 请求头）
      // 请求头示例：X-Socks5: user:pass@host:port 或 [ipv6]:port
      //           X-Http:   user:pass@host:port 或 [ipv6]:port
      //           X-GlobeProxy: 0 或 1
      //           X-Fallback-IP: 兜底域名或地址（含端口形式 [ipv6]:port 或 domain:port）
      const headerSocks = request.headers.get('X-Socks5');
      const headerHttp = request.headers.get('X-Http');
      const headerGlobe = request.headers.get('X-GlobeProxy');

      // 静态配置优先
      if (STATIC_ENABLE_SOCKS && STATIC_SOCKS_ADDRESS) {
        enableSocks = STATIC_ENABLE_SOCKS;
        parsedSocksAddress = await parseSocksAddress(STATIC_SOCKS_ADDRESS);
      } else if (headerSocks) {
        enableSocks = 'socks5';
        parsedSocksAddress = await parseSocksAddress(headerSocks);
      } else if (headerHttp) {
        enableSocks = 'http';
        parsedSocksAddress = await parseSocksAddress(headerHttp);
      } else {
        enableSocks = null;
        parsedSocksAddress = {};
      }

      // globeProxy
      if (typeof STATIC_GLOBE_PROXY === 'number') {
        globeProxy = STATIC_GLOBE_PROXY === 1 ? 1 : 0;
      } else if (headerGlobe) {
        globeProxy = parseInt(headerGlobe, 10) === 1 ? 1 : 0;
      } else {
        globeProxy = 0;
      }

      // 确定 fallbackIP（优先：请求头 -> colo 拼接 -> 默认静态）
      const fallbackIP = request.headers.get('X-Fallback-IP') 
        || (request.cf?.colo ? `${request.cf.colo}.PrOxYip.CmLiuSsSs.nEt` : DEFAULT_FALLBACK_IP);

      const [client, server] = Object.values(new WebSocketPair());
      server.accept();

      handleSession(server, request, fallbackIP).catch(() => safeCloseWebSocket(server));

      const responseInit = { status: 101, webSocket: client };
      if (token) responseInit.headers = { 'Sec-WebSocket-Protocol': token };

      return new Response(null, responseInit);

    } catch (err) {
      return new Response(err.toString(), { status: 500 });
    }
  },
};

// ========== 会话与连接逻辑 ==========
async function handleSession(webSocket, request, fallbackIP) {
  let remoteSocket, remoteWriter, remoteReader;
  let isClosed = false;

  const cleanup = () => {
    if (isClosed) return;
    isClosed = true;
    try { remoteWriter?.releaseLock(); } catch {}
    try { remoteReader?.releaseLock(); } catch {}
    try { remoteSocket?.close(); } catch {}
    remoteWriter = remoteReader = remoteSocket = null;
    safeCloseWebSocket(webSocket);
  };

  const pumpRemoteToWebSocket = async () => {
    try {
      while (!isClosed && remoteReader) {
        const { done, value } = await remoteReader.read();
        if (done) break;
        if (webSocket.readyState !== WS_READY_STATE_OPEN) break;
        if (value?.byteLength > 0) webSocket.send(value);
      }
    } catch {}
    if (!isClosed) {
      try { webSocket.send('CLOSE'); } catch {}
      cleanup();
    }
  };

  const parseAddress = (addr) => {
    if (addr[0] === '[') {
      const end = addr.indexOf(']');
      return { host: addr.substring(1, end), port: parseInt(addr.substring(end + 2), 10) };
    }
    const sep = addr.lastIndexOf(':');
    return { host: addr.substring(0, sep), port: parseInt(addr.substring(sep + 1), 10) };
  };

  const connectToRemote = async (targetAddr, firstFrameData) => {
    const { host, port } = parseAddress(targetAddr);

    // 构造尝试列表（按需求定义的三种模式）
    let attempts = [];
    if (!enableSocks) {
      // 无 socks/http → 原始地址 + fallback
      attempts = [host, fallbackIP];
    } else if (globeProxy === 0) {
      // 有 socks/http 且 globeProxy=0 → 原始地址 + socks/http + fallback
      attempts = [host, 'socks', 'http', fallbackIP];
    } else {
      // 有 socks/http 且 globeProxy=1 → 只走 socks/http
      attempts = ['socks', 'http'];
    }

    for (let i = 0; i < attempts.length; i++) {
      try {
        if (attempts[i] === 'socks') {
          if (enableSocks === 'socks5') {
            remoteSocket = await socks5Connect(2, host, port, parsedSocksAddress); // addressType=2(域名)更通用
          } else {
            continue; // 当前未选择 socks5
          }
        } else if (attempts[i] === 'http') {
          if (enableSocks === 'http') {
            remoteSocket = await httpConnect(2, host, port, parsedSocksAddress);
          } else {
            continue; // 当前未选择 http
          }
        } else {
          // 直接连接（原始目标或 fallbackIP）
          remoteSocket = connect({ hostname: attempts[i], port });
          if (remoteSocket.opened) await remoteSocket.opened;
        }

        remoteWriter = remoteSocket.writable.getWriter();
        remoteReader = remoteSocket.readable.getReader();

        // 首帧数据（文本）写入
        if (firstFrameData) {
          await remoteWriter.write(encoder.encode(firstFrameData));
        }

        webSocket.send('CONNECTED');
        pumpRemoteToWebSocket();
        return;

      } catch (err) {
        // 清理失败的连接并尝试下一个
        try { remoteWriter?.releaseLock(); } catch {}
        try { remoteReader?.releaseLock(); } catch {}
        try { remoteSocket?.close(); } catch {}
        remoteWriter = remoteReader = remoteSocket = null;

        if (i === attempts.length - 1) {
          throw err;
        }
      }
    }
  };

  webSocket.addEventListener('message', async (event) => {
    if (isClosed) return;
    try {
      const data = event.data;
      if (typeof data === 'string') {
        if (data.startsWith('CONNECT:')) {
          const sep = data.indexOf('|', 8);
          await connectToRemote(data.substring(8, sep), data.substring(sep + 1));
        } else if (data.startsWith('DATA:')) {
          if (remoteWriter) await remoteWriter.write(encoder.encode(data.substring(5)));
        } else if (data === 'CLOSE') {
          cleanup();
        }
      } else if (data instanceof ArrayBuffer && remoteWriter) {
        await remoteWriter.write(new Uint8Array(data));
      }
    } catch (err) {
      try { webSocket.send('ERROR:' + err.message); } catch {}
      cleanup();
    }
  });

  webSocket.addEventListener('close', cleanup);
  webSocket.addEventListener('error', cleanup);
}

function safeCloseWebSocket(ws) {
  try {
    if (ws.readyState === WS_READY_STATE_OPEN || ws.readyState === WS_READY_STATE_CLOSING) {
      ws.close(1000, 'Server closed');
    }
  } catch {}
}

// ========== SOCKS5 & HTTP 代理函数（移植自 work.js，并做了边缘适配） ==========

async function socks5Connect(addressType, addressRemote, portRemote, parsedSocks5Address) {
  const { username, password, hostname, port } = parsedSocks5Address;
  if (!hostname || !port) throw new Error('SOCKS5 代理未配置完整');

  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const te = new TextEncoder();

  // 1) 方法协商：支持 无认证(0) 与 用户名密码(2)
  await writer.write(new Uint8Array([5, 2, 0, 2]));
  let res = (await reader.read()).value;
  if (!res || res[0] !== 0x05) throw new Error('SOCKS5 协议错误或无响应');

  // 2) 认证
  if (res[1] === 0x02) {
    if (!username || !password) throw new Error('请提供 SOCKS5 用户名/密码');
    const authRequest = new Uint8Array([1, username.length, ...te.encode(username), password.length, ...te.encode(password)]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (!res || res[0] !== 0x01 || res[1] !== 0x00) throw new Error('SOCKS5 认证失败');
  } else if (res[1] !== 0x00) {
    throw new Error('SOCKS5 不支持的认证方式');
  }

  // 3) CONNECT 请求：根据 addressType 构造 DSTADDR
  let DSTADDR;
  if (addressType === 1) {
    DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
  } else if (addressType === 2) {
    DSTADDR = new Uint8Array([3, addressRemote.length, ...te.encode(addressRemote)]);
  } else if (addressType === 3) {
    // 简化的 IPv6 打包（按 16 字节）：需要传入规范化的 full form
    const parts = addressRemote.split(':').map(x => x.padStart(4, '0'));
    const bytes = [];
    for (const p of parts) {
      const hi = parseInt(p.slice(0, 2), 16);
      const lo = parseInt(p.slice(2), 16);
      bytes.push(hi, lo);
    }
    DSTADDR = new Uint8Array([4, ...bytes]);
  } else {
    throw new Error(`无效的地址类型: ${addressType}`);
  }

  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, (portRemote >> 8) & 0xff, portRemote & 0xff]);
  await writer.write(socksRequest);
  res = (await reader.read()).value;
  if (!res || res[1] !== 0x00) throw new Error('SOCKS5 目标连接失败');

  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

async function httpConnect(addressType, addressRemote, portRemote, parsedSocks5Address) {
  const { username, password, hostname, port } = parsedSocks5Address;
  if (!hostname || !port) throw new Error('HTTP 代理未配置完整');

  const sock = await connect({ hostname, port });

  // 构建 HTTP CONNECT 请求
  let connectRequest = `CONNECT ${addressRemote}:${portRemote} HTTP/1.1\r\n`;
  connectRequest += `Host: ${addressRemote}:${portRemote}\r\n`;
  if (username && password) {
    const base64Auth = btoa(`${username}:${password}`);
    connectRequest += `Proxy-Authorization: Basic ${base64Auth}\r\n`;
  }
  connectRequest += `User-Agent: Mozilla/5.0\r\n`;
  connectRequest += `Proxy-Connection: Keep-Alive\r\n`;
  connectRequest += `Connection: Keep-Alive\r\n`;
  connectRequest += `\r\n`;

  try {
    const writer = sock.writable.getWriter();
    await writer.write(new TextEncoder().encode(connectRequest));
    writer.releaseLock();
  } catch (err) {
    throw new Error(`发送 HTTP CONNECT 请求失败: ${err.message}`);
  }

  // 读取响应，判断是否 200
  const reader = sock.readable.getReader();
  let responseBuffer = new Uint8Array(0);
  let connected = false;

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) throw new Error('HTTP 代理连接中断');

      const newBuffer = new Uint8Array(responseBuffer.length + value.length);
      newBuffer.set(responseBuffer);
      newBuffer.set(value, responseBuffer.length);
      responseBuffer = newBuffer;

      const respText = new TextDecoder().decode(responseBuffer);
      if (respText.includes('\r\n\r\n')) {
        const firstLine = respText.split('\r\n')[0];
        if (firstLine.startsWith('HTTP/1.1 200') || firstLine.startsWith('HTTP/1.0 200')) {
          connected = true;
        } else {
          throw new Error(`HTTP 代理连接失败: ${firstLine}`);
        }
        break;
      }
    }
  } catch (err) {
    reader.releaseLock();
    throw new Error(`处理 HTTP 代理响应失败: ${err.message}`);
  }

  reader.releaseLock();

  if (!connected) {
    throw new Error('HTTP 代理连接失败: 未收到成功响应');
  }

  return sock;
}

// ========== 解析客户端提供的代理地址（移植自 work.js 的 获取SOCKS5账号） ==========
async function parseSocksAddress(address) {
  const lastAtIndex = address.lastIndexOf("@");
  let latter, former;
  if (lastAtIndex === -1) {
    latter = address;
    former = undefined;
  } else {
    latter = address.substring(lastAtIndex + 1);
    former = address.substring(0, lastAtIndex);
  }

  let username, password, hostname, port;

  // 认证部分
  if (former) {
    const formers = former.split(":");
    if (formers.length !== 2) {
      throw new Error('无效的代理地址：认证部分必须是 "username:password"');
    }
    [username, password] = formers;
  }

  // 主机端口部分
  const latters = latter.split(":");
  if (latters.length > 2 && latter.includes("]:")) {
    port = Number(latter.split("]:")[1].replace(/[^\d]/g, ''));
    hostname = latter.split("]:")[0] + "]";
  } else if (latters.length === 2) {
    port = Number(latters.pop().replace(/[^\d]/g, ''));
    hostname = latters.join(":");
  } else {
    port = 80;
    hostname = latter;
  }

  if (isNaN(port)) {
    throw new Error('无效的代理地址：端口号必须是数字');
  }

  // IPv6 校验：必须用 []
  const ipv6Bracket = /^\[.*\]$/;
  if (hostname.includes(":") && !ipv6Bracket.test(hostname)) {
    throw new Error('无效的代理地址：IPv6 必须用 []，如 [2001:db8::1]');
  }

  return { username, password, hostname, port };
}
