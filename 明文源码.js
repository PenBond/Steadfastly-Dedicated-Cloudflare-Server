import { connect } from "cloudflare:sockets";

// Variable Declarations
let password = '';
let proxyIp = '';
let subscriptionConverter = atob('U1VCQVBJLkNNTGl1c3Nzcy5uZXQ='); // Decodes to "SUBAPI.CMLiussss.net"
let subscriptionConfig = atob('aHR0cHM6Ly9yYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tL0FDTDRTU1IvQUNMNFNTUi9tYXN0ZXIvQ2xhc2gvY29uZmlnL0FDTDRTU1JfT25saW5lX01pbmlfTXVsdGlNb2RlLmluaQ=='); // Decodes to a GitHub config URL
let subscriptionProtocol = 'https';
let includeEmoji = 'true';
let socks5Address = '';
let parsedSocks5 = {};
let enableSocks = false;

// DNS configuration
let dohURL = 'https://1.1.1.1/dns-query';
const doh = 'https://1.1.1.1/dns-query';
const dohjson = 'https://1.1.1.1/dns-query';
const contype = 'application/dns-message';
const jstontype = 'application/dns-json';
const r404 = new Response(null, { status: 404 });

const expirationTimestamp = 4102329600; // December 31, 2099
let proxyIps;
let socks5List;
let socks5Patterns = [
    '*ttvnw.net',
    '*tapecontent.net',
    '*cloudatacdn.com',
    '*.loadshare.org',
];
let addresses = [];
let apiAddresses = [];
let csvAddresses = [];
let downloadSpeedLimit = 8;
let remarkColumnIndex = 1; // Offset for remarks column in CSV
let subscriptionFileName = 'epeius';
let botToken = '';
let chatId = '';
let proxyHosts = [];
let proxyHostsUrl = '';
let useRandomProxyIp = 'false';
let httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
let sha224Password;
const addressRegex = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[.*\]):?(\d+)?#?(.*)?$/;
let proxyIpPool = [];
let websocketPath = '/?ed=2560';
let links = [];
let bannedHosts = [atob('c3BlZWQuY2xvdWRmbGFyZS5jb20=')]; // Decodes to "speed.cloudflare.com"

// Main Fetch Handler
export default {
    async fetch(request, env, ctx) {
        try {
            const userAgent = (request.headers.get('User-Agent') || 'null').toLowerCase();
            password = env.PASSWORD || env.pswd || env.UUID || env.uuid || env.TOKEN || password;
            if (!password) {
                return new Response('Please set your PASSWORD variable, or try redeploying to check if the variable is effective.', {
                    status: 404,
                    headers: { "Content-Type": "text/plain;charset=utf-8" }
                });
            }
            sha224Password = env.SHA224 || env.SHA224PASS || sha224(password);

            const currentDate = new Date();
            currentDate.setHours(0, 0, 0, 0);
            const timestamp = Math.ceil(currentDate.getTime() / 1000);
            const fakeUserIdMd5 = await generateDoubleMd5(`${password}${timestamp}`);
            const fakeUserId = [
                fakeUserIdMd5.slice(0, 8),
                fakeUserIdMd5.slice(8, 12),
                fakeUserIdMd5.slice(12, 16),
                fakeUserIdMd5.slice(16, 20),
                fakeUserIdMd5.slice(20)
            ].join('-');
            const fakeHostName = `${fakeUserIdMd5.slice(6, 9)}.${fakeUserIdMd5.slice(13, 19)}`;

            proxyIp = env.PROXYIP || env.proxyip || proxyIp;
            proxyIps = await parseAddresses(proxyIp);
            proxyIp = proxyIps[Math.floor(Math.random() * proxyIps.length)];
	    dohURL = env.DNS_RESOLVER_URL || dohURL;

            socks5Address = env.SOCKS5 || socks5Address;
            socks5List = await parseAddresses(socks5Address);
            socks5Address = socks5List[Math.floor(Math.random() * socks5List.length)];
            socks5Address = socks5Address.split('//')[1] || socks5Address;
            if (env.GO2SOCKS5) socks5Patterns = await parseAddresses(env.GO2SOCKS5);
            if (env.CFPORTS) httpsPorts = await parseAddresses(env.CFPORTS);
            if (env.BAN) bannedHosts = await parseAddresses(env.BAN);

            if (socks5Address) {
                try {
                    parsedSocks5 = socks5AddressParser(socks5Address);
                    useRandomProxyIp = env.RPROXYIP || 'false';
                    enableSocks = true;
                } catch (err) {
                    console.log(err.toString());
                    useRandomProxyIp = env.RPROXYIP || !proxyIp ? 'true' : 'false';
                    enableSocks = false;
                }
            } else {
                useRandomProxyIp = env.RPROXYIP || !proxyIp ? 'true' : 'false';
            }

            const upgradeHeader = request.headers.get("Upgrade");
            const url = new URL(request.url);
            if (!upgradeHeader || upgradeHeader !== "websocket") {
                if (env.ADD) addresses = await parseAddresses(env.ADD);
                if (env.ADDAPI) apiAddresses = await parseAddresses(env.ADDAPI);
                if (env.ADDCSV) csvAddresses = await parseAddresses(env.ADDCSV);
                downloadSpeedLimit = Number(env.DLS) || downloadSpeedLimit;
                remarkColumnIndex = Number(env.CSVREMARK) || remarkColumnIndex;
                botToken = env.TGTOKEN || botToken;
                chatId = env.TGID || chatId;
                subscriptionFileName = env.SUBNAME || subscriptionFileName;
                includeEmoji = env.SUBEMOJI || env.EMOJI || includeEmoji;
                if (includeEmoji === '0') includeEmoji = 'false';
                if (env.LINK) links = await parseAddresses(env.LINK);

                let subscription = env.SUB || '';
                subscriptionConverter = env.SUBAPI || subscriptionConverter;
                if (subscriptionConverter.includes("http://")) {
                    subscriptionConverter = subscriptionConverter.split("//")[1];
                    subscriptionProtocol = 'http';
                } else {
                    subscriptionConverter = subscriptionConverter.split("//")[1] || subscriptionConverter;
                }
                subscriptionConfig = env.SUBCONFIG || subscriptionConfig;
                if (url.searchParams.has('sub') && url.searchParams.get('sub') !== '') subscription = url.searchParams.get('sub');

                if (url.searchParams.has('proxyip')) {
                    websocketPath = `/?ed=2560&proxyip=${url.searchParams.get('proxyip')}`;
                    useRandomProxyIp = 'false';
                } else if (url.searchParams.has('socks5') || url.searchParams.has('socks')) {
                    websocketPath = `/?ed=2560&socks5=${url.searchParams.get('socks5') || url.searchParams.get('socks')}`;
                    useRandomProxyIp = 'false';
                }

                switch (url.pathname) {
                    case '/':
                        if (env.URL302) return Response.redirect(env.URL302, 302);
                        else if (env.URL) return await proxyURL(env.URL, url);
                        else return new Response(JSON.stringify(request.cf, null, 4), {
                            status: 200,
                            headers: { 'content-type': 'application/json' }
                        });
                    case `/${fakeUserId}`:
                        const fakeConfig = await getTrojanConfig(password, request.headers.get('Host'), subscription, 'CF-Workers-SUB', useRandomProxyIp, url, fakeUserId, fakeHostName, env);
                        return new Response(`${fakeConfig}`, { status: 200 });
                    case `/${password}/edit`:
                        const html = await handleKVRequest(request, env);
                        return html;
                    case `/${password}`:
                        await sendMessage(`#GetSubscription ${subscriptionFileName}`, request.headers.get('CF-Connecting-IP'), `UA: ${userAgent}\nDomain: ${url.hostname}\nEntry: ${url.pathname + url.search}`);
                        const trojanConfig = await getTrojanConfig(password, request.headers.get('Host'), subscription, userAgent, useRandomProxyIp, url, fakeUserId, fakeHostName, env);
                        const now = Date.now();
                        const today = new Date(now);
                        today.setHours(0, 0, 0, 0);
                        const usageData = Math.floor(((now - today.getTime()) / 86400000) * 24 * 1099511627776 / 2);
                        const totalData = 24 * 1099511627776;

                        if (userAgent.includes('mozilla') || userAgent.includes('subconverter')) {
                            return new Response(trojanConfig, {
                                status: 200,
                                headers: {
                                    "Content-Type": "text/html;charset=utf-8",
                                    "Profile-Update-Interval": "6",
                                    "Subscription-Userinfo": `upload=${usageData}; download=${usageData}; total=${totalData}; expire=${expirationTimestamp}`,
                                    "Cache-Control": "no-store"
                                }
                            });
                        } else {
                            return new Response(trojanConfig, {
                                status: 200,
                                headers: {
                                    "Content-Disposition": `attachment; filename=${subscriptionFileName}; filename*=utf-8''${encodeURIComponent(subscriptionFileName)}`,
                                    "Profile-Update-Interval": "6",
                                    "Subscription-Userinfo": `upload=${usageData}; download=${usageData}; total=${totalData}; expire=${expirationTimestamp}`
                                }
                            });
                        }
                    default:
                        if (env.URL302) return Response.redirect(env.URL302, 302);
                        else if (env.URL) return await proxyURL(env.URL, url);
                        else return new Response('No doubt about it! Your PASSWORD is incorrect!!!', { status: 404 });
                }
            } else {
                socks5Address = url.searchParams.get('socks5') || socks5Address;
                if (/\/socks5=/i.test(url.pathname)) socks5Address = url.pathname.split('5=')[1];
                else if (/\/socks(5)?:\/\//i.test(url.pathname)) {
                    socks5Address = url.pathname.split('://')[1].split('#')[0];
                    if (socks5Address.includes('@')) {
                        let userPassword = socks5Address.split('@')[0];
                        const base64Regex = /^(?:[A-Z0-9+/]{4})*(?:[A-Z0-9+/]{2}==|[A-Z0-9+/]{3}=)?$/i;
                        if (base64Regex.test(userPassword) && !userPassword.includes(':')) userPassword = atob(userPassword);
                        socks5Address = `${userPassword}@${socks5Address.split('@')[1]}`;
                    }
                }

                if (socks5Address) {
                    try {
                        parsedSocks5 = socks5AddressParser(socks5Address);
                        enableSocks = true;
                    } catch (err) {
                        console.log(err.toString());
                        enableSocks = false;
                    }
                } else {
                    enableSocks = false;
                }

                if (url.searchParams.has('proxyip')) {
                    proxyIp = url.searchParams.get('proxyip');
                    enableSocks = false;
                } else if (/\/proxyip=/i.test(url.pathname)) {
                    proxyIp = url.pathname.toLowerCase().split('/proxyip=')[1];
                    enableSocks = false;
                } else if (/\/proxyip\./i.test(url.pathname)) {
                    proxyIp = `proxyip.${url.pathname.toLowerCase().split("/proxyip.")[1]}`;
                    enableSocks = false;
                } else if (/\/pyip=/i.test(url.pathname)) {
                    proxyIp = url.pathname.toLowerCase().split('/pyip=')[1];
                    enableSocks = false;
                }

                return await handleTrojanOverWebSocket(request);
            }
        } catch (err) {
            return new Response(err.toString());
        }
    }
};

// WebSocket Handler for Trojan Protocol
async function handleTrojanOverWebSocket(request) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();
    let address = "";
    let portWithRandomLog = "";
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
    };
    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null };
    let udpStreamWrite = null;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (udpStreamWrite) return udpStreamWrite(chunk);
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const { hasError, message, portRemote = 443, addressRemote = "", rawClientData, addressType } = await parseTrojanHeader(chunk);
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} tcp`;
            if (hasError) throw new Error(message);
            if (!bannedHosts.includes(addressRemote)) {
                log(`Handling TCP outbound connection to ${addressRemote}:${portRemote}`);
                handleTCPOutbound(remoteSocketWrapper, addressRemote, portRemote, rawClientData, webSocket, log, addressType);
            } else {
                throw new Error(`Blacklisted host, closing TCP outbound connection to ${addressRemote}:${portRemote}`);
            }
        },
        close() {
            log(`readableWebSocketStream is closed`);
        },
        abort(reason) {
            log(`readableWebSocketStream is aborted`, JSON.stringify(reason));
        }
    })).catch((err) => {
        log("readableWebSocketStream pipeTo error", err);
    });

    return new Response(null, {
        status: 101,
        webSocket: client
    });
}

// Parse Trojan Header
async function parseTrojanHeader(buffer) {
    if (buffer.byteLength < 56) {
        return { hasError: true, message: "invalid data" };
    }
    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return { hasError: true, message: "invalid header format (missing CR LF)" };
    }
    const headerPassword = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (headerPassword !== sha224Password) {
        return { hasError: true, message: "invalid password" };
    }

    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return { hasError: true, message: "invalid SOCKS5 request data" };
    }

    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return { hasError: true, message: "unsupported command, only TCP (CONNECT) is allowed" };
    }

    const addressType = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (addressType) {
        case 1: // IPv4
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3: // Domain name
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `invalid addressType is ${addressType}` };
    }

    if (!address) {
        return { hasError: true, message: `address is empty, addressType is ${addressType}` };
    }

    const portIndex = addressIndex + addressLength;
    const portRemote = new DataView(socks5DataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
    return {
        hasError: false,
        addressRemote: address,
        portRemote,
        rawClientData: socks5DataBuffer.slice(portIndex + 4),
        addressType
    };
}

// Handle TCP Outbound Connection
async function handleTCPOutbound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, log, addressType) {
    async function useSocks5Pattern(address) {
        if (socks5Patterns.includes(atob('YWxsIGlu')) || socks5Patterns.includes(atob('Kg=='))) return true;
        return socks5Patterns.some(pattern => {
            let regexPattern = pattern.replace(/\*/g, '.*');
            let regex = new RegExp(`^${regexPattern}$`, 'i');
            return regex.test(address);
        });
    }

    async function connectAndWrite(address, port, useSocks = false) {
        log(`connected to ${address}:${port}`);
        const tcpSocket = useSocks ? await socks5Connect(addressType, address, port, log) : connect({ hostname: address, port });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retry() {
        let tcpSocket;
        if (enableSocks) {
            tcpSocket = await connectAndWrite(addressRemote, portRemote, true);
        } else {
            if (!proxyIp || proxyIp === '') {
                proxyIp = atob('UFJPWFlJUC50cDEuMDkwMjI3Lnh5eg=='); // Decodes to "PROXYIP.tp1.090227.xyz"
            } else if (proxyIp.includes(']:')) {
                portRemote = proxyIp.split(']:')[1] || portRemote;
                proxyIp = proxyIp.split(']:')[0] || proxyIp;
            } else if (proxyIp.split(':').length === 2) {
                portRemote = proxyIp.split(':')[1] || portRemote;
                proxyIp = proxyIp.split(':')[0] || proxyIp;
            }
            if (proxyIp.includes('.tp')) portRemote = proxyIp.split('.tp')[1].split('.')[0] || portRemote;
            tcpSocket = await connectAndWrite(proxyIp || addressRemote, portRemote);
        }
        tcpSocket.closed.catch((error) => {
            console.log("retry tcpSocket closed error", error);
        }).finally(() => {
            safeCloseWebSocket(webSocket);
        });
        remoteSocketToWebSocket(tcpSocket, webSocket, null, log);
    }

    let useSocks = false;
    if (socks5Patterns.length > 0 && enableSocks) useSocks = await useSocks5Pattern(addressRemote);
    let tcpSocket = await connectAndWrite(addressRemote, portRemote, useSocks);
    remoteSocketToWebSocket(tcpSocket, webSocket, retry, log);
}

// Create Readable WebSocket Stream
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    let readableStreamCancel = false;
    const stream = new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (event) => {
                if (readableStreamCancel) return;
                controller.enqueue(event.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (readableStreamCancel) return;
                controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                log("webSocketServer error");
                controller.error(err);
            });
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        pull(controller) {},
        cancel(reason) {
            if (readableStreamCancel) return;
            log(`readableStream was canceled, due to ${reason}`);
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        }
    });
    return stream;
}

// Pipe Remote Socket to WebSocket
async function remoteSocketToWebSocket(remoteSocket, webSocket, retry, log) {
    let hasIncomingData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                controller.error("webSocket connection is not open");
            }
            webSocket.send(chunk);
        },
        close() {
            log(`remoteSocket.readable is closed, hasIncomingData: ${hasIncomingData}`);
        },
        abort(reason) {
            console.error("remoteSocket.readable abort", reason);
        }
    })).catch((error) => {
        console.error(`remoteSocketToWebSocket error:`, error.stack || error);
        safeCloseWebSocket(webSocket);
    });
    if (hasIncomingData === false && retry) {
        log(`retry`);
        retry();
    }
}

async function handleRequest(request) {
  let res = r404;
  const { method, headers, url } = request;
  const { searchParams, pathname } = new URL(url);
  const path = `/${userCode}`; // Define path for consistency

  if (!pathname.startsWith(path)) {
    return r404;
  }
  if (method == 'GET' && searchParams.has('dns')) {
    res = fetch(doh + '?dns=' + searchParams.get('dns'), {
      method: 'GET',
      headers: {
        'Accept': contype,
      }
    });
  } else if (method === 'POST' && headers.get('content-type') === contype) {
    const rostream = request.body;
    res = fetch(doh, {
      method: 'POST',
      headers: {
        'Accept': contype,
        'Content-Type': contype,
      },
      body: rostream,
    });
  } else if (method === 'GET' && headers.get('Accept') === jstontype) {
    const search = new URL(url).search;
    res = fetch(dohjson + search, {
      method: 'GET',
      headers: {
        'Accept': jstontype,
      }
    });
  }
  return res;
}

// Utility Functions
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: undefined, error: null };
    try {
        base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
        const decode = atob(base64Str);
        const arrayBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arrayBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: undefined, error };
    }
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {
        console.error("safeCloseWebSocket error", error);
    }
}

function revertFakeInfo(content, userId, hostName, fakeUserId, fakeHostName, isBase64) {
    if (isBase64) content = atob(content);
    content = content.replace(new RegExp(fakeUserId, 'g'), userId).replace(new RegExp(fakeHostName, 'g'), hostName);
    if (isBase64) content = btoa(content);
    return content;
}

async function generateDoubleMd5(text) {
    const encoder = new TextEncoder();
    const firstPass = await crypto.subtle.digest('MD5', encoder.encode(text));
    const firstPassArray = Array.from(new Uint8Array(firstPass));
    const firstHex = firstPassArray.map(b => b.toString(16).padStart(2, '0')).join('');
    const secondPass = await crypto.subtle.digest('MD5', encoder.encode(firstHex.slice(7, 27)));
    const secondPassArray = Array.from(new Uint8Array(secondPass));
    return secondPassArray.map(b => b.toString(16).padStart(2, '0')).join('').toLowerCase();
}

async function parseAddresses(content) {
    let processedContent = content.replace(/[	|"'\r\n]+/g, ',').replace(/,+/g, ',');
    if (processedContent.charAt(0) === ',') processedContent = processedContent.slice(1);
    if (processedContent.charAt(processedContent.length - 1) === ',') processedContent = processedContent.slice(0, -1);
    return processedContent.split(',');
}

async function proxyURL(proxyUrl, url) {
    const urls = await parseAddresses(proxyUrl);
    const fullUrl = urls[Math.floor(Math.random() * urls.length)];
    let parsedUrl = new URL(fullUrl);
    let protocol = parsedUrl.protocol.slice(0, -1) || 'https';
    let hostname = parsedUrl.hostname;
    let pathname = parsedUrl.pathname;
    let search = parsedUrl.search;
    if (pathname.charAt(pathname.length - 1) === '/') pathname = pathname.slice(0, -1);
    pathname += url.pathname;
    let newUrl = `${protocol}://${hostname}${pathname}${search}`;
    let response = await fetch(newUrl);
    let newResponse = new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers
    });
    newResponse.headers.set('X-New-URL', newUrl);
    return newResponse;
}

function getConfigInfo(password, domainAddress) {
    const protocolType = atob('dHJvamFu'); // "trojan"
    const alias = subscriptionFileName;
    let address = domainAddress;
    let port = 443;
    const transportProtocol = 'ws';
    const disguiseDomain = domainAddress;
    const path = websocketPath;
    let transportSecurity = ['tls', true];
    const sni = domainAddress;
    const fingerprint = 'randomized';

    const v2ray = `${protocolType}://${encodeURIComponent(password)}@${address}:${port}?security=${transportSecurity[0]}&sni=${sni}&alpn=h3&fp=${fingerprint}&allowInsecure=0&type=${transportProtocol}&host=${disguiseDomain}&path=${encodeURIComponent(path)}#${encodeURIComponent(alias)}`;
    const clash = `- {name: ${alias}, server: ${address}, port: ${port}, udp: false, client-fingerprint: ${fingerprint}, type: ${protocolType}, password: ${password}, sni: ${sni}, alpn: [h3], skip-cert-verify: true, network: ${transportProtocol}, ws-opts: {path: "${path}", headers: {Host: ${disguiseDomain}}}}`;
    return [v2ray, clash];
}

let subscriptionParams = ['sub', 'base64', 'b64', 'clash', 'singbox', 'sb', 'surge', 'loon'];
const communityAd = decodeURIComponent(atob(`dGVsZWdyYW0lMjAlRTQlQkElQTQlRTYlQjUlODElRTclQkUlQTQlMjAlRTYlOEElODAlRTYlOUMlQUYlRTUlQTQlQTclRTQlQkQlQUMlN0UlRTUlOUMlQTglRTclQkElQkYlRTUlOEYlOTElRTclODklOEMhJTNDYnIlM0UKJTNDYSUyMGhyZWYlM0QlMjdodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlMjclM0VodHRwcyUzQSUyRiUyRnQubWUlMkZDTUxpdXNzc3MlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKZ2l0aHViJTIwJUU5JUExJUI5JUU3JTlCJUFFJUU1JTlDJUIwJUU1JTlEJTgwJTIwU3RhciFTdGFyIVN0YXIhISElM0NiciUzRQolM0NhJTIwaHJlZiUzRCUyN2h0dHBzJTNBJTJGJTJGZ2l0aHViLmNvbSUyRmNtbGl1JTJGZXBlaXVzJTI3JTNFaHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGY21saXUlMkZlcGVpdXMlM0MlMkZhJTNFJTNDYnIlM0UKLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tJTNDYnIlM0UKJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIzJTIz`));

async function getTrojanConfig(password, hostName, subscription, userAgent, useRandomProxyIp, url, fakeUserId, fakeHostName, env) {
    if (subscription) {
        const match = subscription.match(/^(?:https?:\/\/)?([^\/]+)/);
        if (match) subscription = match[1];
        const subscriptions = await parseAddresses(subscription);
        if (subscriptions.length > 1) subscription = subscriptions[0];
    } else {
        if (env.KV) {
            await migrateAddressList(env);
            const preferredAddresses = await env.KV.get('ADD.txt');
            if (preferredAddresses) {
                const addressArray = await parseAddresses(preferredAddresses);
                const categorizedAddresses = {
                    apiAddresses: new Set(),
                    linkAddresses: new Set(),
                    preferredAddresses: new Set()
                };
                for (const item of addressArray) {
                    if (item.startsWith('https://')) categorizedAddresses.apiAddresses.add(item);
                    else if (item.includes('://')) categorizedAddresses.linkAddresses.add(item);
                    else categorizedAddresses.preferredAddresses.add(item);
                }
                apiAddresses = [...categorizedAddresses.apiAddresses];
                links = [...categorizedAddresses.linkAddresses];
                addresses = [...categorizedAddresses.preferredAddresses];
            }
        }

        if ((addresses.length + apiAddresses.length + csvAddresses.length) === 0) {
            let cloudflareIps = [
                '103.21.244.0/24', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/14',
                '104.16.0.0/14', '104.24.0.0/15', '141.101.64.0/19', '172.64.0.0/14',
                '188.114.96.0/21', '190.93.240.0/21', '162.159.152.0/23', '104.16.0.0/13',
                '104.24.0.0/14', '172.64.0.0/14', '104.16.0.0/14', '104.24.0.0/15',
                '141.101.64.0/19', '172.64.0.0/14', '188.114.96.0/21', '190.93.240.0/21'
            ];
            function generateRandomIpFromCidr(cidr) {
                const [base, mask] = cidr.split('/');
                const baseIp = base.split('.').map(Number);
                const subnetMask = 32 - parseInt(mask, 10);
                const maxHosts = Math.pow(2, subnetMask) - 1;
                const randomHost = Math.floor(Math.random() * maxHosts);
                const randomIp = baseIp.map((octet, index) => {
                    if (index < 2) return octet;
                    if (index === 2) return (octet & (255 << (subnetMask - 8))) + ((randomHost >> 8) & 255);
                    return (octet & (255 << subnetMask)) + (randomHost & 255);
                });
                return randomIp.join('.');
            }
            addresses = addresses.concat('127.0.0.1:1234#CFnat');
            let counter = 1;
            const randomPorts = httpsPorts.concat('443');
            addresses = addresses.concat(
                cloudflareIps.map(cidr => generateRandomIpFromCidr(cidr) + ':' + randomPorts[Math.floor(Math.random() * randomPorts.length)] + '#CFRandomNode' + String(counter++).padStart(2, '0'))
            );
        }
    }

    const uaLower = userAgent.toLowerCase();
    const config = getConfigInfo(password, hostName);
    const v2rayConfig = config[0];
    const clashConfig = config[1];
    let proxyHost = "";
    if (hostName.includes(".workers.dev")) {
        if (proxyHostsUrl && (!proxyHosts || proxyHosts.length === 0)) {
            try {
                const response = await fetch(proxyHostsUrl);
                if (!response.ok) {
                    console.error('Error fetching proxy hosts:', response.status, response.statusText);
                    return;
                }
                const text = await response.text();
                const lines = text.split('\n').filter(line => line.trim() !== '');
                proxyHosts = proxyHosts.concat(lines);
            } catch (error) {
                console.error('Error fetching proxy hosts:', error);
            }
        }
        if (proxyHosts.length !== 0) proxyHost = proxyHosts[Math.floor(Math.random() * proxyHosts.length)] + "/";
    }

    if (uaLower.includes('mozilla') && !subscriptionParams.some(param => url.searchParams.has(param))) {
        let surgeLink = `Surge Subscription URL:<br><a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyHost}${hostName}/${password}?surge','qrcode_4')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyHost}${hostName}/${password}?surge</a><br><div id="qrcode_4" style="margin: 10px 10px 10px 10px;"></div>`;
        if (hostName.includes(".workers.dev")) surgeLink = "Surge subscription requires a custom domain binding";
        const newSocks5List = socks5List.map(addr => addr.includes('@') ? addr.split('@')[1] : addr.split('//')[1] || addr);
        let socks5Info = '';
        if (socks5Patterns.length > 0 && enableSocks) {
            socks5Info = `${decodeURIComponent('SOCKS5%EF%BC%88%E7%99%BD%E5%90%8D%E5%8D%95%EF%BC%89%3A%20')}`;
            if (socks5Patterns.includes(atob('YWxsIGlu')) || socks5Patterns.includes(atob('Kg=='))) socks5Info += `${decodeURIComponent('%E6%89%80%E6%9C%89%E6%B5%81%E9%87%8F')}<br>`;
            else socks5Info += `<br>  ${socks5Patterns.join('<br>  ')}<br>`;
        }

        let subscriptionInfo = '';
        if (subscription) {
            if (enableSocks) subscriptionInfo += `CFCDN (Access Method): Socks5<br>  ${newSocks5List.join('<br>  ')}<br>${socks5Info}`;
            else if (proxyIp && proxyIp !== '') subscriptionInfo += `CFCDN (Access Method): ProxyIP<br>  ${proxyIps.join('<br>  ')}<br>`;
            else if (useRandomProxyIp === 'true') subscriptionInfo += `CFCDN (Access Method): Auto-fetch ProxyIP<br>`;
            else subscriptionInfo += `CFCDN (Access Method): Unreachable, please set proxyIP/PROXYIP!!!<br>`;
            subscriptionInfo += `<br>SUB (Preferred Subscription Generator): ${subscription}`;
        } else {
            if (enableSocks) subscriptionInfo += `CFCDN (Access Method): Socks5<br>  ${newSocks5List.join('<br>  ')}<br>${socks5Info}`;
            else if (proxyIp && proxyIp !== '') subscriptionInfo += `CFCDN (Access Method): ProxyIP<br>  ${proxyIps.join('<br>  ')}<br>`;
            else subscriptionInfo += `CFCDN (Access Method): Unreachable, please set proxyIP/PROXYIP!!!<br>`;
            let kvEditLink = env.KV ? ` <a href='${url.pathname}/edit'>Edit Preferred List</a>` : '';
            subscriptionInfo += `<br>Your subscription content is provided by built-in addresses/ADD* parameters${kvEditLink}<br>`;
            if (addresses.length > 0) subscriptionInfo += `ADD (TLS Preferred Domains & IPs): <br>  ${addresses.join('<br>  ')}<br>`;
            if (apiAddresses.length > 0) subscriptionInfo += `ADDAPI (API for TLS Preferred Domains & IPs): <br>  ${apiAddresses.join('<br>  ')}<br>`;
            if (csvAddresses.length > 0) subscriptionInfo += `ADDCSV (IPTest Speed Test CSV Files, Limit ${downloadSpeedLimit}): <br>  ${csvAddresses.join('<br>  ')}<br>`;
        }

        const configPage = `
            ################################################################<br>
            Subscribe / sub Subscription URL, click the link to automatically <strong>copy the subscription link</strong> and <strong>generate a QR code</strong> <br>
            ---------------------------------------------------------------<br>
            Adaptive Subscription URL:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyHost}${hostName}/${password}?sub','qrcode_0')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyHost}${hostName}/${password}</a><br>
            <div id="qrcode_0" style="margin: 10px 10px 10px 10px;"></div>
            Base64 Subscription URL:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyHost}${hostName}/${password}?b64','qrcode_1')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyHost}${hostName}/${password}?b64</a><br>
            <div id="qrcode_1" style="margin: 10px 10px 10px 10px;"></div>
            Clash Subscription URL:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyHost}${hostName}/${password}?clash','qrcode_2')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyHost}${hostName}/${password}?clash</a><br>
            <div id="qrcode_2" style="margin: 10px 10px 10px 10px;"></div>
            Singbox Subscription URL:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyHost}${hostName}/${password}?sb','qrcode_3')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyHost}${hostName}/${password}?sb</a><br>
            <div id="qrcode_3" style="margin: 10px 10px 10px 10px;"></div>
            Loon Subscription URL:<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('https://${proxyHost}${hostName}/${password}?loon','qrcode_5')" style="color:blue;text-decoration:underline;cursor:pointer;">https://${proxyHost}${hostName}/${password}?loon</a><br>
            <div id="qrcode_5" style="margin: 10px 10px 10px 10px;"></div>
            ${surgeLink}
            <strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">Useful Subscription Tips∨</a></strong><br>
            <div id="noticeContent" class="notice-content" style="display: none;">
                <strong>1.</strong> If using PassWall or PassWall2 router plugin, set the subscription's <strong>User-Agent</strong> to <strong>PassWall</strong>;<br>
                <br>
                <strong>2.</strong> For SSR+ router plugin, use the <strong>Base64 Subscription URL</strong> for subscription;<br>
                <br>
                <strong>3.</strong> To quickly switch to <a href='${atob('aHR0cHM6Ly9naXRodWIuY29tL2NtbGl1L1dvcmtlclZsZXNzMnN1Yg==')}'>Preferred Subscription Generator</a> at sub.google.com, add "?sub=sub.google.com" to the end of the link, e.g.:<br>
                &nbsp;&nbsp;https://${proxyHost}${hostName}/${password}<strong>?sub=sub.google.com</strong><br>
                <br>
                <strong>4.</strong> To quickly change PROXYIP to proxyip.cmliussss.net:443, add "?proxyip=proxyip.cmliussss.net:443" to the end of the link, e.g.:<br>
                &nbsp;&nbsp;https://${proxyHost}${hostName}/${password}<strong>?proxyip=proxyip.cmliussss.net:443</strong><br>
                <br>
                <strong>5.</strong> To quickly change SOCKS5 to user:password@127.0.0.1:1080, add "?socks5=user:password@127.0.0.1:1080" to the end of the link, e.g.:<br>
                &nbsp;&nbsp;https://${proxyHost}${hostName}/${password}<strong>?socks5=user:password@127.0.0.1:1080</strong><br>
                <br>
                <strong>6.</strong> To specify multiple parameters, use '&' as a separator, e.g.:<br>
                &nbsp;&nbsp;https://${proxyHost}${hostName}/${password}?sub=sub.google.com<strong>&</strong>proxyip=proxyip.cmliussss.net<br>
            </div>
            <script src="https://cdn.jsdelivr.net/npm/@keeex/qrcodejs-kx@1.0.2/qrcode.min.js"></script>
            <script>
            function copyToClipboard(text, qrcode) {
                navigator.clipboard.writeText(text).then(() => {
                    alert('Copied to clipboard');
                }).catch(err => {
                    console.error('Copy failed:', err);
                });
                const qrcodeDiv = document.getElementById(qrcode);
                qrcodeDiv.innerHTML = '';
                new QRCode(qrcodeDiv, {
                    text: text,
                    width: 220,
                    height: 220,
                    colorDark: "#000000",
                    colorLight: "#ffffff",
                    correctLevel: QRCode.CorrectLevel.Q,
                    scale: 1
                });
            }

            function toggleNotice() {
                const noticeContent = document.getElementById('noticeContent');
                const noticeToggle = document.getElementById('noticeToggle');
                if (noticeContent.style.display === 'none') {
                    noticeContent.style.display = 'block';
                    noticeToggle.textContent = 'Useful Subscription Tips∧';
                } else {
                    noticeContent.style.display = 'none';
                    noticeToggle.textContent = 'Useful Subscription Tips∨';
                }
            }
            </script>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            ${subscriptionFileName} Configuration Info<br>
            ---------------------------------------------------------------<br>
            HOST: ${hostName}<br>
            PASSWORD: ${password}<br>
            SHA224: ${sha224Password}<br>
            FAKEPASS: ${fakeUserId}<br>
            UA: ${userAgent}<br>
            <br>
            ${subscriptionInfo}<br>
            SUBAPI (Subscription Conversion Backend): ${subscriptionProtocol}://${subscriptionConverter}<br>
            SUBCONFIG (Subscription Conversion Config): ${subscriptionConfig}<br>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            v2ray<br>
            ---------------------------------------------------------------<br>
            <a href="javascript:void(0)" onclick="copyToClipboard('${v2rayConfig}','qrcode_v2ray')" style="color:blue;text-decoration:underline;cursor:pointer;">${v2rayConfig}</a><br>
            <div id="qrcode_v2ray" style="margin: 10px 10px 10px 10px;"></div>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            clash-meta<br>
            ---------------------------------------------------------------<br>
            ${clashConfig}<br>
            ---------------------------------------------------------------<br>
            ################################################################<br>
            ${communityAd}
        `;
        return `<div style="font-size:13px;">${configPage}</div>`;
    } else {
        if (typeof fetch !== 'function') return 'Error: fetch is not available in this environment.';
        let targetHostName = hostName.includes(".workers.dev") ? `${fakeHostName}.workers.dev` : `${fakeHostName}.xyz`;
        let subUrl = `https://${subscription}/sub?host=${targetHostName}&pw=${fakeUserId}&password=${fakeUserId + atob('JmVwZWl1cz1jbWxpdSZwcm94eWlwPQ==') + useRandomProxyIp}&path=${encodeURIComponent(websocketPath)}`;
        let isBase64 = true;
        let newApiAddresses = [];
        let newCsvAddresses = [];

        if (!subscription || subscription === "") {
            if (hostName.includes('workers.dev')) {
                if (proxyHostsUrl && (!proxyHosts || proxyHosts.length === 0)) {
                    try {
                        const response = await fetch(proxyHostsUrl);
                        if (!response.ok) {
                            console.error('Error fetching proxy hosts:', response.status, response.statusText);
                            return;
                        }
                        const text = await response.text();
                        proxyHosts = proxyHosts.concat(text.split('\n').filter(line => line.trim() !== ''));
                    } catch (error) {
                        console.error('Error fetching proxy hosts:', error);
                    }
                }
                proxyHosts = [...new Set(proxyHosts)];
            }
            newApiAddresses = await fetchApiAddresses(apiAddresses);
            newCsvAddresses = await fetchCsvAddresses('TRUE');
            subUrl = `https://${hostName}/${fakeUserId + url.search}`;
        }

        if (!uaLower.includes(('CF-Workers-SUB').toLowerCase()) && !url.searchParams.has('b64') && !url.searchParams.has('base64')) {
            if ((uaLower.includes('clash') && !uaLower.includes('nekobox')) || url.searchParams.has('clash')) {
                subUrl = `${subscriptionProtocol}://${subscriptionConverter}/sub?target=clash&url=${encodeURIComponent(subUrl)}&insert=false&config=${encodeURIComponent(subscriptionConfig)}&emoji=${includeEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (uaLower.includes('sing-box') || uaLower.includes('singbox') || url.searchParams.has('singbox') || url.searchParams.has('sb')) {
                subUrl = `${subscriptionProtocol}://${subscriptionConverter}/sub?target=singbox&url=${encodeURIComponent(subUrl)}&insert=false&config=${encodeURIComponent(subscriptionConfig)}&emoji=${includeEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            } else if (uaLower.includes('surge') || url.searchParams.has('surge')) {
                subUrl = `${subscriptionProtocol}://${subscriptionConverter}/sub?target=surge&ver=4&url=${encodeURIComponent(subUrl)}&insert=false&config=${encodeURIComponent(subscriptionConfig)}&emoji=${includeEmoji}&list=false&xudp=false&udp=false&tfo=false&expand=true&scv=true&fdn=false`;
                isBase64 = false;
            } else if (uaLower.includes('loon') || url.searchParams.has('loon')) {
                subUrl = `${subscriptionProtocol}://${subscriptionConverter}/sub?target=loon&url=${encodeURIComponent(subUrl)}&insert=false&config=${encodeURIComponent(subscriptionConfig)}&emoji=${includeEmoji}&list=false&tfo=false&scv=true&fdn=false&sort=false&new_name=true`;
                isBase64 = false;
            }
        }

        try {
            let content;
            if ((!subscription || subscription === "") && isBase64) {
                content = await generateSubAddresses(targetHostName, fakeUserId, uaLower, newApiAddresses, newCsvAddresses);
            } else {
                const response = await fetch(subUrl, {
                    headers: { 'User-Agent': atob('Q0YtV29ya2Vycy1lcGVpdXMvY21saXU=') } // "CF-Workers-epeius/cmliu"
                });
                content = await response.text();
            }

            if (url.pathname === `/${fakeUserId}`) return content;
            content = revertFakeInfo(content, password, hostName, fakeUserId, targetHostName, isBase64);
            if (uaLower.includes('surge') || url.searchParams.has('surge')) content = formatSurgeConfig(content, `https://${hostName}/${password}?surge`);
            return content;
        } catch (error) {
            console.error('Error fetching content:', error);
            return `Error fetching content: ${error.message}`;
        }
    }
}

async function sendMessage(type, ip, additionalData = "") {
    if (botToken !== '' && chatId !== '') {
        let msg = "";
        const response = await fetch(`http://ip-api.com/json/${ip}?lang=zh-CN`);
        if (response.status === 200) {
            const ipInfo = await response.json();
            msg = `${type}\nIP: ${ip}\nCountry: ${ipInfo.country}\n<tg-spoiler>City: ${ipInfo.city}\nOrganization: ${ipInfo.org}\nASN: ${ipInfo.as}\n${additionalData}`;
        } else {
            msg = `${type}\nIP: ${ip}\n<tg-spoiler>${additionalData}`;
        }

        let url = `https://api.telegram.org/bot${botToken}/sendMessage?chat_id=${chatId}&parse_mode=HTML&text=${encodeURIComponent(msg)}`;
        return fetch(url, {
            method: 'get',
            headers: {
                'Accept': 'text/html,application/xhtml+xml,application/xml;',
                'Accept-Encoding': 'gzip, deflate, br',
                'User-Agent': 'Mozilla/5.0 Chrome/90.0.4430.72'
            }
        });
    }
}

async function socks5Connect(addressType, addressRemote, portRemote, log) {
	const { username, password, hostname, port } = parsedSocks5Address;
	// Connect to the SOCKS server
	const socket = connect({
		hostname,
		port,
	});

	// Request head format (Worker -> Socks Server):
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |	1	 | 1 to 255 |
	// +----+----------+----------+

	// https://en.wikipedia.org/wiki/SOCKS#SOCKS5
	// For METHODS:
	// 0x00 NO AUTHENTICATION REQUIRED
	// 0x02 USERNAME/PASSWORD https://datatracker.ietf.org/doc/html/rfc1929
	const socksGreeting = new Uint8Array([5, 2, 0, 2]);

	const writer = socket.writable.getWriter();

	await writer.write(socksGreeting);
	log('sent socks greeting');

	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();
	let res = (await reader.read()).value;
	// Response format (Socks Server -> Worker):
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1	|
	// +----+--------+
	if (res[0] !== 0x05) {
		log(`socks server version error: ${res[0]} expected: 5`);
		return;
	}
	if (res[1] === 0xff) {
		log("no acceptable methods");
		return;
	}

	// if return 0x0502
	if (res[1] === 0x02) {
		log("socks server needs auth");
		if (!username || !password) {
			log("please provide username/password");
			return;
		}
		// +----+------+----------+------+----------+
		// |VER | ULEN |  UNAME   | PLEN |  PASSWD  |
		// +----+------+----------+------+----------+
		// | 1  |  1   | 1 to 255 |  1   | 1 to 255 |
		// +----+------+----------+------+----------+
		const authRequest = new Uint8Array([
			1,
			username.length,
			...encoder.encode(username),
			password.length,
			...encoder.encode(password)
		]);
		await writer.write(authRequest);
		res = (await reader.read()).value;
		// expected 0x0100
		if (res[0] !== 0x01 || res[1] !== 0x00) {
			log("fail to auth socks server");
			return;
		}
	}

	// Request data format (Worker -> Socks Server):
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |	2	 |
	// +----+-----+-------+------+----------+----------+
	// ATYP: address type of following address
	// 0x01: IPv4 address
	// 0x03: Domain name
	// 0x04: IPv6 address
	// DST.ADDR: desired destination address
	// DST.PORT: desired destination port in network octet order

	// addressType
	// 0x01: IPv4 address
	// 0x03: Domain name
	// 0x04: IPv6 address
	// 1--> ipv4  addressLength =4
	// 2--> domain name
	// 3--> ipv6  addressLength =16
	let DSTADDR;	// DSTADDR = ATYP + DST.ADDR
	switch (addressType) {
		case 1:
			DSTADDR = new Uint8Array(
				[1, ...addressRemote.split('.').map(Number)]
			);
			break;
		case 3:
			DSTADDR = new Uint8Array(
				[3, addressRemote.length, ...encoder.encode(addressRemote)]
			);
			break;
		case 4:
			DSTADDR = new Uint8Array(
				[4, ...addressRemote.split(':').flatMap(x => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)])]
			);
			break;
		default:
			log(`invild  addressType is ${addressType}`);
			return;
	}
	const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
	await writer.write(socksRequest);
	log('sent socks request');

	res = (await reader.read()).value;
	// Response format (Socks Server -> Worker):
	//  +----+-----+-------+------+----------+----------+
	// |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |	2	 |
	// +----+-----+-------+------+----------+----------+
	if (res[1] === 0x00) {
		log("socks connection opened");
	} else {
		log("fail to open socks connection");
		return;
	}
	writer.releaseLock();
	reader.releaseLock();
	return socket;
}

/**
 * 
 * @param {string} address
 */
function socks5AddressParser(address) {
	let [latter, former] = address.split("@").reverse();
	let username, password, hostname, port;
	if (former) {
		const formers = former.split(":");
		if (formers.length !== 2) {
			throw new Error('Invalid SOCKS address format');
		}
		[username, password] = formers;
	}
	const latters = latter.split(":");
	port = Number(latters.pop());
	if (isNaN(port)) {
		throw new Error('Invalid SOCKS address format');
	}
	hostname = latters.join(":");
	const regex = /^\[.*\]$/;
	if (hostname.includes(":") && !regex.test(hostname)) {
		throw new Error('Invalid SOCKS address format');
	}
	//if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(hostname)) hostname = `${atob('d3d3Lg==')}${hostname}${atob('LmlwLjA5MDIyNy54eXo=')}`;
	return {
		username,
		password,
		hostname,
		port,
	}
}

function isValidIPv4(address) {
	const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
	return ipv4Regex.test(address);
}

function generateSubscriptionAddresses(host, password, userAgent, newApiAddresses, newCsvAddresses) {
	addresses = addresses.concat(newApiAddresses);
	addresses = addresses.concat(newCsvAddresses);
	// Remove duplicates using a Set
	const uniqueAddresses = [...new Set(addresses)];

	const responseBody = uniqueAddresses.map(address => {
		let port = "-1";
		let addressId = address;

		const match = addressId.match(addressRegex);
		if (!match) {
			if (address.includes(':') && address.includes('#')) {
				const parts = address.split(':');
				address = parts[0];
				const subParts = parts[1].split('#');
				port = subParts[0];
				addressId = subParts[1];
			} else if (address.includes(':')) {
				const parts = address.split(':');
				address = parts[0];
				port = parts[1];
			} else if (address.includes('#')) {
				const parts = address.split('#');
				address = parts[0];
				addressId = parts[1];
			}

			if (addressId.includes(':')) {
				addressId = addressId.split(':')[0];
			}
		} else {
			address = match[1];
			port = match[2] || port;
			addressId = match[3] || address;
		}

		const httpsPorts = ["2053", "2083", "2087", "2096", "8443"];
		if (!isValidIPv4(address) && port === "-1") {
			for (let httpsPort of httpsPorts) {
				if (address.includes(httpsPort)) {
					port = httpsPort;
					break;
				}
			}
		}
		if (port === "-1") port = "443";

		let disguiseDomain = host;
		let finalPath = websocketPath;
		let nodeRemark = '';

		if (proxyHosts.length > 0 && disguiseDomain.includes('.workers.dev')) {
			finalPath = `/${disguiseDomain}${finalPath}`;
			disguiseDomain = proxyHosts[Math.floor(Math.random() * proxyHosts.length)];
			nodeRemark = ` Temporary domain relay enabled, please bind a custom domain soon!`;
		}
		const matchingProxyIp = proxyIpPool.find(proxyIp => proxyIp.includes(address));
		if (matchingProxyIp) finalPath += `&proxyip=${matchingProxyIp}`;
		let encodedPassword = userAgent.includes('subconverter') ? password : encodeURIComponent(password);

		const protocolType = atob('dHJvamFu'); // "trojan"
		const trojanLink = `${protocolType}://${encodedPassword}@${address}:${port}?security=tls&sni=${disguiseDomain}&fp=randomized&type=ws&host=${disguiseDomain}&path=${encodeURIComponent(finalPath)}#${encodeURIComponent(addressId + nodeRemark)}`;

		return trojanLink;
	}).join('\n');

	let base64Response = responseBody; // Re-encode to Base64
	if (links.length > 0) base64Response += '\n' + links.join('\n');
	return btoa(base64Response);
}

async function fetchApiAddresses(apiUrls) {
	if (!apiUrls || apiUrls.length === 0) return [];

	let apiContent = "";

	// Create an AbortController to manage fetch request cancellation
	const controller = new AbortController();

	const timeout = setTimeout(() => {
		controller.abort(); // Cancel all requests after 2 seconds
	}, 2000);

	try {
		// Use Promise.allSettled to wait for all API requests to complete
		const responses = await Promise.allSettled(apiUrls.map(apiUrl => fetch(apiUrl, {
			method: 'get',
			headers: {
				'Accept': 'text/html,application/xhtml+xml,application/xml;',
				'User-Agent': atob('Q0YtV29ya2Vycy1lcGVpdXMvY21saXU=') // Decoded: "CF-Workers-epeius/cmliu"
			},
			signal: controller.signal
		}).then(response => response.ok ? response.text() : Promise.reject())));

		// Process each response
		for (const [index, response] of responses.entries()) {
			if (response.status === 'fulfilled') {
				const content = response.value;
				const lines = content.split(/\r?\n/);
				let nodeRemark = '';
				let testPort = '443';
				if (lines[0].split(',').length > 3) {
					const idMatch = apiUrls[index].match(/id=([^&]*)/);
					if (idMatch) nodeRemark = idMatch[1];
					const portMatch = apiUrls[index].match(/port=([^&]*)/);
					if (portMatch) testPort = portMatch[1];

					for (let i = 1; i < lines.length; i++) {
						const column = lines[i].split(',')[0];
						if (column) {
							apiContent += `${column}:${testPort}${nodeRemark ? `#${nodeRemark}` : ''}\n`;
							if (apiUrls[index].includes('proxyip=true')) proxyIpPool.push(`${column}:${testPort}`);
						}
					}
				} else {
					if (apiUrls[index].includes('proxyip=true')) {
						proxyIpPool = proxyIpPool.concat((await parseAddresses(content)).map(item => {
							const baseItem = item.split('#')[0] || item;
							if (baseItem.includes(':')) {
								const port = baseItem.split(':')[1];
								if (!httpsPorts.includes(port)) return baseItem;
							} else {
								return `${baseItem}:443`;
							}
							return null;
						}).filter(Boolean));
					}
					apiContent += content + '\n';
				}
			}
		}
	} catch (error) {
		console.error(error);
	} finally {
		clearTimeout(timeout);
	}

	const newApiAddresses = await parseAddresses(apiContent);
	return newApiAddresses;
}

async function fetchCsvAddresses(tls) {
	if (!csvAddresses || csvAddresses.length === 0) {
		return [];
	}

	let newCsvAddresses = [];

	for (const csvUrl of csvAddresses) {
		try {
			const response = await fetch(csvUrl);

			if (!response.ok) {
				console.error('Error fetching CSV address:', response.status, response.statusText);
				continue;
			}

			const text = await response.text();
			const lines = text.includes('\r\n') ? text.split('\r\n') : text.split('\n');

			const header = lines[0].split(',');
			const tlsIndex = header.indexOf('TLS');
			const ipAddressIndex = 0;
			const portIndex = 1;
			const dataCenterIndex = tlsIndex + remarkColumnIndex;

			if (tlsIndex === -1) {
				console.error('CSV file missing required fields');
				continue;
			}

			for (let i = 1; i < lines.length; i++) {
				const columns = lines[i].split(',');
				const speedIndex = columns.length - 1;
				if (columns[tlsIndex].toUpperCase() === tls && parseFloat(columns[speedIndex]) > downloadSpeedLimit) {
					const ipAddress = columns[ipAddressIndex];
					const port = columns[portIndex];
					const dataCenter = columns[dataCenterIndex];

					const formattedAddress = `${ipAddress}:${port}#${dataCenter}`;
					newCsvAddresses.push(formattedAddress);
					if (csvUrl.includes('proxyip=true') && columns[tlsIndex].toUpperCase() === 'TRUE' && !httpsPorts.includes(port)) {
						proxyIpPool.push(`${ipAddress}:${port}`);
					}
				}
			}
		} catch (error) {
			console.error('Error fetching CSV address:', error);
			continue;
		}
	}

	return newCsvAddresses;
}

function formatSurgeConfig(content, url) {
	const lines = content.includes('\r\n') ? content.split('\r\n') : content.split('\n');
	let outputContent = "";
	for (let line of lines) {
		if (line.includes(atob('PSB0cm9qYW4s'))) { // "[ trojan,"
			const host = line.split("sni=")[1].split(",")[0];
			const toReplace = `skip-cert-verify=true, tfo=false, udp-relay=false`;
			const correctConfig = `skip-cert-verify=true, ws=true, ws-path=${websocketPath}, ws-headers=Host:"${host}", tfo=false, udp-relay=false`;
			outputContent += line.replace(new RegExp(toReplace, 'g'), correctConfig).replace("[", "").replace("]", "") + '\n';
		} else {
			outputContent += line + '\n';
		}
	}
	outputContent = `#!MANAGED-CONFIG ${url} interval=86400 strict=false` + outputContent.substring(outputContent.indexOf('\n'));
	return outputContent;
}

function sha224(inputString) {
	// Internal constants and functions
	const K = [
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	];

	function utf8Encode(str) {
		return unescape(encodeURIComponent(str));
	}

	function bytesToHex(bytes) {
		let hex = '';
		for (let i = 0; i < bytes.length; i++) {
			hex += ((bytes[i] >>> 4) & 0x0F).toString(16);
			hex += (bytes[i] & 0x0F).toString(16);
		}
		return hex;
	}

	function sha224Core(input) {
		// SHA-224 initial hash values
		let hash = [
			0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
			0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
		];

		// Pre-processing
		const messageLength = input.length * 8;
		input += String.fromCharCode(0x80);
		while ((input.length * 8) % 512 !== 448) {
			input += String.fromCharCode(0);
		}

		// 64-bit message length
		const lengthHigh = Math.floor(messageLength / 0x100000000);
		const lengthLow = messageLength & 0xFFFFFFFF;
		input += String.fromCharCode(
			(lengthHigh >>> 24) & 0xFF, (lengthHigh >>> 16) & 0xFF,
			(lengthHigh >>> 8) & 0xFF, lengthHigh & 0xFF,
			(lengthLow >>> 24) & 0xFF, (lengthLow >>> 16) & 0xFF,
			(lengthLow >>> 8) & 0xFF, lengthLow & 0xFF
		);

		const words = [];
		for (let i = 0; i < input.length; i += 4) {
			words.push(
				(input.charCodeAt(i) << 24) |
				(input.charCodeAt(i + 1) << 16) |
				(input.charCodeAt(i + 2) << 8) |
				input.charCodeAt(i + 3)
			);
		}

		// Main compression loop
		for (let i = 0; i < words.length; i += 16) {
			const w = new Array(64).fill(0);
			for (let j = 0; j < 16; j++) {
				w[j] = words[i + j];
			}

			for (let j = 16; j < 64; j++) {
				const s0 = rightRotate(w[j - 15], 7) ^ rightRotate(w[j - 15], 18) ^ (w[j - 15] >>> 3);
				const s1 = rightRotate(w[j - 2], 17) ^ rightRotate(w[j - 2], 19) ^ (w[j - 2] >>> 10);
				w[j] = (w[j - 16] + s0 + w[j - 7] + s1) >>> 0;
			}

			let [a, b, c, d, e, f, g, h0] = hash;

			for (let j = 0; j < 64; j++) {
				const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
				const ch = (e & f) ^ (~e & g);
				const temp1 = (h0 + S1 + ch + K[j] + w[j]) >>> 0;
				const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
				const maj = (a & b) ^ (a & c) ^ (b & c);
				const temp2 = (S0 + maj) >>> 0;

				h0 = g;
				g = f;
				f = e;
				e = (d + temp1) >>> 0;
				d = c;
				c = b;
				b = a;
				a = (temp1 + temp2) >>> 0;
			}

			hash[0] = (hash[0] + a) >>> 0;
			hash[1] = (hash[1] + b) >>> 0;
			hash[2] = (hash[2] + c) >>> 0;
			hash[3] = (hash[3] + d) >>> 0;
			hash[4] = (hash[4] + e) >>> 0;
			hash[5] = (hash[5] + f) >>> 0;
			hash[6] = (hash[6] + g) >>> 0;
			hash[7] = (hash[7] + h0) >>> 0;
		}

		// Truncate to 224 bits
		return hash.slice(0, 7);
	}

	function rightRotate(value, amount) {
		return ((value >>> amount) | (value << (32 - amount))) >>> 0;
	}

	// Main function logic
	const encodedInput = utf8Encode(inputString);
	const hashResult = sha224Core(encodedInput);

	// Convert to hex string
	return bytesToHex(
		hashResult.flatMap(h => [
			(h >>> 24) & 0xFF,
			(h >>> 16) & 0xFF,
			(h >>> 8) & 0xFF,
			h & 0xFF
		])
	);
}

async function migrateAddressList(env, txt = 'ADD.txt') {
    const oldData = await env.KV.get(`/${txt}`);
    const newData = await env.KV.get(txt);

    if (oldData && !newData) {
        // Write to new location
        await env.KV.put(txt, oldData);
        // Delete old data
        await env.KV.delete(`/${txt}`);
        return true;
    }
    return false;
}

async function migrateAddressList(env, txt = 'ADD.txt') {
    const oldData = await env.KV.get(`/${txt}`);
    const newData = await env.KV.get(txt);

    if (oldData && !newData) {
        // Write to new location
        await env.KV.put(txt, oldData);
        // Delete old data
        await env.KV.delete(`/${txt}`);
        return true;
    }
    return false;
}

async function KV(request, env, txt = 'ADD.txt') {
    try {
        // Handle POST request
        if (request.method === "POST") {
            if (!env.KV) return new Response("No KV namespace bound", { status: 400 });
            try {
                const content = await request.text();
                await env.KV.put(txt, content);
                return new Response("Save successful");
            } catch (error) {
                console.error('Error occurred while saving to KV:', error);
                return new Response("Save failed: " + error.message, { status: 500 });
            }
        }

        // Handle GET request
        let content = '';
        let hasKV = !!env.KV;

        if (hasKV) {
            try {
                content = await env.KV.get(txt) || '';
            } catch (error) {
                console.error('Error occurred while reading from KV:', error);
                content = 'Error occurred while reading data: ' + error.message;
            }
        }

        const html = `
            <!DOCTYPE html>
            <html>
            <head>
                <title>Preferred Subscription List</title>
                <meta charset="utf-8">
                <meta name="viewport" content="width=device-width, initial-scale=1">
                <style>
                    body {
                        margin: 0;
                        padding: 15px; /* Adjust padding */
                        box-sizing: border-box;
                        font-size: 13px; /* Set global font size */
                    }
                    .editor-container {
                        width: 100%;
                        max-width: 100%;
                        margin: 0 auto;
                    }
                    .editor {
                        width: 100%;
                        height: 520px; /* Adjust height */
                        margin: 15px 0; /* Adjust margin */
                        padding: 10px; /* Adjust padding */
                        box-sizing: border-box;
                        border: 1px solid #ccc;
                        border-radius: 4px;
                        font-size: 13px;
                        line-height: 1.5;
                        overflow-y: auto;
                        resize: none;
                    }
                    .save-container {
                        margin-top: 8px; /* Adjust margin */
                        display: flex;
                        align-items: center;
                        gap: 10px; /* Adjust gap */
                    }
                    .save-btn, .back-btn {
                        padding: 6px 15px; /* Adjust padding */
                        color: white;
                        border: none;
                        border-radius: 4px;
                        cursor: pointer;
                    }
                    .save-btn {
                        background: #4CAF50;
                    }
                    .save-btn:hover {
                        background: #45a049;
                    }
                    .back-btn {
                        background: #666;
                    }
                    .back-btn:hover {
                        background: #555;
                    }
                    .save-status {
                        color: #666;
                    }
                    .notice-content {
                        display: none;
                        margin-top: 10px;
                        font-size: 13px;
                        color: #333;
                    }
                </style>
            </head>
            <body>
                ################################################################<br>
                ${FileName} Preferred Subscription List:<br>
                ---------------------------------------------------------------<br>
                  <strong><a href="javascript:void(0);" id="noticeToggle" onclick="toggleNotice()">Notes ∨</a></strong><br>
                <div id="noticeContent" class="notice-content">
                    ${decodeURIComponent(atob('JTA5JTA5JTA5JTA5JTA5JTNDc3Ryb25nJTNFMS4lM0MlMkZzdHJvbmclM0UlMjBBRERBUEklMjAlRTUlQTYlODIlRTYlOUUlOUMlRTYlOTglQUYlRTUlOEYlOEQlRTQlQkIlQTNJUCVFRiVCQyU4QyVFNSU4RiVBRiVFNCVCRCU5QyVFNCVCOCVCQVBST1hZSVAlRTclOUElODQlRTglQUYlOUQlRUYlQkMlOEMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwcm94eWlwJTNEdHJ1ZSUyMiVFNSU4RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU8OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGYWRkcmVzc2VzYXBpLnR4dCUzQ3N0cm9uZyUzRSUzRnByb3h5aXAlM0R0cnVlJTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklM0NzdHJvbmclM0UyLiUzQyUyRnN0cm9uZyUzRSUyMEFEREFQSSUyMCVFNSVBNiU4MiVFNiU5RSU9QyVFNiU5OCVBRiUyMCUzQ2ElMjBocmVmJTNEJTI3aHR0cHMlM0ElMkYlMkZnaXRodWIuY29tJTJGWElVMiUyRkNsb3VkZmxhcmVTcGVlZFRlc3QlMjclM0VDbG91ZGZsYXJlU3BlZWRUZXN0JTNDJTJGYSUzRSUyMCVFNyU5QSU4NCUyMGNzdiUyMCVFNyVCQiU5MyVFNiU5RSU5QyVFNiU5NiU4NyVFNCVCQiVCNiVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NiciUzRSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCLSUyMCVFNSVBNiU4MiVFOSU5QyU4MCVFNiU4QyU4NyVFNSVBRSU5QTIwNTMlRTclQUIlQUYlRTUlOEYlQTMlRTUlOEYlQUYlRTUlQjAlODYlMjIlM0Zwb3J0JTNEMjA1MyUyMiVFNSU8RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU5QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0Zwb3J0JTNEMjA1MyUzQyUyRnN0cm9uZyUzRSUzQ2JyJTNFJTNDYnIlM0UKJTA5JTA5JTA5JTA5JTA5JTI2bmJzcCUzBiUyNm5ic3AlM0ItJTIwJUU1JUE2JTgyJUU5JTlDJTgwJUU2JThDJTg3JUU1JUFFJTlBJUU4JThBJTgyJUU3JTgyJUI5JUU1JUE0JTg3JUU2JUIzJUE4JUU1JThGJUFGJUU1JUIwJTg2JTIyJTNGaWQlM0RDRiVFNCVCQyU5OCVFOSU4MCU4OSUyMiVFNSU8RiU4MiVFNiU5NSVCMCVFNiVCNyVCQiVFNSU4QSVBMCVFNSU4OCVCMCVFOSU5MyVCRSVFNiU4RSVBNSVFNiU9QyVBQiVFNSVCMCVCRSVFRiVCQyU4QyVFNCVCRSU4QiVFNSVBNiU4MiVFRiVCQyU5QSUzQ2JyJTNFCiUwOSUwOSUwOSUwOSUwOSUyNm5ic3AlM0IlMjZuYnNwJTNCaHR0cHMlM0ElMkYlMkZyYXcuZ2l0aHVidXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0NzdHJvbmclM0UlM0ZpZCUzRENGJUU0JUJDJTk4JUU5JTgwJTg5JTNDJTJGc3Ryb25nJTNFJTNDYnIlM0UlM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQi0lMjAlRTUlQTYlODIlRTklOUMlODAlRTYlOEMlODclRTUlQUUlOUElRTUlQTQlOUElRTQlQjglQUElRTUlOEYlODIlRTYlOTUlQjAlRTUlODglOTklRTklOUMlODAlRTglQTYlODElRTQlQkQlQkYlRTclOTQlQTglMjclMjYlMjclRTUlODElOUElRTklOTclQjQlRTklOUElOTQlRUYlQkMlOEMlRTQlQkUlOEIlRTUlQTYlODIlRUYlQkMlOUElM0NiciUzRQolMDklMDklMDklMDklMDklMjZuYnNwJTNCJTI2bmJzcCUzQmh0dHBzJTNBJTJGJTJGcmF3Lmdith1idXNlcmNvbnRlbnQuY29tJTJGY21saXUlMkZXb3JrZXJWbGVzczJzdWIlMkZtYWluJTJGQ2xvdWRmbGFyZVNwZWVkVGVzdC5jc3YlM0ZpZCUzRENGJUU0JUJDJTk4JUU5JTgwJTg5JTNDc3Ryb25nJTNFJTI2JTNDJTJGc3Ryb25nJTNFcG9ydCUzRDIwNTMlM0NiciUzRQ==')))}
                </div>
                <div class="editor-container">
                    ${hasKV ? `
                    <textarea class="editor" 
                        placeholder="${decodeURIComponent(atob('QUREJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCnZpc2EuY24lMjMlRTQlQkMlOTglRTklODAlODklRTUlOUYlOUYlRTUlOTAlOEQKMTI3LjAuMC4xJTNBMTIzNCUyM0NGbmF0CiU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MyUyM0lQdjYKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QQolRTYlQUYlOEYlRTglQTElOEMlRTQlQjglODAlRTQlQjglQUElRTUlOUMlQjAlRTUlOUQlODAlRUYlQkMlOEMlRTYlQTAlQkMlRTUlQkMlOEYlRTQlQjglQkElMjAlRTUlOUMlQjAlRTUlOUQlODAlM0ElRTclQUIlQUYlRTUlOEYlQTMlMjMlRTUlQTQlODclRTYlQjMlQTgKSVB2NiVFNSU5QyVCMCVFNSU9RCU4MCVFOSU5QyU4MCVFOCVBNiU4MSVFNyU5NCVBOCVFNCVCOCVBRCVFNiU4QiVBQyVFNSU8RiVCNyVFNiU4QiVBQyVFOCVCNSVCNyVFNiU5RCVBNSVFRiVCQyU4QyVFNSVBNiU4MiVFRiVCQyU5QSU1QjI2MDYlM0E0NzAwJTNBJTNBJTVEJTNBMjA1MwolRTclQUIlQUYlRTUlOEYlQTMlRTQlQjglOEQlRTUlODYlOTklRUYlQkMlOEMlRTklQkIlOTglRTglQUUlQTQlRTQlQjglQkElMjA0NDMlMjAlRTclQUIlQUYlRTUlOEYlQTMlRUYlQkMlOEMlRTUlQTYlODIlRUYlQkMlOUF2aXNhLmNuJTIzJUU0JUJDJTk4JUU5JTgwJTg5JUU1JTlGJTlGJUU1JTkwJThECgoKQUREQVBJJUU3JUE0JUJBJUU0JUJFJThCJUVGJUJDJTlBCmh0dHBzJTNBJTJGJTJGcmF3LmdpdGh1YnVzZXJjb250ZW50LmNvbSUyRmNtbGl1JTJGV29ya2VyVmxlc3Myc3ViJTJGcmVmcyUyRmhlYWRzJTJGbWFpbiUyRmFkZHJlc3Nlc2FwaS50eHQKCiVFNiVCMyVBOCVFNiU4NCU4RiVFRiVCQyU5QUFEREFQSSVFNyU5QiVCNCVFNiU4RSVBNSVFNiVCNyVCQiVFNSU4QSVBMCVFNyU5QiVCNCVFOSU5MyVCRSVFNSU8RCVCMyVFNSU8RiVBRg=='))}"
                        id="content">${content}</textarea>
                    <div class="save-container">
                        <button class="back-btn" onclick="goBack()">Back to Config Page</button>
                        <button class="save-btn" onclick="saveContent(this)">Save</button>
                        <span class="save-status" id="saveStatus"></span>
                    </div>
                    <br>
                    ################################################################<br>
                    ${cmad}
                    ` : '<p>No KV namespace bound</p>'}
                </div>
        
                <script>
                if (document.querySelector('.editor')) {
                    let timer;
                    const textarea = document.getElementById('content');
                    const originalContent = textarea.value;
        
                    function goBack() {
                        const currentUrl = window.location.href;
                        const parentUrl = currentUrl.substring(0, currentUrl.lastIndexOf('/'));
                        window.location.href = parentUrl;
                    }
        
                    function replaceFullwidthColon() {
                        const text = textarea.value;
                        textarea.value = text.replace(/：/g, ':');
                    }
                    
                    function saveContent(button) {
                        try {
                            const updateButtonText = (step) => {
                                button.textContent = `Saving: ${step}`;
                            };
                            // Detect if the device is iOS
                            const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent);
                            
                            // Execute replaceFullwidthColon only on non-iOS devices
                            if (!isIOS) {
                                replaceFullwidthColon();
                            }
                            updateButtonText('Starting save');
                            button.disabled = true;
                            // Get textarea content and original content
                            const textarea = document.getElementById('content');
                            if (!textarea) {
                                throw new Error('Text editor area not found');
                            }
                            updateButtonText('Fetching content');
                            let newContent;
                            let originalContent;
                            try {
                                newContent = textarea.value || '';
                                originalContent = textarea.defaultValue || '';
                            } catch (e) {
                                console.error('Error fetching content:', e);
                                throw new Error('Unable to fetch edited content');
                            }
                            updateButtonText('Preparing status update function');
                            const updateStatus = (message, isError = false) => {
                                const statusElem = document.getElementById('saveStatus');
                                if (statusElem) {
                                    statusElem.textContent = message;
                                    statusElem.style.color = isError ? 'red' : '#666';
                                }
                            };
                            updateButtonText('Preparing button reset function');
                            const resetButton = () => {
                                button.textContent = 'Save';
                                button.disabled = false;
                            };
                            if (newContent !== originalContent) {
                                updateButtonText('Sending save request');
                                fetch(window.location.href, {
                                    method: 'POST',
                                    body: newContent,
                                    headers: {
                                        'Content-Type': 'text/plain;charset=UTF-8'
                                    },
                                    cache: 'no-cache'
                                })
                                .then(response => {
                                    updateButtonText('Checking response status');
                                    if (!response.ok) {
                                        throw new Error(`HTTP error! status: ${response.status}`);
                                    }
                                    updateButtonText('Updating save status');
                                    const now = new Date().toLocaleString();
                                    document.title = `Edit saved ${now}`;
                                    updateStatus(`Saved ${now}`);
                                })
                                .catch(error => {
                                    updateButtonText('Handling error');
                                    console.error('Save error:', error);
                                    updateStatus(`Save failed: ${error.message}`, true);
                                })
                                .finally(() => {
                                    resetButton();
                                });
                            } else {
                                updateButtonText('Checking content changes');
                                updateStatus('Content unchanged');
                                resetButton();
                            }
                        } catch (error) {
                            console.error('Error during save process:', error);
                            button.textContent = 'Save';
                            button.disabled = false;
                            const statusElem = document.getElementById('saveStatus');
                            if (statusElem) {
                                statusElem.textContent = `Error: ${error.message}`;
                                statusElem.style.color = 'red';
                            }
                        }
                    }
        
                    textarea.addEventListener('blur', saveContent);
                    textarea.addEventListener('input', () => {
                        clearTimeout(timer);
                        timer = setTimeout(saveContent, 5000);
                    });
                }
        
                function toggleNotice() {
                    const noticeContent = document.getElementById('noticeContent');
                    const noticeToggle = document.getElementById('noticeToggle');
                    if (noticeContent.style.display === 'none' || noticeContent.style.display === '') {
                        noticeContent.style.display = 'block';
                        noticeToggle.textContent = 'Notes ∧';
                    } else {
                        noticeContent.style.display = 'none';
                        noticeToggle.textContent = 'Notes ∨';
                    }
                }
        
                // Initialize noticeContent display property
                document.addEventListener('DOMContentLoaded', () => {
                    document.getElementById('noticeContent').style.display = 'none';
                });
                </script>
            </body>
            </html>
        `;

        return new Response(html, {
            headers: { "Content-Type": "text/html;charset=utf-8" }
        });
    } catch (error) {
        console.error('Error occurred while processing request:', error);
        return new Response("Server error: " + error.message, {
            status: 500,
            headers: { "Content-Type": "text/plain;charset=utf-8" }
        });
    }
}
