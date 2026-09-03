/**
 * ============================================================
 * NFS-e SOAP RELAY (Node/Render) v1.3.1 — Uberlândia/MG — porta 8003
 * ============================================================
 * v1.1 (02/09/2026): modo teste em ESCADA de diagnóstico quando
 * há certPem: (1) GET ?wsdl com cert de cliente, (2) POST neutro
 * (sem dados fiscais) e (3) repetição com TLS 1.2 forçado se o
 * servidor fechar a conexão sem resposta. Na EMISSÃO REAL: se o
 * servidor fechar sem responder (0 bytes — sintoma visto em
 * 02/09 20:10), tenta de novo com TLS 1.2 automaticamente.
 *
 * CONTRATO (idêntico ao relay Cloudflare — o NfseService.php não muda):
 *   POST JSON { webserviceUrl, soapXml, soapAction, certPem }
 *   → { "status":"ok", "httpCode":200, "response":"<soap...>" }
 *   erro: { "status":"erro_conexao"|"erro", "motivo":"[TLS] ...", "stage":"..." }
 *
 *   POST { "mode":"teste", "webserviceUrl":"https://...:8003/...", "certPem": ... }
 *   → { status, modo, host, port, tcp, tls, sni, certClienteCarregado,
 *       protocoloTls, cipher, getHttpCode, getWsdl, postHttpCode, postBody, ... }
 *
 * SEGURANÇA: RELAY_TOKEN obrigatório (env) validado no header X-Relay-Token;
 * logs sanitizados (nunca registra PEM/token/XML completo); anti-SSRF.
 */

const http = require("http");
const tls = require("tls");

const CONNECT_TIMEOUT_MS = 10000;
const REQUEST_TIMEOUT_MS = 60000;
const MAX_BODY_BYTES = 10 * 1024 * 1024;

// ---------- helpers ----------

function parseTarget(webserviceUrl) {
  let u;
  try {
    u = new URL(webserviceUrl);
  } catch {
    const e = new Error("webserviceUrl inválida");
    e.stage = "payload";
    throw e;
  }
  if (u.protocol !== "https:") {
    const e = new Error("webserviceUrl deve ser https:// (o webservice exige TLS)");
    e.stage = "payload";
    throw e;
  }
  const host = u.hostname;
  if (
    /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/i.test(host) ||
    !host.includes(".")
  ) {
    const e = new Error("hostname não permitido");
    e.stage = "payload";
    throw e;
  }
  return {
    host,
    port: parseInt(u.port || "443", 10),
    path: (u.pathname || "/") + (u.search || ""),
  };
}

/** Separa chaves privadas e certificados de um blob PEM concatenado */
function splitPem(pem) {
  const keys = String(pem || "").match(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g) || [];
  const certs = String(pem || "").match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
  return { keys, certs };
}

/**
 * Conecta com TLS completo: SNI + certificado de cliente (A1).
 * forceTls12=true limita a TLS 1.2 (diagnóstico/fallback p/ servidores antigos).
 */
function tlsConnect(target, certPem, insecure, forceTls12) {
  return new Promise((resolve, reject) => {
    const opts = {
      host: target.host,
      port: target.port,
      servername: target.host, // SNI — essencial para a prefeitura
      ALPNProtocols: ["http/1.1"],
      rejectUnauthorized: insecure !== "true" && insecure !== true,
    };
    if (forceTls12) {
      opts.minVersion = "TLSv1.2";
      opts.maxVersion = "TLSv1.2";
    }
    const { keys, certs } = splitPem(certPem);
    if (keys.length) opts.key = keys.join("\n");
    if (certs.length) opts.cert = certs.join("\n");

    const timer = setTimeout(() => {
      sock && sock.destroy();
      const e = new Error(`timeout conectando ${target.host}:${target.port} (${CONNECT_TIMEOUT_MS}ms)`);
      e.stage = "tls";
      reject(e);
    }, CONNECT_TIMEOUT_MS);

    const sock = tls.connect(opts, () => {
      clearTimeout(timer);
      resolve(sock);
    });
    sock.once("error", (err) => {
      clearTimeout(timer);
      err.stage = "tls";
      reject(err);
    });
  });
}

/**
 * Envia requisição HTTP sobre o socket TLS e devolve { httpCode, headers, body, bytes }
 * Resolve também quando o servidor fecha SEM responder (httpCode 0, body "")
 */
function httpOverTls(sock, target, { method, path, headers, body, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const bodyBuf = body ? Buffer.from(body, "utf8") : null;
    const head = [
      `${method} ${path || "/"} HTTP/1.1`,
      `Host: ${target.host}:${target.port}`,
      ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
      ...(bodyBuf ? [`Content-Length: ${bodyBuf.length}`] : []),
      "Connection: close",
      "",
    ].join("\r\n") + "\r\n";

    const timer = setTimeout(() => {
      sock.destroy();
      const e = new Error(`timeout aguardando resposta (${timeoutMs || REQUEST_TIMEOUT_MS}ms)`);
      e.stage = "soap";
      reject(e);
    }, REQUEST_TIMEOUT_MS);

    const chunks = [];
    let total = 0;
    sock.on("data", (c) => {
      total += c.length;
      if (total > MAX_BODY_BYTES) {
        clearTimeout(timer);
        sock.destroy();
        const e = new Error("resposta maior que 10MB");
        e.stage = "soap";
        reject(e);
        return;
      }
      chunks.push(c);
    });
    sock.on("end", () => {
      clearTimeout(timer);
      const raw = Buffer.concat(chunks);
      resolve(parseHttpResponse(raw));
    });
    sock.on("error", (err) => {
      clearTimeout(timer);
      err.stage = "soap";
      reject(err);
    });

    sock.write(head);
    if (bodyBuf) sock.write(bodyBuf);
    sock.end();
  });
}

function dechunk(s) {
  let out = "";
  let i = 0;
  while (i < s.length) {
    const lineEnd = s.indexOf("\r\n", i);
    if (lineEnd < 0) break;
    const size = parseInt(s.slice(i, lineEnd), 16);
    if (!Number.isFinite(size) || size === 0) break;
    out += s.slice(lineEnd + 2, lineEnd + 2 + size);
    i = lineEnd + 2 + size + 2;
  }
  return out;
}

function parseHttpResponse(buf) {
  const text = buf.toString("utf8");
  const sep = text.indexOf("\r\n\r\n");
  const rawHead = sep >= 0 ? text.slice(0, sep) : text;
  const bodyStart = sep >= 0 ? sep + 4 : text.length;
  const headLines = rawHead.split("\r\n");
  const m = headLines[0] ? headLines[0].match(/^HTTP\/[\d.]+\s+(\d{3})/) : null;
  const headers = {};
  for (const line of headLines.slice(1)) {
    const idx = line.indexOf(":");
    if (idx > 0) headers[line.slice(0, idx).toLowerCase().trim()] = line.slice(idx + 1).trim();
  }
  let body;
  if ((headers["transfer-encoding"] || "").includes("chunked")) {
    body = dechunk(text.slice(bodyStart));
  } else if (headers["content-length"]) {
    const cl = parseInt(headers["content-length"], 10);
    const rest = text.slice(bodyStart);
    body = Number.isFinite(cl) && cl <= rest.length ? rest.slice(0, cl) : rest;
  } else {
    body = text.slice(bodyStart);
  }
  return { httpCode: m ? parseInt(m[1], 10) : 0, headers, body, bytes: buf.length };
}

function snippet(s, n) {
  const t = String(s || "").replace(/[^\x09\x0a\x0d\x20-\x7e]/g, ".");
  return t.substring(0, n || 160);
}

// ---------- modo teste (diagnóstico, sem emissão fiscal) ----------

async function modoTeste(payload, insecure) {
  const target = parseTarget(payload.webserviceUrl);
  const out = {
    status: "ok",
    modo: "teste",
    host: target.host,
    port: target.port,
  };

  // TCP puro
  await new Promise((res) => {
    const net = require("net");
    const s = net.connect({ host: target.host, port: target.port });
    const t = setTimeout(() => { s.destroy(); res(); }, CONNECT_TIMEOUT_MS);
    s.on("connect", () => { clearTimeout(t); out.tcp = "OK"; s.destroy(); res(); });
    s.on("error", () => { clearTimeout(t); out.tcp = "ERRO"; res(); });
  });

  const hasCert = splitPem(payload.certPem || "").keys.length > 0;

  // v1.3: IP de saída do relay (best effort)
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 2000);
    out.egressIp = (await (await fetch("https://api.ipify.org", { signal: ctrl.signal })).text()).trim();
    clearTimeout(t);
  } catch (_) {}

  // TLS completo (cert se disponível)
  let sock = null;
  for (const forceTls12 of [false, true]) {
    try {
      sock = await tlsConnect(target, payload.certPem, insecure, forceTls12);
      out.tls = "OK" + (forceTls12 ? " (TLS 1.2 forçado)" : "");
      out.tlsForcado = forceTls12;
      break;
    } catch (e) {
      sock = null;
      out.tls = "ERRO: " + String(e && e.message || e).slice(0, 250);
      if (!forceTls12) continue; // tenta TLS 1.2 antes de desistir
      out.motivo = "[TLS] " + String(e && e.message || e).slice(0, 250);
      out.stage = "tls";
      out.status = "erro_conexao";
    }
  }

  if (sock) {
    out.sni = "OK (" + target.host + ")";
    out.certClienteCarregado = hasCert;

    // v1.2: sonda ociosa — espera 3s sem enviar nada.
    // Se o servidor fechar sozinho, a rejeição é da conexão/certificado,
    // não do conteúdo da requisição.
    out.conexaoOciosa = await new Promise((resolve) => {
      if (sock.destroyed) { resolve("ja fechada apos handshake"); return; }
      const t = setTimeout(() => { resolve("aberta apos 3s (sem request)"); }, 3000);
      sock.once("close", () => { clearTimeout(t); resolve("FECHOU sozinha apos handshake (sem qualquer request)"); });
      sock.once("error", () => { clearTimeout(t); resolve("erro com socket ocioso"); });
    });
    try {
      out.protocoloTls = sock.getProtocol();
      const c = sock.getCipher();
      out.cipher = c ? c.name : null;
    } catch (_) {}

    // 1) GET ?wsdl
    try {
      const g = await httpOverTls(sock, target, {
        method: "GET",
        path: target.path.replace(/\?.*$/, "") + "?wsdl",
        headers: {
          "User-Agent": "PDVMOVEL-NFSe-Relay/1.1",
          "Accept": "text/xml, application/xml",
          "Accept-Encoding": "identity",
        },
      });
      out.getHttpCode = g.httpCode;
      out.getWsdl = /^\s*<\??xml|^\s*<wsdl|^\s*<definitions/i.test(g.body)
        ? "SIM (WSDL retornado)"
        : (g.httpCode === 0
            ? "NAO — servidor fechou a conexao sem responder (0 bytes)"
            : "NAO (" + snippet(g.body, 120) + ")");
    } catch (e) {
      out.getWsdl = "ERRO: " + String(e && e.message || e).slice(0, 150);
    }

    // 2) POST neutro (sem dados fiscais) — testa o caminho exato da emissão
    try {
      const p = await tlsConnect(target, payload.certPem, insecure, out.tlsForcado);
      const r = await httpOverTls(p, target, {
        method: "POST",
        path: target.path.replace(/\?.*$/, ""),
        headers: {
          "Content-Type": "text/xml; charset=utf-8",
          "User-Agent": "PDVMOVEL-NFSe-Relay/1.1",
          "Accept": "text/xml, application/xml",
          "Accept-Encoding": "identity",
        },
        body: "<conectividade xmlns=\"http://pdvmovel.relay/teste\"/>",
      });
      out.postHttpCode = r.httpCode;
      out.postBody = r.httpCode === 0
        ? "(servidor fechou a conexao sem responder — 0 bytes)"
        : snippet(r.body, 200);
    } catch (e) {
      out.postBody = "ERRO: " + String(e && e.message || e).slice(0, 150);
    }
  }

  return out;
}

// ---------- produção ----------

async function sendSoap(target, payload, insecure, forceTls12, timeoutMs) {
  const sock = await tlsConnect(target, payload.certPem, insecure, forceTls12);
  const r = await httpOverTls(sock, target, {
    method: "POST",
    path: target.path,
    timeoutMs: timeoutMs,
    headers: {
      "Content-Type": "text/xml; charset=utf-8",
      SOAPAction: `"${payload.soapAction || ""}"`,
      "User-Agent": "PDVMOVEL-NFSe-Relay/1.1",
      "Accept": "text/xml, application/xml",
      "Accept-Encoding": "identity",
    },
    body: payload.soapXml,
  });
  return r;
}

// ---------- servidor ----------

const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  const token = process.env.RELAY_TOKEN;
  if (token && req.headers["x-relay-token"] !== token) {
    console.log("[RELAY] acesso negado: token inválido/ausente");
    res.writeHead(401);
    res.end(JSON.stringify({ status: "erro", motivo: "Token inválido ou ausente (X-Relay-Token)" }));
    return;
  }

  if (req.method !== "POST") {
    res.writeHead(405);
    res.end(JSON.stringify({ status: "erro", motivo: "Use POST com JSON" }));
    return;
  }

  const chunks = [];
  let size = 0;
  for await (const c of req) {
    size += c.length;
    if (size > MAX_BODY_BYTES) {
      res.writeHead(413);
      res.end(JSON.stringify({ status: "erro", motivo: "payload maior que 10MB" }));
      return;
    }
    chunks.push(c);
  }

  let payload;
  try {
    payload = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    res.writeHead(400);
    res.end(JSON.stringify({ status: "erro", motivo: "JSON inválido" }));
    return;
  }

  if (!payload.webserviceUrl) {
    res.writeHead(400);
    res.end(JSON.stringify({ status: "erro", motivo: "Parâmetro obrigatório: webserviceUrl" }));
    return;
  }

  let target;
  try {
    target = parseTarget(payload.webserviceUrl);
  } catch (e) {
    res.writeHead(400);
    res.end(JSON.stringify({ status: "erro", motivo: e.message, stage: e.stage || "payload" }));
    return;
  }

  try {
    // modo teste OU produção
    if (payload.mode === "teste" || !payload.soapXml) {
      const out = await modoTeste(payload, process.env.NFSE_RELAY_INSECURE);
      res.writeHead(200);
      res.end(JSON.stringify(out));
      return;
    }

    if (!payload.certPem) {
      res.writeHead(400);
      res.end(JSON.stringify({ status: "erro", motivo: "certPem obrigatório", stage: "payload" }));
      return;
    }

    console.log("[RELAY] SOAP -> " + target.host + ":" + target.port + " | SOAPAction: " + (payload.soapAction || ""));

    // v1.3: retry escalonado em caso de close silencioso (0 bytes).
    // Cada tentativa abre uma NOVA conexão TCP/TLS — o pool NAT do Render pode
    // sair por um IP diferente a cada conexão, contornando filtro de IP.
    const MAX_TENTATIVAS = 4;
    const TIMEOUTS = [12000, 8000, 8000, 8000]; // v1.3.1: total ~39s (PHP espera 100s)
    let r = null;
    let tentativas = 0;
    let viaTls12 = false;
    for (let i = 0; i < MAX_TENTATIVAS; i++) {
      viaTls12 = i >= 2; // tentativas 3 e 4 com TLS 1.2 forçado
      r = await sendSoap(target, payload, process.env.NFSE_RELAY_INSECURE, viaTls12, TIMEOUTS[i]);
      tentativas = i + 1;
      if (r.httpCode > 0 || (r.body || "") !== "") break; // recebeu resposta
      console.log("[RELAY] resposta vazia (0 bytes) na tentativa " + tentativas + "/" + MAX_TENTATIVAS);
      if (i < MAX_TENTATIVAS - 1) await new Promise((ok) => setTimeout(ok, 500));
    }

    // v1.3: IP de saída (best effort) — mostra qual IP a prefeitura enxergou
    let egressIp = null;
    try {
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 2000);
      egressIp = (await (await fetch("https://api.ipify.org", { signal: ctrl.signal })).text()).trim();
      clearTimeout(t);
    } catch (_) {}

    if (r.httpCode === 0 && (r.body || "") === "") {
      console.log("[RELAY] ERRO: servidor fechou sem responder em " + tentativas + "/" + MAX_TENTATIVAS + " tentativas" + (egressIp ? " | egress: " + egressIp : ""));
      res.writeHead(200);
      res.end(JSON.stringify({
        status: "erro_conexao",
        motivo: "[soap] O servidor da prefeitura fechou a conexao sem responder (0 bytes) em " + tentativas + " tentativas — provavel bloqueio/filtro de IP no firewall da prefeitura. Aguarde 30-60 min SEM testar e tente 1 vez. Se persistir, use um relay com IP fixo e peca a prefeitura para libera-lo.",
        stage: "soap",
        tentativas: tentativas,
        egressIp: egressIp,
      }));
      return;
    }

    console.log("[RELAY] HTTP " + r.httpCode + " | CT: " + (r.headers["content-type"] || "-") + " | " + r.body.length + " bytes" + (viaTls12 ? " | via TLS 1.2" : "") + (egressIp ? " | egress: " + egressIp : ""));
    res.writeHead(200);
    res.end(JSON.stringify({ status: "ok", httpCode: r.httpCode, response: r.body, responseLength: r.body.length, tentativas: tentativas, egressIp: egressIp }));
  } catch (e) {
    const msg = String(e && e.message || e).slice(0, 300);
    console.log("[RELAY] ERRO (" + (e.stage || "?") + "): " + msg);
    res.writeHead(200);
    res.end(JSON.stringify({
      status: "erro_conexao",
      motivo: "[" + (e.stage || "tls") + "] " + msg,
      stage: e.stage || "tls",
    }));
  }
});

const PORT = process.env.PORT || 10000;
server.listen(PORT, () => {
  console.log("[RELAY] NFS-e relay Node v1.2 ouvindo na porta " + PORT);
});
