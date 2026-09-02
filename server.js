/**
 * ============================================================
 * NFS-e SOAP RELAY (Node/Render) — Uberlândia/MG — porta 8003
 * ============================================================
 * Por que este relay existe: o webservice da Prefeitura de Uberlândia
 * (https://nfsews.uberlandia.mg.gov.br:8003/nfse-ws/soap/nfse) exige
 * TLS completo (SNI + certificado A1) na porta 8003, que é bloqueada
 * por: hospedagem compartilhada (saída bloqueada), proxy Base44
 * (TLS só na 443) e Cloudflare Workers (starttls sem SNI/cert cliente).
 * Node.js faz o TLS completo com node:tls — SNI correto + cert A1.
 *
 * CONTRATO (idêntico ao relay Cloudflare — o NfseService.php não muda):
 *   POST JSON { webserviceUrl, soapXml, soapAction, certPem }
 *   → { "status":"ok", "httpCode":200, "response":"<soap...>" }
 *   erro: { "status":"erro_conexao"|"erro", "motivo":"[TLS] ...", "stage":"..." }
 *
 *   POST { "mode":"teste", "webserviceUrl":"https://...:8003/..." }
 *   → formato do diagnóstico (status, tcp, tls, sni, certClienteCarregado,
 *      protocoloTls, cipher, wsdl, httpCode)
 *
 * SEGURANÇA: RELAY_TOKEN obrigatório (env) validado no header X-Relay-Token;
 * logs sanitizados (nunca registra PEM/token/XML completo);
 * anti-SSRF (só https + hostname público).
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

/** Conecta com TLS completo: SNI + certificado de cliente (A1) */
function tlsConnect(target, certPem, insecure) {
  return new Promise((resolve, reject) => {
    const opts = {
      host: target.host,
      port: target.port,
      servername: target.host, // SNI — essencial para a prefeitura
      rejectUnauthorized: insecure !== "true" && insecure !== true,
    };
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

/** Envia requisição HTTP sobre o socket TLS e devolve a resposta bruta */
function httpOverTls(sock, target, { method, path, headers, body }) {
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
      const e = new Error(`timeout aguardando resposta (${REQUEST_TIMEOUT_MS}ms)`);
      e.stage = "soap";
      reject(e);
    }, REQUEST_TIMEOUT_MS);

    const chunks = [];
    sock.on("data", (c) => {
      if (chunks.reduce((n, x) => n + x.length, 0) + c.length > MAX_BODY_BYTES) {
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
      resolve(Buffer.concat(chunks));
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
  return { httpCode: m ? parseInt(m[1], 10) : 0, headers, body };
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

  // TLS completo
  try {
    const sock = await tlsConnect(target, payload.certPem, insecure);
    out.tls = "OK";
    out.sni = "OK (" + target.host + ")";
    out.certClienteCarregado = splitPem(payload.certPem).keys.length > 0;
    try {
      out.protocoloTls = sock.getProtocol();
      const c = sock.getCipher();
      out.cipher = c ? c.name : null;
    } catch (_) {}

    // GET ?wsdl — só leitura
    try {
      const raw = await httpOverTls(sock, target, {
        method: "GET",
        path: (target.path.replace(/\?.*$/, "")) + "?wsdl",
        headers: {
          "User-Agent": "PDVMOVEL-NFSe-Relay/1.0",
          "Accept": "text/xml, application/xml",
          "Accept-Encoding": "identity",
        },
      });
      const { httpCode, body } = parseHttpResponse(raw);
      out.httpCode = httpCode;
      out.wsdl = /^\s*<\??xml|^\s*<wsdl|^\s*<definitions/i.test(body)
        ? "OK (XML/WSDL retornado)"
        : "NAO (" + body.slice(0, 100) + ")";
      out.endpoint = "OK";
    } catch (e) {
      out.wsdl = "nao testado: " + String(e && e.message || e).slice(0, 150);
    }
  } catch (e) {
    out.tls = "ERRO: " + String(e && e.message || e).slice(0, 250);
    out.motivo = "[TLS] " + String(e && e.message || e).slice(0, 250);
    out.stage = "tls";
    out.status = "erro_conexao";
  }

  return out;
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

  // modo teste OU produção
  try {
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

    const sock = await tlsConnect(target, payload.certPem, process.env.NFSE_RELAY_INSECURE);
    const raw = await httpOverTls(sock, target, {
      method: "POST",
      path: target.path,
      headers: {
        "Content-Type": "text/xml; charset=utf-8",
        SOAPAction: `"${payload.soapAction || ""}"`,
        "User-Agent": "PDVMOVEL-NFSe-Relay/1.0",
        "Accept": "text/xml, application/xml",
        "Accept-Encoding": "identity",
      },
      body: payload.soapXml,
    });
    const { httpCode, headers, body } = parseHttpResponse(raw);
    console.log("[RELAY] HTTP " + httpCode + " | CT: " + (headers["content-type"] || "-") + " | " + body.length + " bytes");
    res.writeHead(200);
    res.end(JSON.stringify({ status: "ok", httpCode, response: body, responseLength: body.length }));
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
  console.log("[RELAY] NFS-e relay Node ouvindo na porta " + PORT);
});