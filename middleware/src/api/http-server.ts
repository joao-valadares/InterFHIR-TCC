import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { X509Certificate } from "node:crypto";
import type { Server as HttpServer } from "node:http";
import type { TLSSocket } from "node:tls";

import type { ApiRequest, ApiResponse } from "./api-handler.js";
import { assertCertificateIdentity, certificateIdentityFromX509 } from "../pki/certificate-identity.js";

interface Api {
  handle(request: ApiRequest): Promise<ApiResponse>;
}

export function createHttpServer(api: Api) {
  return createServer((request, response) => void handleRequest(api, request, response));
}

export function createMutualTlsServer(
  api: Api,
  options: {
    key: string | Buffer;
    cert: string | Buffer;
    ca: string | Buffer;
    expectedOrganization: string;
    healthPath?: string;
  }
): HttpsServer {
  const { healthPath = "/health", ...tlsOptions } = options;
  return createHttpsServer({ ...tlsOptions, requestCert: true, rejectUnauthorized: false }, (request, response) => {
    const socket = request.socket as TLSSocket;
    if (request.method === "GET" && normalizePath(request.url ?? "/") === healthPath) {
      void handleRequest(api, request, response);
      return;
    }

    const peer = socket.getPeerCertificate();
    try {
      if (!peer.raw) throw new Error("CLIENT_CERTIFICATE_REQUIRED");
      if (!socket.authorized) throw new Error("CLIENT_CERTIFICATE_NOT_TRUSTED");
      const certificateIdentity = certificateIdentityFromX509(new X509Certificate(peer.raw));
      assertCertificateIdentity(certificateIdentity, { expectedOrganization: options.expectedOrganization });
      void handleRequest(api, request, response, certificateIdentity);
    } catch (error) {
      writeJson(response, { status: 403, body: { error: error instanceof Error ? error.message : "CLIENT_CERTIFICATE_INVALID" } });
    }
  });
}

async function handleRequest(api: Api, request: IncomingMessage, response: ServerResponse, certificateIdentity?: ApiRequest["certificateIdentity"]) {
  try {
  const apiResponse = await api.handle({
    method: request.method ?? "GET",
    path: request.url ?? "/",
    body: await readJsonBody(request),
    authorization: request.headers.authorization,
    idempotencyKey: Array.isArray(request.headers["idempotency-key"])
      ? request.headers["idempotency-key"][0]
      : request.headers["idempotency-key"],
    headers: Object.fromEntries(
      Object.entries(request.headers).map(([name, value]) => [
        name.toLowerCase(),
        Array.isArray(value) ? value[0] : value
      ])
    ),
    ...(certificateIdentity ? { certificateIdentity } : {})
  });
  writeJson(response, apiResponse);
  } catch (error) {
    if (response.destroyed || response.writableEnded) return;
    if (response.headersSent) { response.destroy(); return; }
    const known = error instanceof BodyError;
    writeJson(response, { status: known ? error.status : 500, body: { error: known ? error.message : "INTERNAL_SERVER_ERROR" } });
  }
}

async function readJsonBody(request: IncomingMessage) {
  if (request.method === "GET" || request.method === "HEAD") {
    return undefined;
  }

  const chunks: Buffer[] = [];
  await new Promise<void>((resolve, reject) => {
    let size = 0;
    const finish = (error?: Error) => {
      clearTimeout(timer);
      request.removeListener("data", data);
      request.removeListener("end", end);
      request.removeListener("aborted", aborted);
      request.removeListener("error", failed);
      // Drain a rejected body without retaining it or triggering unhandled stream errors.
      if (error) { request.on("error", () => undefined); request.resume(); reject(error); }
      else resolve();
    };
    const data = (chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      size += buffer.length;
      if (size > 1024 * 1024) finish(new BodyError(413, "REQUEST_BODY_TOO_LARGE"));
      else chunks.push(buffer);
    };
    const end = () => finish();
    const aborted = () => finish(new BodyError(400, "REQUEST_ABORTED"));
    const failed = () => finish(new BodyError(400, "REQUEST_BODY_UNREADABLE"));
    const timer = setTimeout(() => finish(new BodyError(408, "REQUEST_BODY_TIMEOUT")), 30_000);
    timer.unref();
    request.on("data", data).once("end", end).once("aborted", aborted).once("error", failed);
  });

  const rawBody = Buffer.concat(chunks).toString("utf8").trim();
  if (rawBody.length === 0) {
    return undefined;
  }

  if (request.headers["content-type"]?.startsWith("application/x-www-form-urlencoded")) {
    return Object.fromEntries(new URLSearchParams(rawBody));
  }

  try {
    return JSON.parse(rawBody) as unknown;
  } catch {
    throw new BodyError(400, "INVALID_JSON");
  }
}

class BodyError extends Error {
  constructor(readonly status: number, code: string) { super(code); }
}

function writeJson(response: ServerResponse, apiResponse: ApiResponse) {
  response.statusCode = apiResponse.status;
  response.setHeader("content-type", "application/json; charset=utf-8");
  for (const [name, value] of Object.entries(apiResponse.headers ?? {})) {
    response.setHeader(name, value);
  }
  response.end(`${JSON.stringify(apiResponse.body, null, 2)}\n`);
}

function normalizePath(value: string) {
  const cleanPath = value.split("?")[0] ?? "/";
  if (cleanPath.length > 1 && cleanPath.endsWith("/")) return cleanPath.slice(0, -1);
  return cleanPath;
}
