import http, { type IncomingMessage, type ServerResponse } from 'node:http';
import { createReadStream } from 'node:fs';
import { realpath, stat } from 'node:fs/promises';
import { dirname, extname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { AiService, RequestError, validateExplainRequest, type LocalModelBackend } from './ai';

const MIME: Record<string, string> = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.ico': 'image/x-icon', '.json': 'application/json; charset=utf-8',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json', '.woff2': 'font/woff2',
};
const CSP = [
  "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' blob: data:",
  "font-src 'self'", "connect-src 'self'", "worker-src 'self' blob:", "media-src 'none'",
  "object-src 'none'", "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
].join('; ');

function headers(response: ServerResponse): void {
  response.setHeader('Content-Security-Policy', CSP);
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
  response.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
  response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  response.setHeader('Cache-Control', 'no-store');
}
function json(response: ServerResponse, status: number, data: unknown): void {
  if (response.destroyed || response.writableEnded) return;
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  response.end(JSON.stringify(data));
}
async function readJson(request: IncomingMessage): Promise<unknown> {
  if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') throw new RequestError(415, 'Use application/json.');
  if (request.headers['content-encoding']) throw new RequestError(415, 'Compressed request bodies are not supported.');
  const size = Number(request.headers['content-length'] ?? 0);
  if (!Number.isFinite(size) || size > 32_768) throw new RequestError(413, 'Request is too large.');
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > 32_768) throw new RequestError(413, 'Request is too large.');
    chunks.push(Buffer.from(chunk));
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); }
  catch { throw new RequestError(400, 'Invalid JSON body.'); }
}
function within(root: string, path: string): boolean {
  const rel = relative(root, path);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

export interface ServerOptions { distDir?: string; backend?: LocalModelBackend; aiTimeoutMs?: number; }
export function createAppServer(options: ServerOptions = {}): http.Server {
  const distDir = resolve(options.distDir ?? resolve(dirname(fileURLToPath(import.meta.url)), '../dist'));
  const ai = new AiService(options.backend, options.aiTimeoutMs);
  let activeStatus = 0;
  const server = http.createServer({ maxHeaderSize: 8192, requestTimeout: 10_000, headersTimeout: 5000, keepAliveTimeout: 5000 }, async (request, response) => {
    headers(response);
    try {
      const address = server.address();
      const port = address && typeof address === 'object' ? address.port : 4173;
      const authority = `127.0.0.1:${port}`;
      // Exact loopback Host/Origin checks defend against DNS rebinding and web-page requests.
      if (request.headers.host !== authority || (request.headers.origin && request.headers.origin !== `http://${authority}`)
          || request.headers['sec-fetch-site'] === 'cross-site') {
        throw new RequestError(403, 'This application only accepts requests from its own local page.');
      }
      const rawPath = (request.url ?? '/').split('?')[0];
      if (rawPath === '/api/health' && request.method === 'GET') {
        json(response, 200, { ok: true, offline: true, version: '1.0.0' }); return;
      }
      if (rawPath === '/api/ai/status' && request.method === 'GET') {
        if (activeStatus >= 4) throw new RequestError(429, 'Too many status requests.');
        activeStatus++;
        try { json(response, 200, await ai.status()); } finally { activeStatus--; }
        return;
      }
      if (rawPath === '/api/ai/explain' && request.method === 'POST') {
        if (request.headers.origin !== `http://${authority}`) throw new RequestError(403, 'An explanation must be requested from the local page.');
        const body = validateExplainRequest(await readJson(request));
        const cancelled = new AbortController();
        response.on('close', () => { if (!response.writableEnded) cancelled.abort(); });
        json(response, 200, await ai.explain(body, cancelled.signal));
        return;
      }
      if (rawPath.startsWith('/api/')) { json(response, 404, { error: 'API endpoint not found.' }); return; }
      if (request.method !== 'GET' && request.method !== 'HEAD') throw new RequestError(405, 'Method not allowed.');
      let decoded: string;
      try { decoded = decodeURIComponent(rawPath); } catch { throw new RequestError(400, 'Invalid path.'); }
      if (!decoded.startsWith('/') || /[\\\x00-\x1f:]/.test(decoded) || decoded.split('/').some((part) => part === '..' || part === '.')) {
        throw new RequestError(400, 'Invalid path.');
      }
      const target = resolve(distDir, `.${decoded === '/' ? '/index.html' : decoded}`);
      if (!within(distDir, target)) throw new RequestError(403, 'Invalid path.');
      let physical: string;
      let root: string;
      try { [physical, root] = await Promise.all([realpath(target), realpath(distDir)]); }
      catch { throw new RequestError(404, 'File not found. Build the application before starting it.'); }
      if (!within(root, physical) || !(await stat(physical)).isFile()) throw new RequestError(404, 'File not found.');
      if (!Object.hasOwn(MIME, extname(physical))) throw new RequestError(404, 'File not found.');
      response.setHeader('Content-Type', MIME[extname(physical)]);
      if (/\/assets\/[\w.-]+-[\w-]{8,}\.(?:js|css|woff2)$/.test(decoded)) response.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
      response.setHeader('Content-Length', (await stat(physical)).size);
      if (request.method === 'HEAD') { response.end(); return; }
      const stream = createReadStream(physical);
      stream.on('error', () => response.destroy());
      response.on('close', () => stream.destroy());
      stream.pipe(response);
    } catch (error) {
      if (error instanceof RequestError) json(response, error.status, { error: error.message });
      else json(response, 500, { error: 'The local server could not complete this request.' });
    }
  });
  server.maxConnections = 64;
  server.on('clientError', (_error, socket) => {
    if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
  });
  return server;
}

export function startServer(): http.Server {
  const configuredPort = process.env.PHISHLENS_PORT ?? '4173';
  if (!/^\d+$/.test(configuredPort) || Number(configuredPort) < 1024 || Number(configuredPort) > 65535) throw new Error('PHISHLENS_PORT must be between 1024 and 65535.');
  const server = createAppServer();
  server.listen(Number(configuredPort), '127.0.0.1', () => {
    process.stdout.write(`PhishLens is available at http://127.0.0.1:${configuredPort}\nYour submitted URLs are never visited or logged.\n`);
  });
  server.on('error', () => { process.stderr.write('PhishLens could not start. Check whether its local port is already in use.\n'); process.exitCode = 1; });
  const shutdown = () => {
    server.close();
    server.closeIdleConnections();
    const timer = setTimeout(() => server.closeAllConnections(), 3000);
    timer.unref();
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);
  return server;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) startServer();
