import fs from 'node:fs/promises';
import path from 'node:path';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';
import type { APIRequestContext, Page } from '@playwright/test';

export interface PngOptions {
  width?: number;
  height?: number;
  /** Solid fill as [r, g, b]. */
  color?: [number, number, number];
  /** Stored verbatim in a tEXt chunk so the marker can be asserted on the raw response body. */
  comment?: string;
}

/** Writes a small valid solid-colour PNG without any image library (dependency-free, deterministic). */
export async function writePngFile(filePath: string, options: PngOptions = {}): Promise<void> {
  const width = options.width ?? 64;
  const height = options.height ?? 48;
  const [r, g, b] = options.color ?? [196, 102, 58];
  const row = Buffer.alloc(1 + width * 3);
  for (let x = 0; x < width; x += 1) {
    row[1 + x * 3] = r;
    row[2 + x * 3] = g;
    row[3 + x * 3] = b;
  }
  const raw = Buffer.concat(Array.from({ length: height }, () => row));

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // colour type: RGB
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const chunks = [pngChunk('IHDR', ihdr)];
  if (options.comment) {
    chunks.push(pngChunk('tEXt', Buffer.concat([Buffer.from('Comment', 'latin1'), Buffer.from([0]), Buffer.from(options.comment, 'latin1')])));
  }
  chunks.push(pngChunk('IDAT', zlib.deflateSync(raw)));
  chunks.push(pngChunk('IEND', Buffer.alloc(0)));

  await fs.mkdir(path.dirname(filePath), { recursive: true });
  await fs.writeFile(filePath, Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), ...chunks]));
}

function pngChunk(type: string, data: Buffer): Buffer {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length, 0);
  const typeAndData = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeAndData), 0);
  return Buffer.concat([length, typeAndData, crc]);
}

function crc32(buffer: Buffer): number {
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc ^= byte;
    for (let i = 0; i < 8; i += 1) {
      crc = (crc >>> 1) ^ (0xedb88320 & -(crc & 1));
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

export async function createE2EUser(request: APIRequestContext, suffix: string, role: 'user' | 'admin' = 'user') {
  const email = `e2e-${suffix}-${Date.now()}@example.test`;
  const response = await request.post('/api/e2e/users', {
    form: {
      email,
      password: 'P@ssw0rd!123',
      role
    }
  });

  if (!response.ok()) {
    throw new Error(`Failed to create e2e user: ${response.status()} ${await response.text()}`);
  }

  const json = await response.json();
  return {
    email: json.email as string,
    password: json.password as string,
  };
}

export async function login(page: Page, email: string, password: string) {
  const targetUrl = /\/($|dashboard|shares\/new(\?.*)?)/;

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    await page.goto('/login');
    await submitLoginForm(page, email, password);

    try {
      await page.waitForURL(targetUrl, { timeout: 12_000 });
      return;
    } catch {
      if (attempt === 3) {
        throw new Error('Login did not complete after 3 attempts.');
      }
    }
  }
}

/** Fills and submits the sign-in form on the current page (for example /login?returnUrl=...) without navigating first. */
export async function submitLoginForm(page: Page, email: string, password: string) {
  const loginForm = page.locator('form[action="/login"]').first();
  await loginForm.locator('input[name="email"]').fill(email);
  await loginForm.locator('input[name="password"]').fill(password);

  await page.evaluate(() => {
    const form = document.querySelector('form[action="/login"]');
    if (!form) return;
    const parts = document.cookie ? document.cookie.split(';') : [];
    const tokenCookie = parts
      .map((x) => x.trim())
      .find((x) => x.startsWith('agora.csrf.request='));
    if (!tokenCookie) return;
    const token = decodeURIComponent(tokenCookie.slice('agora.csrf.request='.length));
    let input = form.querySelector('input[name="__RequestVerificationToken"]') as HTMLInputElement | null;
    if (!input) {
      input = document.createElement('input');
      input.type = 'hidden';
      input.name = '__RequestVerificationToken';
      form.appendChild(input);
    }
    input.value = token;
  });

  await loginForm.locator('button[type="submit"]').click();
}

export async function createTempFiles(baseDir: string, files: Array<{ name: string; content: string | Buffer }>) {
  await fs.mkdir(baseDir, { recursive: true });
  const paths: string[] = [];
  for (const file of files) {
    const filePath = path.join(baseDir, file.name);
    if (Buffer.isBuffer(file.content)) {
      await fs.writeFile(filePath, file.content);
    } else {
      await fs.writeFile(filePath, file.content, 'utf8');
    }
    paths.push(filePath);
  }
  return paths;
}

export function extractShareUrl(text: string, fallbackPageUrl?: string): string {
  const match = text.match(/https?:\/\/[^\s]+\/s\/[A-Za-z0-9_-]+/);
  if (match) {
    return match[0];
  }

  if (fallbackPageUrl) {
    // The created page is /shares/created/{token} (older builds used ?token=).
    const fallback = new URL(fallbackPageUrl);
    const routeToken = fallback.pathname.match(/\/shares\/created\/([^/?#]+)$/)?.[1];
    const token = routeToken ? decodeURIComponent(routeToken) : fallback.searchParams.get('token');
    if (token) {
      return `${fallback.origin}/s/${token}`;
    }
  }

  throw new Error(`Could not find share URL in text: ${text}`);
}

export function tokenFromShareUrl(shareUrl: string): string {
  const parsed = new URL(shareUrl);
  const parts = parsed.pathname.split('/').filter(Boolean);
  const token = parts[1];
  if (!token) {
    throw new Error(`Invalid share URL: ${shareUrl}`);
  }
  return token;
}

export async function waitForShareReady(page: Page, shareUrl: string, timeoutMs = 120_000): Promise<void> {
  const token = tokenFromShareUrl(shareUrl);
  const startedAt = Date.now();

  while (Date.now() - startedAt < timeoutMs) {
    const response = await page.request.get(`/api/shares/${token}/status`);
    if (response.ok()) {
      const payload = await response.json() as { ready?: boolean; state?: string };
      if (payload.ready || payload.state === 'completed') {
        return;
      }
    }

    await page.waitForTimeout(1000);
  }

  throw new Error(`Timed out waiting for share ${token} to become ready.`);
}

type FileSystemEmailRecord = {
  to?: string;
  metadata?: { ActionUrl?: string };
};

/** The newest E2E run's email output directory (the filesystem email sender writes one JSON file per message). */
async function latestEmailDirectory(): Promise<string> {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
  const runsRoot = path.join(repoRoot, '.e2e-data', 'runs');
  const entries = await fs.readdir(runsRoot, { withFileTypes: true }).catch(() => []);
  const candidates: Array<{ dir: string; mtimeMs: number }> = [];
  for (const entry of entries) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(runsRoot, entry.name, 'emails');
    const stats = await fs.stat(dir).catch(() => null);
    if (stats?.isDirectory()) candidates.push({ dir, mtimeMs: stats.mtimeMs });
  }
  if (candidates.length === 0) throw new Error(`No email output directories under ${runsRoot}`);
  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return candidates[0].dir;
}

/** Waits for an email to <to> whose action link contains <pathPart> and returns that link. */
export async function waitForEmailActionUrl(to: string, pathPart: string, timeoutMs = 60_000): Promise<string> {
  const startedAt = Date.now();
  const dir = await latestEmailDirectory();
  while (Date.now() - startedAt < timeoutMs) {
    for (const name of (await fs.readdir(dir).catch(() => [])).filter((x) => x.endsWith('.json'))) {
      const record = JSON.parse(await fs.readFile(path.join(dir, name), 'utf8')) as FileSystemEmailRecord;
      const actionUrl = record.metadata?.ActionUrl ?? '';
      if (record.to === to && actionUrl.includes(pathPart)) {
        return actionUrl;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error(`Timed out waiting for an email to ${to} with ${pathPart}.`);
}

/** Opens an emailed account confirmation link and confirms it with the account password. */
export async function confirmEmailWithPassword(page: Page, confirmUrl: string, password: string) {
  await page.goto(confirmUrl);
  const form = page.locator('form').filter({ has: page.locator('input[name="token"]') }).first();
  await form.locator('input[name="password"]').fill(password);
  await form.locator('button[type="submit"]').click();
}
