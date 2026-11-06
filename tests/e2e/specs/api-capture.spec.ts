import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import type { APIRequestContext, Page } from '@playwright/test';
import { createE2EUser, createTempFiles, extractShareUrl, login, submitLoginForm, waitForShareReady, writePngFile } from '../support/helpers';

// Capture app sign-in (OAuth authorization code + PKCE with a loopback redirect) and the /api/v1 bearer API.
// Contract: docs/api/v1.md. Bearer tokens work only on /api/v1; cookies never work there.
const CLIENT_ID = 'agora-capture';
const DEVICE_NAME = "AgoraCapture on E2E's Mac";

interface Pkce {
  verifier: string;
  challenge: string;
}

interface AuthorizeParams {
  redirectUri: string;
  state: string;
  challenge: string;
  deviceName?: string;
  method?: string;
}

interface ConnectedApp {
  accessToken: string;
  tokenId: string;
}

function newPkce(): Pkce {
  const verifier = crypto.randomBytes(32).toString('base64url');
  const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function newState(): string {
  return crypto.randomBytes(16).toString('base64url');
}

function authorizePath(params: AuthorizeParams): string {
  const query = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: params.redirectUri,
    state: params.state,
    code_challenge: params.challenge,
    code_challenge_method: params.method ?? 'S256',
    device_name: params.deviceName ?? DEVICE_NAME,
  });
  return `/connect/authorize?${query.toString()}`;
}

function bearer(token: string): Record<string, string> {
  return { Authorization: `Bearer ${token}` };
}

/** A one-shot loopback listener standing in for the app's callback server. */
async function startCallbackServer(): Promise<{ redirectUri: string; received: Promise<URL>; close: () => Promise<void> }> {
  let resolveReceived: (url: URL) => void = () => {};
  const received = new Promise<URL>((resolve) => {
    resolveReceived = resolve;
  });
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1');
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end('<!doctype html><title>Connected</title><p>You can close this tab.</p>');
    if (url.pathname === '/callback') {
      resolveReceived(url);
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    redirectUri: `http://127.0.0.1:${port}/callback`,
    received,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/**
 * Opens the consent page in the signed-in browser and posts the decision with the browser's cookies, not following
 * the redirect, so the Location header can be read without a loopback listener.
 */
async function decide(page: Page, params: AuthorizeParams, decision: 'approve' | 'deny') {
  await page.goto(authorizePath(params));
  const form = page.locator('[data-connect-form]');
  await expect(form).toBeVisible();
  const fields: Record<string, string> = { decision };
  for (const input of await form.locator('input[type="hidden"]').all()) {
    fields[(await input.getAttribute('name')) ?? ''] = (await input.getAttribute('value')) ?? '';
  }
  return page.request.post('/connect/authorize', { form: fields, maxRedirects: 0 });
}

async function approveForCode(page: Page, params: AuthorizeParams): Promise<string> {
  const response = await decide(page, params, 'approve');
  expect(response.status()).toBe(302);
  const location = new URL(response.headers().location);
  expect(`${location.origin}${location.pathname}`).toBe(params.redirectUri);
  expect(location.searchParams.get('state')).toBe(params.state);
  const code = location.searchParams.get('code');
  expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);
  return code!;
}

function exchange(request: APIRequestContext, code: string, verifier: string, redirectUri: string) {
  return request.post('/api/v1/auth/token', {
    data: { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: redirectUri, client_id: CLIENT_ID },
  });
}

/** The whole connect flow for an already signed-in browser page; returns the app's bearer token. */
async function connectApp(page: Page, request: APIRequestContext, deviceName = DEVICE_NAME): Promise<ConnectedApp> {
  const pkce = newPkce();
  const params: AuthorizeParams = { redirectUri: 'http://127.0.0.1:53682/callback', state: newState(), challenge: pkce.challenge, deviceName };
  const code = await approveForCode(page, params);
  const response = await exchange(request, code, pkce.verifier, params.redirectUri);
  expect(response.status()).toBe(200);
  const body = await response.json() as { access_token: string; token_type: string; token_id: string };
  expect(body.token_type).toBe('Bearer');
  expect(body.access_token).toMatch(/^agora_pat_[A-Za-z0-9_-]{43}$/);
  return { accessToken: body.access_token, tokenId: body.token_id };
}

async function uploadCapture(request: APIRequestContext, token: string, pngPath: string, duration = '30m') {
  return request.post(`/api/v1/captures?duration=${duration}`, {
    headers: bearer(token),
    multipart: {
      file: { name: 'capture.png', mimeType: 'image/png', buffer: await fs.readFile(pngPath) },
    },
  });
}

async function expectMe(request: APIRequestContext, token: string, status: number) {
  const response = await request.get('/api/v1/me', { headers: bearer(token), maxRedirects: 0 });
  expect(response.status()).toBe(status);
  return response;
}

test.describe('Capture app API', () => {
  test('signs in through the browser: login round trip, consent, loopback callback, code exchange', async ({ page, request }) => {
    const user = await createE2EUser(request, 'api-connect');
    const callback = await startCallbackServer();
    try {
      const pkce = newPkce();
      const params: AuthorizeParams = { redirectUri: callback.redirectUri, state: newState(), challenge: pkce.challenge };
      const authorizeUrl = authorizePath(params);

      // Not signed in: the consent page sends the browser to /login and the full authorize URL survives the round trip.
      await page.goto(authorizeUrl);
      await expect(page).toHaveURL(/\/login\?returnUrl=/);
      expect(new URL(page.url()).searchParams.get('returnUrl')).toBe(authorizeUrl);
      await submitLoginForm(page, user.email, user.password);
      await page.waitForURL((url) => url.pathname === '/connect/authorize');
      expect(`${new URL(page.url()).pathname}${new URL(page.url()).search}`).toBe(authorizeUrl);

      await expect(page.locator('[data-connect-device]')).toHaveText(DEVICE_NAME);
      await expect(page.locator('[data-connect-email]')).toHaveText(user.email);
      const consent = await page.request.get(authorizeUrl, { maxRedirects: 0 });
      expect(consent.headers()['cache-control']).toContain('no-store');
      expect(consent.headers()['referrer-policy']).toBe('no-referrer');

      // Approve in the real browser: Chromium follows the redirect to the app's loopback listener.
      await page.getByRole('button', { name: 'Approve' }).click();
      const callbackUrl = await callback.received;
      expect(callbackUrl.searchParams.get('state')).toBe(params.state);
      const code = callbackUrl.searchParams.get('code') ?? '';
      expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);
      await expect(page.getByText('You can close this tab.')).toBeVisible();

      const exchanged = await exchange(request, code, pkce.verifier, params.redirectUri);
      expect(exchanged.status()).toBe(200);
      const body = await exchanged.json() as { access_token: string; token_type: string; email: string };
      expect(body.token_type).toBe('Bearer');
      expect(body.email).toBe(user.email);

      const me = await expectMe(request, body.access_token, 200);
      const meBody = await me.json() as { email: string; directLinkDurations: string[]; maxFileSizeBytes: number; serverVersion: string };
      expect(meBody.email).toBe(user.email);
      expect(meBody.directLinkDurations).toEqual(['30m', '6h', '1d', '7d']);
      expect(meBody.maxFileSizeBytes).toBeGreaterThan(0);
      expect(meBody.serverVersion).not.toBe('');

      // Codes are single use.
      const second = await exchange(request, code, pkce.verifier, params.redirectUri);
      expect(second.status()).toBe(400);
      expect((await second.json() as { error: string }).error).toBe('invalid_grant');
    } finally {
      await callback.close();
    }
  });

  test('consent page validates the request: bad redirect is shown, other errors and Deny go back to the app', async ({ page, request }) => {
    const user = await createE2EUser(request, 'api-consent');
    await login(page, user.email, user.password);
    const pkce = newPkce();
    const redirectUri = 'http://127.0.0.1:53682/callback';
    const state = newState();

    // An invalid redirect_uri is never redirected to.
    for (const bad of ['http://localhost:53682/callback', 'https://example.com/callback', 'http://127.0.0.1@example.com:53682/callback']) {
      const response = await page.request.get(authorizePath({ redirectUri: bad, state, challenge: pkce.challenge }), { maxRedirects: 0 });
      expect(response.status()).toBe(400);
      expect(response.headers().location).toBeUndefined();
    }
    await page.goto(authorizePath({ redirectUri: 'http://example.com/callback', state, challenge: pkce.challenge }));
    await expect(page.locator('[data-connect-error]')).toBeVisible();
    await expect(page.locator('[data-connect-form]')).toHaveCount(0);

    // Other invalid parameters: error=invalid_request back to the (valid) loopback redirect, with the state.
    const plain = await page.request.get(authorizePath({ redirectUri, state, challenge: pkce.challenge, method: 'plain' }), { maxRedirects: 0 });
    expect(plain.status()).toBe(302);
    const plainLocation = new URL(plain.headers().location);
    expect(`${plainLocation.origin}${plainLocation.pathname}`).toBe(redirectUri);
    expect(plainLocation.searchParams.get('error')).toBe('invalid_request');
    expect(plainLocation.searchParams.get('state')).toBe(state);
    const noState = await page.request.get(authorizePath({ redirectUri, state, challenge: pkce.challenge }).replace(/&state=[^&]*/, ''), { maxRedirects: 0 });
    expect(noState.status()).toBe(302);
    expect(new URL(noState.headers().location).searchParams.get('error')).toBe('invalid_request');
    expect(new URL(noState.headers().location).searchParams.has('state')).toBe(false);

    // Deny.
    const denied = await decide(page, { redirectUri, state, challenge: pkce.challenge }, 'deny');
    expect(denied.status()).toBe(302);
    expect(denied.headers()['cache-control']).toContain('no-store');
    const deniedLocation = new URL(denied.headers().location);
    expect(deniedLocation.searchParams.get('error')).toBe('access_denied');
    expect(deniedLocation.searchParams.get('state')).toBe(state);
    expect(deniedLocation.searchParams.has('code')).toBe(false);

    // The POST re-validates the hidden fields: a tampered redirect_uri is shown as an error, not followed.
    await page.goto(authorizePath({ redirectUri, state, challenge: pkce.challenge }));
    const fields: Record<string, string> = { decision: 'approve' };
    for (const input of await page.locator('[data-connect-form] input[type="hidden"]').all()) {
      fields[(await input.getAttribute('name')) ?? ''] = (await input.getAttribute('value')) ?? '';
    }
    const tampered = await page.request.post('/connect/authorize', { form: { ...fields, redirect_uri: 'https://example.com/callback' }, maxRedirects: 0 });
    expect(tampered.status()).toBe(400);
    expect(tampered.headers().location).toBeUndefined();
  });

  test('a token creates and deletes captures and works nowhere but /api/v1', async ({ page, request }, testInfo) => {
    const user = await createE2EUser(request, 'api-capture');
    await login(page, user.email, user.password);
    const app = await connectApp(page, request);

    const pngPath = path.join(testInfo.outputPath('files'), 'capture.png');
    // Over the app-wide 1 MiB body limit: only the capture route may take a body this large.
    await writePngFile(pngPath, { comment: `api-capture-marker${'x'.repeat(1_500_000)}` });

    const created = await uploadCapture(request, app.accessToken, pngPath);
    expect(created.status()).toBe(200);
    const capture = await created.json() as { url: string; token: string; expiresAtUtc: string };
    expect(capture.url).toBe(`http://127.0.0.1:18090/s/${capture.token}`);
    expect(new Date(capture.expiresAtUtc).getTime()).toBeGreaterThan(Date.now());

    const view = await request.get(capture.url);
    expect(view.status()).toBe(200);
    expect(view.headers()['content-type']).toBe('image/png');
    expect((await view.body()).includes(Buffer.from('api-capture-marker'))).toBe(true);

    // Refusals before any body processing.
    expect((await uploadCapture(request, app.accessToken, pngPath, '2d')).status()).toBe(400);
    const notImage = await request.post('/api/v1/captures?duration=30m', {
      headers: bearer(app.accessToken),
      multipart: { file: { name: 'notes.txt', mimeType: 'text/plain', buffer: Buffer.from('hello') } },
    });
    expect(notImage.status()).toBe(400);

    // The token is ignored by every cookie endpoint: JSON 401/403, never a login redirect.
    for (const target of [`/api/shares/${capture.token}/status`, '/admin', '/account/settings']) {
      const response = await request.get(target, { headers: bearer(app.accessToken), maxRedirects: 0 });
      expect([401, 403]).toContain(response.status());
      expect(response.headers().location).toBeUndefined();
    }
    const tokenPost = await request.post(`/shares/${crypto.randomUUID()}/delete`, { headers: bearer(app.accessToken), maxRedirects: 0 });
    expect([401, 403]).toContain(tokenPost.status());

    // The browser cookie is ignored by /api/v1.
    const cookieOnly = await page.request.get('/api/v1/me', { maxRedirects: 0 });
    expect(cookieOnly.status()).toBe(401);
    expect(cookieOnly.headers()['www-authenticate']).toContain('Bearer');

    // A normal (non-direct) share of the same user and another user's direct link are both 404 for the token.
    const files = await createTempFiles(testInfo.outputPath('files-normal'), [{ name: 'normal.txt', content: 'normal share' }]);
    await page.goto('/shares/new');
    await page.setInputFiles('[data-file-input]', files);
    await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
    await page.locator('[data-submit]').click();
    await page.waitForURL(/\/shares\/created\//);
    const normalUrl = extractShareUrl(await page.locator('main').innerText(), page.url());
    await waitForShareReady(page, normalUrl);
    const normalToken = new URL(normalUrl).pathname.split('/')[2];
    const normalDelete = await request.delete(`/api/v1/shares/${normalToken}`, { headers: bearer(app.accessToken) });
    expect(normalDelete.status()).toBe(404);
    expect((await page.request.get(`/api/shares/${normalToken}`)).status()).toBe(200);

    const otherUser = await createE2EUser(request, 'api-capture-other');
    const otherContext = await page.context().browser()!.newContext({ baseURL: 'http://127.0.0.1:18090' });
    try {
      const otherPage = await otherContext.newPage();
      await login(otherPage, otherUser.email, otherUser.password);
      const otherApp = await connectApp(otherPage, request, 'Other Mac');
      const otherCapture = await (await uploadCapture(request, otherApp.accessToken, pngPath)).json() as { token: string; url: string };
      const crossDelete = await request.delete(`/api/v1/shares/${otherCapture.token}`, { headers: bearer(app.accessToken) });
      expect(crossDelete.status()).toBe(404);
      expect((await request.get(otherCapture.url)).status()).toBe(200);
    } finally {
      await otherContext.close();
    }

    // Deleting the own direct link: 204, then gone; a repeat is still 204.
    const deleted = await request.delete(`/api/v1/shares/${capture.token}`, { headers: bearer(app.accessToken) });
    expect(deleted.status()).toBe(204);
    expect((await request.get(capture.url)).status()).toBe(410);
    expect((await request.delete(`/api/v1/shares/${capture.token}`, { headers: bearer(app.accessToken) })).status()).toBe(204);

    // Disconnect from the app revokes the calling token.
    const disconnect = await request.delete('/api/v1/auth/token', { headers: bearer(app.accessToken) });
    expect(disconnect.status()).toBe(204);
    const revoked = await expectMe(request, app.accessToken, 401);
    expect(revoked.headers()['www-authenticate']).toContain('invalid_token');
  });

  test('revoking in Settings disconnects the app', async ({ page, request }) => {
    const user = await createE2EUser(request, 'api-revoke');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    await expect(page.locator('[data-connected-apps-empty]')).toHaveText('No apps connected.');

    const app = await connectApp(page, request, 'Revoke Test Mac');
    await expectMe(request, app.accessToken, 200);

    await page.goto('/account/settings');
    const row = page.locator(`[data-connected-app="${app.tokenId}"]`);
    await expect(row.locator('[data-connected-app-name]')).toHaveText('Revoke Test Mac');
    await expect(row).toContainText(`agora_pat_${app.accessToken.slice('agora_pat_'.length, 'agora_pat_'.length + 8)}`);
    await expect(row.locator('[data-local-datetime]').first()).not.toHaveText('');

    await row.locator('[data-revoke-app-trigger]').click();
    const dialog = page.locator('[data-revoke-app-dialog]');
    await expect(dialog).toBeVisible();
    await expect(dialog.locator('[data-revoke-app-name]')).toHaveText('Revoke Test Mac');
    await dialog.locator('[data-revoke-app-confirm]').click();
    await page.waitForURL(/\/account\/settings\?msg=App%20disconnected#connected-apps$/);
    await expect(page.locator('[data-connected-apps-empty]')).toBeVisible();

    await expectMe(request, app.accessToken, 401);
  });

  test('a password change disconnects the app', async ({ page, request }) => {
    const user = await createE2EUser(request, 'api-password');
    await login(page, user.email, user.password);
    const app = await connectApp(page, request);
    await expectMe(request, app.accessToken, 200);

    const startedAt = Date.now();
    await page.goto('/account/settings');
    const form = page.locator('form[action*="handler=ChangePassword"]');
    await form.locator('input[name="currentPasswordForPassword"]').fill(user.password);
    await form.locator('input[name="newPassword"]').fill('N3w-P@ssw0rd!456');
    await form.locator('input[name="confirmPassword"]').fill('N3w-P@ssw0rd!456');
    await form.locator('button[type="submit"]').click();
    await page.waitForURL(/msg=Check%20your%20email/);

    const actionUrl = await waitForEmailActionUrl(user.email, '/auth/confirm-password-change', startedAt);
    await page.goto(actionUrl);
    await page.getByRole('button', { name: 'Confirm password change' }).click();
    await page.waitForURL(/\/login\?msg=Password%20updated/);

    await expectMe(request, app.accessToken, 401);
  });
});

type FileSystemEmailRecord = {
  to?: string;
  metadata?: { ActionUrl?: string };
};

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

async function waitForEmailActionUrl(to: string, pathPart: string, startedAt: number): Promise<string> {
  const dir = await latestEmailDirectory();
  while (Date.now() - startedAt < 60_000) {
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
