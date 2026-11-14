import { expect, test } from '@playwright/test';
import type { APIRequestContext, Page } from '@playwright/test';
import {
  McpHttpClient,
  bearer,
  createE2EUser,
  createTempFiles,
  exchangeFormCode,
  extractShareUrl,
  login,
  mcpAuthorizePath,
  newPkce,
  newState,
  registerOAuthClient,
  startCallbackServer,
  tokenFromShareUrl,
  waitForShareReady,
} from '../support/helpers';

// Agent access: MCP OAuth sign-in (dynamic client registration, consent with an access level, form-encoded code
// exchange), the hosted MCP endpoint at /mcp and agent tokens created in Settings. Contract: docs/api/agents.md.
const LOOPBACK_CLIENT = 'Claude Code E2E';

interface Metadata {
  resource: string;
  authorizationServers: string[];
  issuer: string;
}

async function metadata(request: APIRequestContext): Promise<Metadata> {
  const prm = await (await request.get('/.well-known/oauth-protected-resource/mcp')).json() as { resource: string; authorization_servers: string[] };
  const authz = await (await request.get('/.well-known/oauth-authorization-server')).json() as { issuer: string };
  return { resource: prm.resource, authorizationServers: prm.authorization_servers, issuer: authz.issuer };
}

/** Approves the consent page already open in the browser and returns what the client's redirect received. */
async function approveInBrowser(page: Page, level?: 'own' | 'all') {
  if (level) {
    await page.locator(`input[name="accessLevel"][value="${level}"]`).check();
  }
  await page.getByRole('button', { name: 'Approve' }).click();
}

/** Registers a loopback client, signs the browser in through consent and exchanges the code; returns the agent token. */
async function connectAgent(page: Page, request: APIRequestContext, level: 'own' | 'all', clientName = LOOPBACK_CLIENT) {
  const callback = await startCallbackServer();
  try {
    const { resource } = await metadata(request);
    const clientId = await registerOAuthClient(request, clientName, [callback.redirectUri]);
    const pkce = newPkce();
    const state = newState();
    await page.goto(mcpAuthorizePath(clientId, callback.redirectUri, state, pkce.challenge, resource));
    await approveInBrowser(page, level);
    const received = await callback.received;
    expect(received.searchParams.get('state')).toBe(state);
    const exchanged = await exchangeFormCode(request, clientId, received.searchParams.get('code')!, pkce.verifier, undefined, resource);
    expect(exchanged.status()).toBe(200);
    const body = await exchanged.json() as { access_token: string; token_id: string };
    return { token: body.access_token, tokenId: body.token_id, clientId };
  } finally {
    await callback.close();
  }
}

async function createBrowserShare(page: Page, testInfo: { outputPath: (name: string) => string }): Promise<string> {
  const files = await createTempFiles(testInfo.outputPath('browser-share'), [{ name: 'from-browser.txt', content: 'created in the browser' }]);
  await page.goto('/shares/new');
  await page.setInputFiles('[data-file-input]', files);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await page.locator('[data-submit]').click();
  await page.waitForURL(/\/shares\/created\/[^/?#]+$/);
  const shareUrl = extractShareUrl(await page.locator('main').innerText(), page.url());
  await waitForShareReady(page, shareUrl);
  return tokenFromShareUrl(shareUrl);
}

test.describe('Agent OAuth and MCP', () => {
  test('/mcp answers 401 with the protected resource metadata, and the metadata documents agree', async ({ request }) => {
    const bare = await new McpHttpClient(request, undefined).post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    expect(bare.status()).toBe(401);
    const challenge = bare.headers()['www-authenticate'];
    expect(challenge).toMatch(/^Bearer resource_metadata="[^"]+\/\.well-known\/oauth-protected-resource\/mcp"$/);

    const invalid = await new McpHttpClient(request, 'agora_pat_dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk').post({ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} });
    expect(invalid.status()).toBe(401);
    expect(invalid.headers()['www-authenticate']).toContain('error="invalid_token"');
    expect(invalid.headers()['www-authenticate']).toContain('resource_metadata=');

    const { resource, authorizationServers, issuer } = await metadata(request);
    const base = new URL(resource).origin;
    expect(challenge).toContain(`resource_metadata="${base}/.well-known/oauth-protected-resource/mcp"`);
    expect(resource).toBe(`${base}/mcp`);
    expect(authorizationServers).toEqual([issuer]);

    const prmResponse = await request.get('/.well-known/oauth-protected-resource/mcp');
    expect(prmResponse.headers()['cache-control']).toContain('no-store');
    const as = await (await request.get('/.well-known/oauth-authorization-server')).json() as Record<string, unknown>;
    expect(as).toMatchObject({
      issuer,
      authorization_endpoint: `${base}/connect/authorize`,
      token_endpoint: `${base}/api/v1/auth/token`,
      registration_endpoint: `${base}/oauth/register`,
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
    });
    expect((await request.get('/.well-known/oauth-protected-resource')).status()).toBe(404);
  });

  test('dynamic client registration accepts a loopback redirect and refuses others', async ({ request }) => {
    const ok = await request.post('/oauth/register', { data: { client_name: 'DCR E2E', redirect_uris: ['http://127.0.0.1:41234/callback'] } });
    expect(ok.status()).toBe(201);
    const body = await ok.json() as { client_id: string; client_name: string; token_endpoint_auth_method: string };
    expect(body.client_id).toMatch(/^agora_mcp_/);
    expect(body.client_name).toBe('DCR E2E');
    expect(body.token_endpoint_auth_method).toBe('none');

    const evil = await request.post('/oauth/register', { data: { client_name: 'Evil', redirect_uris: ['https://evil.example/cb'] } });
    expect(evil.status()).toBe(400);
    expect((await evil.json() as { error: string }).error).toBe('invalid_redirect_uri');
  });

  test('consent, form exchange, MCP upload and share (AE1), Settings level change and revoke (AE7)', async ({ page, request, browser }, testInfo) => {
    const user = await createE2EUser(request, 'agent-oauth');
    await login(page, user.email, user.password);
    const browserShare = await createBrowserShare(page, testInfo);

    const callback = await startCallbackServer();
    const { resource } = await metadata(request);
    const clientId = await registerOAuthClient(request, LOOPBACK_CLIENT, [callback.redirectUri]);
    const pkce = newPkce();
    const state = newState();

    // Consent: the client's (unverified) name, where approving returns to, and "Only shares it creates" preselected.
    await page.goto(mcpAuthorizePath(clientId, callback.redirectUri, state, pkce.challenge, resource));
    await expect(page.locator('[data-connect-device]')).toHaveText(LOOPBACK_CLIENT);
    await expect(page.locator('[data-connect-unverified]')).toContainText('The name is chosen by the app and is not verified.');
    await expect(page.locator('[data-connect-redirect-host]')).toHaveText(new URL(callback.redirectUri).host);
    await expect(page.locator('input[name="accessLevel"][value="own"]')).toBeChecked();
    await expect(page.locator('input[name="accessLevel"][value="all"]')).not.toBeChecked();
    await expect(page.getByText('Only shares it creates')).toBeVisible();
    await expect(page.getByText('All my shares')).toBeVisible();

    await approveInBrowser(page);
    const received = await callback.received;
    await callback.close();
    expect(received.searchParams.get('state')).toBe(state);
    const code = received.searchParams.get('code')!;
    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const exchanged = await exchangeFormCode(request, clientId, code, pkce.verifier, undefined, resource);
    expect(exchanged.status()).toBe(200);
    expect(exchanged.headers()['cache-control']).toContain('no-store');
    const { access_token: token, token_id: tokenId } = await exchanged.json() as { access_token: string; token_id: string };
    expect(token).toMatch(/^agora_pat_/);
    const me = await (await request.get('/api/v1/me', { headers: bearer(token) })).json() as { accessLevel: string; email: string };
    expect(me).toMatchObject({ accessLevel: 'own', email: user.email });
    expect((await exchangeFormCode(request, clientId, code, pkce.verifier)).status()).toBe(400);

    // MCP: tools of level "own", then two uploads into one draft and a share with a 7-day expiry and a password.
    const mcp = new McpHttpClient(request, token);
    await mcp.initialize();
    const tools = await mcp.listTools();
    expect(tools.sort()).toEqual(['create_share', 'delete_share', 'get_share', 'get_upload_url', 'list_shares', 'upload_file']);
    expect(tools).not.toContain('read_share_file');

    const first = await mcp.callTool('upload_file', { file_name: 'report.txt', text: 'quarterly report' });
    expect(first.isError, first.text).toBe(false);
    const draftId = first.structured!.draftId as string;
    const second = await mcp.callTool('upload_file', {
      file_name: 'chart.bin',
      content_base64: Buffer.from([1, 2, 3, 4]).toString('base64'),
      draft_id: draftId,
    });
    expect(second.isError, second.text).toBe(false);
    expect(second.structured!.draftId).toBe(draftId);

    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const created = await mcp.callTool('create_share', {
      draft_id: draftId,
      expires_at: expiresAt.toISOString(),
      download_password: 'agent-pass-phrase',
      message: 'From my agent',
    });
    expect(created.isError, created.text).toBe(false);
    const share = created.structured as { token: string; url: string; ready: boolean; password: string; expiresAtUtc?: string };
    expect(share.ready).toBe(true);
    expect(share.password).toBe('agent-pass-phrase');
    expect(share.url).toMatch(new RegExp(`/s/${share.token}$`));

    const details = (await mcp.callTool('get_share', { token: share.token })).structured as { passwordProtected: boolean; expiresAtUtc: string; files: Array<{ name: string }> };
    expect(details.passwordProtected).toBe(true);
    expect(details.files.map((file) => file.name).sort()).toEqual(['chart.bin', 'report.txt']);
    expect(Math.abs(new Date(`${details.expiresAtUtc.replace(/Z?$/, 'Z')}`).getTime() - expiresAt.getTime())).toBeLessThan(60_000);

    // The link asks a visitor for the password.
    const visitor = await browser.newContext();
    try {
      const visitorPage = await visitor.newPage();
      await visitorPage.goto(share.url);
      await expect(visitorPage.locator('#download-password')).toBeVisible();
    } finally {
      await visitor.close();
    }

    // Level "own": only this agent's shares are visible; the browser-created share can be neither seen nor deleted.
    const listed = (await mcp.callTool('list_shares')).structured as { shares: Array<{ token: string }> };
    expect(listed.shares.map((x) => x.token)).toEqual([share.token]);
    const refused = await mcp.callTool('delete_share', { token: browserShare });
    expect(refused.isError).toBe(true);
    expect(refused.text).toMatch(/^Refused \(404\): /);
    expect((await request.delete(`/api/v1/shares/${browserShare}`, { headers: bearer(token) })).status()).toBe(404);
    expect((await request.get(`/api/v1/shares/${browserShare}/files`, { headers: bearer(token) })).status()).toBe(404);

    // Settings > Connected apps: the client is listed; raise it to "All my shares" (AE7).
    await page.goto('/account/settings');
    const row = page.locator(`[data-connected-app="${tokenId}"]`);
    await expect(row.locator('[data-connected-app-name]')).toHaveText(LOOPBACK_CLIENT);
    await row.locator('select[name="accessLevel"]').selectOption('all');
    await row.getByRole('button', { name: 'Save' }).click();
    await page.waitForURL(/\/account\/settings/);

    // The same token, the next call: every share, and read_share_file is offered to the next session.
    const all = new McpHttpClient(request, token);
    const allListed = (await all.callTool('list_shares')).structured as { shares: Array<{ token: string }> };
    expect(allListed.shares.map((x) => x.token).sort()).toEqual([browserShare, share.token].sort());
    expect(await all.listTools()).toContain('read_share_file');
    const fileId = (await all.callTool('get_share', { token: browserShare })).structured!.files[0].id as string;
    const read = await all.callTool('read_share_file', { token: browserShare, file_id: fileId });
    expect(read.isError, read.text).toBe(false);
    expect(read.text).toBe('created in the browser');
    expect((await request.get('/api/v1/me', { headers: bearer(token) }).then((r) => r.json()) as { accessLevel: string }).accessLevel).toBe('all');

    // Revoke in Settings: every later call is refused (AE7).
    await page.goto('/account/settings');
    await page.locator(`[data-connected-app="${tokenId}"]`).locator('[data-revoke-app-trigger]').click();
    await page.locator('[data-revoke-app-dialog] [data-revoke-app-confirm]').click();
    await page.waitForURL(/\/account\/settings\?msg=App%20disconnected/);
    const afterRevoke = await new McpHttpClient(request, token).post({ jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} });
    expect(afterRevoke.status()).toBe(401);
    expect(afterRevoke.headers()['www-authenticate']).toContain('invalid_token');
    expect((await request.get('/api/v1/me', { headers: bearer(token) })).status()).toBe(401);
  });

  test('a capture token is refused on /mcp and an agent token on /api/v1/captures', async ({ page, request }) => {
    const user = await createE2EUser(request, 'agent-capture-split');
    await login(page, user.email, user.password);
    const { token } = await connectAgent(page, request, 'own');

    const captures = await request.post('/api/v1/captures?duration=1d', {
      headers: bearer(token),
      multipart: { file: { name: 'capture.png', mimeType: 'image/png', buffer: Buffer.from([0x89, 0x50, 0x4e, 0x47]) } },
    });
    expect(captures.status()).toBe(403);

    // The capture app's own token still cannot use /mcp.
    const pkce = newPkce();
    const callback = await startCallbackServer();
    try {
      const state = newState();
      const query = new URLSearchParams({ client_id: 'agora-capture', redirect_uri: callback.redirectUri, state, code_challenge: pkce.challenge, code_challenge_method: 'S256', device_name: 'E2E Mac' });
      await page.goto(`/connect/authorize?${query}`);
      await page.getByRole('button', { name: 'Approve' }).click();
      const code = (await callback.received).searchParams.get('code')!;
      const captureToken = (await (await request.post('/api/v1/auth/token', {
        data: { grant_type: 'authorization_code', code, code_verifier: pkce.verifier, redirect_uri: callback.redirectUri, client_id: 'agora-capture' },
      })).json() as { access_token: string }).access_token;
      const mcp = await new McpHttpClient(request, captureToken).post({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
      expect(mcp.status()).toBe(403);
    } finally {
      await callback.close();
    }
  });

  test('a claude.ai style https redirect is accepted and receives code and state', async ({ page, request }) => {
    const user = await createE2EUser(request, 'agent-https-redirect');
    await login(page, user.email, user.password);
    const redirectUri = 'https://claude.ai/api/mcp/auth_callback';
    const clientId = await registerOAuthClient(request, 'Claude', [redirectUri]);
    const { resource } = await metadata(request);
    const pkce = newPkce();
    const state = newState();

    // The browser must never reach the real claude.ai. A redirect hop of a navigation is not routable, so the 302 of the
    // consent POST is read from its response and the navigation to the (blocked) host is aborted.
    await page.route('https://claude.ai/**', (route) => route.abort());

    await page.goto(mcpAuthorizePath(clientId, redirectUri, state, pkce.challenge, resource));
    await expect(page.locator('[data-connect-redirect-host]')).toHaveText('claude.ai');
    const decision = page.waitForResponse((response) => response.url().endsWith('/connect/authorize') && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Approve' }).click();
    const response = await decision;
    expect(response.status()).toBe(302);
    const intercepted = new URL(response.headers().location);
    expect(`${intercepted.origin}${intercepted.pathname}`).toBe(redirectUri);
    expect(intercepted.searchParams.get('state')).toBe(state);
    const code = intercepted.searchParams.get('code')!;
    expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/);

    const exchanged = await exchangeFormCode(request, clientId, code, pkce.verifier, redirectUri, resource);
    expect(exchanged.status()).toBe(200);
  });

  test('an unregistered redirect or a foreign https host shows the error and never redirects', async ({ page, request }) => {
    const user = await createE2EUser(request, 'agent-bad-redirect');
    await login(page, user.email, user.password);
    const clientId = await registerOAuthClient(request, 'Strict', ['http://127.0.0.1:41000/callback']);
    const pkce = newPkce();

    const other = await page.goto(mcpAuthorizePath(clientId, 'http://127.0.0.1:41000/other', newState(), pkce.challenge));
    expect(other!.status()).toBe(400);
    await expect(page.locator('[data-connect-error]')).toBeVisible();

    const foreign = await request.post('/oauth/register', { data: { client_name: 'Phish', redirect_uris: ['https://claude.ai.evil.example/cb'] } });
    expect(foreign.status()).toBe(400);
  });

  test('a token created in Settings works with plain HTTP against /api/v1/shares', async ({ page, request }) => {
    const user = await createE2EUser(request, 'agent-settings-token');
    await login(page, user.email, user.password);
    await page.goto('/account/settings');

    await page.locator('[data-create-agent-token-form] input[name="agentName"]').fill('Nightly report bot');
    await page.locator('[data-create-agent-token-form]').getByRole('button', { name: 'Create agent token' }).click();
    const token = await page.locator('[data-agent-token-value]').inputValue();
    expect(token).toMatch(/^agora_pat_[A-Za-z0-9_-]{43}$/);
    await expect(page.locator('[data-agent-token-panel]')).toContainText('Nightly report bot');
    await expect(page.locator('[data-connected-app-kind]').filter({ hasText: 'Agent token' })).toBeVisible();

    const created = await request.post('/api/v1/shares', {
      headers: bearer(token),
      data: { files: [{ fileName: 'nightly.txt', text: 'all green' }], downloadPassword: 'nightly-pass-1', waitSeconds: 40 },
    });
    expect(created.status()).toBe(201);
    const share = await created.json() as { token: string; url: string; ready: boolean; password: string };
    expect(share.ready).toBe(true);
    expect(share.password).toBe('nightly-pass-1');
    expect(created.headers().location).toBe(`/api/v1/shares/${share.token}`);

    const listed = await (await request.get('/api/v1/shares', { headers: bearer(token) })).json() as { shares: Array<{ token: string; passwordProtected: boolean }> };
    expect(listed.shares).toEqual([expect.objectContaining({ token: share.token, passwordProtected: true })]);
    expect((await request.get('/api/v1/shares')).status()).toBe(401);
    expect((await request.delete(`/api/v1/shares/${share.token}`, { headers: bearer(token) })).status()).toBe(204);
    expect((await request.get(`/api/v1/shares/${share.token}`, { headers: bearer(token) })).status()).toBe(404);
  });
});

