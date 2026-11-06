import path from 'node:path';
import fs from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { createE2EUser, createTempFiles, login, waitForShareReady, writePngFile } from '../support/helpers';

// HTTP-level contract for user-uploaded content (stored XSS hardening): the extension decides the
// content type, only an allowlist is served inline, and every user-content response is nosniff + CSP.
const FULL_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

/** Waits for a download notification email to <to> written after <since> by the filesystem email sender. */
async function waitForDownloadEmail(to: string, since: number, timeoutMs = 60_000): Promise<{ subject: string }> {
  const runsRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../.e2e-data/runs');
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const runs = await fs.readdir(runsRoot, { withFileTypes: true }).catch(() => []);
    for (const run of runs.filter((entry) => entry.isDirectory())) {
      const dir = path.join(runsRoot, run.name, 'emails');
      const names = await fs.readdir(dir).catch(() => [] as string[]);
      for (const name of names.filter((n) => n.endsWith('.json'))) {
        const file = path.join(dir, name);
        const stats = await fs.stat(file).catch(() => null);
        if (!stats || stats.mtimeMs < since) continue;
        const record = JSON.parse(await fs.readFile(file, 'utf8')) as { to?: string; kind?: string; subject?: string };
        if (record.kind === 'download_notification' && record.to?.toLowerCase() === to.toLowerCase()) {
          return { subject: record.subject ?? '' };
        }
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`No download notification email to ${to}`);
}

async function readCsrfToken(page: Page): Promise<string> {
  const token = await page.evaluate(() => {
    const cookie = document.cookie
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith('agora.csrf.request='));
    return cookie ? decodeURIComponent(cookie.slice('agora.csrf.request='.length)) : '';
  });
  if (!token) {
    throw new Error('Missing CSRF token cookie');
  }
  return token;
}

async function openNewShareDraft(page: Page): Promise<{ draftShareId: string; csrfToken: string }> {
  await page.goto('/shares/new');
  await page.waitForSelector('[data-share-form]');
  const draftShareId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  if (!draftShareId) {
    throw new Error('Missing draftShareId');
  }
  return { draftShareId, csrfToken: await readCsrfToken(page) };
}

async function createPreviewShare(page: Page, files: string[], extraFields: Record<string, string> = {}): Promise<string> {
  const { draftShareId, csrfToken } = await openNewShareDraft(page);

  const uploadIds: string[] = [];
  for (const filePath of files) {
    const response = await page.request.post(`/api/uploads/stage?draftShareId=${encodeURIComponent(draftShareId)}`, {
      headers: { 'X-CSRF-TOKEN': csrfToken },
      multipart: {
        file: {
          name: path.basename(filePath),
          // Deliberately wrong on purpose: the server must ignore the declared type.
          mimeType: 'text/html',
          buffer: await fs.readFile(filePath)
        }
      }
    });
    expect(response.ok(), `staging ${filePath}: ${response.status()}`).toBeTruthy();
    uploadIds.push(String((await response.json()).uploadId || ''));
  }

  const token = `hdr${Date.now().toString(36)}`;
  const form = new URLSearchParams();
  form.append('__RequestVerificationToken', csrfToken);
  form.append('draftShareId', draftShareId);
  form.append('shareToken', token);
  form.append('notifyMode', extraFields.notifyMode ?? 'none');
  form.append('expiryMode', '7_days');
  form.append('templateMode', 'account_default');
  form.append('showPreviews', '1');
  for (const uploadId of uploadIds) {
    form.append('uploadedFileIds', uploadId);
  }
  for (const [key, value] of Object.entries(extraFields)) {
    if (key === 'notifyMode') continue;
    form.append(key, value);
  }
  const createResponse = await page.request.post('/api/shares', {
    data: form.toString(),
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRF-TOKEN': csrfToken }
  });
  expect(createResponse.ok(), `create share: ${createResponse.status()} ${await createResponse.text()}`).toBeTruthy();

  await waitForShareReady(page, `${new URL(page.url()).origin}/s/${token}`);
  return token;
}

test('uploaded files are served by extension with nosniff and CSP', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'content-headers');
  await login(page, user.email, user.password);

  const html = '<html><body><script>document.title="xss"</script></body></html>';
  const files = await createTempFiles(testInfo.outputPath('files'), [
    { name: 'evil.html', content: html },
    { name: 'evil.svg', content: '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>' },
    { name: 'page.xml', content: '<?xml version="1.0"?><root/>' },
    { name: 'noextension', content: html },
    { name: 'doc.pdf', content: '%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n' }
  ]);
  const token = await createPreviewShare(page, files);

  const listing = await page.request.get(`/s/${token}/files`);
  expect(listing.ok()).toBeTruthy();
  const entries = await listing.json() as Array<{ originalFilename: string; url: string; detectedContentType: string }>;
  const byName = new Map(entries.map((entry) => [entry.originalFilename, entry]));
  expect([...byName.keys()].sort()).toEqual(['doc.pdf', 'evil.html', 'evil.svg', 'noextension', 'page.xml']);

  for (const name of ['evil.html', 'evil.svg', 'page.xml', 'noextension']) {
    const entry = byName.get(name)!;
    const response = await page.request.get(entry.url);
    expect(response.status(), name).toBe(200);
    const headers = response.headers();
    expect(headers['content-type'], name).toBe('application/octet-stream');
    expect(headers['content-disposition'], name).toContain('attachment');
    expect(headers['content-disposition'], name).toContain(name);
    expect(headers['x-content-type-options'], name).toBe('nosniff');
    expect(headers['content-security-policy'], name).toBe(FULL_CSP);
    // Originals are never kept by browser or shared caches (a signed-in session may answer with its own
    // no-cache,no-store; anonymous visitors get private, no-store).
    expect(headers['cache-control'], name).toContain('no-store');
  }
  // The declared text/html never reached storage either.
  expect(byName.get('noextension')!.detectedContentType).toBe('application/octet-stream');
  expect(byName.get('evil.html')!.detectedContentType).toBe('text/html');

  const pdf = byName.get('doc.pdf')!;
  const inlinePdf = await page.request.get(pdf.url);
  expect(inlinePdf.status()).toBe(200);
  expect(inlinePdf.headers()['content-type']).toBe('application/pdf');
  expect(inlinePdf.headers()['content-disposition'] || '').not.toContain('attachment');
  expect(inlinePdf.headers()['x-content-type-options']).toBe('nosniff');
  expect(inlinePdf.headers()['content-security-policy']).toBeUndefined();

  const downloadPdf = await page.request.get(`${pdf.url}?download=1`);
  expect(downloadPdf.status()).toBe(200);
  expect(downloadPdf.headers()['content-type']).toBe('application/pdf');
  expect(downloadPdf.headers()['content-disposition']).toContain('attachment');
  expect(downloadPdf.headers()['x-content-type-options']).toBe('nosniff');
  expect(downloadPdf.headers()['content-security-policy']).toBe(FULL_CSP);

  const zip = await page.request.post(`/s/${token}/download`, {
    form: { __RequestVerificationToken: await readCsrfToken(page) }
  });
  expect(zip.status()).toBe(200);
  expect(zip.headers()['content-type']).toContain('application/zip');
  expect(zip.headers()['content-disposition']).toContain('attachment');
  expect(zip.headers()['x-content-type-options']).toBe('nosniff');
  expect(zip.headers()['content-security-policy']).toBe(FULL_CSP);
});

test('svg backgrounds are rejected on both upload routes', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'svg-background');
  await login(page, user.email, user.password);

  const svgPath = path.join(testInfo.outputPath('background'), 'bg.svg');
  await fs.mkdir(path.dirname(svgPath), { recursive: true });
  await fs.writeFile(svgPath, '<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>', 'utf8');
  const svgBuffer = await fs.readFile(svgPath);
  const pngPath = path.join(testInfo.outputPath('background'), 'bg.png');
  await writePngFile(pngPath, { comment: 'png-ok' });

  const { draftShareId, csrfToken } = await openNewShareDraft(page);

  // Share draft route: JSON 400.
  const draftSvg = await page.request.post(`/api/uploads/stage-template-background?draftShareId=${encodeURIComponent(draftShareId)}`, {
    headers: { 'X-CSRF-TOKEN': csrfToken },
    multipart: {
      file: { name: 'bg.svg', mimeType: 'image/png', buffer: svgBuffer }
    }
  });
  expect(draftSvg.status()).toBe(400);
  expect(await draftSvg.text()).toContain('Only JPG, PNG, or WEBP');

  const draftPng = await page.request.post(`/api/uploads/stage-template-background?draftShareId=${encodeURIComponent(draftShareId)}`, {
    headers: { 'X-CSRF-TOKEN': csrfToken },
    multipart: {
      file: { name: 'bg.png', mimeType: 'image/svg+xml', buffer: await fs.readFile(pngPath) }
    }
  });
  expect(draftPng.status()).toBe(200);

  // Account template route (submitted by the designer script with the header token): it redirects back with
  // the rejection message and must not store the file.
  const accountSvg = await page.request.post('/api/account/template', {
    maxRedirects: 0,
    headers: { 'X-CSRF-TOKEN': csrfToken },
    multipart: {
      title: 'Title',
      h1: 'Heading',
      description: 'Description',
      backgroundColorMode: 'default',
      containerPosition: 'center',
      backgroundImageFile: { name: 'bg.svg', mimeType: 'image/png', buffer: svgBuffer }
    }
  });
  expect(accountSvg.status()).toBe(302);
  expect(decodeURIComponent(accountSvg.headers()['location'] || '')).toContain('Only JPG, PNG, or WEBP');

  const accountBackground = await page.request.get('/account/template/background');
  expect(accountBackground.status()).toBe(404);
});

// Public share metadata: password-protected shares reveal nothing but the password flag, the Open Graph image is a
// cached, sandboxed PNG, and a deleted share is indistinguishable from an unknown token on every public route.
test('share summary, og-image and deleted shares expose nothing beyond the download page', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'public-share-state');
  await login(page, user.email, user.password);

  const files = await createTempFiles(testInfo.outputPath('files-state'), [
    { name: 'secret-report.txt', content: 'confidential' }
  ]);
  const token = await createPreviewShare(page, files, { downloadPassword: 'correct horse battery' });

  const summary = await page.request.get(`/api/shares/${token}`);
  expect(summary.status()).toBe(200);
  const payload = await summary.json() as Record<string, unknown>;
  expect(payload.requiresPassword).toBe(true);
  expect(Object.keys(payload).sort()).toEqual(['expiresAtUtc', 'requiresPassword']);

  // Link previews are fetched by anonymous crawlers; the owner's own session gets cookie-renewal no-store headers.
  const ogImage = await request.get(`/s/${token}/og-image`);
  expect(ogImage.status()).toBe(200);
  expect(ogImage.headers()['content-type']).toContain('image/png');
  expect(ogImage.headers()['cache-control']).toContain('max-age=3600');
  expect(ogImage.headers()['x-content-type-options']).toBe('nosniff');
  expect(ogImage.headers()['content-security-policy']).toBe(FULL_CSP);
  const cachedOgImage = await request.get(`/s/${token}/og-image`);
  expect(cachedOgImage.status()).toBe(200);
  expect(cachedOgImage.headers()['etag']).toBe(ogImage.headers()['etag']);

  await page.goto('/');
  const deleteForm = page.locator('form[data-share-delete-form]').first();
  const deleteAction = (await deleteForm.getAttribute('action')) || '';
  expect(deleteAction).toMatch(/\/shares\/[0-9a-f-]{36}\/delete$/);
  const deleteResponse = await page.request.post(deleteAction, {
    form: { __RequestVerificationToken: await readCsrfToken(page) }
  });
  expect(deleteResponse.status()).toBeLessThan(400);

  for (const route of [`/s/${token}`, `/s/${token}/og-image`, `/s/${token}/files`, `/s/${token}/download`, `/s/${token}/gallery`, `/s/${token}/background`, `/api/shares/${token}`]) {
    const response = await page.request.get(route, { maxRedirects: 0 });
    expect(response.status(), route).toBe(404);
  }
});

// A password-protected share page shows a generic card (no name, size, title or background) until the password was
// entered; the unlock sets a share-scoped cookie, after which the page and its background show as usual.
test('password-protected share page stays generic until unlocked', async ({ page, request, browser }, testInfo) => {
  const user = await createE2EUser(request, 'locked-share');
  await login(page, user.email, user.password);

  const files = await createTempFiles(testInfo.outputPath('files-locked'), [
    { name: 'secret-plan.txt', content: 'confidential' }
  ]);
  const token = await createPreviewShare(page, files, { downloadPassword: 'correct horse battery', notifyMode: 'every_time' });
  const startedAt = Date.now();

  const visitor = await browser.newContext();
  try {
    const visitorPage = await visitor.newPage();
    const locked = await visitorPage.goto(`/s/${token}`);
    expect(locked?.status()).toBe(200);
    await expect(visitorPage.getByRole('heading', { name: 'Password-protected share' })).toBeVisible();
    await expect(visitorPage).toHaveTitle('Password-protected share - Agora');
    const lockedHtml = await visitorPage.content();
    expect(lockedHtml).not.toContain('secret-plan');
    expect(lockedHtml).not.toContain('/background');
    expect((await visitorPage.request.get(`/s/${token}/background`)).status()).toBe(404);

    await visitorPage.fill('#download-password', 'wrong password');
    await visitorPage.getByRole('button', { name: 'Unlock' }).click();
    await expect(visitorPage.locator('.download-error')).toContainText('Password was incorrect');
    expect(await visitorPage.content()).not.toContain('secret-plan');

    await visitorPage.fill('#download-password', 'correct horse battery');
    await visitorPage.getByRole('button', { name: 'Unlock' }).click();
    await expect(visitorPage.locator('[data-share-preview-card]')).toBeVisible();
    await expect(visitorPage.locator('[data-share-preview-card]')).toContainText('1 file');
    const cookies = await visitor.cookies();
    const unlock = cookies.find((cookie) => cookie.name === 'agora.share.unlock');
    expect(unlock?.httpOnly).toBe(true);
    expect(unlock?.path).toBe(`/s/${token}`);

    // The download still asks for the password (it decrypts the archive) and works as before.
    await visitorPage.fill('#download-password', 'correct horse battery');
    const [download] = await Promise.all([
      visitorPage.waitForEvent('download'),
      visitorPage.getByRole('button', { name: 'Download' }).click()
    ]);
    expect(download.suggestedFilename()).toMatch(/\.zip$/);
  } finally {
    await visitor.close();
  }

  // The every_time notification runs through the coalescing job and renders the download email for the owner.
  const email = await waitForDownloadEmail(user.email, startedAt);
  expect(email.subject).toBe('Your shared file was downloaded');
});

