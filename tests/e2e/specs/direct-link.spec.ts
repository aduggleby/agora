import path from 'node:path';
import fs from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { createE2EUser, createTempFiles, extractShareUrl, login, waitForShareReady, writePngFile } from '../support/helpers';

// Temporary direct links: one inline-safe file, served as raw bytes at /s/{token} (no download page), every view
// counted, expired after the chosen duration (410 with the expired page), never re-enabled.
const FULL_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";

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

async function createDirectLink(page: Page, filePath: string): Promise<string> {
  await page.setInputFiles('[data-file-input]', [filePath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  const directButton = page.locator('[data-direct-link]');
  await expect(directButton).toBeEnabled();
  await directButton.click();
  await expect(page.locator('[data-direct-link-success]')).toBeVisible();
  return ((await page.locator('[data-direct-link-url]').textContent()) || '').trim();
}

test('creates a temporary direct link, serves the file inline and expires it', async ({ page, context, request }, testInfo) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const user = await createE2EUser(request, 'direct-link');
  await login(page, user.email, user.password);

  const pngPath = path.join(testInfo.outputPath('files'), 'photo.png');
  await writePngFile(pngPath, { comment: 'direct-link-marker' });

  await page.goto('/shares/new');
  const directButton = page.locator('[data-direct-link]');
  await expect(directButton).toBeDisabled();
  await expect(directButton).toHaveAttribute('title', 'Upload one file first.');

  await page.setInputFiles('[data-file-input]', [pngPath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(directButton).toBeEnabled();

  await page.selectOption('[data-direct-duration]', '30m');
  await directButton.click();

  const result = page.locator('[data-direct-link-result]');
  await expect(result).toBeVisible();
  await expect(page.locator('[data-direct-link-notice]')).toHaveText('Copied to clipboard');
  const url = ((await page.locator('[data-direct-link-url]').textContent()) || '').trim();
  expect(url).toMatch(/^http:\/\/127\.0\.0\.1:18090\/s\/[A-Za-z0-9]{8}$/);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(url);
  expect(await page.evaluate(() => localStorage.getItem('agora.directLink.duration'))).toBe('30m');
  const expiryText = ((await page.locator('[data-direct-link-expiry]').textContent()) || '').trim();
  expect(expiryText.length).toBeGreaterThan(0);

  // The page is ready for the next upload: list cleared, button disabled again, a fresh draft id.
  await expect(page.locator('[data-upload-list] li')).toHaveCount(0);
  await expect(directButton).toBeDisabled();
  await expect(page.locator('[data-draft-share-id]')).toHaveValue(/^[0-9a-f]{32}$/);

  const token = url.slice(url.lastIndexOf('/') + 1);

  // Exactly one anonymous view: the bytes come back inline under the user-content policy.
  const view = await request.get(url);
  expect(view.status()).toBe(200);
  expect(view.headers()['content-type']).toBe('image/png');
  expect(view.headers()['content-disposition']).toBeUndefined();
  expect(view.headers()['x-content-type-options']).toBe('nosniff');
  expect(view.headers()['content-security-policy']).toBe(FULL_CSP);
  expect((await view.body()).toString('latin1')).toContain('direct-link-marker');

  // Sub-routes and metadata stay closed: no preview, no page summary, no social image.
  expect((await request.get(`${url}/files`)).status()).toBe(403);
  expect((await request.get(`/api/shares/${token}`)).status()).toBe(404);
  expect((await request.get(`${url}/og-image`)).status()).toBe(404);
  expect((await request.get(`${url}/download`, { maxRedirects: 0 })).status()).toBe(302);

  await page.goto('/');
  const row = page.locator('tr', { hasText: 'photo.png' }).first();
  await expect(row.locator('[data-direct-link-badge]')).toBeVisible();
  await expect(row.locator('td').nth(5)).toHaveText('1');
  await expect(row.locator('td').nth(4).locator('[data-local-datetime]')).not.toHaveText('');

  // "Show link" opens the simplified card.
  await row.getByRole('button', { name: 'Show link' }).click();
  await page.waitForURL(new RegExp(`/shares/created/${token}$`));
  await expect(page.locator('[data-created-direct-link]')).toContainText(url);
  await expect(page.locator('[data-created-ready]')).toHaveCount(0);

  const setExpiry = await request.post(`/api/e2e/shares/${token}/expires-in-seconds`, { form: { seconds: '-1' } });
  expect(setExpiry.ok()).toBeTruthy();

  const expired = await request.get(url);
  expect(expired.status()).toBe(410);
  expect(expired.headers()['content-type'] || '').toContain('text/html');
  expect(await expired.text()).toContain('This link has expired.');

  await page.goto('/');
  const expiredRow = page.locator('tr', { hasText: 'photo.png' }).first();
  await expect(expiredRow.locator('td').nth(2)).toHaveText('Expired');
  await expect(expiredRow.getByRole('button', { name: 'Re-enable 24h' })).toHaveCount(0);

  // A direct link deleted early from My shares answers like an expired one (410), not like a wrong link.
  await page.goto('/shares/new');
  const secondUrl = await createDirectLink(page, pngPath);
  expect(secondUrl).not.toBe(url);
  await page.goto('/');
  const activeRow = page.locator('tr', { hasText: 'photo.png' }).filter({ hasText: 'Active' }).first();
  await activeRow.locator('[data-share-delete-trigger]').click();
  await page.locator('[data-share-delete-confirm]').click();
  await page.waitForURL(/\/\?msg=/);
  await expect(page.locator('tr', { hasText: 'photo.png' }).filter({ hasText: 'Active' })).toHaveCount(0);
  const deleted = await request.get(secondUrl);
  expect(deleted.status()).toBe(410);
  expect(deleted.headers()['content-type'] || '').toContain('text/html');
  expect(await deleted.text()).toContain('This link has expired.');
});

test('the replacement draft starts clean and an ordinary share can be created from it', async ({ page, context, request }, testInfo) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const user = await createE2EUser(request, 'direct-link-draft');
  await login(page, user.email, user.password);

  const pngPath = path.join(testInfo.outputPath('files'), 'photo.png');
  await writePngFile(pngPath, { comment: 'draft-reset' });
  const backgroundPath = path.join(testInfo.outputPath('files'), 'bg.png');
  await writePngFile(backgroundPath, { width: 32, height: 32, color: [91, 122, 94] });
  const [textPath] = await createTempFiles(testInfo.outputPath('files'), [{ name: 'notes.txt', content: 'after the direct link' }]);

  // Customise the draft's download page with a staged background, as the designer does.
  await page.goto('/shares/new');
  const firstDraftId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  expect(firstDraftId).not.toBe('');
  const csrfToken = await readCsrfToken(page);
  const background = await page.request.post(`/api/uploads/stage-template-background?draftShareId=${encodeURIComponent(firstDraftId)}`, {
    headers: { 'X-CSRF-TOKEN': csrfToken },
    multipart: { file: { name: 'bg.png', mimeType: 'image/png', buffer: await fs.readFile(backgroundPath) } }
  });
  expect(background.ok()).toBeTruthy();
  const backgroundUploadId = String((await background.json()).uploadId || '');
  const saveTemplate = await page.request.post(`/api/share-drafts/${firstDraftId}/template`, {
    maxRedirects: 0,
    form: {
      __RequestVerificationToken: csrfToken,
      title: 'Custom title',
      h1: 'Custom heading',
      description: 'Custom description',
      backgroundUploadId,
      containerPosition: 'center'
    }
  });
  expect(saveTemplate.status()).toBe(302);

  await page.goto(`/shares/new?draftShareId=${encodeURIComponent(firstDraftId)}`);
  await expect(page.locator('[data-template-mode]')).toHaveValue('per_upload');
  await expect(page.locator('[data-template-background-upload-id]')).toHaveValue(backgroundUploadId);

  const url = await createDirectLink(page, pngPath);
  expect(url).toMatch(/\/s\/[A-Za-z0-9]{8}$/);

  // The replacement draft: new id in the form and the URL, template back to the account default, background gone.
  const secondDraftId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  expect(secondDraftId).toMatch(/^[0-9a-f]{32}$/);
  expect(secondDraftId).not.toBe(firstDraftId);
  expect(new URL(page.url()).searchParams.get('draftShareId')).toBe(secondDraftId);
  await expect(page.locator('[data-template-mode]')).toHaveValue('account_default');
  await expect(page.locator('[data-template-background-upload-id]')).toHaveValue('');
  await expect(page.locator('[data-template-title]')).toHaveValue('');
  await expect(page.locator('[data-template-custom-actions]')).toBeHidden();
  await expect(page.locator('[data-template-designer-link]')).toHaveAttribute('href', `/share/landing-page-designer?draftShareId=${secondDraftId}`);

  // An ordinary share from the replacement draft must succeed.
  await page.setInputFiles('[data-file-input]', [textPath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(page.locator('[data-submit]')).toBeEnabled();
  await page.locator('[data-submit]').click();
  await page.waitForURL(/\/shares\/created\/[^/?#]+$/);
  const shareUrl = extractShareUrl(await page.locator('main').innerText(), page.url());
  await waitForShareReady(page, shareUrl);
  const summary = await request.get(`/api/shares/${shareUrl.slice(shareUrl.lastIndexOf('/') + 1)}`);
  expect(summary.status()).toBe(200);
  expect((await summary.json()).fileCount).toBe(1);
});

test('draft mutations are blocked while a direct link is being created', async ({ page, context, request }, testInfo) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const user = await createE2EUser(request, 'direct-link-lock');
  await login(page, user.email, user.password);

  const pngPath = path.join(testInfo.outputPath('files'), 'photo.png');
  await writePngFile(pngPath, { comment: 'lock' });

  await page.goto('/shares/new');
  const firstDraftId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  await page.setInputFiles('[data-file-input]', [pngPath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);

  // A slow clipboard keeps the creation window open after the server has answered.
  await page.evaluate(() => {
    const original = navigator.clipboard.writeText.bind(navigator.clipboard);
    Object.defineProperty(navigator.clipboard, 'writeText', {
      configurable: true,
      value: (text: string) => new Promise<void>((resolve, reject) => {
        window.setTimeout(() => original(text).then(resolve, reject), 4000);
      })
    });
  });

  const directButton = page.locator('[data-direct-link]');
  await directButton.click();
  await expect(directButton).toBeDisabled();
  await expect(page.locator('[data-pick-files]')).toBeDisabled();
  await expect(page.locator('[data-file-input]')).toBeDisabled();
  await expect(page.locator('[data-submit]')).toBeDisabled();

  // A drop during the window is ignored; nothing is staged into the finalized draft.
  const dataTransfer = await page.evaluateHandle(() => {
    const transfer = new DataTransfer();
    transfer.items.add(new File(['late'], 'late.txt', { type: 'text/plain' }));
    return transfer;
  });
  await page.dispatchEvent('[data-dropzone]', 'drop', { dataTransfer });
  await expect(page.locator('[data-direct-link-success]')).toBeHidden();
  await expect(page.locator('[data-upload-list] li')).toHaveCount(0);

  await expect(page.locator('[data-direct-link-notice]')).toHaveText('Copied to clipboard', { timeout: 15_000 });
  const url = ((await page.locator('[data-direct-link-url]').textContent()) || '').trim();
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(url);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(0);
  await expect(page.locator('[data-pick-files]')).toBeEnabled();
  await expect(page.locator('[data-file-input]')).toBeEnabled();
  const secondDraftId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  expect(secondDraftId).not.toBe(firstDraftId);

  // The same drop outside the window does stage the file (so the empty list above proves the lock), and it
  // attaches to the replacement draft; nothing landed in the old one.
  await page.dispatchEvent('[data-dropzone]', 'drop', { dataTransfer });
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(page.locator('[data-upload-list] li').first()).toContainText('late.txt');
  await page.goto(`/shares/new?draftShareId=${encodeURIComponent(firstDraftId)}`);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(0);
  await page.goto(`/shares/new?draftShareId=${encodeURIComponent(secondDraftId)}`);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(page.locator('[data-upload-list] li').first()).toContainText('late.txt');
});

test('the direct link button explains why it is disabled', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'direct-link-disabled');
  await login(page, user.email, user.password);

  const files = await createTempFiles(testInfo.outputPath('files'), [
    { name: 'one.txt', content: 'one' },
    { name: 'two.txt', content: 'two' },
    { name: 'page.html', content: '<html></html>' }
  ]);
  const directButton = page.locator('[data-direct-link]');

  await page.goto('/shares/new');
  await page.setInputFiles('[data-file-input]', [files[0], files[1]]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(2);
  await expect(directButton).toBeDisabled();
  await expect(directButton).toHaveAttribute('title', /only one file/);
  await expect(page.locator('[data-submit]')).toBeEnabled();

  await page.goto('/shares/new');
  await page.setInputFiles('[data-file-input]', [files[2]]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(directButton).toBeDisabled();
  await expect(directButton).toHaveAttribute('title', /only be downloaded/);

  // Server-rendered rows carry the same flag when the draft is reopened.
  const draftShareId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  expect(draftShareId).not.toBe('');
  await page.goto(`/shares/new?draftShareId=${encodeURIComponent(draftShareId)}`);
  await expect(page.locator('[data-upload-list] li[data-direct-link-eligible="false"]')).toHaveCount(1);
  await expect(directButton).toBeDisabled();
  await expect(directButton).toHaveAttribute('title', /only be downloaded/);
});
