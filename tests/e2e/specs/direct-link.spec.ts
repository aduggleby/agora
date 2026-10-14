import path from 'node:path';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { createE2EUser, createTempFiles, extractShareUrl, login, waitForShareReady, writePngFile } from '../support/helpers';

// Temporary direct links: one inline-safe file, served as raw bytes at /s/{token} (no download page), every view
// counted, expired after the chosen duration (410 with the expired page), never re-enabled. Creating one copies
// the URL and lands on the created page, which confirms the copy.
const FULL_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox";
const CREATED_URL = /\/shares\/created\/[A-Za-z0-9]{8}$/;

function createdLinkText(page: Page): Promise<string> {
  return page.locator('[data-created-direct-link] a[href^="http"]').first().textContent().then((text) => (text || '').trim());
}

async function createDirectLink(page: Page, filePath: string): Promise<string> {
  await page.setInputFiles('[data-file-input]', [filePath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  const directButton = page.locator('[data-direct-link]');
  await expect(directButton).toBeEnabled();
  await directButton.click();
  await page.waitForURL(CREATED_URL);
  return createdLinkText(page);
}

test('creates a temporary direct link, serves the file inline and expires it', async ({ page, context, request }, testInfo) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const user = await createE2EUser(request, 'direct-link');
  await login(page, user.email, user.password);

  const pngPath = path.join(testInfo.outputPath('files'), 'photo.png');
  await writePngFile(pngPath, { comment: 'direct-link-marker' });

  await page.goto('/shares/new');
  const firstDraftId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  expect(firstDraftId).toMatch(/^[0-9a-f]{32}$/);
  const directButton = page.locator('[data-direct-link]');
  await expect(directButton).toBeDisabled();
  await expect(directButton).toHaveAttribute('title', 'Upload one file first.');
  await expect(page.locator('[data-direct-link-error]')).toBeHidden();

  await page.setInputFiles('[data-file-input]', [pngPath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(directButton).toBeEnabled();

  await page.selectOption('[data-direct-duration]', '30m');
  await directButton.click();

  // The flow ends on the created page: the link was copied on the way, and the card says so once.
  await page.waitForURL(CREATED_URL, { waitUntil: 'commit' });
  const card = page.locator('[data-created-direct-link]');
  const copyButton = card.getByRole('button');
  await expect(copyButton).toHaveText(/Copied/);
  await expect(page.locator('[data-created-ready]')).toHaveCount(0);
  const url = await createdLinkText(page);
  expect(url).toMatch(/^http:\/\/127\.0\.0\.1:18090\/s\/[A-Za-z0-9]{8}$/);
  const token = url.slice(url.lastIndexOf('/') + 1);
  expect(page.url()).toBe(`http://127.0.0.1:18090/shares/created/${token}`);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(url);
  expect(await page.evaluate(() => sessionStorage.getItem('agora.directLink.copied'))).toBeNull();
  expect(await page.evaluate(() => localStorage.getItem('agora.directLink.duration'))).toBe('30m');
  await expect(card.locator('[data-local-datetime]')).not.toHaveText('');
  await expect(copyButton).toHaveText('Copy link', { timeout: 10_000 });

  // A reload shows the plain card: the confirmation is shown only once.
  await page.reload();
  await expect(copyButton).toHaveText('Copy link');
  await expect(copyButton).not.toHaveText(/Copied/);

  // The next new-share visit starts on a fresh draft.
  await page.goto('/shares/new');
  const secondDraftId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  expect(secondDraftId).toMatch(/^[0-9a-f]{32}$/);
  expect(secondDraftId).not.toBe(firstDraftId);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(0);
  await expect(directButton).toBeDisabled();

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

  // "Show link" opens the same simplified card.
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

test('the form stays locked from the click until the created page opens', async ({ page, context, request }, testInfo) => {
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
  await expect(directButton).toHaveAttribute('title', 'Creating your direct link...');
  await expect(page.locator('[data-pick-files]')).toBeDisabled();
  await expect(page.locator('[data-file-input]')).toBeDisabled();
  await expect(page.locator('[data-submit]')).toBeDisabled();
  await expect(page.locator('[data-upload-list] [data-upload-remove]')).toBeDisabled();

  // A drop during the window is ignored; nothing is staged into the finalized draft and the page has not left yet.
  const dataTransfer = await page.evaluateHandle(() => {
    const transfer = new DataTransfer();
    transfer.items.add(new File(['late'], 'late.txt', { type: 'text/plain' }));
    return transfer;
  });
  await page.dispatchEvent('[data-dropzone]', 'drop', { dataTransfer });
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  expect(page.url()).toContain('/shares/new');
  await expect(directButton).toBeDisabled();

  // The window closes with the clipboard write: the browser leaves for the created page.
  await page.waitForURL(CREATED_URL, { timeout: 15_000 });
  const url = await createdLinkText(page);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(url);

  // The finalized draft is empty when reopened; the same drop on a fresh draft does stage the file (so the
  // untouched list above proves the lock).
  await page.goto(`/shares/new?draftShareId=${encodeURIComponent(firstDraftId)}`);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(0);
  await page.goto('/shares/new');
  const secondDraftId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  expect(secondDraftId).toMatch(/^[0-9a-f]{32}$/);
  expect(secondDraftId).not.toBe(firstDraftId);
  const lateDrop = await page.evaluateHandle(() => {
    const transfer = new DataTransfer();
    transfer.items.add(new File(['late'], 'late.txt', { type: 'text/plain' }));
    return transfer;
  });
  await page.dispatchEvent('[data-dropzone]', 'drop', { dataTransfer: lateDrop });
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(page.locator('[data-upload-list] li').first()).toContainText('late.txt');
});

test('a failed create keeps the draft usable and reports the error', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'direct-link-error');
  await login(page, user.email, user.password);

  const pngPath = path.join(testInfo.outputPath('files'), 'photo.png');
  await writePngFile(pngPath, { comment: 'error-path' });

  await page.goto('/shares/new');
  await page.setInputFiles('[data-file-input]', [pngPath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  const directButton = page.locator('[data-direct-link]');
  const error = page.locator('[data-direct-link-error]');
  const expectUnlocked = async () => {
    await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
    await expect(directButton).toBeEnabled();
    await expect(page.locator('[data-submit]')).toBeEnabled();
    await expect(page.locator('[data-pick-files]')).toBeEnabled();
    await expect(page.locator('[data-file-input]')).toBeEnabled();
    await expect(page.locator('[data-upload-list] [data-upload-remove]')).toBeEnabled();
    expect(page.url()).toContain('/shares/new');
  };

  // (a) The request never reaches the server.
  await page.route('**/api/shares/direct-link', (route) => route.abort('connectionrefused'));
  await directButton.click();
  await expect(error).toBeVisible();
  await expect(error).toHaveText('Could not create the direct link. Check your connection and try again.');
  await expectUnlocked();
  await page.unroute('**/api/shares/direct-link');

  // (b) The server refuses with a message.
  await page.route('**/api/shares/direct-link', (route) =>
    route.fulfill({ status: 503, contentType: 'application/json', body: JSON.stringify({ error: 'The direct link could not be created right now.' }) })
  );
  await directButton.click();
  await expect(error).toHaveText('The direct link could not be created right now.');
  await expectUnlocked();
  await page.unroute('**/api/shares/direct-link');

  // The staged file still becomes an ordinary share.
  await page.locator('[data-submit]').click();
  await page.waitForURL(/\/shares\/created\/[^/?#]+$/);
  const shareUrl = extractShareUrl(await page.locator('main').innerText(), page.url());
  await waitForShareReady(page, shareUrl);
  const summary = await request.get(`/api/shares/${shareUrl.slice(shareUrl.lastIndexOf('/') + 1)}`);
  expect(summary.status()).toBe(200);
  expect((await summary.json()).fileCount).toBe(1);
});

test('the created page confirms the copy only when it happened', async ({ page, context, request }, testInfo) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  const user = await createE2EUser(request, 'direct-link-copied');
  await login(page, user.email, user.password);

  const pngPath = path.join(testInfo.outputPath('files'), 'photo.png');
  await writePngFile(pngPath, { comment: 'copied-flag' });
  const card = page.locator('[data-created-direct-link]');
  const copyButton = card.getByRole('button');

  // (a) A flag for another token is ignored and discarded.
  await page.goto('/shares/new');
  const url = await createDirectLink(page, pngPath);
  await page.evaluate(() => sessionStorage.setItem('agora.directLink.copied', 'other000'));
  await page.reload();
  await expect(copyButton).toHaveText('Copy link');
  await expect(copyButton).not.toHaveText(/Copied/);
  expect(await page.evaluate(() => sessionStorage.getItem('agora.directLink.copied'))).toBeNull();

  // (b) A rejected clipboard write still lands on the created page, without a confirmation; the button copies.
  await page.goto('/shares/new');
  await page.setInputFiles('[data-file-input]', [pngPath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await page.evaluate(() => {
    Object.defineProperty(navigator.clipboard, 'writeText', { configurable: true, value: () => Promise.reject(new Error('denied')) });
    document.execCommand = () => false;
  });
  await page.locator('[data-direct-link]').click();
  await page.waitForURL(CREATED_URL);
  const secondUrl = await createdLinkText(page);
  expect(secondUrl).not.toBe(url);
  await expect(copyButton).toHaveText('Copy link');
  await expect(copyButton).not.toHaveText(/Copied/);
  expect(await page.evaluate(() => sessionStorage.getItem('agora.directLink.copied'))).toBeNull();
  await copyButton.click();
  await expect(copyButton).toHaveText(/Copied/);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(secondUrl);

  // (c) Blocked storage neither stops the navigation nor the page.
  await page.goto('/shares/new');
  await page.setInputFiles('[data-file-input]', [pngPath]);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await page.evaluate(() => {
    const blocked = () => {
      throw new Error('storage blocked');
    };
    Storage.prototype.setItem = blocked;
    Storage.prototype.getItem = blocked;
    Storage.prototype.removeItem = blocked;
  });
  await page.locator('[data-direct-link]').click();
  await page.waitForURL(CREATED_URL);
  const thirdUrl = await createdLinkText(page);
  expect(thirdUrl).toMatch(/\/s\/[A-Za-z0-9]{8}$/);
  expect(thirdUrl).not.toBe(secondUrl);
  await expect(card).toContainText(thirdUrl);
  await expect(copyButton).toHaveText(/Copy link|Copied/);
  expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(thirdUrl);
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
