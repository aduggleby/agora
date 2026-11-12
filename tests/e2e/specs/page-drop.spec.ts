import path from 'node:path';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { createE2EUser, login, writePngFile } from '../support/helpers';

// Files dropped anywhere on an upload page (not only on the dropzone) are taken, and a full-page hint appears while
// files are dragged over the window. Drags without files are left to the browser.

async function fileTransfer(page: Page, name: string, content = 'page drop') {
  return page.evaluateHandle(([fileName, body]) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([body], fileName, { type: fileName.endsWith('.png') ? 'image/png' : 'text/plain' }));
    return transfer;
  }, [name, content] as const);
}

async function textTransfer(page: Page) {
  return page.evaluateHandle(() => {
    const transfer = new DataTransfer();
    transfer.setData('text/plain', 'just text');
    return transfer;
  });
}

async function dropOnFooter(page: Page, name: string) {
  const dataTransfer = await fileTransfer(page, name);
  await page.dispatchEvent('footer', 'dragenter', { dataTransfer });
  await expect(page.locator('[data-page-drop-overlay]')).toBeVisible();
  await page.dispatchEvent('footer', 'drop', { dataTransfer });
  await expect(page.locator('[data-page-drop-overlay]')).toBeHidden();
}

test('new share page takes files dropped outside the dropzone', async ({ page, request }) => {
  const user = await createE2EUser(request, 'page-drop-new');
  await login(page, user.email, user.password);
  await page.goto('/shares/new');

  // A text drag shows no hint.
  const text = await textTransfer(page);
  await page.dispatchEvent('footer', 'dragenter', { dataTransfer: text });
  await expect(page.locator('[data-page-drop-overlay]')).toBeHidden();

  await dropOnFooter(page, 'dropped-anywhere.txt');
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(page.locator('[data-upload-list] li').first()).toContainText('dropped-anywhere.txt');
  expect(page.url()).toContain('/shares/new');
});

test('home page quick share takes files dropped outside the dropzone', async ({ page, request }) => {
  const user = await createE2EUser(request, 'page-drop-home');
  await login(page, user.email, user.password);
  await page.goto('/');
  await expect(page.locator('[data-quick-share-dropzone]')).toBeVisible();

  await dropOnFooter(page, 'quick.txt');
  await page.waitForURL(/\/shares\/new\?draftShareId=/);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(page.locator('[data-upload-list] li').first()).toContainText('quick.txt');
});

test('public upload page takes files dropped outside the dropzone', async ({ page, browser, request }) => {
  const user = await createE2EUser(request, 'page-drop-public');
  await login(page, user.email, user.password);
  await page.goto('/account/settings');
  const prefix = (await page.locator('[data-upload-url-prefix]').innerText()).trim();
  const token = (await page.locator('#uploadToken').inputValue()).trim();

  const anon = await browser.newContext();
  const anonPage = await anon.newPage();
  await anonPage.goto(`${prefix}${encodeURIComponent(token)}`);
  await expect(anonPage.locator('[data-public-upload-form]')).toBeVisible();

  await dropOnFooter(anonPage, 'for-you.txt');
  await expect(anonPage.locator('[data-public-upload-list] li')).toHaveCount(1);
  await expect(anonPage.locator('[data-public-upload-list] li').first()).toContainText('for-you.txt');
  await anon.close();
});

test('account landing page designer takes a background image dropped anywhere and saves it', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'page-drop-designer');
  await login(page, user.email, user.password);
  await page.goto('/account/landing-page-designer');

  const pngPath = path.join(testInfo.outputPath('files'), 'bg.png');
  await writePngFile(pngPath, { comment: 'page-drop' });
  const bytes = (await import('node:fs')).readFileSync(pngPath).toString('base64');
  const dataTransfer = await page.evaluateHandle((b64) => {
    const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const transfer = new DataTransfer();
    transfer.items.add(new File([raw], 'bg.png', { type: 'image/png' }));
    return transfer;
  }, bytes);
  await page.dispatchEvent('footer', 'dragenter', { dataTransfer });
  await page.dispatchEvent('footer', 'drop', { dataTransfer });
  await expect(page.locator('[data-preview-upload-status]')).toContainText('bg.png');

  // The dropped file is part of the saved form, not only the preview.
  await page.locator('#account-template-form button[type="submit"]').first().click();
  await page.waitForURL(/\/account\/landing-page-designer/);
  await expect(page.locator('[data-preview-upload-status]')).toContainText('Uploaded background image selected.');
});

// Pasting files (for example a screenshot on the clipboard) uploads them like a drop.
async function pasteFiles(page: Page, selector: string | null, withText = false) {
  await page.evaluate(([target, text]) => {
    const transfer = new DataTransfer();
    transfer.items.add(new File([new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10])], 'image.png', { type: 'image/png' }));
    if (text) transfer.setData('text/plain', 'copied text');
    const element = target ? document.querySelector(target) : document.body;
    (element as HTMLElement | null)?.focus();
    (element ?? document.body).dispatchEvent(new ClipboardEvent('paste', { clipboardData: transfer, bubbles: true, cancelable: true }));
  }, [selector, withText] as const);
}

test('new share page uploads a pasted image with a distinct name', async ({ page, request }) => {
  const user = await createE2EUser(request, 'page-paste-new');
  await login(page, user.email, user.password);
  await page.goto('/shares/new');

  await pasteFiles(page, null);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await expect(page.locator('[data-upload-list] li').first()).toContainText(/pasted-\d{4}-\d{2}-\d{2}-\d{6}\.png/);
});

test('public upload page uploads pasted files, but a text paste into the message stays text', async ({ page, browser, request }) => {
  const user = await createE2EUser(request, 'page-paste-public');
  await login(page, user.email, user.password);
  await page.goto('/account/settings');
  const prefix = (await page.locator('[data-upload-url-prefix]').innerText()).trim();
  const token = (await page.locator('#uploadToken').inputValue()).trim();

  const anon = await browser.newContext();
  const anonPage = await anon.newPage();
  await anonPage.goto(`${prefix}${encodeURIComponent(token)}`);
  await expect(anonPage.locator('[data-public-upload-form]')).toBeVisible();

  // Text plus a picture of it (as Office apps copy) into the message field: no upload.
  await pasteFiles(anonPage, 'textarea', true);
  await anonPage.waitForTimeout(300);
  await expect(anonPage.locator('[data-public-upload-list] li')).toHaveCount(0);

  await pasteFiles(anonPage, null);
  await expect(anonPage.locator('[data-public-upload-list] li')).toHaveCount(1);
  await expect(anonPage.locator('[data-public-upload-list] li').first()).toContainText('pasted-');
  await anon.close();
});
