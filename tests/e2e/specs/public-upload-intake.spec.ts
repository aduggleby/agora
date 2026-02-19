import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';
import { createE2EUser, createTempFiles, login } from '../support/helpers';

type FileSystemEmailRecord = {
  to?: string;
  subject?: string;
  kind?: string;
  html?: string;
  metadata?: {
    ActionUrl?: string;
  };
};

async function uploadUrlFromSettings(page: Page): Promise<string> {
  const prefix = (await page.locator('[data-upload-url-prefix]').innerText()).trim();
  const token = (await page.locator('#uploadToken').inputValue()).trim();
  if (!prefix || !token) {
    throw new Error(`Could not build upload URL from settings. Prefix='${prefix}' token='${token}'.`);
  }

  return `${prefix}${encodeURIComponent(token)}`;
}

function resolveRepoRoot(): string {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(thisDir, '../../..');
}

async function resolveLatestEmailDirectory(repoRoot: string): Promise<string> {
  const runsRoot = path.join(repoRoot, '.e2e-data', 'runs');
  const runs = await fs.readdir(runsRoot, { withFileTypes: true }).catch(() => []);

  const candidates: Array<{ dir: string; mtimeMs: number }> = [];
  for (const entry of runs) {
    if (!entry.isDirectory()) continue;
    const emailsDir = path.join(runsRoot, entry.name, 'emails');
    const stats = await fs.stat(emailsDir).catch(() => null);
    if (!stats?.isDirectory()) continue;
    candidates.push({ dir: emailsDir, mtimeMs: stats.mtimeMs });
  }

  if (candidates.length === 0) {
    throw new Error(`No email output directories found under ${runsRoot}`);
  }

  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return candidates[0].dir;
}

async function waitForReadyEmail(to: string, startedAt: number): Promise<FileSystemEmailRecord> {
  const repoRoot = resolveRepoRoot();
  const emailsDir = await resolveLatestEmailDirectory(repoRoot);
  const timeoutMs = 90_000;

  while (Date.now() - startedAt < timeoutMs) {
    const names = await fs.readdir(emailsDir).catch(() => []);
    const jsonFiles = names.filter((name) => name.endsWith('.json'));

    const parsed = await Promise.all(jsonFiles.map(async (name) => {
      const fullPath = path.join(emailsDir, name);
      const stats = await fs.stat(fullPath);
      const text = await fs.readFile(fullPath, 'utf8');
      const payload = JSON.parse(text) as FileSystemEmailRecord;
      return { stats, payload };
    }));

    const match = parsed
      .filter((entry) => entry.stats.mtimeMs >= startedAt - 2000)
      .sort((a, b) => b.stats.mtimeMs - a.stats.mtimeMs)
      .find((entry) =>
        entry.payload.to === to
        && entry.payload.subject === 'Your share link is ready'
        && entry.payload.kind === 'auth');

    if (match) {
      return match.payload;
    }

    await new Promise((resolve) => setTimeout(resolve, 1000));
  }

  throw new Error(`Timed out waiting for ready email for ${to}.`);
}

test.describe('Public upload intake', () => {
  test('shows account upload link and rejects invalid token routes', async ({ page, request }) => {
    const user = await createE2EUser(request, 'public-upload-regenerate');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const uploadUrl = await uploadUrlFromSettings(page);

    await page.goto(uploadUrl);
    await expect(page.getByRole('heading', { name: 'Send files' })).toBeVisible();
    await expect(page.locator('[data-public-upload-form]')).toBeVisible();

    await page.goto('/u/not-a-real-upload-token');
    await expect(page.getByText('Upload link unavailable')).toBeVisible();
  });

  test('upload page toggles select button style/text and requires sender email before enabling send button', async ({ browser, page, request }, testInfo) => {
    const user = await createE2EUser(request, 'public-upload-cta-state');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const uploadUrl = await uploadUrlFromSettings(page);

    const files = await createTempFiles(testInfo.outputPath('public-intake-cta-state'), [
      { name: 'cta-state.txt', content: 'state check' },
    ]);

    const anonPage = await browser.newPage();
    await anonPage.goto(uploadUrl);

    const pickButton = anonPage.locator('[data-public-pick-files]');
    const submitButton = anonPage.locator('[data-public-submit]');

    await expect(pickButton).toHaveText('Select files');
    await expect(pickButton).toHaveClass(/bg-terra/);
    await expect(submitButton).toBeHidden();

    await anonPage.setInputFiles('[data-public-file-input]', files);
    await expect(anonPage.locator('[data-public-upload-list] li')).toHaveCount(1);

    await expect(pickButton).toHaveText('Add more files');
    await expect(pickButton).toHaveClass(/bg-cream/);
    await expect(pickButton).toHaveClass(/border/);
    await expect(submitButton).toBeVisible();
    await expect(submitButton).toBeDisabled();
    await expect(submitButton).toHaveAttribute('title', 'Enter your email first.');

    await anonPage.locator('input[name="senderEmail"]').fill('sender@example.test');
    await expect(submitButton).toBeEnabled();
    await expect(submitButton).toHaveAttribute('title', '');
    await anonPage.close();
  });

  test('accepts anonymous upload and emails owner with sender details and share link', async ({ browser, page, request }, testInfo) => {
    const user = await createE2EUser(request, 'public-upload-happy');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const uploadUrl = await uploadUrlFromSettings(page);

    const files = await createTempFiles(testInfo.outputPath('public-intake-files'), [
      { name: 'public-upload.txt', content: 'hello from public intake e2e' },
    ]);

    const senderName = 'External Sender';
    const senderEmail = 'sender@example.test';
    const senderMessage = 'Please review this upload.';

    const startMs = Date.now();
    const anonPage = await browser.newPage();
    await anonPage.goto(uploadUrl);
    await expect(anonPage.locator('[data-public-submit]')).toBeHidden();
    await expect(anonPage.locator('[data-public-pick-files]')).toHaveText('Select files');
    await anonPage.locator('input[name="senderName"]').fill(senderName);
    await anonPage.locator('input[name="senderEmail"]').fill(senderEmail);
    await anonPage.locator('textarea[name="senderMessage"]').fill(senderMessage);

    await anonPage.setInputFiles('[data-public-file-input]', files);
    await expect(anonPage.locator('[data-public-upload-list] li')).toHaveCount(1);
    await expect(anonPage.locator('[data-public-pick-files]')).toHaveText('Add more files');
    await expect(anonPage.locator('[data-public-submit]')).toBeVisible();
    await expect(anonPage.locator('[data-public-submit]')).toBeEnabled();

    await anonPage.locator('[data-public-submit]').click();
    await anonPage.waitForURL(/\/u\/[A-Za-z0-9]{2,64}\?msg=/);
    await expect(anonPage.getByText('Thanks, your files are being processed.')).toBeVisible();

    const readyEmail = await waitForReadyEmail(user.email, startMs);
    const html = readyEmail.html || '';
    const actionUrl = readyEmail.metadata?.ActionUrl || '';

    expect(html).toContain(`Sender name: ${senderName}`);
    expect(html).toContain(`Sender email: ${senderEmail}`);
    expect(html).toContain(`Message: ${senderMessage}`);
    expect(actionUrl).toContain('/s/');

    const resolvedActionUrl = new URL(actionUrl, anonPage.url()).toString();
    await anonPage.goto(resolvedActionUrl, { waitUntil: 'domcontentloaded' });
    await expect(anonPage.getByRole('button', { name: 'Download' }).or(anonPage.getByRole('link', { name: 'Download' }))).toBeVisible();
    await anonPage.close();
  });

  test('rejects invalid sender email on create-share endpoint', async ({ browser, page, request }, testInfo) => {
    const user = await createE2EUser(request, 'public-upload-invalid-email');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const uploadUrl = await uploadUrlFromSettings(page);

    const files = await createTempFiles(testInfo.outputPath('public-intake-invalid-email'), [
      { name: 'invalid-email-check.txt', content: 'invalid email test' },
    ]);

    const anonPage = await browser.newPage();
    await anonPage.goto(uploadUrl);

    const uploadToken = await anonPage.locator('[data-public-upload-token]').inputValue();
    const draftShareId = await anonPage.locator('[data-public-draft-share-id]').inputValue();
    const csrfToken = await anonPage.evaluate(() => {
      const tokenCookie = document.cookie
        .split(';')
        .map((part) => part.trim())
        .find((part) => part.startsWith('agora.csrf.request='));
      return tokenCookie ? decodeURIComponent(tokenCookie.slice('agora.csrf.request='.length)) : '';
    });
    expect(csrfToken).not.toBe('');

    const stageResponse = await anonPage.request.post('/api/public-uploads/stage', {
      multipart: {
        __RequestVerificationToken: csrfToken,
        uploadToken,
        draftShareId,
        file: {
          name: path.basename(files[0]),
          mimeType: 'text/plain',
          buffer: await fs.readFile(files[0]),
        },
      },
    });
    expect(stageResponse.ok()).toBeTruthy();
    const staged = await stageResponse.json() as { uploadId?: string };
    expect(staged.uploadId).toBeTruthy();

    const form = new URLSearchParams();
    form.set('__RequestVerificationToken', csrfToken);
    form.set('uploadToken', uploadToken);
    form.set('draftShareId', draftShareId);
    form.set('senderName', 'Invalid Sender');
    form.set('senderEmail', 'invalid-email-format');
    form.set('senderMessage', 'Hello');
    form.append('uploadedFileIds', staged.uploadId || '');

    const createResponse = await anonPage.request.post('/api/public-uploads/create-share', {
      data: form.toString(),
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });
    expect(createResponse.status()).toBe(400);
    expect(await createResponse.text()).toContain('senderEmail must be a valid email address.');
    await anonPage.close();
  });

  test('shows limit dialog when selected files exceed max-per-share', async ({ browser, page, request }, testInfo) => {
    const user = await createE2EUser(request, 'public-upload-limit');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const uploadUrl = await uploadUrlFromSettings(page);

    const files = await createTempFiles(
      testInfo.outputPath('public-intake-limit-files'),
      Array.from({ length: 21 }, (_, index) => ({
        name: `limit-file-${index + 1}.txt`,
        content: `file-${index + 1}`
      })));

    const anonPage = await browser.newPage();
    await anonPage.goto(uploadUrl);
    await anonPage.setInputFiles('[data-public-file-input]', files);

    const dialog = anonPage.locator('dialog');
    await expect(dialog).toBeVisible();
    await expect(dialog.getByText('Upload limit reached')).toBeVisible();
    await expect(dialog.getByText('You selected 21 file(s) but can only add 20 more (limit: 20 per share).')).toBeVisible();
    await expect(anonPage.locator('[data-public-upload-list] li')).toHaveCount(0);
    await anonPage.close();
  });

  test('remembers sender name and email in localStorage', async ({ browser, page, request }) => {
    const user = await createE2EUser(request, 'public-upload-remember-sender');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const uploadUrl = await uploadUrlFromSettings(page);

    const anonPage = await browser.newPage();
    await anonPage.goto(uploadUrl);

    const senderName = `Stored Sender ${Date.now()}`;
    const senderEmail = `stored-${Date.now()}@example.test`;
    await anonPage.locator('input[name="senderName"]').fill(senderName);
    await anonPage.locator('input[name="senderEmail"]').fill(senderEmail);

    await anonPage.reload();

    await expect(anonPage.locator('input[name="senderName"]')).toHaveValue(senderName);
    await expect(anonPage.locator('input[name="senderEmail"]')).toHaveValue(senderEmail);
    await anonPage.close();
  });

  test('uses account display name on upload page and in account menu', async ({ browser, page, request }) => {
    const user = await createE2EUser(request, 'public-upload-display-name');
    await login(page, user.email, user.password);

    const displayName = `Jordan ${Date.now().toString(36).slice(-5)}`;
    await page.goto('/account/settings');
    await page.locator('input[name="displayName"]').fill(displayName);
    await page.getByRole('button', { name: 'Save profile' }).click();
    await page.waitForURL(/\/account\/settings\?msg=/);

    const menuToggle = page.locator('summary[data-account-menu-toggle]');
    await expect(menuToggle).toContainText(displayName);

    const uploadUrl = await uploadUrlFromSettings(page);
    const anonPage = await browser.newPage();
    await anonPage.goto(uploadUrl);
    await expect(anonPage.getByText(`Share your files with ${displayName}.`)).toBeVisible();
    await expect(anonPage.getByText(user.email)).toHaveCount(0);
    await anonPage.close();
  });

  test('regenerates upload link and invalidates the previous token', async ({ page, request }) => {
    const user = await createE2EUser(request, 'public-upload-regenerated-token');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const originalUploadUrl = await uploadUrlFromSettings(page);

    const regenerate = await request.post('/api/e2e/users/regenerate-upload-token', {
      form: {
        email: user.email
      }
    });
    expect(regenerate.ok()).toBeTruthy();
    const regeneratePayload = await regenerate.json() as { uploadToken?: string };
    const newToken = regeneratePayload.uploadToken || '';
    expect(newToken).not.toBe('');
    const regeneratedUploadUrl = new URL(`/u/${encodeURIComponent(newToken)}`, page.url()).toString();

    await page.goto('/account/settings');
    const updatedUploadUrl = await uploadUrlFromSettings(page);
    expect(updatedUploadUrl).toBe(regeneratedUploadUrl);
    expect(updatedUploadUrl).not.toBe(originalUploadUrl);

    await page.goto(originalUploadUrl);
    await expect(page.getByText('Upload link unavailable')).toBeVisible();

    await page.goto(regeneratedUploadUrl);
    await expect(page.getByRole('heading', { name: 'Send files' })).toBeVisible();
    await expect(page.locator('[data-public-upload-form]')).toBeVisible();
  });

  test('regenerate random code from settings UI does not 400 and rotates upload link', async ({ page, request }) => {
    const user = await createE2EUser(request, 'public-upload-regenerate-ui');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const originalUploadUrl = await uploadUrlFromSettings(page);

    const [postResponse] = await Promise.all([
      page.waitForResponse((response) =>
        response.request().method() === 'POST'
        && response.url().includes('/account/settings?handler=RegenerateUploadLink')),
      page.getByRole('button', { name: 'Regenerate random code' }).click()
    ]);

    expect(postResponse.status()).not.toBe(400);
    expect(postResponse.status()).toBeLessThan(500);

    await page.goto('/account/settings');
    const updatedUploadUrl = await uploadUrlFromSettings(page);
    expect(updatedUploadUrl).not.toBe(originalUploadUrl);

    await page.goto(originalUploadUrl);
    await expect(page.getByText('Upload link unavailable')).toBeVisible();
  });

  test('custom upload code update rotates link and invalidates previous code', async ({ page, request }) => {
    const user = await createE2EUser(request, 'public-upload-custom-code');
    await login(page, user.email, user.password);

    const customCode = `Ab${Date.now().toString(36).slice(-6)}`;

    await page.goto('/account/settings');
    const originalUploadUrl = await uploadUrlFromSettings(page);

    await expect(page.getByRole('button', { name: 'Save code' })).toBeHidden();
    await expect(page.getByRole('button', { name: 'Copy URL' })).toBeVisible();
    await page.locator('#uploadToken').fill(customCode);
    await expect(page.getByRole('button', { name: 'Save code' })).toBeVisible();
    await expect(page.getByRole('button', { name: 'Copy URL' })).toBeHidden();
    const [saveResponse] = await Promise.all([
      page.waitForResponse((response) =>
        response.request().method() === 'POST'
        && response.url().includes('/account/settings?handler=SetUploadLink')),
      page.getByRole('button', { name: 'Save code' }).click()
    ]);
    expect(saveResponse.status()).toBeLessThan(500);
    await page.waitForURL(/\/account\/settings\?msg=/);

    const updatedUploadUrl = await uploadUrlFromSettings(page);
    expect(updatedUploadUrl).toContain(`/u/${customCode}`);
    expect(updatedUploadUrl).not.toBe(originalUploadUrl);
    await expect(page.getByRole('button', { name: 'Save code' })).toBeHidden();
    await expect(page.getByRole('button', { name: 'Copy URL' })).toBeVisible();

    await page.goto(originalUploadUrl);
    await expect(page.getByText('Upload link unavailable')).toBeVisible();

    await page.goto(updatedUploadUrl);
    await expect(page.locator('[data-public-upload-form]')).toBeVisible();
  });

  test('duplicate custom upload code shows a user-facing error and keeps existing link', async ({ browser, request }) => {
    const first = await createE2EUser(request, 'public-upload-custom-duplicate-a');
    const second = await createE2EUser(request, 'public-upload-custom-duplicate-b');
    const code = `Cd${Date.now().toString(36).slice(-6)}`;

    const contextA = await browser.newContext();
    const pageA = await contextA.newPage();
    await login(pageA, first.email, first.password);
    await pageA.goto('/account/settings');
    await pageA.locator('#uploadToken').fill(code);
    await pageA.getByRole('button', { name: 'Save code' }).click();
    await pageA.waitForURL(/\/account\/settings\?msg=/);
    await contextA.close();

    const contextB = await browser.newContext();
    const pageB = await contextB.newPage();
    await login(pageB, second.email, second.password);
    await pageB.goto('/account/settings');
    const previousUrl = await uploadUrlFromSettings(pageB);

    await pageB.locator('#uploadToken').fill(code);
    await pageB.getByRole('button', { name: 'Save code' }).click();
    await pageB.waitForURL(/\/account\/settings\?msg=/);
    await expect(pageB.getByText('That upload code is already in use.')).toBeVisible();

    const afterUrl = await uploadUrlFromSettings(pageB);
    expect(afterUrl).toBe(previousUrl);
    expect(afterUrl).not.toContain(`/u/${code}`);
    await contextB.close();
  });

  test('invalid custom upload code returns a user-facing validation error', async ({ page, request }) => {
    const user = await createE2EUser(request, 'public-upload-custom-invalid');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    await page.evaluate(() => {
      const form = document.querySelector('form[action*="handler=SetUploadLink"]') as HTMLFormElement | null;
      const input = document.querySelector<HTMLInputElement>('#uploadToken');
      if (!form || !input) return;
      input.value = 'bad-token';
      form.submit();
    });

    await page.waitForURL(/\/account\/settings\?msg=/);
    await expect(page.getByText('Upload code must be 2-64 letters or numbers.')).toBeVisible();
  });

});
