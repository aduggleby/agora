import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
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

function extractUploadUrl(text: string): string {
  const match = text.match(/https?:\/\/[^\s]+\/u\/[A-Za-z0-9_-]+/);
  if (!match) {
    throw new Error(`Could not find upload URL in: ${text}`);
  }

  return match[0];
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
    const settingsText = await page.locator('#upload-link-settings').innerText();
    const uploadUrl = extractUploadUrl(settingsText);

    await page.goto(uploadUrl);
    await expect(page.getByRole('heading', { name: 'Send files' })).toBeVisible();
    await expect(page.locator('[data-public-upload-form]')).toBeVisible();

    await page.goto('/u/not-a-real-upload-token');
    await expect(page.getByText('Upload link unavailable')).toBeVisible();
  });

  test('accepts anonymous upload and emails owner with sender details and share link', async ({ browser, page, request }, testInfo) => {
    const user = await createE2EUser(request, 'public-upload-happy');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const settingsText = await page.locator('#upload-link-settings').innerText();
    const uploadUrl = extractUploadUrl(settingsText);

    const files = await createTempFiles(testInfo.outputPath('public-intake-files'), [
      { name: 'public-upload.txt', content: 'hello from public intake e2e' },
    ]);

    const senderName = 'External Sender';
    const senderEmail = 'sender@example.test';
    const senderMessage = 'Please review this upload.';

    const startMs = Date.now();
    const anonPage = await browser.newPage();
    await anonPage.goto(uploadUrl);
    await anonPage.locator('input[name="senderName"]').fill(senderName);
    await anonPage.locator('input[name="senderEmail"]').fill(senderEmail);
    await anonPage.locator('textarea[name="senderMessage"]').fill(senderMessage);

    await anonPage.setInputFiles('[data-public-file-input]', files);
    await expect(anonPage.locator('[data-public-upload-list] li')).toHaveCount(1);
    await expect(anonPage.locator('[data-public-submit]')).toBeEnabled();

    await anonPage.locator('[data-public-submit]').click();
    await anonPage.waitForURL(/\/u\/[A-Za-z0-9_-]+\?msg=/);
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
    const settingsText = await page.locator('#upload-link-settings').innerText();
    const uploadUrl = extractUploadUrl(settingsText);

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
    const settingsText = await page.locator('#upload-link-settings').innerText();
    const uploadUrl = extractUploadUrl(settingsText);

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

  test('regenerates upload link and invalidates the previous token', async ({ page, request }) => {
    const user = await createE2EUser(request, 'public-upload-regenerated-token');
    await login(page, user.email, user.password);

    await page.goto('/account/settings');
    const beforeText = await page.locator('#upload-link-settings').innerText();
    const originalUploadUrl = extractUploadUrl(beforeText);

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
    const afterText = await page.locator('#upload-link-settings').innerText();
    const updatedUploadUrl = extractUploadUrl(afterText);
    expect(updatedUploadUrl).toBe(regeneratedUploadUrl);
    expect(updatedUploadUrl).not.toBe(originalUploadUrl);

    await page.goto(originalUploadUrl);
    await expect(page.getByText('Upload link unavailable')).toBeVisible();

    await page.goto(regeneratedUploadUrl);
    await expect(page.getByRole('heading', { name: 'Send files' })).toBeVisible();
    await expect(page.locator('[data-public-upload-form]')).toBeVisible();
  });
});
