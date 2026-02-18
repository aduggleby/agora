import path from 'node:path';
import AdmZip from 'adm-zip';
import { expect, test } from '@playwright/test';
import { createE2EUser, createTempFiles, extractShareUrl, login, tokenFromShareUrl } from '../support/helpers';

test.describe('Share user stories', () => {
  test('uses a custom share link slug when provided', async ({ page, request }, testInfo) => {
    const user = await createE2EUser(request, 'custom-share-slug');
    await login(page, user.email, user.password);

    const inputFiles = await createTempFiles(testInfo.outputPath('files-custom-slug'), [
      { name: 'slug-proof.txt', content: 'custom slug proof' },
    ]);

    await page.goto('/shares/new');
    await page.setInputFiles('[data-file-input]', inputFiles);
    await expect(page.locator('[data-upload-list] li')).toHaveCount(1);

    await page.locator('[data-options-toggle]').click();
    await expect(page.locator('[data-options-panel]')).toBeVisible();

    const customSlug = `custom-slug-${Date.now().toString().slice(-6)}`;
    await page.locator('[data-share-token]').fill(customSlug);

    await page.locator('[data-submit]').click();
    await page.waitForURL(new RegExp(`/shares/created\\?token=${customSlug}$`));

    const shareUrlText = await page.locator('main').innerText();
    const shareUrl = extractShareUrl(shareUrlText);
    const parsed = new URL(shareUrl);
    expect(parsed.pathname).toBe(`/s/${customSlug}`);
  });

  test('uploads 3 files from dashboard quick dropzone and creates downloadable share', async ({ page, request }, testInfo) => {
    const user = await createE2EUser(request, 'three-files-default');
    await login(page, user.email, user.password);

    const inputFiles = await createTempFiles(testInfo.outputPath('files-default'), [
      { name: 'alpha.txt', content: 'alpha content' },
      { name: 'beta.txt', content: 'beta content' },
      { name: 'gamma.txt', content: 'gamma content' },
    ]);

    await page.setInputFiles('[data-quick-share-input]', inputFiles);
    await page.waitForURL(/\/shares\/new\?draftShareId=/);

    const uploadList = page.locator('[data-upload-list] li');
    await expect(uploadList).toHaveCount(3);
    await expect(uploadList.filter({ hasText: 'alpha.txt' })).toBeVisible();
    await expect(uploadList.filter({ hasText: 'beta.txt' })).toBeVisible();
    await expect(uploadList.filter({ hasText: 'gamma.txt' })).toBeVisible();

    const createButton = page.locator('[data-submit]');
    await expect(createButton).toBeEnabled();
    await createButton.click();

    await page.waitForURL(/\/shares\/created\?token=/);
    const messageText = await page.locator('main').innerText();
    const shareUrl = extractShareUrl(messageText);

    await page.goto(shareUrl);
    await expect(page.getByRole('button', { name: 'Download' }).or(page.getByRole('link', { name: 'Download' }))).toBeVisible();

    const csrfToken = await page.locator('input[name="__RequestVerificationToken"]').inputValue();
    const download = await page.request.post(`${shareUrl}/download`, {
      form: {
        __RequestVerificationToken: csrfToken,
      },
    });
    expect(download.ok()).toBeTruthy();
    const zipBuffer = Buffer.from(await download.body());
    const zip = new AdmZip(zipBuffer);
    const names = zip.getEntries().map((entry) => entry.entryName).sort();
    expect(names).toEqual(['alpha.txt', 'beta.txt', 'gamma.txt']);
  });

  test('uploads a PDF and creates a downloadable shared archive', async ({ page, request }, testInfo) => {
    const user = await createE2EUser(request, 'pdf-share');
    await login(page, user.email, user.password);

    const minimalPdf = `%PDF-1.1
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>
endobj
trailer
<< /Root 1 0 R >>
%%EOF
`;

    const inputFiles = await createTempFiles(testInfo.outputPath('files-pdf'), [
      { name: 'proof.pdf', content: minimalPdf },
    ]);

    await page.goto('/shares/new');
    await page.setInputFiles('[data-file-input]', inputFiles);

    const uploadList = page.locator('[data-upload-list] li');
    await expect(uploadList).toHaveCount(1);
    await expect(uploadList.filter({ hasText: 'proof.pdf' })).toBeVisible();

    await page.locator('[data-submit]').click();
    await page.waitForURL(/\/shares\/created\?token=/);

    const messageText = await page.locator('main').innerText();
    const shareUrl = extractShareUrl(messageText);

    await page.goto(shareUrl);
    await expect(page.getByRole('button', { name: 'Download' }).or(page.getByRole('link', { name: 'Download' }))).toBeVisible();

    const csrfToken = await page.locator('input[name="__RequestVerificationToken"]').inputValue();
    const download = await page.request.post(`${shareUrl}/download`, {
      form: {
        __RequestVerificationToken: csrfToken,
      },
    });
    expect(download.ok()).toBeTruthy();
    expect(download.headers()['content-type'] || '').toContain('application/zip');

    const zipBuffer = Buffer.from(await download.body());
    const zip = new AdmZip(zipBuffer);
    const names = zip.getEntries().map((entry) => entry.entryName);
    expect(names).toContain('proof.pdf');
  });

  test('allows download before 5-second expiry and shows expired download page after', async ({ page, request }, testInfo) => {
    const user = await createE2EUser(request, 'three-files-short-expiry');
    await login(page, user.email, user.password);

    const inputFiles = await createTempFiles(testInfo.outputPath('files-short-expiry'), [
      { name: 'one.txt', content: 'one' },
      { name: 'two.txt', content: 'two' },
      { name: 'three.txt', content: 'three' },
    ]);

    await page.setInputFiles('[data-quick-share-input]', inputFiles);
    await page.waitForURL(/\/shares\/new\?draftShareId=/);
    await expect(page.locator('[data-upload-list] li')).toHaveCount(3);

    await page.locator('[data-submit]').click();
    await page.waitForURL(/\/shares\/created\?token=/);

    const messageText = await page.locator('main').innerText();
    const shareUrl = extractShareUrl(messageText);
    const token = tokenFromShareUrl(shareUrl);

    const setExpiry = await request.post(`/api/e2e/shares/${token}/expires-in-seconds`, {
      form: { seconds: '5' },
    });
    expect(setExpiry.ok()).toBeTruthy();

    const preExpiryDownload = await page.request.get(`${shareUrl}/download`);
    expect(preExpiryDownload.ok()).toBeTruthy();

    await page.waitForTimeout(6000);

    await page.goto(shareUrl);
    await expect(page.getByText('This link has expired.')).toBeVisible();
    await expect(page.getByRole('button', { name: 'Download' })).toBeDisabled();

    const expiredDownload = await page.request.get(`${shareUrl}/download`);
    expect(expiredDownload.ok()).toBeTruthy();
    expect((expiredDownload.headers()['content-type'] || '')).toContain('text/html');
    const expiredBody = await expiredDownload.text();
    expect(expiredBody).toContain('This link has expired.');
  });
});
