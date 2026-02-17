import path from 'node:path';
import AdmZip from 'adm-zip';
import { expect, test } from '@playwright/test';
import { createE2EUser, createTempFiles, extractShareUrl, login, tokenFromShareUrl } from '../support/helpers';

test.describe('Share user stories', () => {
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

    await page.waitForURL(/\/(\?.*)?$/);
    const messageText = await page.locator('main').innerText();
    const shareUrl = extractShareUrl(messageText);

    await page.goto(shareUrl);
    await expect(page.getByRole('button', { name: 'Download' }).or(page.getByRole('link', { name: 'Download' }))).toBeVisible();

    const download = await page.request.get(`${shareUrl}/download`);
    expect(download.ok()).toBeTruthy();
    const zipBuffer = Buffer.from(await download.body());
    const zip = new AdmZip(zipBuffer);
    const names = zip.getEntries().map((entry) => entry.entryName).sort();
    expect(names).toEqual(['alpha.txt', 'beta.txt', 'gamma.txt']);
  });

  test('allows download before 5-second expiry and shows expired landing page after', async ({ page, request }, testInfo) => {
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
    await page.waitForURL(/\/(\?.*)?$/);

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
