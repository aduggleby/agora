import path from 'node:path';
import fs from 'node:fs/promises';
import { expect, test } from '@playwright/test';
import { createE2EUser, createTempFiles, extractShareUrl, login } from '../support/helpers';

test('account default background image is shown on download page', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'default-bg');
  await login(page, user.email, user.password);

  const bgFilePath = path.join(testInfo.outputPath('background'), 'bg.svg');
  const accountMarker = 'account-default-marker-e2e';
  await fs.mkdir(path.dirname(bgFilePath), { recursive: true });
  await fs.writeFile(
    bgFilePath,
    `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800"><rect width="100%" height="100%" fill="#c4663a"/><text x="24" y="48">${accountMarker}</text></svg>`,
    'utf8'
  );

  await page.goto('/account/landing-page-designer');
  await page.setInputFiles('[data-preview-background-file]', bgFilePath);
  await page.getByRole('button', { name: 'Save template' }).click();
  await page.waitForURL(/\/account\/landing-page-designer\?msg=Template%20saved/);

  const uploadFiles = await createTempFiles(testInfo.outputPath('files'), [
    { name: 'proof.txt', content: 'proof' }
  ]);

  await page.goto('/shares/new');
  await page.setInputFiles('[data-file-input]', uploadFiles);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await page.locator('[data-submit]').click();
  await page.waitForURL(/\/shares\/created\?token=/);

  const shareUrlText = await page.locator('main').innerText();
  const shareUrl = extractShareUrl(shareUrlText, page.url());
  const sharePath = new URL(shareUrl).pathname;

  const backgroundLoad = page.waitForResponse((response) =>
    response.url().endsWith(`${sharePath}/background`) && response.status() === 200
  );
  await page.goto(shareUrl);
  await backgroundLoad;
  const backgroundImage = await page.evaluate(() => getComputedStyle(document.body).backgroundImage);
  expect(backgroundImage).toContain('/background');
  expect(backgroundImage).toContain(sharePath);

  const backgroundResponse = await page.request.get(`${shareUrl}/background`);
  expect(backgroundResponse.ok()).toBeTruthy();
  const contentType = backgroundResponse.headers()['content-type'] || '';
  expect(contentType).toContain('image/svg+xml');
  const backgroundBody = await backgroundResponse.text();
  expect(backgroundBody).toContain(accountMarker);
});

test('per-share custom background image is shown on download page', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'custom-bg');
  await login(page, user.email, user.password);

  const customBgPath = path.join(testInfo.outputPath('background-custom'), 'custom-bg.svg');
  const customMarker = 'per-share-marker-e2e';
  await fs.mkdir(path.dirname(customBgPath), { recursive: true });
  await fs.writeFile(
    customBgPath,
    `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="800"><rect width="100%" height="100%" fill="#5b7a5e"/><text x="24" y="48">${customMarker}</text></svg>`,
    'utf8'
  );

  const uploadFiles = await createTempFiles(testInfo.outputPath('files-custom'), [
    { name: 'proof-custom.txt', content: 'proof-custom' }
  ]);

  await page.goto('/shares/new');
  await page.setInputFiles('[data-file-input]', uploadFiles);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(1);
  await page.locator('[data-options-toggle]').click();
  await expect(page.locator('[data-options-panel]')).toBeVisible();

  await page.selectOption('select[name="templateMode"]', 'per_upload');
  await page.locator('[data-template-designer-link]').click();
  await page.waitForURL(/\/share\/landing-page-designer\?draftShareId=/);
  await page.setInputFiles('[data-template-background-file]', customBgPath);
  await page.getByRole('button', { name: 'Save and return' }).click();
  await page.waitForURL(/\/shares\/new\?draftShareId=/);
  await expect(page.locator('[data-upload-list] li')).toHaveCount(2);
  await expect(page.locator('[data-upload-list] li').filter({ hasText: 'proof-custom.txt' })).toBeVisible();

  await page.locator('[data-submit]').click();
  await page.waitForURL(/\/shares\/created\?token=/);

  const shareUrlText = await page.locator('main').innerText();
  const shareUrl = extractShareUrl(shareUrlText, page.url());
  const sharePath = new URL(shareUrl).pathname;

  const backgroundLoad = page.waitForResponse((response) =>
    response.url().endsWith(`${sharePath}/background`) && response.status() === 200
  );
  await page.goto(shareUrl);
  await backgroundLoad;
  const backgroundImage = await page.evaluate(() => getComputedStyle(document.body).backgroundImage);
  expect(backgroundImage).toContain('/background');
  expect(backgroundImage).toContain(sharePath);

  const backgroundResponse = await page.request.get(`${shareUrl}/background`);
  expect(backgroundResponse.ok()).toBeTruthy();
  const contentType = backgroundResponse.headers()['content-type'] || '';
  expect(contentType).toContain('image/svg+xml');
  const backgroundBody = await backgroundResponse.text();
  expect(backgroundBody).toContain(customMarker);
});
