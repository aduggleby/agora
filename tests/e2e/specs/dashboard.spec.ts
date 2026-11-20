import { expect, test } from '@playwright/test';
import { bearer, createE2EUser, login } from '../support/helpers';

test('the dashboard keeps every share action inside the table and always shows the received section', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'dashboard-layout');
  await login(page, user.email, user.password);

  // A Settings agent token is the quickest way to create a ready share without the upload UI.
  await page.goto('/account/settings');
  await page.locator('[data-create-agent-token-form] input[name="agentName"]').fill('Dashboard bot');
  await page.locator('[data-create-agent-token-form]').getByRole('button', { name: 'Create agent token' }).click();
  const token = await page.locator('[data-agent-token-value]').inputValue();

  const created = await request.post('/api/v1/shares', {
    headers: bearer(token),
    data: { files: [{ fileName: 'a-rather-long-file-name-for-the-archive-column.txt', text: 'x' }], waitSeconds: 40 },
  });
  expect(created.status()).toBe(201);
  const share = await created.json() as { token: string; ready: boolean };
  expect(share.ready).toBe(true);
  expect((await request.post(`/api/e2e/shares/${share.token}/expires-in-seconds`, { form: { seconds: '-1' } })).ok()).toBeTruthy();

  await page.goto('/');
  const table = page.locator('section', { hasText: 'Previous shares' }).locator('table');
  const row = table.locator('tbody tr').first();
  await expect(row.locator('td').nth(2)).toHaveText('Expired');
  const tableBox = (await table.boundingBox())!;
  for (const name of ['Show link', 'Re-enable', 'Delete']) {
    const box = (await row.getByRole('button', { name }).boundingBox())!;
    expect(box.x, `${name} starts inside the table`).toBeGreaterThanOrEqual(tableBox.x);
    expect(box.x + box.width, `${name} ends inside the table`).toBeLessThanOrEqual(tableBox.x + tableBox.width);
  }
  await expect(row.getByRole('button', { name: 'Re-enable' })).toHaveAttribute('title', /24 hours/);

  // Without received files the section still explains where they would appear.
  await expect(page.getByRole('heading', { name: 'Files sent to me' })).toBeVisible();
  await expect(page.locator('[data-received-empty]')).toContainText('upload link');
  await expect(page.getByRole('button', { name: 'Delete selected' })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath('dashboard.png'), fullPage: true });
});
