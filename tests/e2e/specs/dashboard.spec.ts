import { expect, test } from '@playwright/test';
import type { APIRequestContext, Browser, Page } from '@playwright/test';
import { bearer, createE2EUser, createTempFiles, login } from '../support/helpers';

/** A Settings agent token is the quickest way to create ready shares without the upload UI. */
async function createShares(page: Page, request: APIRequestContext, names: string[]): Promise<string[]> {
  await page.goto('/account/settings');
  await page.locator('[data-create-agent-token-form] input[name="agentName"]').fill('Dashboard bot');
  await page.locator('[data-create-agent-token-form]').getByRole('button', { name: 'Create agent token' }).click();
  const token = await page.locator('[data-agent-token-value]').inputValue();

  const tokens: string[] = [];
  for (const name of names) {
    const created = await request.post('/api/v1/shares', {
      headers: bearer(token),
      data: { files: [{ fileName: name, text: 'x' }], waitSeconds: 40 },
    });
    expect(created.status()).toBe(201);
    const share = await created.json() as { token: string; ready: boolean };
    expect(share.ready).toBe(true);
    tokens.push(share.token);
  }
  return tokens;
}

async function expire(request: APIRequestContext, shareToken: string): Promise<void> {
  expect((await request.post(`/api/e2e/shares/${shareToken}/expires-in-seconds`, { form: { seconds: '-1' } })).ok()).toBeTruthy();
}

/** Sends a file through the owner's upload link in a separate, signed-out browser page. */
async function receiveFile(browser: Browser, code: string, fileName: string, senderName: string, message: string, dir: string): Promise<void> {
  const files = await createTempFiles(dir, [{ name: fileName, content: 'received content' }]);
  const anon = await browser.newPage();
  await anon.goto(`/u/${code}`);
  await anon.locator('input[name="senderName"]').fill(senderName);
  await anon.locator('input[name="senderEmail"]').fill('sender@example.test');
  const messageField = anon.locator('textarea[name="senderMessage"]');
  if (await messageField.count()) await messageField.fill(message);
  await anon.setInputFiles('[data-public-file-input]', files);
  await anon.locator('[data-public-submit]').click();
  await anon.waitForURL(/\/u\/[A-Za-z0-9]{2,64}\?submitted=1/);
  await anon.close();
}

test('the dashboard groups expired shares, offers row and batch menus and re-enables a batch', async ({ page, request }, testInfo) => {
  const user = await createE2EUser(request, 'dashboard-layout');
  await login(page, user.email, user.password);
  const [expiredToken] = await createShares(page, request, ['a-rather-long-file-name-for-the-archive-column.txt', 'active-share.txt']);
  await expire(request, expiredToken);

  await page.goto('/');
  await expect(page.getByRole('heading', { name: 'Share files' })).toBeVisible();
  await expect(page.locator('[data-quick-share-dropzone]')).toBeVisible();

  // Tabs: My shares is selected, Received is reachable and the URL follows the tab.
  const mineTab = page.getByRole('tab', { name: /My shares/ });
  const receivedTab = page.getByRole('tab', { name: /Received/ });
  await expect(mineTab).toHaveAttribute('aria-selected', 'true');
  await expect(mineTab).toContainText('2');

  // Expired shares hide behind a toggle; the active one is listed.
  const activeRow = page.locator('[data-active-list] li', { hasText: 'active-share' });
  await expect(activeRow).toBeVisible();
  await expect(activeRow.locator('[data-local-datetime]').first()).not.toHaveText('');
  await expect(page.locator('[data-expired-list]')).toBeHidden();
  const toggle = page.getByRole('button', { name: /Show expired \(1\)/ });
  await expect(toggle).toContainText('Re-enable within 7 days of expiry, then they are removed');
  await toggle.click();
  await expect(page.getByRole('button', { name: /Hide expired \(1\)/ })).toHaveAttribute('aria-expanded', 'true');
  const expiredRow = page.locator('[data-expired-list] li').first();
  await expect(expiredRow).toContainText('Expired:');
  // The choice is remembered per browser.
  await page.reload();
  await expect(page.locator('[data-expired-list]')).toBeVisible();

  // Row menu: closes on Escape and offers Show link, Re-enable and Delete for an expired share.
  const menuButton = expiredRow.getByRole('button', { name: /More actions/ });
  await menuButton.click();
  await expect(menuButton).toHaveAttribute('aria-expanded', 'true');
  for (const name of ['Show link', 'Re-enable for 24 hours', 'Delete']) {
    await expect(expiredRow.getByRole('button', { name, exact: true })).toBeVisible();
  }
  await expect(expiredRow.getByRole('button', { name: 'Re-enable for 24 hours' })).toHaveAttribute('title', /24 hours/);
  await page.keyboard.press('Escape');
  await expect(expiredRow.getByRole('button', { name: 'Show link' })).toBeHidden();
  await activeRow.getByRole('button', { name: /More actions/ }).click();
  await expect(activeRow.getByRole('button', { name: /Re-enable/ })).toHaveCount(0);
  await page.locator('h1').click();
  await expect(activeRow.getByRole('button', { name: 'Show link' })).toBeHidden();

  // Canceling a delete gives focus back to the menu button that opened it.
  const activeMenuButton = activeRow.getByRole('button', { name: /More actions/ });
  await activeMenuButton.click();
  await activeRow.getByRole('button', { name: 'Delete', exact: true }).click();
  await page.locator('[data-share-delete-cancel]').click();
  await expect(activeMenuButton).toBeFocused();

  // The batch bar only exists while rows are selected.
  const bar = page.locator('[data-batch-bar="mine"]');
  await expect(bar).toBeHidden();
  await expect(page.getByRole('button', { name: 'Delete selected' })).toBeHidden();
  await activeRow.getByRole('checkbox').check();
  await expect(bar).toBeVisible();
  await expect(bar).toContainText('1 selected');
  await bar.getByRole('button', { name: /Batch actions/ }).click();
  const reenable = bar.getByRole('button', { name: 'Re-enable for 24 hours' });
  await expect(reenable).toBeDisabled();
  await expect(reenable).toHaveAttribute('title', /expired share/);
  await page.screenshot({ path: testInfo.outputPath('dashboard.png'), fullPage: true });

  // Canceling a batch delete (Escape) gives focus back to "Batch actions".
  const batchButton = bar.getByRole('button', { name: /Batch actions/ });
  await bar.getByRole('button', { name: 'Delete selected' }).click();
  await page.keyboard.press('Escape');
  await expect(batchButton).toBeFocused();
  await expiredRow.getByRole('checkbox').check();
  await expect(bar).toContainText('2 selected');
  // Clicking a row closed the batch menu; open it again.
  await bar.getByRole('button', { name: /Batch actions/ }).click();
  await expect(reenable).toBeEnabled();
  await reenable.click();
  await page.waitForURL(/msg=Re-enabled/);
  expect(decodeURIComponent(page.url())).toContain('Re-enabled 1 share(s) for 24 hours, skipped 1');
  await expect(page.locator('[data-expired-toggle]')).toHaveCount(0);
  await expect(page.locator('[data-active-list] li')).toHaveCount(2);

  // Clear empties the selection and hides the bar again.
  await page.locator('[data-active-list] li').first().getByRole('checkbox').check();
  await expect(bar).toBeVisible();
  await bar.getByRole('button', { name: 'Clear' }).click();
  await expect(bar).toBeHidden();

  // Without received files the tab still explains where they would appear.
  await receivedTab.click();
  await expect(page).toHaveURL(/\?tab=received/);
  await expect(page.locator('[data-received-empty]')).toContainText('Nothing received yet');
  await expect(page.locator('[data-upload-link]')).toContainText('/u/');
  await expect(page.locator('[data-received-badge]')).toHaveCount(0);
  await expect(page.getByRole('link', { name: /Show history/ })).toHaveAttribute('href', '/received/history');
});

test('received files get a new badge that clears after the tab was opened, and history keeps deleted ones', async ({ browser, page, request }, testInfo) => {
  test.setTimeout(180_000);
  const user = await createE2EUser(request, 'dashboard-received');
  await login(page, user.email, user.password);
  await page.goto('/account/settings');
  const code = (await page.locator('#uploadToken').inputValue()).trim();

  await receiveFile(browser, code, 'contract.txt', 'Maria Huber', 'Signed copy', testInfo.outputPath('received-files'));

  // The share is created in the background; wait until it shows up.
  const badge = page.locator('[data-received-badge]');
  await expect(async () => {
    await page.goto('/');
    await expect(badge).toHaveText('1 new', { timeout: 1000 });
  }).toPass({ timeout: 90_000 });
  await expect(page.getByRole('tab', { name: /My shares/ })).toHaveAttribute('aria-selected', 'true');

  // Opening the tab marks everything seen, but the markers stay for this page view.
  const seen = page.waitForResponse((response) => response.url().includes('/account/received-seen') && response.request().method() === 'POST');
  await page.getByRole('tab', { name: /Received/ }).click();
  expect((await seen).status()).toBe(204);
  await expect(page).toHaveURL(/\?tab=received/);
  const row = page.locator('[data-received-share]', { hasText: 'contract' });
  await expect(row).toBeVisible();
  await expect(row).toContainText('From Maria Huber');
  await expect(row).toContainText('sender@example.test');
  await expect(row).toContainText('1 file');
  await expect(row.locator('[data-received-new]')).toBeVisible();
  await expect(badge).toBeVisible();
  await expect(row.locator('[data-local-datetime]').first()).not.toHaveText('');
  await expect(page.locator('[data-upload-link]')).toContainText(`/u/${code}`);

  // The next load shows no badge and no marker, and keeps the Received tab.
  await page.reload();
  await expect(page.getByRole('tab', { name: /Received/ })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('[data-received-badge]')).toHaveCount(0);
  await expect(page.locator('[data-received-new]')).toHaveCount(0);

  // Row menu: Download opens the share page.
  const received = page.locator('[data-received-share]', { hasText: 'contract' });
  await received.getByRole('button', { name: /More actions/ }).click();
  await expect(received.getByRole('link', { name: 'Download' })).toHaveAttribute('href', /^\/s\/[A-Za-z0-9]+$/);
  await page.keyboard.press('Escape');

  // Batch delete from the Received tab returns to the same tab.
  const bar = page.locator('[data-batch-bar="received"]');
  await expect(bar).toBeHidden();
  await received.getByRole('checkbox').check();
  await expect(bar).toContainText('1 selected');
  await bar.getByRole('button', { name: /Batch actions/ }).click();
  await expect(bar.getByRole('button', { name: /Re-enable/ })).toHaveCount(0);
  await bar.getByRole('button', { name: 'Delete selected' }).click();
  await page.locator('[data-batch-delete-confirm]').click();
  await page.waitForURL(/tab=received/);
  await expect(page.getByRole('tab', { name: /Received/ })).toHaveAttribute('aria-selected', 'true');
  await expect(page.locator('[data-received-empty]')).toBeVisible();

  // History still lists it, as deleted and without actions.
  await page.getByRole('link', { name: /Show history/ }).click();
  await page.waitForURL(/\/received\/history/);
  const historyRow = page.locator('[data-history-row]', { hasText: 'contract' });
  await expect(historyRow).toBeVisible();
  await expect(historyRow.locator('[data-history-status]')).toHaveText('Deleted');
  await expect(historyRow).toContainText('Maria Huber');
  await expect(historyRow.getByRole('link', { name: 'Download' })).toHaveCount(0);
  await page.screenshot({ path: testInfo.outputPath('history.png'), fullPage: true });
});

test('opening the Received tab directly clears the badge, and history shows expired files without a download', async ({ browser, page, request }, testInfo) => {
  test.setTimeout(180_000);
  const user = await createE2EUser(request, 'dashboard-direct-received');
  await login(page, user.email, user.password);
  await page.goto('/account/settings');
  const code = (await page.locator('#uploadToken').inputValue()).trim();
  await receiveFile(browser, code, 'direct.txt', 'Peter Gruber', 'Hello', testInfo.outputPath('received-direct'));

  const badge = page.locator('[data-received-badge]');
  await expect(async () => {
    await page.goto('/');
    await expect(badge).toHaveText('1 new', { timeout: 1000 });
  }).toPass({ timeout: 90_000 });

  // A bookmark or redirect that lands on the tab sends the seen marker with the CSRF header (204, not 400).
  const seen = page.waitForResponse((response) => response.url().includes('/account/received-seen') && response.request().method() === 'POST');
  await page.goto('/?tab=received');
  expect((await seen).status()).toBe(204);
  await expect(page.locator('[data-received-new]')).toBeVisible();
  await page.reload();
  await expect(page.locator('[data-received-badge]')).toHaveCount(0);
  await expect(page.locator('[data-received-new]')).toHaveCount(0);

  // An expired received share stays in history, marked Expired and without Download.
  const href = await page.locator('[data-received-share]', { hasText: 'direct' }).locator('a[href^="/s/"]').getAttribute('href');
  const shareToken = (href ?? '').split('/').pop() ?? '';
  expect(shareToken).not.toBe('');
  await expire(request, shareToken);
  await page.goto('/received/history');
  const historyRow = page.locator('[data-history-row]', { hasText: 'direct' });
  await expect(historyRow.locator('[data-history-status]')).toHaveText('Expired');
  await expect(historyRow.getByRole('link', { name: 'Download' })).toHaveCount(0);
});
