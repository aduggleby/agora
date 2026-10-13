import { expect, test } from '@playwright/test';
import { createE2EUser, login } from '../support/helpers';

test('new share options toggle expands/collapses and persists in localStorage', async ({ page, request }) => {
  const user = await createE2EUser(request, 'options-toggle');
  await login(page, user.email, user.password);

  await page.goto('/shares/new');
  const panel = page.locator('[data-options-panel]');
  const toggle = page.locator('[data-options-toggle]');

  await expect(panel).toBeHidden();
  await toggle.click();
  await expect(panel).toBeVisible();

  await page.reload();
  await expect(panel).toBeVisible();

  await toggle.click();
  await expect(panel).toBeHidden();

  await page.reload();
  await expect(panel).toBeHidden();
});
