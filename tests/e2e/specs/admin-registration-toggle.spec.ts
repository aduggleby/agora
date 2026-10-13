import { expect, test, type Page } from '@playwright/test';
import { createE2EUser, login } from '../support/helpers';

const formSelector = 'form[action="/admin/settings/registration"]';

function toggle(page: Page) {
  return page.locator('[data-registration-toggle]');
}

function status(page: Page) {
  return page.locator(`${formSelector} label > span`).last();
}

test.describe('Admin registration toggle', () => {
  test.afterEach(async ({ page }) => {
    // Registration is a global setting; leave it open for the specs that follow even if this one failed midway.
    await page.goto('/admin');
    if (await toggle(page).count() > 0 && !(await toggle(page).isChecked())) {
      await page.locator(`${formSelector} label`).click();
      await page.waitForURL(/\/admin\?msg=Registration%20enabled/);
    }
  });

  test('disables and re-enables registration from the admin page', async ({ page, request }) => {
    const admin = await createE2EUser(request, 'admin-toggle', 'admin');
    await login(page, admin.email, admin.password);

    await page.goto('/admin');
    await expect(toggle(page)).toBeChecked();
    await expect(status(page)).toHaveText('Open');

    await page.locator(`${formSelector} label`).click();
    await page.waitForURL(/\/admin\?msg=Registration%20disabled/);
    await expect(toggle(page)).not.toBeChecked();
    await expect(status(page)).toHaveText('Closed');
    const closed = await request.get('/register');
    expect(await closed.text()).toContain('Registration disabled');

    // The checkbox posts "false,true" (hidden fallback plus the box); the last value must win.
    await page.locator(`${formSelector} label`).click();
    await page.waitForURL(/\/admin\?msg=Registration%20enabled/);
    await expect(toggle(page)).toBeChecked();
    await expect(status(page)).toHaveText('Open');
    const open = await request.get('/register');
    expect(await open.text()).toContain('Create account');
  });
});
