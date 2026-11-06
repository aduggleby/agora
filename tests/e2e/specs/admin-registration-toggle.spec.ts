import { expect, test, type Page } from '@playwright/test';
import { confirmEmailWithPassword, createE2EUser, login, waitForEmailActionUrl } from '../support/helpers';

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

// In this file so it never runs while the toggle test has registration closed (files run in parallel).
test.describe('Registration', () => {
  test('confirming a registration requires the account password', async ({ page }) => {
    const email = `confirm-${Date.now()}@example.test`;
    const password = 'Confirm-Passw0rd!';
    await page.goto('/register');
    const form = page.locator('form[action="/register"]');
    await form.locator('input[name="email"]').fill(email);
    await form.locator('input[name="password"]').fill(password);
    await form.locator('button[type="submit"]').click();
    await expect(page).toHaveURL(/\/login\?msg=Check%20your%20email/);

    const confirmUrl = await waitForEmailActionUrl(email, '/auth/confirm-email');
    await page.goto(confirmUrl);
    const passwordInput = page.locator('input[name="password"]');
    await expect(passwordInput).toHaveAttribute('autocomplete', 'current-password');

    // A wrong password keeps the link on screen and usable.
    await confirmEmailWithPassword(page, confirmUrl, 'not-the-password');
    await expect(page.locator('[data-confirm-error]')).toContainText("That password doesn't match this registration");
    await expect(page.locator('input[name="token"]')).toHaveCount(1);

    await page.locator('input[name="password"]').fill(password);
    await page.locator('form').filter({ has: page.locator('input[name="token"]') }).locator('button[type="submit"]').click();
    await expect(page).toHaveURL(/\/login\?msg=Email%20confirmed/);

    await login(page, email, password);
    await expect(page).toHaveURL('/');
  });
});
