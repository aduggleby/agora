import { expect, test } from '@playwright/test';
import { createE2EUser, login } from '../support/helpers';

test.describe('CSRF and auth', () => {
  test('rejects direct login POST without CSRF token', async ({ request }) => {
    const response = await request.post('/login', {
      form: {
        email: 'nobody@example.test',
        password: 'invalid'
      }
    });

    expect(response.status()).toBe(400);
    const json = await response.json();
    expect(json.error).toContain('CSRF token');
  });

  test('injects CSRF token into login form and authenticates successfully', async ({ page, request }) => {
    const user = await createE2EUser(request, 'csrf-login');

    await login(page, user.email, user.password);
    await expect(page).toHaveURL('/');
  });

  test('rejects direct logout POST without token but allows UI logout form submit', async ({ page, request }) => {
    const user = await createE2EUser(request, 'csrf-logout');
    await login(page, user.email, user.password);

    const badLogout = await page.request.post('/logout');
    expect(badLogout.status()).toBe(400);

    await page.locator('header details summary').click();
    await page.locator('form[action="/logout"] button[type="submit"]').click();
    await expect(page).toHaveURL(/\/login\?msg=Signed%20out/);
  });
});
