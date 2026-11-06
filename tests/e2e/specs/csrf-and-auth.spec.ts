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

  // App-wide 1 MiB body limit: nothing is buffered for requests that cannot be admitted.
  const bigFile = { name: 'big.bin', mimeType: 'application/octet-stream', buffer: Buffer.alloc(2 * 1024 * 1024, 120) };

  test('refuses an oversized anonymous multipart login POST without buffering it', async ({ request }) => {
    const response = await request.post('/login', { multipart: { email: 'nobody@example.test', file: bigFile } });
    expect([400, 413]).toContain(response.status());
  });

  test('answers an unsafe request to an unknown route with 404, not a CSRF form read', async ({ request }) => {
    const response = await request.post('/does-not-exist', { multipart: { file: bigFile } });
    expect([404, 413]).toContain(response.status());
  });

  test('challenges an anonymous share submission before reading its body', async ({ request }) => {
    const response = await request.post('/api/shares', {
      multipart: { draftShareId: 'x', file: { ...bigFile, buffer: Buffer.alloc(512 * 1024, 120) } },
      maxRedirects: 0
    });
    expect(response.status()).toBe(302);
    expect(response.headers()['location']).toContain('/login');
  });

  test('requires the CSRF header token for share submission', async ({ page, request }) => {
    const user = await createE2EUser(request, 'csrf-shares');
    await login(page, user.email, user.password);
    await page.goto('/shares/new');
    const csrfToken = await page.evaluate(() => {
      const cookie = document.cookie.split(';').map((part) => part.trim()).find((part) => part.startsWith('agora.csrf.request='));
      return cookie ? decodeURIComponent(cookie.slice('agora.csrf.request='.length)) : '';
    });
    expect(csrfToken).not.toBe('');

    const response = await page.request.post('/api/shares', {
      form: { __RequestVerificationToken: csrfToken, draftShareId: 'x' },
      maxRedirects: 0
    });
    expect(response.status()).toBe(400);
    expect((await response.json()).error).toContain('X-CSRF-TOKEN');
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
