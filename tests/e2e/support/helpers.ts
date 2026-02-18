import fs from 'node:fs/promises';
import path from 'node:path';
import type { APIRequestContext, Page } from '@playwright/test';

export async function createE2EUser(request: APIRequestContext, suffix: string) {
  const email = `e2e-${suffix}-${Date.now()}@example.test`;
  const response = await request.post('/api/e2e/users', {
    form: {
      email,
      password: 'P@ssw0rd!123'
    }
  });

  if (!response.ok()) {
    throw new Error(`Failed to create e2e user: ${response.status()} ${await response.text()}`);
  }

  const json = await response.json();
  return {
    email: json.email as string,
    password: json.password as string,
  };
}

export async function login(page: Page, email: string, password: string) {
  const targetUrl = /\/($|dashboard|shares\/new(\?.*)?)/;

  for (let attempt = 1; attempt <= 3; attempt += 1) {
    await page.goto('/login');
    const loginForm = page.locator('form[action="/login"]').first();
    await loginForm.locator('input[name="email"]').fill(email);
    await loginForm.locator('input[name="password"]').fill(password);

    await page.evaluate(() => {
      const form = document.querySelector('form[action="/login"]');
      if (!form) return;
      const parts = document.cookie ? document.cookie.split(';') : [];
      const tokenCookie = parts
        .map((x) => x.trim())
        .find((x) => x.startsWith('agora.csrf.request='));
      if (!tokenCookie) return;
      const token = decodeURIComponent(tokenCookie.slice('agora.csrf.request='.length));
      let input = form.querySelector('input[name="__RequestVerificationToken"]') as HTMLInputElement | null;
      if (!input) {
        input = document.createElement('input');
        input.type = 'hidden';
        input.name = '__RequestVerificationToken';
        form.appendChild(input);
      }
      input.value = token;
    });

    await loginForm.locator('button[type="submit"]').click();

    try {
      await page.waitForURL(targetUrl, { timeout: 12_000 });
      return;
    } catch {
      if (attempt === 3) {
        throw new Error('Login did not complete after 3 attempts.');
      }
    }
  }
}

export async function createTempFiles(baseDir: string, files: Array<{ name: string; content: string }>) {
  await fs.mkdir(baseDir, { recursive: true });
  const paths: string[] = [];
  for (const file of files) {
    const filePath = path.join(baseDir, file.name);
    await fs.writeFile(filePath, file.content, 'utf8');
    paths.push(filePath);
  }
  return paths;
}

export function extractShareUrl(text: string): string {
  const match = text.match(/https?:\/\/[^\s]+\/s\/[A-Za-z0-9_-]+/);
  if (!match) {
    throw new Error(`Could not find share URL in text: ${text}`);
  }
  return match[0];
}

export function tokenFromShareUrl(shareUrl: string): string {
  const parsed = new URL(shareUrl);
  const parts = parsed.pathname.split('/').filter(Boolean);
  const token = parts[1];
  if (!token) {
    throw new Error(`Invalid share URL: ${shareUrl}`);
  }
  return token;
}
