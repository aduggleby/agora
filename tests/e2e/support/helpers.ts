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
  await page.goto('/login');
  await page.locator('input[name="email"]').fill(email);
  await page.locator('input[name="password"]').fill(password);
  await page.locator('form[action="/login"] button[type="submit"]').click();
  await page.waitForURL('/');
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
