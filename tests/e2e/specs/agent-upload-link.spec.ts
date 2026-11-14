import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { expect, test } from '@playwright/test';
import type { APIRequestContext, Page } from '@playwright/test';
import { createE2EUser, createTempFiles, login } from '../support/helpers';
import { callAnonymousTool } from '../support/mcp-anon';

type FileSystemEmailRecord = { to?: string; subject?: string; html?: string };

const DISABLED_MESSAGE = 'The owner of this upload link does not accept uploads from AI agents.';

async function uploadCodeFromSettings(page: Page): Promise<string> {
  await page.goto('/account/settings');
  return (await page.locator('#uploadToken').inputValue()).trim();
}

async function latestEmailDirectory(): Promise<string> {
  const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../..');
  const runsRoot = path.join(repoRoot, '.e2e-data', 'runs');
  const runs = await fs.readdir(runsRoot, { withFileTypes: true }).catch(() => []);
  const candidates: Array<{ dir: string; mtimeMs: number }> = [];
  for (const entry of runs) {
    if (!entry.isDirectory()) continue;
    const dir = path.join(runsRoot, entry.name, 'emails');
    const stats = await fs.stat(dir).catch(() => null);
    if (stats?.isDirectory()) candidates.push({ dir, mtimeMs: stats.mtimeMs });
  }
  if (candidates.length === 0) throw new Error(`No email output directories under ${runsRoot}`);
  candidates.sort((a, b) => b.mtimeMs - a.mtimeMs);
  return candidates[0].dir;
}

/** The newest dev-sink email to `to` with `subject` written after `since`, optionally containing `contains`. */
async function waitForEmail(to: string, subject: string, since: number, contains?: string): Promise<FileSystemEmailRecord> {
  const dir = await latestEmailDirectory();
  while (Date.now() - since < 90_000) {
    for (const name of (await fs.readdir(dir).catch(() => [])).filter((x) => x.endsWith('.json'))) {
      const full = path.join(dir, name);
      const stats = await fs.stat(full);
      if (stats.mtimeMs < since - 2000) continue;
      const record = JSON.parse(await fs.readFile(full, 'utf8')) as FileSystemEmailRecord;
      if (record.to === to && record.subject === subject && (!contains || (record.html ?? '').includes(contains))) {
        return record;
      }
    }
    await new Promise((resolve) => setTimeout(resolve, 1000));
  }
  throw new Error(`Timed out waiting for the "${subject}" email to ${to}.`);
}

async function setAgentSwitch(page: Page, on: boolean): Promise<void> {
  await page.goto('/account/settings');
  const toggle = page.locator('[data-allow-agent-uploads]');
  await toggle.setChecked(on);
  await page.locator('[data-agent-uploads-form] button[type="submit"]').click();
  await page.waitForURL(/\/account\/settings/);
  await expect(page.locator('[data-allow-agent-uploads]')).toBeChecked({ checked: on });
}

/** Steps of the curl recipe in llms.txt, done with Playwright's request context. */
async function sendByRecipe(request: APIRequestContext, code: string, fileName: string, content: Buffer, sender: Record<string, string>) {
  const issued = await request.post(`/api/v1/upload-links/${code}/upload-urls`, { data: { fileName, sizeBytes: content.length } });
  expect(issued.status()).toBe(201);
  const { draftId, uploadUrl } = (await issued.json()) as { draftId: string; uploadUrl: string };
  const uploadPath = new URL(uploadUrl).pathname;

  const put = await request.put(uploadPath, { data: content, headers: { 'Content-Type': 'application/octet-stream' } });
  expect(put.status()).toBe(201);
  // AE6: the URL is single use.
  expect((await request.put(uploadPath, { data: content, headers: { 'Content-Type': 'application/octet-stream' } })).status()).toBe(404);

  return request.post(`/api/v1/upload-links/${code}/send`, { data: { draftId, ...sender } });
}

test.describe('Agent upload link', () => {
  test('agents are refused while the switch is off, served once it is on, and cut off when the code is regenerated', async ({ browser, page, request }, testInfo) => {
    test.setTimeout(240_000);
    const user = await createE2EUser(request, 'agent-upload-link');
    await login(page, user.email, user.password);
    const code = await uploadCodeFromSettings(page);
    await expect(page.locator('[data-allow-agent-uploads]')).not.toBeChecked();

    // ---- switch off (AE4) ----
    const anon = await browser.newPage();
    await anon.goto(`/u/${code}`);
    await expect(anon.locator('[data-public-upload-form]')).toBeVisible();
    await expect(anon.locator('[data-agent-instructions-hint]')).toHaveCount(0);
    await expect(anon.locator('link[rel="alternate"][type="text/markdown"]')).toHaveCount(0);
    expect((await request.get(`/u/${code}/llms.txt`)).status()).toBe(404);

    const refusedHttp = await request.post(`/api/v1/upload-links/${code}/send`, {
      data: { files: [{ fileName: 'a.txt', text: 'a' }], senderName: 'Bot', senderEmail: 'bot@example.test' },
    });
    expect(refusedHttp.status()).toBe(403);
    expect((await refusedHttp.json()).error).toContain(DISABLED_MESSAGE);
    expect((await refusedHttp.json()).error).toContain(`/u/${code} in a browser.`);
    const refusedMcp = await callAnonymousTool(request, code, 'send_files', {
      sender_name: 'Bot', sender_email: 'bot@example.test', files: [{ file_name: 'a.txt', text: 'a' }],
    });
    expect(refusedMcp.isError).toBe(true);
    expect(refusedMcp.text).toContain(`Refused (403): ${DISABLED_MESSAGE}`);

    // The browser form on the same page still delivers.
    const files = await createTempFiles(testInfo.outputPath('agent-link-files'), [{ name: 'browser.txt', content: 'from a browser' }]);
    const browserStart = Date.now();
    await anon.locator('input[name="senderName"]').fill('Browser Person');
    await anon.locator('input[name="senderEmail"]').fill('person@example.test');
    await anon.setInputFiles('[data-public-file-input]', files);
    await anon.locator('[data-public-submit]').click();
    await anon.waitForURL(/\/u\/[A-Za-z0-9]{2,64}\?submitted=1/);
    const browserEmail = await waitForEmail(user.email, 'Files were sent to you and processed', browserStart);
    expect(browserEmail.html).toContain('Browser Person');
    await anon.close();

    // ---- switch on in Settings ----
    await setAgentSwitch(page, true);
    await expect(page.locator('[data-agent-instructions-url]')).toContainText(`/u/${code}/llms.txt`);

    const hinted = await browser.newPage();
    await hinted.goto(`/u/${code}`);
    await expect(hinted.locator('[data-agent-instructions-hint] a')).toHaveAttribute('href', `/u/${code}/llms.txt`);
    await expect(hinted.locator('link[rel="alternate"][type="text/markdown"]')).toHaveAttribute('href', `/u/${code}/llms.txt`);
    await hinted.close();

    const instructions = await request.get(`/u/${code}/llms.txt`);
    expect(instructions.status()).toBe(200);
    expect(instructions.headers()['content-type']).toContain('text/markdown');
    expect(instructions.headers()['cache-control']).toContain('no-store');
    const text = await instructions.text();
    expect(text).toContain(`/mcp?upload=${code}`);
    expect(text).toContain('curl');
    expect(text).toContain('/upload-urls');
    expect(text).toContain('/send');

    // ---- the curl recipe (AE6, AE3) ----
    const recipeStart = Date.now();
    const sent = await sendByRecipe(request, code, 'report.txt', Buffer.from('quarterly numbers'), {
      senderName: 'Recipe Bot', senderEmail: 'recipe@example.test', message: 'Sent by the recipe',
    });
    expect(sent.status()).toBe(202);
    expect(await sent.json()).toEqual({ state: 'queued' });

    const agentEmail = await waitForEmail(user.email, 'Files were sent to you by an AI agent', recipeStart, 'Recipe Bot');
    expect(agentEmail.html).toContain('recipe@example.test');
    expect(agentEmail.html).toContain('Sent by the recipe');
    expect(agentEmail.html).toMatch(/agent interface/);

    await page.goto('/');
    const recipeRow = page.locator('tr', { hasText: 'Recipe Bot' });
    await expect(recipeRow.locator('span[data-share-sent-by-agent]')).toHaveText('Agent');
    await recipeRow.locator('[data-share-details-trigger]').click();
    await expect(page.locator('[data-share-details-sent-by-agent]')).toHaveText('Sent through the agent interface');
    await expect(page.locator('[data-share-details-sender-message]')).toContainText('Sent by the recipe');
    await page.keyboard.press('Escape');

    // ---- inline MCP send_files ----
    const mcpStart = Date.now();
    const mcp = await callAnonymousTool(request, code, 'send_files', {
      sender_name: 'MCP Bot', sender_email: 'mcp@example.test', message: 'Sent through MCP',
      files: [{ file_name: 'notes.txt', text: 'inline notes' }],
    });
    expect(mcp.isError).toBe(false);
    expect(mcp.structured).toEqual({ state: 'queued' });
    const mcpEmail = await waitForEmail(user.email, 'Files were sent to you by an AI agent', mcpStart, 'MCP Bot');
    expect(mcpEmail.html).toContain('Sent through MCP');
    await page.goto('/');
    const mcpRow = page.locator('tr', { hasText: 'MCP Bot' });
    await expect(mcpRow.locator('span[data-share-sent-by-agent]')).toHaveText('Agent');

    // ---- regenerating the code ends the old one (R17) ----
    await page.goto('/account/settings');
    await page.getByRole('button', { name: 'Regenerate random code' }).click();
    await page.waitForURL(/\/account\/settings/);
    expect(await uploadCodeFromSettings(page)).not.toBe(code);

    expect((await request.get(`/u/${code}/llms.txt`)).status()).toBe(404);
    const oldSend = await request.post(`/api/v1/upload-links/${code}/send`, {
      data: { files: [{ fileName: 'a.txt', text: 'a' }], senderName: 'Bot', senderEmail: 'bot@example.test' },
    });
    expect(oldSend.status()).toBe(404);
    expect((await oldSend.json()).error).toBe('Upload link not found.');
    const oldMcp = await callAnonymousTool(request, code, 'get_upload_url', { file_name: 'a.txt', size_bytes: 1 });
    expect(oldMcp.isError).toBe(true);
    expect(oldMcp.text).toBe('Refused (404): Upload link not found.');
  });
});
