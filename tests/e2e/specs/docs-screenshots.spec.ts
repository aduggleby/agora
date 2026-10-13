import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from '@playwright/test';
import type { Locator } from '@playwright/test';
import { createE2EUser, login } from '../support/helpers';

// Generates the documentation screenshots from realistic share flows so docs stay synchronized with the UI.
const screenshotFiles = {
  newShare: 'new-share-page.png',
  download: 'download-page.png',
  designer: 'landing-page-editor.png',
  password: 'new-share-password-option.png',
  gallery: 'account-password-settings.png',
  mixed: 'new-share-gallery-option.png',
  galleryReal: 'gallery-real-photos.png',
  filePreviewPdf: 'file-preview-sample-pdf.png'
};
let tokenCounter = 0;

async function writeSvgImage(filePath: string, index: number): Promise<void> {
  const hue = (index * 53) % 360;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="900"><defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="hsl(${hue} 70% 70%)"/><stop offset="100%" stop-color="hsl(${(hue + 48) % 360} 65% 55%)"/></linearGradient></defs><rect width="1200" height="900" fill="url(#g)"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" font-family="DM Sans, Arial, sans-serif" font-size="84" fill="rgba(255,255,255,0.9)">Image ${index + 1}</text></svg>`;
  await fs.writeFile(filePath, svg, 'utf8');
}

async function loadImageSamples(tempRoot: string, required: number): Promise<string[]> {
  const picturesRoot = path.join(os.homedir(), 'Pictures');
  const entries = await fs.readdir(picturesRoot, { withFileTypes: true }).catch(() => []);
  const pictureImages = entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(picturesRoot, entry.name))
    .filter((filePath) => /\.(jpg|jpeg|png|webp)$/i.test(filePath))
    .sort((a, b) => a.localeCompare(b));

  if (pictureImages.length >= required) {
    return pictureImages.slice(0, required);
  }

  const fallback: string[] = [...pictureImages];
  for (let i = fallback.length; i < required; i += 1) {
    const filePath = path.join(tempRoot, `image-${i + 1}.svg`);
    await writeSvgImage(filePath, i);
    fallback.push(filePath);
  }
  return fallback;
}

async function writePdf(filePath: string, label: string): Promise<void> {
  const stream = [
    '%PDF-1.4',
    '1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj',
    '2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj',
    '3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj',
    `4 0 obj << /Length 80 >> stream\nBT /F1 28 Tf 72 720 Td (${label}) Tj ET\nendstream endobj`,
    '5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj',
    'xref',
    '0 6',
    '0000000000 65535 f ',
    '0000000010 00000 n ',
    '0000000060 00000 n ',
    '0000000117 00000 n ',
    '0000000275 00000 n ',
    '0000000404 00000 n ',
    'trailer << /Root 1 0 R /Size 6 >>',
    'startxref',
    '490',
    '%%EOF'
  ].join('\n');
  await fs.writeFile(filePath, stream, 'utf8');
}

async function downloadSamplePdf(filePath: string): Promise<void> {
  const response = await fetch('https://pdfobject.com/pdf/sample.pdf');
  if (!response.ok) {
    throw new Error(`Failed to download sample PDF: ${response.status}`);
  }

  const bytes = Buffer.from(await response.arrayBuffer());
  await fs.writeFile(filePath, bytes);
}

async function createShareAndGetToken(
  page: Parameters<typeof test>[0]['page'],
  files: string[],
  options: { password?: string; showPreviews?: boolean }
): Promise<string> {
  await page.goto('/shares/new');
  await page.waitForSelector('[data-share-form]');

  const draftShareId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  if (!draftShareId) {
    throw new Error('Missing draftShareId');
  }

  const csrfToken = await page.evaluate(() => {
    const tokenCookie = document.cookie
      .split(';')
      .map((part) => part.trim())
      .find((part) => part.startsWith('agora.csrf.request='));
    return tokenCookie ? decodeURIComponent(tokenCookie.slice('agora.csrf.request='.length)) : '';
  });
  if (!csrfToken) {
    throw new Error('Missing CSRF token cookie');
  }

  const uploadIds: string[] = [];
  for (const filePath of files) {
    const fileName = path.basename(filePath);
    const buffer = await fs.readFile(filePath);
    const response = await page.request.post('/api/uploads/stage', {
      multipart: {
        __RequestVerificationToken: csrfToken,
        draftShareId,
        file: {
          name: fileName,
          mimeType: guessContentType(fileName),
          buffer
        }
      }
    });

    if (!response.ok()) {
      throw new Error(`Staging failed for ${fileName}: ${response.status()} ${await response.text()}`);
    }

    const payload = await response.json();
    uploadIds.push(String(payload.uploadId || ''));
  }

  tokenCounter += 1;
  const forcedToken = `docs${Date.now().toString(36)}${tokenCounter.toString(36)}`.slice(0, 24);
  const form = new URLSearchParams();
  form.append('__RequestVerificationToken', csrfToken);
  form.append('draftShareId', draftShareId);
  form.append('shareToken', forcedToken);
  form.append('notifyMode', 'none');
  form.append('expiryMode', '7_days');
  form.append('templateMode', 'account_default');
  if (options.password) {
    form.append('downloadPassword', options.password);
  }
  if (options.showPreviews) {
    form.append('showPreviews', '1');
  }
  for (const uploadId of uploadIds) {
    form.append('uploadedFileIds', uploadId);
  }

  const createResponse = await page.request.post('/api/shares', {
    data: form.toString(),
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded'
    }
  });
  if (!createResponse.ok()) {
    throw new Error(`Create share failed: ${createResponse.status()} ${await createResponse.text()}`);
  }

  return forcedToken;
}

async function openPublicShareAndWaitForSelector(
  page: Parameters<typeof test>[0]['page'],
  token: string,
  selector: string
): Promise<void> {
  await page.goto(`/s/${token}`, { waitUntil: 'domcontentloaded' });
  await page.waitForSelector(selector, { timeout: 45_000 });
}

async function waitForShareReady(page: Parameters<typeof test>[0]['page'], token: string): Promise<void> {
  for (let attempt = 0; attempt < 90; attempt += 1) {
    const response = await page.request.get(`/api/shares/${encodeURIComponent(token)}`);
    if (response.ok()) {
      return;
    }
    await page.waitForTimeout(1000);
  }
  throw new Error(`Timed out waiting for share ${token} to become available.`);
}

async function waitForMosaicPreviewsReady(page: Parameters<typeof test>[0]['page']): Promise<void> {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const allReady = await page.evaluate(async () => {
      const images = Array.from(document.querySelectorAll<HTMLImageElement>('.mosaic-grid img[data-preview-status-url]'));
      if (images.length === 0) {
        return false;
      }

      const checks = await Promise.all(images.map(async (image) => {
        const statusUrl = image.getAttribute('data-preview-status-url') || '';
        if (!statusUrl) {
          return false;
        }

        try {
          const response = await fetch(statusUrl, { credentials: 'same-origin', cache: 'no-store' });
          if (!response.ok) {
            return false;
          }

          const payload = await response.json() as { state?: string };
          return payload.state === 'ready';
        } catch {
          return false;
        }
      }));

      return checks.every(Boolean);
    });

    if (allReady) {
      return;
    }

    await page.waitForTimeout(1000);
  }

  throw new Error('Timed out waiting for mosaic previews to become ready.');
}

async function selectFileAndWaitForPreviewReady(
  page: Parameters<typeof test>[0]['page'],
  fileName: string
): Promise<void> {
  const target = page.locator('[data-preview-select]').filter({ hasText: fileName }).first();
  await target.click();
  await target.evaluate((element) => {
    element.dispatchEvent(new Event('click', { bubbles: true }));
  });

  await expectSelectedAndPreviewReady(page, target);
}

async function expectSelectedAndPreviewReady(
  page: Parameters<typeof test>[0]['page'],
  selectedItem: Locator
): Promise<void> {
  await selectedItem.waitFor({ state: 'visible', timeout: 30_000 });
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const ready = await selectedItem.evaluate(async (element) => {
      const item = element as HTMLElement;
      if (!item.classList.contains('active')) {
        return false;
      }

      const statusUrl = item.getAttribute('data-preview-status-url') || '';
      if (!statusUrl) {
        return false;
      }

      try {
        const response = await fetch(statusUrl, { credentials: 'same-origin', cache: 'no-store' });
        if (!response.ok) {
          return false;
        }

        const payload = await response.json() as { state?: string };
        if (payload.state !== 'ready') {
          return false;
        }
      } catch {
        return false;
      }

      const viewerImage = document.querySelector<HTMLImageElement>('[data-preview-viewer] img[data-preview-image]');
      return !!viewerImage && viewerImage.complete && viewerImage.naturalWidth > 0 && viewerImage.naturalHeight > 0;
    });

    if (ready) {
      return;
    }

    await page.waitForTimeout(1000);
  }

  throw new Error('Timed out waiting for selected file preview to become ready.');
}

function guessContentType(fileName: string): string {
  const ext = path.extname(fileName).toLowerCase();
  if (ext === '.svg') return 'image/svg+xml';
  if (ext === '.png') return 'image/png';
  if (ext === '.jpg' || ext === '.jpeg') return 'image/jpeg';
  if (ext === '.webp') return 'image/webp';
  if (ext === '.pdf') return 'application/pdf';
  if (ext === '.txt') return 'text/plain';
  return 'application/octet-stream';
}

test('remake docs screenshots', async ({ page, request }) => {
  test.setTimeout(10 * 60 * 1000);
  await page.setViewportSize({ width: 1000, height: 1000 });

  const user = await createE2EUser(request, 'docs-shots');
  await login(page, user.email, user.password);

  const tempRoot = await fs.mkdtemp(path.join(os.tmpdir(), 'agora-doc-shots-'));
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const docsRoot = path.resolve(thisDir, '../../..', 'docs', 'screenshots');

  const images = await loadImageSamples(tempRoot, 6);

  const textA = path.join(tempRoot, 'notes-a.txt');
  const textB = path.join(tempRoot, 'notes-b.txt');
  await fs.writeFile(textA, 'Mixed preview example text file A.\nLine two.', 'utf8');
  await fs.writeFile(textB, 'Mixed preview example text file B.\nLine two.', 'utf8');

  const pdfA = path.join(tempRoot, 'a-sample-pdf.pdf');
  const pdfB = path.join(tempRoot, 'brief-b.pdf');
  await downloadSamplePdf(pdfA);
  await writePdf(pdfB, 'PDF Example B');

  await page.goto('/shares/new');
  await page.waitForSelector('[data-share-form]');
  await page.click('[data-options-toggle]');
  await page.waitForSelector('[data-options-panel]:not(.hidden)');
  await page.screenshot({
    path: path.join(docsRoot, screenshotFiles.newShare)
  });

  const draftShareId = (await page.getAttribute('[data-draft-share-id]', 'value')) || '';
  if (!draftShareId) {
    throw new Error('Missing draftShareId on /shares/new');
  }

  await page.goto(`/share/landing-page-designer?draftShareId=${encodeURIComponent(draftShareId)}`);
  await page.waitForSelector('#share-template-form');
  await page.screenshot({
    path: path.join(docsRoot, screenshotFiles.designer)
  });

  const downloadToken = await createShareAndGetToken(page, [textA], {
    showPreviews: false
  });
  await waitForShareReady(page, downloadToken);
  await openPublicShareAndWaitForSelector(page, downloadToken, '[data-share-preview-card]');
  await page.screenshot({
    path: path.join(docsRoot, screenshotFiles.download)
  });

  const passwordToken = await createShareAndGetToken(page, [textA], {
    password: 'P@ssword123',
    showPreviews: false
  });
  await waitForShareReady(page, passwordToken);
  await openPublicShareAndWaitForSelector(page, passwordToken, '#download-password');
  await page.screenshot({
    path: path.join(docsRoot, screenshotFiles.password)
  });

  const galleryToken = await createShareAndGetToken(page, images, {
    showPreviews: true
  });
  await waitForShareReady(page, galleryToken);
  await openPublicShareAndWaitForSelector(page, galleryToken, '.mosaic-grid');
  await waitForMosaicPreviewsReady(page);
  await page.screenshot({
    path: path.join(docsRoot, screenshotFiles.gallery)
  });
  await page.screenshot({
    path: path.join(docsRoot, screenshotFiles.galleryReal)
  });

  const mixedToken = await createShareAndGetToken(page, [images[0], images[1], textA, textB, pdfA, pdfB], {
    showPreviews: true
  });
  await waitForShareReady(page, mixedToken);
  // The mixed-content screenshot should show a selected file preview in the browser pane.
  await openPublicShareAndWaitForSelector(page, mixedToken, '[data-file-browser]');
  await page.click('[data-preview-select]');
  await page.screenshot({
    path: path.join(docsRoot, screenshotFiles.mixed)
  });

  const filePreviewToken = await createShareAndGetToken(page, [images[0], images[1], textA, textB, pdfA, pdfB], {
    showPreviews: true
  });
  await waitForShareReady(page, filePreviewToken);
  await openPublicShareAndWaitForSelector(page, filePreviewToken, '[data-file-browser]');
  await selectFileAndWaitForPreviewReady(page, 'a-sample-pdf.pdf');
  await page.screenshot({
    path: path.join(docsRoot, screenshotFiles.filePreviewPdf)
  });
});
