import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from '@playwright/test';
import type { Locator } from '@playwright/test';
import { createE2EUser, login, writePngFile } from '../support/helpers';

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

async function writePlaceholderImage(filePath: string, index: number): Promise<void> {
  // SVG is no longer served inline (it is downloaded as an attachment), so fallbacks are solid-colour PNGs.
  const hue = (index * 53) % 360;
  await writePngFile(filePath, { width: 1200, height: 900, color: hslToRgb(hue, 0.7, 0.7) });
}

function hslToRgb(h: number, s: number, l: number): [number, number, number] {
  const k = (n: number) => (n + h / 30) % 12;
  const a = s * Math.min(l, 1 - l);
  const f = (n: number) => l - a * Math.max(-1, Math.min(k(n) - 3, Math.min(9 - k(n), 1)));
  return [Math.round(f(0) * 255), Math.round(f(8) * 255), Math.round(f(4) * 255)];
}

// Preview generation budgets (Agora__Previews__*): keep sample pictures well inside them so every preview becomes ready.
const MAX_SAMPLE_BYTES = 8 * 1024 * 1024;
const MAX_SAMPLE_PIXELS = 20_000_000;

/** Reads the pixel size from a PNG IHDR, a WEBP VP8/VP8L/VP8X header or a JPEG SOF marker; undefined when it cannot be determined. */
async function readImageDimensions(filePath: string): Promise<{ width: number; height: number } | undefined> {
  const handle = await fs.open(filePath, 'r');
  try {
    const head = Buffer.alloc(64 * 1024);
    const { bytesRead } = await handle.read(head, 0, head.length, 0);
    const bytes = head.subarray(0, bytesRead);
    if (bytes.length >= 24 && bytes.toString('ascii', 1, 4) === 'PNG') {
      return { width: bytes.readUInt32BE(16), height: bytes.readUInt32BE(20) };
    }
    if (bytes.length >= 30 && bytes.toString('ascii', 0, 4) === 'RIFF' && bytes.toString('ascii', 8, 12) === 'WEBP') {
      const chunk = bytes.toString('ascii', 12, 16);
      if (chunk === 'VP8 ' && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a) {
        return { width: bytes.readUInt16LE(26) & 0x3fff, height: bytes.readUInt16LE(28) & 0x3fff };
      }
      if (chunk === 'VP8L' && bytes[20] === 0x2f) {
        const bits = bytes.readUInt32LE(21);
        return { width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
      }
      if (chunk === 'VP8X') {
        return { width: bytes.readUIntLE(24, 3) + 1, height: bytes.readUIntLE(27, 3) + 1 };
      }
      return undefined;
    }
    if (bytes.length >= 4 && bytes[0] === 0xff && bytes[1] === 0xd8) {
      let offset = 2;
      while (offset + 9 < bytes.length) {
        if (bytes[offset] !== 0xff) {
          offset += 1;
          continue;
        }
        const marker = bytes[offset + 1];
        const length = bytes.readUInt16BE(offset + 2);
        const isSof = marker >= 0xc0 && marker <= 0xcf && marker !== 0xc4 && marker !== 0xc8 && marker !== 0xcc;
        if (isSof) {
          return { height: bytes.readUInt16BE(offset + 5), width: bytes.readUInt16BE(offset + 7) };
        }
        offset += 2 + length;
      }
    }
    return undefined;
  } finally {
    await handle.close();
  }
}

async function isWithinPreviewBudget(filePath: string): Promise<boolean> {
  const stat = await fs.stat(filePath).catch(() => undefined);
  if (!stat || stat.size > MAX_SAMPLE_BYTES) {
    return false;
  }
  const dimensions = await readImageDimensions(filePath).catch(() => undefined);
  // Files whose size cannot be verified from the header are skipped, never trusted.
  return dimensions !== undefined && dimensions.width > 0 && dimensions.height > 0
    && dimensions.width * dimensions.height <= MAX_SAMPLE_PIXELS;
}

async function loadImageSamples(tempRoot: string, required: number): Promise<string[]> {
  const picturesRoot = path.join(os.homedir(), 'Pictures');
  const entries = await fs.readdir(picturesRoot, { withFileTypes: true }).catch(() => []);
  const candidates = entries
    .filter((entry) => entry.isFile())
    .map((entry) => path.join(picturesRoot, entry.name))
    .filter((filePath) => /\.(jpg|jpeg|png|webp)$/i.test(filePath))
    .sort((a, b) => a.localeCompare(b));
  const pictureImages: string[] = [];
  for (const filePath of candidates) {
    if (pictureImages.length >= required) {
      break;
    }
    if (await isWithinPreviewBudget(filePath)) {
      pictureImages.push(filePath);
    }
  }

  if (pictureImages.length >= required) {
    return pictureImages.slice(0, required);
  }

  const fallback: string[] = [...pictureImages];
  for (let i = fallback.length; i < required; i += 1) {
    const filePath = path.join(tempRoot, `image-${i + 1}.png`);
    await writePlaceholderImage(filePath, i);
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
