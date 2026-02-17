import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export default async function globalSetup() {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(thisDir, '../../..');
  const dataRoot = process.env.PLAYWRIGHT_E2E_DATA_ROOT || path.join(repoRoot, '.e2e-data');

  await fs.mkdir(path.join(dataRoot, 'storage'), { recursive: true });
  await fs.mkdir(path.join(dataRoot, 'emails'), { recursive: true });
  await fs.mkdir(path.join(dataRoot, 'logs'), { recursive: true });
}
