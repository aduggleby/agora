import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

async function exists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}

export default async function globalSetup() {
  const thisDir = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(thisDir, '../../..');
  const dataRoot = path.join(repoRoot, '.e2e-data');

  if (await exists(dataRoot)) {
    await fs.rm(dataRoot, { recursive: true, force: true });
  }

  await fs.mkdir(path.join(dataRoot, 'storage'), { recursive: true });
  await fs.mkdir(path.join(dataRoot, 'emails'), { recursive: true });
  await fs.mkdir(path.join(dataRoot, 'logs'), { recursive: true });
}
