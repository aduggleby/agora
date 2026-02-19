import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export default async function globalTeardown() {
  const containerName = process.env.PLAYWRIGHT_E2E_SQL_CONTAINER_NAME;
  if (!containerName) {
    return;
  }

  try {
    await execFileAsync('docker', ['rm', '-f', containerName]);
  } catch {
    // No-op when container does not exist.
  }
}
