import { execFile } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

async function countLocalFiles(dir: string): Promise<number> {
  try {
    const entries = await fs.readdir(dir, { recursive: true, withFileTypes: true });
    return entries.filter((entry) => entry.isFile()).length;
  } catch {
    return 0;
  }
}

async function countBucketObjects(container: string, bucket: string, prefix: string): Promise<number> {
  const { stdout } = await execFileAsync('docker', ['exec', container, 'mc', 'ls', '--recursive', `local/${bucket}/${prefix}`]);
  return stdout.split('\n').filter((line) => line.trim().length > 0).length;
}

/**
 * S3 leg: proves durable content went to MinIO, not to local disk (StorageRoot must hold no shares/zips/previews).
 * Returns a failure message, or null.
 */
async function verifyS3Storage(container: string): Promise<string | null> {
  const bucket = process.env.PLAYWRIGHT_E2E_MINIO_BUCKET ?? 'agora-e2e';
  const storageRoot = process.env.PLAYWRIGHT_E2E_STORAGE_ROOT ?? '';
  const bucketCounts: Record<string, number> = {};
  const localCounts: Record<string, number> = {};
  for (const area of ['shares', 'zips', 'previews', 'uploads/templates']) {
    bucketCounts[area] = await countBucketObjects(container, bucket, `${area}/`);
    localCounts[area] = await countLocalFiles(path.join(storageRoot, area));
  }

  // Preview .lock/.failed markers are local scratch by design; anything else under previews/ would be a leak.
  const localPreviewImages = (await fs.readdir(path.join(storageRoot, 'previews'), { recursive: true }).catch(() => []))
    .filter((name) => String(name).endsWith('.jpg')).length;
  localCounts.previews = localPreviewImages;

  console.log(`[e2e storage] MinIO objects: ${JSON.stringify(bucketCounts)}; local StorageRoot files: ${JSON.stringify(localCounts)}`);
  if (bucketCounts.shares === 0 || bucketCounts.zips === 0) {
    return 'expected share files and archives in MinIO';
  }

  const leaked = Object.entries(localCounts).filter(([, count]) => count > 0);
  return leaked.length > 0 ? `durable content written to local disk: ${JSON.stringify(Object.fromEntries(leaked))}` : null;
}

export default async function globalTeardown() {
  const minioContainer = process.env.PLAYWRIGHT_E2E_MINIO_CONTAINER_NAME;
  let failure: string | null = null;
  if (minioContainer) {
    try {
      failure = await verifyS3Storage(minioContainer);
    } catch (error) {
      failure = `could not verify MinIO contents: ${error}`;
    }
  }

  // Remove only this run's containers (database per PLAYWRIGHT_E2E_DB, MinIO for the s3 leg).
  for (const containerName of [process.env.PLAYWRIGHT_E2E_SQL_CONTAINER_NAME, minioContainer]) {
    if (!containerName) {
      continue;
    }

    try {
      await execFileAsync('docker', ['rm', '-f', containerName]);
    } catch {
      // No-op when container does not exist.
    }
  }

  if (failure) {
    throw new Error(`[e2e storage] ${failure}`);
  }
}
