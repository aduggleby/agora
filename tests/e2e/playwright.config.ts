import { defineConfig } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(thisDir, '../..');
const runId = process.env.PLAYWRIGHT_E2E_RUN_ID ?? `${Date.now()}`;
const dataRoot = path.join(repoRoot, '.e2e-data', 'runs', runId);
// PLAYWRIGHT_E2E_DB=sqlserver (default) | postgres selects the dedicated E2E database container.
const dbKind = (process.env.PLAYWRIGHT_E2E_DB ?? 'sqlserver').toLowerCase();
if (dbKind !== 'sqlserver' && dbKind !== 'postgres') {
  throw new Error(`PLAYWRIGHT_E2E_DB must be 'sqlserver' or 'postgres' (got '${dbKind}').`);
}
const isPostgres = dbKind === 'postgres';
const sqlContainerName = isPostgres ? `agora-e2e-pg-${runId}` : `agora-e2e-sql-${runId}`;
const sqlPort = Number.parseInt(process.env.PLAYWRIGHT_E2E_SQL_PORT ?? (isPostgres ? '18092' : '18091'), 10);
const sqlPassword = process.env.PLAYWRIGHT_E2E_SQL_PASSWORD ?? 'AgoraE2E!Passw0rd';
const connectionString = isPostgres
  ? `Host=127.0.0.1;Port=${sqlPort};Database=agora_e2e;Username=postgres;Password=${sqlPassword};GSS Encryption Mode=Disable`
  : `Server=127.0.0.1,${sqlPort};Database=agora_e2e;User Id=sa;Password=${sqlPassword};Encrypt=True;TrustServerCertificate=True`;
process.env.PLAYWRIGHT_E2E_SQL_CONTAINER_NAME = sqlContainerName;
// PLAYWRIGHT_E2E_STORAGE=filesystem (default) | s3 selects the object store; s3 runs a dedicated MinIO container.
const storageKind = (process.env.PLAYWRIGHT_E2E_STORAGE ?? 'filesystem').toLowerCase();
if (storageKind !== 'filesystem' && storageKind !== 's3') {
  throw new Error(`PLAYWRIGHT_E2E_STORAGE must be 'filesystem' or 's3' (got '${storageKind}').`);
}
const isS3 = storageKind === 's3';
const minioContainerName = isS3 ? `agora-e2e-minio-${runId}` : '';
const minioPort = Number.parseInt(process.env.PLAYWRIGHT_E2E_MINIO_PORT ?? '18093', 10);
const minioUser = 'agora-e2e';
const minioPassword = 'AgoraE2E-Minio-Passw0rd';
const minioBucket = 'agora-e2e';
const storageRoot = path.join(dataRoot, 'storage');
process.env.PLAYWRIGHT_E2E_STORAGE = storageKind;
process.env.PLAYWRIGHT_E2E_MINIO_CONTAINER_NAME = minioContainerName;
process.env.PLAYWRIGHT_E2E_MINIO_BUCKET = minioBucket;
process.env.PLAYWRIGHT_E2E_STORAGE_ROOT = storageRoot;
const storageEnv: Record<string, string> = isS3
  ? {
      Storage__Provider: 'S3',
      Storage__S3__ServiceUrl: `http://127.0.0.1:${minioPort}`,
      Storage__S3__Region: 'us-east-1',
      Storage__S3__Bucket: minioBucket,
      Storage__S3__AccessKeyId: minioUser,
      Storage__S3__SecretAccessKey: minioPassword,
      Storage__S3__ForcePathStyle: 'true',
    }
  : { Storage__Provider: 'FileSystem' };

export default defineConfig({
  testDir: './specs',
  fullyParallel: false,
  retries: 0,
  timeout: 90_000,
  expect: {
    timeout: 10_000,
  },
  reporter: [['list'], ['html', { open: 'never' }]],
  globalTeardown: './support/global-teardown.ts',
  use: {
    baseURL: 'http://127.0.0.1:18090',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: {
    command: 'bash ./tests/e2e/support/start-e2e-server.sh',
    cwd: repoRoot,
    port: 18090,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      PLAYWRIGHT_E2E_DATA_ROOT: dataRoot,
      ASPNETCORE_ENVIRONMENT: 'E2E',
      AGORA_E2E: '1',
      PLAYWRIGHT_E2E_DB: dbKind,
      PLAYWRIGHT_E2E_SQL_CONTAINER_NAME: sqlContainerName,
      PLAYWRIGHT_E2E_SQL_PORT: sqlPort.toString(),
      PLAYWRIGHT_E2E_SQL_PASSWORD: sqlPassword,
      Database__Provider: isPostgres ? 'Postgres' : 'SqlServer',
      ConnectionStrings__Default: connectionString,
      PLAYWRIGHT_E2E_STORAGE: storageKind,
      PLAYWRIGHT_E2E_MINIO_CONTAINER_NAME: minioContainerName,
      PLAYWRIGHT_E2E_MINIO_PORT: minioPort.toString(),
      PLAYWRIGHT_E2E_MINIO_USER: minioUser,
      PLAYWRIGHT_E2E_MINIO_PASSWORD: minioPassword,
      PLAYWRIGHT_E2E_MINIO_BUCKET: minioBucket,
      ...storageEnv,
      Agora__StorageRoot: storageRoot,
      // Revalidate the sign-in cookie against the database on every request so the suite exercises that path.
      Agora__Auth__SessionRevalidationMinutes: '0',
      Email__Provider: 'filesystem',
      Email__FileSystem__OutputDirectory: path.join(dataRoot, 'emails'),
      Agora__Logging__File__Path: path.join(dataRoot, 'logs')
    }
  },
  globalSetup: './support/global-setup.ts'
});
