import { defineConfig } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(thisDir, '../..');
const runId = process.env.PLAYWRIGHT_E2E_RUN_ID ?? `${Date.now()}`;
const dataRoot = path.join(repoRoot, '.e2e-data', 'runs', runId);
const sqlContainerName = `agora-e2e-sql-${runId}`;
const sqlPort = Number.parseInt(process.env.PLAYWRIGHT_E2E_SQL_PORT ?? '18091', 10);
const sqlPassword = process.env.PLAYWRIGHT_E2E_SQL_PASSWORD ?? 'AgoraE2E!Passw0rd';
process.env.PLAYWRIGHT_E2E_SQL_CONTAINER_NAME = sqlContainerName;

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
      PLAYWRIGHT_E2E_SQL_CONTAINER_NAME: sqlContainerName,
      PLAYWRIGHT_E2E_SQL_PORT: sqlPort.toString(),
      PLAYWRIGHT_E2E_SQL_PASSWORD: sqlPassword,
      ConnectionStrings__Default: `Server=127.0.0.1,${sqlPort};Database=agora_e2e;User Id=sa;Password=${sqlPassword};Encrypt=True;TrustServerCertificate=True`,
      Agora__StorageRoot: path.join(dataRoot, 'storage'),
      Email__Provider: 'filesystem',
      Email__FileSystem__OutputDirectory: path.join(dataRoot, 'emails'),
      Serilog__WriteTo__0__Args__path: path.join(dataRoot, 'logs', 'agora-.log')
    }
  },
  globalSetup: './support/global-setup.ts'
});
