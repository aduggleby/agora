import { defineConfig } from '@playwright/test';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const thisDir = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(thisDir, '../..');
const dataRoot = path.join(repoRoot, '.e2e-data');

export default defineConfig({
  testDir: './specs',
  fullyParallel: false,
  retries: 0,
  timeout: 90_000,
  expect: {
    timeout: 10_000,
  },
  reporter: [['list'], ['html', { open: 'never' }]],
  use: {
    baseURL: 'http://127.0.0.1:18090',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },
  webServer: {
    command: 'dotnet run --project src/Agora.Web/Agora.Web.csproj --urls http://127.0.0.1:18090',
    cwd: repoRoot,
    port: 18090,
    timeout: 120_000,
    reuseExistingServer: false,
    env: {
      ASPNETCORE_ENVIRONMENT: 'E2E',
      AGORA_E2E: '1',
      ConnectionStrings__Default: `Data Source=${path.join(dataRoot, 'agora_e2e.db')}`,
      Agora__StorageRoot: path.join(dataRoot, 'storage'),
      Email__Provider: 'filesystem',
      Email__FileSystem__OutputDirectory: path.join(dataRoot, 'emails'),
      Serilog__WriteTo__0__Args__path: path.join(dataRoot, 'logs', 'agora-.log')
    }
  },
  globalSetup: './support/global-setup.ts'
});
