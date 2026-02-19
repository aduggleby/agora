import { build } from 'esbuild';

const entryPoints = [
  'scripts/ts/index.ts',
  'scripts/ts/shares-new.ts',
  'scripts/ts/admin-index.ts',
  'scripts/ts/csrf-client.ts',
  'scripts/ts/share-download.ts',
  'scripts/ts/account-landing-designer.ts',
  'scripts/ts/share-landing-designer.ts',
  'scripts/ts/template-designer-preview.ts',
  'scripts/ts/share-template.ts',
  'scripts/ts/share-template-designer-legacy.ts',
  'scripts/ts/shares-created.ts',
  'scripts/ts/local-datetime.ts',
  'scripts/ts/share-delete.ts',
  'scripts/ts/quick-share-dropzone.ts',
  'scripts/ts/lightbox.ts'
];

await build({
  absWorkingDir: process.cwd(),
  entryPoints,
  outdir: 'wwwroot/js',
  bundle: true,
  format: 'iife',
  target: ['es2020'],
  sourcemap: true,
  logLevel: 'info'
});
