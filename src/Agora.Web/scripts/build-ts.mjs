import { build } from 'esbuild';

const entryPoints = [
  'Scripts/index.ts',
  'Scripts/shares-new.ts',
  'Scripts/admin-index.ts',
  'Scripts/csrf-client.ts',
  'Scripts/share-download.ts',
  'Scripts/account-landing-designer.ts',
  'Scripts/share-landing-designer.ts',
  'Scripts/template-designer-preview.ts',
  'Scripts/share-template.ts',
  'Scripts/share-template-designer-legacy.ts',
  'Scripts/shares-created.ts',
  'Scripts/local-datetime.ts',
  'Scripts/share-delete.ts',
  'Scripts/quick-share-dropzone.ts'
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
