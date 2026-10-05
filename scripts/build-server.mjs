import { build } from 'esbuild';

await build({
  entryPoints: ['src/server.ts'], bundle: true, platform: 'node', target: 'node22',
  format: 'esm', outfile: 'dist-server/server.mjs', sourcemap: false, legalComments: 'none',
});
