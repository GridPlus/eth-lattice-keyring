import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'tsup';

const __dirname = dirname(fileURLToPath(import.meta.url));
const pkg = JSON.parse(
  readFileSync(resolve(__dirname, 'package.json'), 'utf8'),
);

const external = Object.keys({
  ...(pkg.dependencies ?? {}),
  ...(pkg.peerDependencies ?? {}),
});

export default defineConfig({
  entry: ['src/index.ts'],
  outDir: 'dist',
  format: ['esm', 'cjs'],
  dts: true,
  sourcemap: true,
  clean: true,
  target: 'node16',
  platform: 'node',
  bundle: true,
  external,
  outExtension({ format }) {
    return {
      js: format === 'esm' ? '.js' : '.cjs',
    };
  },
});
