import { readFile, writeFile } from 'node:fs/promises';
const packages = [
  ['jsqr', 'LICENSE'], ['tldts', 'LICENSE'], ['tldts-core', 'LICENSE'], ['punycode', 'LICENSE-MIT.txt']
];
const notices = ['PhishLens runtime dependency notices. Bundled libraries are unmodified; tooling may minify their code.\n'];
for (const [name, license] of packages) {
  const pkg = JSON.parse(await readFile(`node_modules/${name}/package.json`, 'utf8'));
  notices.push(`${name} ${pkg.version}\n${'='.repeat(60)}\n${await readFile(`node_modules/${name}/${license}`, 'utf8')}`);
}
await writeFile('public/third-party-notices.txt', notices.join('\n\n'));
