import QRCode from 'qrcode';
import { mkdir, writeFile } from 'node:fs/promises';
await mkdir('demo', { recursive: true });
const urls = {
  'ordinary-qr': 'https://portal.campus.example/notices',
  'deceptive-qr': 'https://campus.example@other.example/login',
  'hidden-destination-qr': 'https://portal.campus.example/continue?next=https%3A%2F%2Fcampus.example%40other.example%2Flogin',
  'ambiguous-qr': 'https://short.example/abc123'
};
for (const [name, url] of Object.entries(urls)) {
  await QRCode.toFile(`demo/${name}.png`, url, { width: 600, margin: 4, errorCorrectionLevel: 'M' });
}
await writeFile('demo/urls.txt', Object.entries(urls).map(([name, url]) => `${name}\n${url}\n`).join('\n'));
console.log('Created four safe .example QR images and demo/urls.txt.');
