import { describe, expect, it } from 'vitest';
import QRCode from 'qrcode';
import { imageDimensions } from './qr';

describe('QR image input boundaries', () => {
  it('reads dimensions of a real generated PNG', async () => {
    const png = await QRCode.toBuffer('https://campus.example/notices', { width: 320 });
    expect(imageDimensions(png)).toEqual({ width: 320, height: 320 });
  });
  it('rejects executable SVG and unrelated bytes before decoding', () => {
    expect(() => imageDimensions(new TextEncoder().encode('<svg onload="alert(1)"></svg>'))).toThrow('valid PNG');
    expect(() => imageDimensions(new Uint8Array(0))).toThrow();
  });
  it('recognizes excessive PNG dimensions for allocation guard', () => {
    const bytes = new Uint8Array(24); bytes.set([137, 80, 78, 71]);
    new DataView(bytes.buffer).setUint32(16, 40000);
    new DataView(bytes.buffer).setUint32(20, 40000);
    expect(imageDimensions(bytes)).toEqual({ width: 40000, height: 40000 });
  });
});
