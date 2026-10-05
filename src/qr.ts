import jsQR from 'jsqr';

const MAX_BYTES = 8 * 1024 * 1024;
const MAX_PIXELS = 20_000_000;

/** Header inspection bounds image allocation before passing user content to the decoder. */
export function imageDimensions(bytes: Uint8Array): { width: number; height: number } {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length >= 24 && bytes[0] === 137 && bytes[1] === 80 && bytes[2] === 78 && bytes[3] === 71) {
    return { width: view.getUint32(16), height: view.getUint32(20) };
  }
  if (bytes.length >= 12 && bytes[0] === 255 && bytes[1] === 216) {
    let offset = 2;
    while (offset + 9 < bytes.length) {
      if (bytes[offset++] !== 255) throw new Error('The JPEG header could not be read. Try a PNG image.');
      while (bytes[offset] === 255) offset++;
      const marker = bytes[offset++];
      if (marker === 0xD9 || marker === 0xDA) break;
      if (marker === 0x01 || (marker >= 0xD0 && marker <= 0xD7)) continue;
      if (offset + 2 > bytes.length) break;
      const length = view.getUint16(offset);
      if (length < 2 || offset + length > bytes.length) break;
      if ([0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF].includes(marker)) {
        return { height: view.getUint16(offset + 3), width: view.getUint16(offset + 5) };
      }
      offset += length;
    }
  }
  if (bytes.length >= 30 && String.fromCharCode(...bytes.slice(0, 4)) === 'RIFF' && String.fromCharCode(...bytes.slice(8, 12)) === 'WEBP') {
    const kind = String.fromCharCode(...bytes.slice(12, 16));
    if (kind === 'VP8X') return { width: 1 + bytes[24] + (bytes[25] << 8) + (bytes[26] << 16), height: 1 + bytes[27] + (bytes[28] << 8) + (bytes[29] << 16) };
    if (kind === 'VP8L' && bytes[20] === 0x2f) {
      const bits = view.getUint32(21, true);
      return { width: (bits & 0x3fff) + 1, height: ((bits >>> 14) & 0x3fff) + 1 };
    }
    if (kind === 'VP8 ' && bytes[23] === 0x9d && bytes[24] === 1 && bytes[25] === 0x2a) {
      return { width: view.getUint16(26, true) & 0x3fff, height: view.getUint16(28, true) & 0x3fff };
    }
  }
  throw new Error('Use a valid PNG, JPEG, or WebP image. SVG and animated formats are not supported.');
}

export async function decodeQr(file: File): Promise<string> {
  if (!file.size || file.size > MAX_BYTES) throw new Error('Choose a QR image smaller than 8 MB.');
  const bytes = new Uint8Array(await file.arrayBuffer());
  const { width, height } = imageDimensions(bytes);
  if (!width || !height || width * height > MAX_PIXELS || width > 16000 || height > 16000) {
    throw new Error('This image is too large. Crop it around the QR code and try again (maximum 20 megapixels).');
  }
  let bitmap: ImageBitmap;
  try { bitmap = await createImageBitmap(file); }
  catch { throw new Error('This image could not be decoded. Try a clear PNG or JPEG.'); }
  try {
    const canvas = document.createElement('canvas');
    const scale = Math.min(1, 1600 / Math.max(bitmap.width, bitmap.height));
    canvas.width = Math.max(1, Math.round(bitmap.width * scale));
    canvas.height = Math.max(1, Math.round(bitmap.height * scale));
    const ctx = canvas.getContext('2d', { willReadFrequently: true });
    if (!ctx) throw new Error('Image processing is unavailable in this browser. Paste the URL instead.');
    ctx.fillStyle = '#fff';
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.drawImage(bitmap, 0, 0, canvas.width, canvas.height);
    const frame = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const code = jsQR(frame.data, frame.width, frame.height, { inversionAttempts: 'attemptBoth' });
    if (!code?.data) throw new Error('No readable QR code found. Crop closer, improve the lighting, or paste the URL.');
    if (new TextEncoder().encode(code.data).length > 8192) throw new Error('The QR payload exceeds the 8 KB URL limit.');
    if (!/^(?:[a-z][a-z\d+.-]*:|\/\/|(?:[a-z\d\u0080-\uffff-]+\.)+[a-z\u0080-\uffff]{2,}(?::\d+)?(?:[/?#]|$))/i.test(code.data.trim())) {
      throw new Error('This QR contains text rather than a recognizable URL. PhishLens checks URL text only.');
    }
    return code.data;
  } finally { bitmap.close(); }
}
