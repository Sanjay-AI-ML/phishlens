import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import QRCode from 'qrcode';
import { PRESETS } from '../src/presets';

test('every demo URL produces its stated verdict and remains local', async ({ page }) => {
  const external: string[] = [];
  const errors: string[] = [];
  page.on('request', req => { if (!req.url().startsWith('http://127.0.0.1:4173/') && !req.url().startsWith('blob:') && !req.url().startsWith('data:')) external.push(req.url()); });
  page.on('pageerror', e => errors.push(e.message));
  await page.goto('/');
  for (const preset of PRESETS) {
    await page.locator('#url-input').fill(preset.url);
    await page.locator('#analyze-button').click();
    await expect(page.locator('#verdict-label'), preset.label).toHaveText(new RegExp(preset.expected, 'i'));
    await expect(page.locator('#rules-list')).toBeAttached();
  }
  expect(external).toEqual([]);
  expect(errors).toEqual([]);
  const storage = await page.evaluate(() => ({ local: Object.keys(localStorage), session: Object.keys(sessionStorage) }));
  expect(storage).toEqual({ local: [], session: [] });
});

test('reveals actual host and nested deception without active links', async ({ page }) => {
  await page.goto('/');
  await page.locator('#url-input').fill(PRESETS.find(p => p.id === 'nested')!.url);
  await page.locator('#analyze-button').click();
  await expect(page.locator('#actual-host')).toHaveText('portal.campus.example');
  await expect(page.locator('#xray-tree')).toContainText('other.example');
  await expect(page.locator('#xray-tree')).toContainText('R2');
  expect(await page.locator('a[href*="other.example"]').count()).toBe(0);
  expect(await page.locator('a[href*="campus.example"]').count()).toBe(0);
});

test('rendered URL markup cannot execute and passwords are masked', async ({ page }) => {
  await page.goto('/');
  await page.locator('#url-input').fill('https://campus.example@other.example/<img src=x onerror=alert(1)>?token=secret');
  await page.locator('#analyze-button').click();
  expect(await page.locator('#result-region img').count()).toBe(0);
  await page.locator('#url-input').fill('https://campus.example:do-not-show-this@other.example/login');
  await page.locator('#analyze-button').click();
  await expect(page.locator('#result-region')).not.toContainText('do-not-show-this');
  await expect(page.locator('#actual-host')).toHaveText('other.example');
});

test('source selection leaves URL verdict unchanged and clear removes results', async ({ page }) => {
  await page.goto('/');
  await page.locator('#url-input').fill('https://short.example/abc123');
  await page.locator('#analyze-button').click();
  await expect(page.locator('#verdict-label')).toHaveText(/review/i);
  await page.locator('#source-context').selectOption('sticker');
  await expect(page.locator('#verdict-label')).toHaveText(/review/i);
  await page.locator('#clear-button').click();
  await expect(page.locator('#url-input')).toHaveValue('');
  await expect(page.locator('#actual-host')).not.toBeVisible();
});

test('actual PNG QR decodes locally and reaches the same engine', async ({ page }) => {
  await page.goto('/');
  const buffer = await QRCode.toBuffer('https://campus.example@other.example/login', { width: 512, margin: 3 });
  await page.locator('#qr-file').setInputFiles({ name: 'campus-demo.png', mimeType: 'image/png', buffer });
  await expect(page.locator('#url-input')).toHaveValue('https://campus.example@other.example/login');
  await page.locator('#analyze-button').click();
  await expect(page.locator('#actual-host')).toHaveText('other.example');
  await expect(page.locator('#verdict-label')).toHaveText(/suspicious/i);
});

test('offline browser still analyzes new URL text with loaded assets', async ({ page, context }) => {
  await page.goto('/');
  await context.setOffline(true);
  await page.locator('#url-input').fill('https://campvs.example/login');
  await page.locator('#analyze-button').click();
  await expect(page.locator('#verdict-label')).toHaveText(/suspicious/i);
  await context.setOffline(false);
});

test('keyboard form and result pass automated accessibility checks', async ({ page }) => {
  await page.goto('/');
  await page.locator('#url-input').focus();
  await page.keyboard.type('https://campus.example@other.example/login');
  await page.locator('#analyze-button').focus();
  await page.keyboard.press('Enter');
  await expect(page.locator('#actual-host')).toHaveText('other.example');
  const scan = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21aa']).analyze();
  expect(scan.violations.map(v => ({ id: v.id, nodes: v.nodes.map(n => ({ target: n.target, reason: n.failureSummary })) }))).toEqual([]);
});

test('small viewport has no horizontal overflow and keeps primary action visible', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto('/');
  await page.locator('#url-input').fill(PRESETS.find(p => p.id === 'nested')!.url);
  await page.locator('#analyze-button').click();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect(page.locator('#actual-host')).toBeVisible();
  await page.screenshot({ path: 'artifacts/mobile.png', fullPage: true });
});

test('local AI failure preserves the verdict and deterministic explanation', async ({ page }) => {
  await page.route('**/api/ai/status', route => route.fulfill({ json: { available: false, models: [], message: 'No local model available.' } }));
  await page.goto('/');
  await page.locator('#url-input').fill(PRESETS.find(p => p.id === 'userinfo')!.url);
  await page.locator('#analyze-button').click();
  await page.locator('#ai-check').click();
  await expect(page.locator('#verdict-label')).toHaveText(/suspicious/i);
  await expect(page.locator('#result-region')).toContainText('other.example');
});

test('desktop visual snapshots show ready and result layouts', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 1000 });
  await page.goto('/');
  await page.screenshot({ path: 'artifacts/home.png', fullPage: true });
  await page.locator('#url-input').fill(PRESETS.find(p => p.id === 'nested')!.url);
  await page.locator('#analyze-button').click();
  await page.screenshot({ path: 'artifacts/xray.png', fullPage: true });
});

test('two-minute demonstration advances, pauses, resumes, and completes', async ({ page }) => {
  await page.clock.install();
  await page.goto('/');
  await page.locator('#demo-play').click();
  await expect(page.locator('#actual-host')).toHaveText('portal.campus.example');
  await page.clock.fastForward(21000);
  await expect(page.locator('#actual-host')).toContainText('week-3-lab-manual');
  await page.locator('#demo-pause').click();
  await page.clock.fastForward(40000);
  await expect(page.locator('#actual-host')).toContainText('week-3-lab-manual');
  await page.locator('#demo-pause').click();
  await page.clock.fastForward(21000);
  await expect(page.locator('#actual-host')).toHaveText('other.example');
  await page.clock.fastForward(25000);
  await expect(page.locator('#xray-tree')).toContainText('other.example');
  await page.clock.fastForward(30000);
  await expect(page.locator('#actual-host')).toHaveText('short.example');
  await expect(page.locator('#verdict-label')).toHaveText(/review/i);
  await page.clock.fastForward(25000);
  await expect(page.locator('#demo-title')).toContainText('complete');
  await expect(page.locator('#demo-play')).toBeVisible();
});

test('AI request omits private URL values and generated output cannot change the verdict', async ({ page }) => {
  let body: Record<string, unknown> | undefined;
  await page.route('**/api/ai/status', route => route.fulfill({ json: { available: true, models: ['local-test:latest'], message: 'Local model ready.' } }));
  await page.route('**/api/ai/explain', route => {
    body = route.request().postDataJSON();
    return route.fulfill({ json: { explanation: 'The familiar text before the at sign can disguise the actual host. Confirm the intended service before sharing information.', action: 'UNTRUSTED ACTION MUST NOT REPLACE THE RULE', model: 'local-test:latest', generated: true } });
  });
  await page.goto('/');
  await page.locator('#url-input').fill('https://campus.example:private-password@other.example/login?token=private-token');
  await page.locator('#analyze-button').click();
  const action = await page.locator('#next-step-text').textContent();
  await page.locator('#ai-check').click();
  await page.locator('#ai-explain').click();
  await expect(page.locator('#ai-output')).toBeVisible();
  expect(JSON.stringify(body)).not.toContain('private-password');
  expect(JSON.stringify(body)).not.toContain('private-token');
  await expect(page.locator('#next-step-text')).toHaveText(action!);
  await expect(page.locator('#verdict-label')).toHaveText(/suspicious/i);
});

test('clearing while AI is pending cannot resurrect a previous result', async ({ page }) => {
  await page.route('**/api/ai/status', route => route.fulfill({ json: { available: true, models: ['local-test:latest'], message: 'Local model ready.' } }));
  let release: (() => void) | undefined;
  const delayed = new Promise<void>(resolve => { release = resolve; });
  await page.route('**/api/ai/explain', async route => { await delayed; await route.fulfill({ json: { explanation: 'An old result that must never reappear.', model: 'local-test:latest', generated: true, action: '' } }).catch(() => {}); });
  await page.goto('/');
  await page.locator('#url-input').fill('https://campus.example@other.example/login');
  await page.locator('#analyze-button').click();
  await page.locator('#ai-check').click();
  const requested = page.waitForRequest('**/api/ai/explain');
  await page.locator('#ai-explain').click();
  await requested;
  await page.locator('#clear-button').click();
  release!();
  await expect(page.locator('#actual-host')).not.toBeVisible();
  await expect(page.locator('#result-region')).not.toContainText('An old result');
  await expect(page.locator('#url-input')).toHaveValue('');
});
