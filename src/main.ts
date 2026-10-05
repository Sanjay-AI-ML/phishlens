import './styles.css';
import { analyzeUrl } from './engine';
import { decodeQr } from './qr';
import { PRESETS } from './presets';
import type { Analysis, AiStatus, DestinationNode, Preset, Verdict } from './types';

const icons: Record<string, string> = {
  scan: '<path d="M8 3H5a2 2 0 0 0-2 2v3m13-5h3a2 2 0 0 1 2 2v3M3 16v3a2 2 0 0 0 2 2h3m8 0h3a2 2 0 0 0 2-2v-3"/><circle cx="11" cy="11" r="4"/><path d="m14 14 3 3"/>',
  arrow: '<path d="M5 12h14m-5-5 5 5-5 5"/>',
  shield: '<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  grid: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  book: '<path d="M12 5v16m0-16C8 2 3 3 3 3v16s5-1 9 2c4-3 9-2 9-2V3s-5-1-9 2Z"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  spark: '<path d="m12 3 2.5 6.5L21 12l-6.5 2.5L12 21l-2.5-6.5L3 12l6.5-2.5L12 3Z"/>',
  link: '<path d="m10 13 4-4m-6 7-1 1a4 4 0 0 1-6-6l4-4a4 4 0 0 1 6 0m2 4a4 4 0 0 1 0-6l4-4a4 4 0 0 1 6 6l-1 1" transform="translate(1 2) scale(.85)"/>',
  upload: '<path d="M12 16V3m-5 5 5-5 5 5M4 15v5h16v-5"/>',
  play: '<path d="m9 5 11 7-11 7V5Z"/>',
  chevron: '<path d="m9 5 7 7-7 7"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v1"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  alert: '<path d="m12 3 10 18H2L12 3Zm0 6v5m0 3v1"/>',
  copy: '<rect x="8" y="8" width="12" height="13" rx="2"/><path d="M16 8V3H3v13h5"/>',
  audio: '<path d="M4 9h4l5-5v16l-5-5H4V9Zm12-1a6 6 0 0 1 0 8m3-11a10 10 0 0 1 0 14"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  globe: '<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>',
};
const icon = (name: string, cls = '') => `<svg class="icon ${cls}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] ?? icons.info}</svg>`;
const escape = (value: unknown): string => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]!));
const el = <T extends HTMLElement = HTMLElement>(id: string): T => document.getElementById(id) as T;
const verdictName = (v: Verdict) => v.charAt(0).toUpperCase() + v.slice(1);
let current: Analysis | null = null;
let currentPresetId = '';
let aiStatus: AiStatus | null = null;
let currentAiRequest: AbortController | null = null;
let resultRevision = 0;
let qrRevision = 0;
let inputMode: 'url' | 'qr' = 'url';

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
<a class="skip-link" href="#main-content">Skip to URL inspector</a>
<aside class="sidebar" aria-label="Main navigation">
  <a class="brand" href="#main-content" aria-label="PhishLens home"><span class="brand-symbol">${icon('scan')}</span><span>Phish<span class="brand-light">Lens</span><small>SEE BEFORE YOU CLICK</small></span></a>
  <div class="nav-label">WORKSPACE</div>
  <nav class="main-nav"><a href="#inspector" class="nav-item active" aria-label="Link inspector" aria-current="page">${icon('scan')}<span>Link inspector</span><span class="nav-indicator"></span></a><button class="nav-item" aria-label="Demo library" data-open-presets>${icon('grid')}<span>Demo library</span><span class="nav-count">${PRESETS.length}</span></button><button class="nav-item" aria-label="How it works" data-open-policy>${icon('book')}<span>How it works</span></button></nav>
  <div class="sidebar-bottom"><div class="privacy-note"><span class="privacy-icon">${icon('lock')}</span><strong>Your links stay yours.</strong><p>Checked on this device.<br>No destination is visited.</p><button class="text-button" data-open-policy>Our privacy promise ${icon('arrow')}</button></div><div class="sidebar-meta"><span class="status-dot"></span> OFFLINE BY DESIGN<span>v1.0</span></div></div>
</aside>
<div class="workspace">
  <header class="topbar"><div class="breadcrumb">Workspace ${icon('chevron')} <strong>Link inspector</strong></div><div class="local-pill"><span class="status-dot"></span>Local processing</div></header>
  <main id="main-content" tabindex="-1">
    <section class="hero" aria-labelledby="page-title"><div class="eyebrow"><span></span> A LITTLE CLARITY. A SAFER NEXT STEP.</div><h1 id="page-title">Clarity before you <span>click.</span></h1><p>Uncover the real destination behind a link.<br class="mobile-break"> Understand the warning. Choose your next step.</p></section>
    <section class="input-card" id="inspector" aria-label="Inspect a link">
      <div class="input-card-top"><div class="input-tabs" role="tablist" aria-label="Input type"><button id="url-tab" role="tab" aria-selected="true" aria-controls="url-panel" class="input-tab active">${icon('link')}Paste a URL</button><button id="qr-tab" role="tab" aria-selected="false" aria-controls="qr-panel" tabindex="-1" class="input-tab">${icon('grid')}Upload a QR</button></div><span class="private-label">${icon('lock')}Private by default</span></div>
      <form id="inspect-form" novalidate>
        <div id="url-panel" role="tabpanel" aria-labelledby="url-tab"><label class="sr-only" for="url-input">URL to inspect</label><textarea id="url-input" name="url" rows="2" maxlength="16384" spellcheck="false" autocapitalize="off" autocomplete="off" placeholder="Paste a link here. We’ll reveal where it really points." aria-describedby="input-hint input-error"></textarea></div>
        <div id="qr-panel" role="tabpanel" aria-labelledby="qr-tab" hidden><label class="qr-drop" id="qr-drop" for="qr-file">${icon('upload')}<strong>Drop a QR image here</strong><span>or choose a PNG, JPG or WebP · decoded on this device</span><input id="qr-file" type="file" accept="image/png,image/jpeg,image/webp"/><span class="secondary-button file-button">Choose image</span></label><p id="qr-status" class="field-hint" role="status"></p></div>
        <div class="input-footer"><div class="source-field"><label for="source-context">Where did you find it?</label><select id="source-context"><option value="unknown">Not specified</option><option value="pdf">Official digital document</option><option value="poster">Bulletin board poster</option><option value="sticker">Random sticker</option></select></div><div class="form-actions"><button id="clear-button" class="text-button clear-button" type="button">Clear</button><button id="analyze-button" type="submit" class="primary-button">Inspect link ${icon('arrow')}</button></div></div>
        <div class="form-under"><span id="input-hint">${icon('shield')}We inspect the text. The destination is never opened.</span><span class="key-hint"><kbd>Ctrl</kbd> + <kbd>Enter</kbd> to inspect</span></div><p id="input-error" class="input-error" role="alert" hidden></p>
      </form>
    </section>
    <div class="example-row"><span>Try an example</span><div id="quick-presets" class="quick-presets"></div><button class="text-button all-examples" data-open-presets>View all ${icon('arrow')}</button></div>
    <div class="demo-bar" id="demo-bar"><span class="demo-icon">${icon('play')}</span><div class="demo-copy"><strong id="demo-title">See the difference in 2 minutes</strong><span id="demo-description">Ordinary, disguised, hidden and uncertain destinations.</span></div><div class="demo-controls"><span id="demo-time" hidden>0:00 / 2:00</span><button class="secondary-button small" id="demo-play">Play demo ${icon('play')}</button><button class="secondary-button small" id="demo-pause" hidden>Pause</button><button class="text-button" id="demo-stop" hidden>Stop</button></div><div id="demo-progress" class="demo-progress" style="width:0%"></div></div>
    <section id="result-region" aria-label="Inspection results"></section>
    <footer class="page-footer"><span>${icon('shield')} A clear signal, never a guarantee.</span><button class="text-button" data-open-policy>View rules &amp; limitations ${icon('arrow')}</button></footer>
  </main>
</div>
<dialog id="library-dialog" class="app-dialog"><div class="dialog-heading"><div><div class="eyebrow">SAFE, SYNTHETIC EXAMPLES</div><h2>Explore the demo library</h2></div><button class="icon-button" data-close-dialog aria-label="Close demo library">${icon('close')}</button></div><p class="dialog-intro">Every named destination uses reserved .example domains. Numeric examples use documentation or local address ranges. Nothing is opened.</p><div id="preset-library"></div></dialog>
<dialog id="policy-dialog" class="app-dialog policy-dialog"><div class="dialog-heading"><div><div class="eyebrow">TRANSPARENT BY DESIGN</div><h2>How PhishLens makes a decision</h2></div><button class="icon-button" data-close-dialog aria-label="Close policy">${icon('close')}</button></div><div class="policy-body"><p>The same URL and policy produce the same verdict for every department. Your reported source adds separate context; it never changes the URL verdict.</p><div class="policy-tiers"><div><span class="verdict-badge suspicious">Suspicious</span><p>A strong warning sign was found.</p></div><div><span class="verdict-badge review">Review</span><p>Uncertainty, a review rule, or two independent weak signals.</p></div><div><span class="verdict-badge safe">Safe</span><p>No review threshold reached. This does not establish trust.</p></div></div><h3>A fixed demo directory</h3><p>The following synthetic institution domains and their subdomains are approved by this demo policy. An approved name does not exempt a link from hidden-target, userinfo, or transport checks.</p><div class="domain-list"><code>campus.example</code><code>library.example</code><code>studentportal.example</code><code>research.example</code><code>university.example</code></div><p>A real deployment needs an institution-maintained domain list. PhishLens does not authenticate the sender, verify website ownership, scan page content, or follow server redirects.</p><h3>Privacy and local AI</h3><p>Inspection runs in your browser. There is no history, analytics, or remote URL lookup. Clear removes the current input and result. QR images are decoded locally.</p><p>AI explanation is optional and starts only when you ask. It requires a separately downloaded model running on this computer. The local bridge receives permitted finding details and the parsed hostname. The model receives fixed descriptions of the detected rules, with no submitted URL text or hostname. URL paths, query values, user information, and QR images are excluded. Fixed rule explanations always remain available.</p><h3>Bounded inspection</h3><p>Embedded URLs are inspected within fixed input, decoding, candidate, and nesting limits. If a limit is reached, the result explicitly says inspection is incomplete. An embedded URL is evidence of text in a parameter, not proof that a server redirects to it.</p><h3>Accessible by default</h3><p>All verdicts use words as well as color. Results work with a keyboard and screen reader. Read aloud uses an available on-device English voice; it will not select a remote voice.</p><p class="policy-version" id="policy-version">Policy details are included with each inspection result.</p></div></dialog>
<div class="sr-only" id="live-announcement" role="status" aria-live="polite" aria-atomic="true"></div>
<div class="toast" id="toast" role="status" hidden></div>`;

const input = el<HTMLTextAreaElement>('url-input');
const source = el<HTMLSelectElement>('source-context');
const result = el('result-region');

function announce(text: string) { el('live-announcement').textContent = text; }
let toastTimer: ReturnType<typeof setTimeout>;
function toast(text: string) { el('toast').textContent = text; el('toast').hidden = false; clearTimeout(toastTimer); toastTimer = setTimeout(() => { el('toast').hidden = true; }, 4000); }
function showError(text: string) { el('input-error').textContent = text; el('input-error').hidden = !text; input.setAttribute('aria-invalid', String(Boolean(text))); }
function openDialog(id: string) { el<HTMLDialogElement>(id).showModal(); }
document.querySelectorAll('[data-open-presets]').forEach(button => button.addEventListener('click', () => openDialog('library-dialog')));
document.querySelectorAll('[data-open-policy]').forEach(button => button.addEventListener('click', () => openDialog('policy-dialog')));
document.querySelectorAll('[data-close-dialog]').forEach(button => button.addEventListener('click', () => button.closest('dialog')?.close()));
document.querySelectorAll('dialog').forEach(dialog => dialog.addEventListener('click', e => { if (e.target === dialog) { const r = dialog.getBoundingClientRect(); if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) dialog.close(); } }));

function emptyState() {
  result.innerHTML = `<div class="empty-grid"><div class="anatomy-card"><div class="section-eyebrow">A FAMILIAR NAME ISN’T ALWAYS THE DESTINATION</div><h2>Look beyond the disguise.</h2><p>The part that looks official may be a distraction.<br>We bring the real destination into focus.</p><div class="anatomy-url" aria-label="Example: campus dot example before the at sign is misleading text; other dot example is the actual host."><span class="anatomy-scheme">https://</span><span class="anatomy-bait">campus.example<span class="anatomy-label bait-label">The disguise</span></span><span class="anatomy-at">@</span><span class="anatomy-host">other.example<span class="anatomy-label host-label">The actual host ${icon('arrow')}</span></span></div><div class="anatomy-caption">${icon('info')}Text before <code>@</code> is user information. It is not the host.</div></div><div class="capabilities-card"><div class="feature-item"><span class="feature-icon blue">${icon('scan')}</span><div><h3>Reveal the destination</h3><p>See the real host and the details designed to distract you.</p></div></div><div class="feature-item"><span class="feature-icon violet">${icon('grid')}</span><div><h3>See the hidden layers</h3><p>Unpack encoded destinations buried inside URL parameters.</p></div></div><div class="feature-item"><span class="feature-icon teal">${icon('spark')}</span><div><h3>Understand your next step</h3><p>Clear reasons, practical guidance, and optional local AI explanations.</p></div></div></div></div>`;
}

function setMode(mode: 'url' | 'qr') {
  inputMode = mode;
  for (const m of ['url', 'qr']) { const active = m === mode; const tab = el(`${m}-tab`); tab.classList.toggle('active', active); tab.setAttribute('aria-selected', String(active)); tab.tabIndex = active ? 0 : -1; el(`${m}-panel`).hidden = !active; }
  el<HTMLButtonElement>('analyze-button').disabled = mode === 'qr' && !input.value.trim();
}
el('url-tab').addEventListener('click', () => setMode('url'));
el('qr-tab').addEventListener('click', () => setMode('qr'));
document.querySelector('.input-tabs')!.addEventListener('keydown', e => { const key = (e as KeyboardEvent).key; if (['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(key)) { e.preventDefault(); setMode(key === 'Home' ? 'url' : key === 'End' ? 'qr' : inputMode === 'url' ? 'qr' : 'url'); el(`${inputMode}-tab`).focus(); } });
input.addEventListener('input', () => {
  showError(''); currentPresetId = ''; highlightPreset();
  stopDemo(false); currentAiRequest?.abort(); resultRevision++; qrRevision++;
  if ('speechSynthesis' in window) window.speechSynthesis.cancel();
  if (current) {
    current = null;
    result.innerHTML = `<div class="changed-input" role="status">${icon('info')}<div><strong>Input changed. Inspect this link again.</strong><p>The previous result has been cleared so it cannot be mistaken for this URL.</p></div></div>`;
  }
});
input.addEventListener('keydown', e => { if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); inspect(); } });
el('inspect-form').addEventListener('submit', e => { e.preventDefault(); inspect(); });
el('clear-button').addEventListener('click', clear);

function clear() {
  stopDemo(false); currentAiRequest?.abort(); current = null; currentPresetId = ''; resultRevision++; qrRevision++;
  if ('speechSynthesis' in window) window.speechSynthesis.cancel();
  input.value = ''; source.value = 'unknown'; el<HTMLInputElement>('qr-file').value = ''; el('qr-status').textContent = ''; setMode('url'); showError(''); emptyState(); highlightPreset(); input.focus(); announce('Input and inspection cleared.');
}
function inspect(preserveDemo = false) {
  if (!preserveDemo) stopDemo(false);
  if (!input.value.trim()) { showError('Paste a URL to inspect, or upload a QR image.'); setMode('url'); input.focus(); return; }
  currentAiRequest?.abort(); resultRevision++;
  if ('speechSynthesis' in window) window.speechSynthesis.cancel();
  try {
    current = analyzeUrl(input.value); showError(''); renderResult(current); announce(current.accessibleSummary);
    if (!preserveDemo && window.matchMedia('(max-width: 760px)').matches) result.scrollIntoView({ block: 'start', behavior: 'instant' });
  }
  catch { showError('This input could not be inspected. Try a shorter URL or choose a demo example.'); }
}
function choosePreset(preset: Preset, preserveDemo = false) {
  input.value = preset.url; currentPresetId = preset.id; setMode('url'); el<HTMLDialogElement>('library-dialog').close(); inspect(preserveDemo); highlightPreset();
}
function highlightPreset() { document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach(button => button.classList.toggle('selected', button.dataset.preset === currentPresetId)); }

const quick = [PRESETS.find(p => p.category.toLowerCase().includes('ordinary')), PRESETS.find(p => p.url.includes('@')), PRESETS.find(p => p.url.includes('?next=')), PRESETS.find(p => p.url.includes('short.example'))].filter((p): p is Preset => Boolean(p));
el('quick-presets').innerHTML = quick.map((p, i) => `<button class="preset-chip" data-preset="${escape(p.id)}"><span class="preset-dot ${p.expected}"></span>${escape(['Ordinary link', 'The @ disguise', 'Hidden destination', 'Shortened link'][i])}</button>`).join('');
const categories = [...new Set(PRESETS.map(p => p.category))];
el('preset-library').innerHTML = categories.map(category => `<section class="preset-group"><h3>${escape(category)}</h3><div class="preset-grid">${PRESETS.filter(p => p.category === category).map(p => `<button class="preset-option" data-preset="${escape(p.id)}"><span class="preset-option-heading"><strong>${escape(p.label)}</strong><span class="verdict-badge ${p.expected}">${verdictName(p.expected)}</span></span><span>${escape(p.description)}</span><code dir="ltr">${escape(p.url)}</code></button>`).join('')}</div></section>`).join('');
document.querySelectorAll<HTMLButtonElement>('[data-preset]').forEach(button => button.addEventListener('click', () => { const preset = PRESETS.find(p => p.id === button.dataset.preset); if (preset) choosePreset(preset); }));

function sourceCaution(a: Analysis): string {
  const type = source.value;
  if (type === 'unknown') return '';
  const shortener = a.findings.some(f => f.ruleId === 'R6') || a.destinations.some(d => d.findings.some(f => f.ruleId === 'R6'));
  const text = type === 'sticker' ? (shortener ? 'A random sticker and a hidden short-link destination leave two things unverified. Confirm the poster or sender and request the full destination before signing in.' : 'A sticker may be replaced or added by someone else. Confirm its source independently before trusting the destination.') : type === 'poster' ? 'The source of a physical poster cannot be verified offline. Check that this is the destination the institution intended.' : 'A familiar document can still contain an unexpected link. This source is reported by you and cannot be authenticated offline.';
  return `<aside class="source-caution">${icon('info')}<div><strong>Source context · separate from the URL verdict</strong><p>${escape(text)}</p></div></aside>`;
}

function nodeCard(node: DestinationNode): string {
  return `<div class="destination-branch"><div class="destination-connector"><span></span><span>Parameter <code>${escape(node.parameter)}</code> · ${node.decodeSteps} decoding ${node.decodeSteps === 1 ? 'step' : 'steps'}</span></div><div class="destination-node ${node.verdict}"><span class="destination-index">${node.depth + 1}</span><div class="destination-node-body"><div class="destination-node-top"><strong dir="ltr">${escape(node.host || 'No web hostname')}</strong><span class="verdict-badge ${node.verdict}">${verdictName(node.verdict)}</span></div><p>${escape(node.explanation)}</p>${node.findings.filter(f => f.severity !== 'info').map(f => `<div class="nested-finding"><code>${escape(f.ruleId)}</code><span>${escape(f.explanation)}</span></div>`).join('')}</div></div>${node.children.map(nodeCard).join('')}</div>`;
}

function renderResult(a: Analysis) {
  const p = a.parts;
  const matching = a.findings.find(f => f.ruleId === a.decisiveRule);
  const embeddingCheck = a.checks.find(c => c.id === 'R7');
  const emptyXrayReason = a.limitsReached ? 'Embedded inspection is incomplete because an inspection limit was reached.'
    : embeddingCheck?.state === 'not-applicable' ? 'Embedded destination inspection does not apply to this URL scheme.'
    : !p || !embeddingCheck || embeddingCheck.state === 'not-evaluated' ? 'Embedded destinations could not be evaluated for this input.'
    : 'No embedded URL targets were detected within inspection limits.';
  const fields = p ? [['Scheme', p.scheme], ['User information', p.username ? `${p.username}${p.hasPassword ? ' · password hidden' : ''}` : 'None'], ['Real hostname', p.hostname], ['Unicode hostname', p.unicodeHostname || p.hostname], ['Main domain', p.domain || (p.isIp ? 'IP address · no registrable domain' : 'Not available')], ['Port', p.port ? `${p.port} (explicit)` : `${p.effectivePort || 'None'}${p.effectivePort ? ' (default)' : ''}`], ['Path', p.path || '/'], ['Query', p.query || 'None'], ['Fragment', p.fragment || 'None']] : [];
  result.innerHTML = `<div class="result-heading"><div class="section-eyebrow">YOUR INSPECTION</div><span>${icon('lock')}Processed locally</span></div><div class="result-grid"><div class="result-main"><article class="destination-card ${a.verdict}" aria-labelledby="destination-title"><div class="destination-card-top"><span class="verdict-badge large ${a.verdict}" id="verdict-label">${icon(a.verdict === 'safe' ? 'check' : 'alert')}${verdictName(a.verdict)}</span><span class="rule-chip" id="decisive-rule">${escape(a.decisiveRule)}</span></div><div class="host-eyebrow" id="destination-title">${p ? 'THE ACTUAL DESTINATION' : 'DESTINATION COULD NOT BE ESTABLISHED'}</div><div class="host-line"><h2 id="actual-host" dir="ltr">${escape(p?.hostname || 'No web hostname')}</h2>${p?.hostname ? `<button class="icon-button copy-host" id="copy-host" aria-label="Copy hostname">${icon('copy')}</button>` : ''}</div><p class="verdict-summary">${escape(a.summary)}</p><div class="host-meta">${p ? `<span>${icon('globe')}<strong>${escape(p.scheme.toUpperCase().replace(':', ''))}</strong></span><span><span class="meta-dot"></span>${p.trusted ? 'Approved demo domain' : p.isIp ? `${escape(p.ipScope || 'Unknown')} IP address` : 'Outside the demo directory'}</span>` : '<span>Check the input before proceeding.</span>'}</div>${a.verdict === 'safe' ? '<div class="safe-boundary">No review threshold was reached. Website safety is not verified.</div>' : ''}</article><article class="panel anatomy-result"><div class="panel-heading"><h3>See the link clearly</h3><span class="subtle-label">TEXT ONLY</span></div><div class="annotated-url" dir="ltr">${a.segments.map(s => `<span class="url-segment ${s.kind}"${s.kind === 'userinfo' ? ' aria-label="User information, not the host"' : ''}>${escape(s.text)}</span>`).join('')}</div><div class="url-legend"><span><i class="legend-host"></i>Actual host</span>${a.segments.some(s => s.kind === 'userinfo') ? '<span><i class="legend-userinfo"></i>User information · not the host</span>' : ''}<span><i class="legend-other"></i>Other URL text</span></div>${a.normalizationNotes.length ? `<div class="normalization-notes">${icon('info')}<div><strong>Parsing notes</strong>${a.normalizationNotes.map(n => `<p>${escape(n)}</p>`).join('')}</div></div>` : ''}<details class="components"><summary>All parsed components <span>${fields.length} fields ${icon('chevron')}</span></summary>${fields.length ? `<dl>${fields.map(([name, value]) => `<div><dt>${escape(name)}</dt><dd dir="ltr">${escape(value)}</dd></div>`).join('')}</dl>` : '<p class="field-hint">This input has no valid web URL components.</p>'}</details></article><article class="panel xray-panel"><div class="panel-heading"><div><div class="section-eyebrow">DESTINATION X-RAY</div><h3>${a.destinations.length ? 'There’s another layer to this link.' : 'The destination, in focus.'}</h3></div><span class="feature-icon violet small">${icon('grid')}</span></div><div id="xray-tree"><div class="destination-node outer"><span class="destination-index">1</span><div class="destination-node-body"><span class="subtle-label">OUTER URL</span><strong dir="ltr">${escape(p?.hostname || 'No web hostname')}</strong></div><span class="node-tag">${p?.trusted ? 'Approved demo host' : 'Pasted destination'}</span></div>${a.destinations.map(nodeCard).join('')}</div>${!a.destinations.length ? `<div class="xray-empty">${icon('check')}<span>${a.parts ? 'No embedded URL targets detected within inspection limits.' : 'Embedded destinations could not be evaluated for this input.'}</span></div>` : '<p class="xray-boundary">These destinations were found in the URL text. Whether the site uses them for a redirect is unverified.</p>'}${a.limitsReached ? '<div class="limit-warning">Inspection reached a limit. Some content remains unchecked; review is required.</div>' : ''}</article></div><aside class="result-side"><article class="explanation-card"><div class="panel-heading"><h3>${icon('spark')}Why this matters</h3><button id="read-aloud" class="icon-button" aria-label="Read explanation aloud using a local voice">${icon('audio')}</button></div><div class="explanation-label">${matching ? `${escape(matching.ruleId)} · ${escape(matching.title)}` : 'The rule-based explanation'}</div><p id="plain-explanation">${escape(matching?.explanation || a.summary)}</p><div class="next-step"><span class="section-eyebrow">YOUR NEXT STEP</span><p id="next-step-text">${escape(a.action)}</p></div><div class="ai-section"><div class="ai-section-title"><span>${icon('spark')}Explain with local AI</span><span class="optional-label">OPTIONAL</span></div><p>Ask an on-device model to explain these findings in everyday language.</p><button id="ai-check" class="secondary-button">Check local AI ${icon('arrow')}</button><div id="ai-options" hidden><label for="ai-model">Local model</label><select id="ai-model"></select><label for="ai-language">Explanation language</label><select id="ai-language"><option>English</option><option>Hindi</option></select><button id="ai-explain" class="primary-button">Explain these findings ${icon('spark')}</button></div><p id="ai-status" class="ai-status" role="status">No model contacted. The explanation above comes from fixed rules.</p><div id="ai-output" class="ai-output" hidden><span class="section-eyebrow">LOCAL AI EXPLANATION</span><p id="ai-explanation-text"></p><small id="ai-model-label"></small><p class="ai-boundary">The verdict and recommended action remain those of the rules engine.</p></div></div></article><div id="source-caution">${sourceCaution(a)}</div><article class="quiet-card"><span class="feature-icon teal small">${icon('shield')}</span><div><strong>Your link stayed on this device.</strong><p>No website visit. No reputation lookup. No saved URL history.</p></div></article></aside></div><section class="panel rules-panel"><div class="panel-heading"><div><div class="section-eyebrow">THE EVIDENCE BEHIND THE VERDICT</div><h3>Every rule, accounted for.</h3></div><span class="policy-tag">Policy ${escape(a.policyVersion)}</span></div><p class="rules-intro">Strong warning → Suspicious. Review finding or two independent weak signals → Review. Otherwise → Safe.</p><div id="rules-list" class="rules-list">${a.checks.map(c => `<details class="rule-row ${c.state}"><summary><span class="rule-id">${escape(c.id)}</span><span class="rule-name">${escape(c.name)}</span><span class="rule-state ${c.state === 'triggered' ? escape(c.severity) : ''}">${c.state === 'triggered' ? c.severity === 'weak' ? 'Weak signal' : c.severity === 'info' ? 'Information' : 'Triggered' : c.state === 'not-triggered' ? 'Not triggered' : c.state === 'not-applicable' ? 'Not applicable' : 'Not evaluated'}</span>${icon('chevron')}</summary><p>${escape(c.explanation)}</p></details>`).join('')}</div>${a.findings.some(f => !a.checks.some(c => c.id === f.ruleId)) ? `<div class="additional-findings"><h4>Additional findings</h4>${a.findings.filter(f => !a.checks.some(c => c.id === f.ruleId)).map(f => `<div><span class="rule-id">${escape(f.ruleId)}</span><p><strong>${escape(f.title)}</strong><br>${escape(f.explanation)}</p></div>`).join('')}</div>` : ''}</section>`;
  el('policy-version').textContent = `Active policy: ${a.policyVersion}. Explanations and findings show the exact rules used.`;
  el('copy-host')?.addEventListener('click', async () => { try { await navigator.clipboard.writeText(p?.hostname || ''); toast('Hostname copied.'); } catch { toast('Clipboard unavailable. Select and copy the hostname above.'); } });
  el('read-aloud').addEventListener('click', readAloud);
  el('ai-check').addEventListener('click', checkAi);
  el('ai-explain').addEventListener('click', explainAi);
  if (aiStatus) displayAiStatus(aiStatus);
}
source.addEventListener('change', () => { if (current) { el('source-caution').innerHTML = sourceCaution(current); announce('Source context updated. The URL verdict is unchanged.'); } });

function readAloud() {
  if (!current || !('speechSynthesis' in window)) { toast('Speech is unavailable. The explanation is available as accessible text.'); return; }
  const voice = window.speechSynthesis.getVoices().find(v => v.localService && /^en\b/i.test(v.lang));
  if (!voice) { toast('No local English voice is available. No remote voice will be used.'); return; }
  window.speechSynthesis.cancel(); const utterance = new SpeechSynthesisUtterance(current.accessibleSummary); utterance.voice = voice; utterance.lang = voice.lang; utterance.rate = 0.95; window.speechSynthesis.speak(utterance);
}

function displayAiStatus(status: AiStatus) {
  const statusText = el('ai-status'); if (!statusText) return;
  statusText.textContent = status.message; el('ai-options').hidden = !status.available || !status.models.length;
  const model = el<HTMLSelectElement>('ai-model'); model.replaceChildren(...status.models.map(name => { const option = document.createElement('option'); option.value = name; option.textContent = name; return option; }));
  const preferred = status.models.find(name => name.startsWith('llama3.2'));
  if (preferred) model.value = preferred;
  el('ai-check').textContent = status.available ? 'Refresh local models' : 'Check again';
}
async function checkAi() {
  const rev = resultRevision;
  const button = el<HTMLButtonElement>('ai-check'); button.disabled = true; el('ai-status').textContent = 'Checking the local model service…';
  const controller = new AbortController(); currentAiRequest?.abort(); currentAiRequest = controller;
  const timer = setTimeout(() => controller.abort(), 7000);
  try { const response = await fetch('/api/ai/status', { signal: controller.signal, cache: 'no-store' }); if (!response.ok) throw new Error('Unavailable'); const data = await response.json() as AiStatus; if (!Array.isArray(data.models) || typeof data.available !== 'boolean') throw new Error('Invalid'); if (rev !== resultRevision) return; aiStatus = data; displayAiStatus(data); }
  catch { if (rev === resultRevision) { aiStatus = { available: false, models: [], message: 'Local AI is unavailable. Start the local PhishLens server and an installed on-device model. The fixed-rule explanation remains available.' }; displayAiStatus(aiStatus); } }
  finally { clearTimeout(timer); if (rev === resultRevision) button.disabled = false; }
}
async function explainAi() {
  if (!current || !aiStatus?.available) return;
  const rev = resultRevision; const a = current;
  const language = el<HTMLSelectElement>('ai-language').value;
  const button = el<HTMLButtonElement>('ai-explain'); button.disabled = true;
  el('ai-status').textContent = 'The local model is explaining the findings. The verdict is already final.';
  el('ai-output').hidden = true;
  const controller = new AbortController(); currentAiRequest?.abort(); currentAiRequest = controller; const timer = setTimeout(() => controller.abort(), 90000);
  try {
    const response = await fetch('/api/ai/explain', { method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: controller.signal, body: JSON.stringify({ model: el<HTMLSelectElement>('ai-model').value, language: el<HTMLSelectElement>('ai-language').value, verdict: a.verdict, host: a.parts?.hostname || '', findings: a.findings.map(({ ruleId, title, severity, explanation, action }) => ({ ruleId, title, severity, explanation, action })) }) });
    const data = await response.json(); if (!response.ok || typeof data.explanation !== 'string' || data.generated !== true) throw new Error(typeof data.error === 'string' ? data.error : 'The local model did not return a generated explanation.');
    if (rev !== resultRevision) return;
    el('ai-explanation-text').textContent = data.explanation; el('ai-explanation-text').lang = language === 'Hindi' ? 'hi' : 'en'; el('ai-model-label').textContent = `Generated locally with ${String(data.model || 'the selected model')}. AI wording may be imperfect; the exact rule evidence is shown below.`; el('ai-output').hidden = false; el('ai-status').textContent = 'Explanation complete. The rule-based verdict and next step are unchanged.'; announce('Local AI explanation ready. The rule-based verdict is unchanged.');
  } catch (error) { if (rev === resultRevision) el('ai-status').textContent = error instanceof Error && error.name !== 'AbortError' ? `${error.message} The fixed-rule explanation above remains available in English.` : 'The local model took too long or was stopped. The fixed-rule explanation above remains available in English.'; }
  finally { clearTimeout(timer); if (rev === resultRevision) button.disabled = false; }
}

async function handleQr(file: File) {
  const rev = ++qrRevision; el('qr-status').textContent = 'Decoding the image on this device…'; el<HTMLButtonElement>('analyze-button').disabled = true; showError('');
  try { const text = await decodeQr(file); if (rev !== qrRevision) return; input.value = text; el('qr-status').textContent = 'QR decoded locally. The extracted text is ready for inspection.'; setMode('url'); inspect(); announce('QR image decoded locally. ' + (current?.accessibleSummary || '')); }
  catch (error) { if (rev === qrRevision) el('qr-status').textContent = error instanceof Error ? error.message : 'No readable QR code was found. Try a clearer image.'; }
  finally { if (rev === qrRevision) el<HTMLButtonElement>('analyze-button').disabled = inputMode === 'qr' && !input.value.trim(); }
}
el<HTMLInputElement>('qr-file').addEventListener('change', e => { const file = (e.target as HTMLInputElement).files?.[0]; if (file) void handleQr(file); });
const drop = el('qr-drop');
drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('dragging'); });
drop.addEventListener('dragleave', () => drop.classList.remove('dragging'));
drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('dragging'); const file = e.dataTransfer?.files[0]; if (file) void handleQr(file); });

const demoPresets = [PRESETS.find(p => p.category.toLowerCase().includes('ordinary')), PRESETS.find(p => p.category.toLowerCase().includes('unusual')), PRESETS.find(p => p.url.includes('@')), PRESETS.find(p => p.url.includes('?next=') && p.expected === 'suspicious'), PRESETS.find(p => p.url.includes('short.example'))].filter((p): p is Preset => Boolean(p));
const demoBoundaries = [0, 20000, 40000, 65000, 95000, 120000];
let demoTimer: ReturnType<typeof setInterval> | null = null;
let demoElapsed = 0;
let demoLastTick = 0;
let demoIndex = -1;
let demoActive = false;
let demoPaused = false;
function updateDemo() {
  if (!demoActive) return;
  const time = performance.now(); if (!demoPaused) demoElapsed += time - demoLastTick; demoLastTick = time;
  if (demoElapsed >= 120000) { stopDemo(true); return; }
  const index = Math.min(demoPresets.length - 1, demoBoundaries.findIndex((b, i) => i > 0 && demoElapsed < b) - 1);
  if (index >= 0 && index !== demoIndex) { demoIndex = index; source.value = index === 4 ? 'sticker' : 'unknown'; choosePreset(demoPresets[index]!, true); el('demo-title').textContent = `Step ${index + 1} of ${demoPresets.length} · ${demoPresets[index]!.label}`; el('demo-description').textContent = demoPresets[index]!.description; }
  const s = Math.floor(demoElapsed / 1000); el('demo-time').textContent = `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} / 2:00`; el('demo-progress').style.width = `${demoElapsed / 1200}%`;
}
function playDemo() {
  if (!demoPresets.length) return;
  stopDemo(false); demoActive = true; demoPaused = false; demoElapsed = 0; demoIndex = -1; demoLastTick = performance.now();
  el('demo-play').hidden = true; el('demo-pause').hidden = false; el('demo-stop').hidden = false; el('demo-time').hidden = false; el('demo-pause').textContent = 'Pause'; el('demo-bar').classList.add('playing'); updateDemo(); demoTimer = setInterval(updateDemo, 250); announce('Two-minute demo started. Use Pause or Stop at any time.');
}
function stopDemo(completed: boolean) {
  if (demoTimer) clearInterval(demoTimer); demoTimer = null;
  const wasActive = demoActive; demoActive = false; demoPaused = false;
  el('demo-play').hidden = false; el('demo-pause').hidden = true; el('demo-stop').hidden = true; el('demo-time').hidden = !completed; el('demo-bar').classList.remove('playing'); el('demo-progress').style.width = completed ? '100%' : '0%';
  el('demo-title').textContent = completed ? 'Demo complete. Every finding has a reason.' : 'See the difference in 2 minutes'; el('demo-description').textContent = completed ? 'Explore the full library to try more edge cases.' : 'Ordinary, disguised, hidden and uncertain destinations.';
  if (completed) { el('demo-time').textContent = '2:00 / 2:00'; announce('Two-minute demo complete.'); }
  else if (wasActive) announce('Demo stopped.');
}
el('demo-play').addEventListener('click', playDemo);
el('demo-pause').addEventListener('click', () => { demoPaused = !demoPaused; demoLastTick = performance.now(); el('demo-pause').textContent = demoPaused ? 'Resume' : 'Pause'; announce(demoPaused ? 'Demo paused.' : 'Demo resumed.'); });
el('demo-stop').addEventListener('click', () => stopDemo(false));
emptyState();
