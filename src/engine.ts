import { parse as parseDomain } from 'tldts';
import { toUnicode } from 'punycode/';
import { POLICY } from './policy';
import type { Analysis, DestinationNode, Finding, RuleCheck, Severity, UrlParts, UrlSegment, Verdict } from './types';

const RULES = [
  ['R1', 'Scheme'], ['R2', 'Misleading user information'], ['R3', 'IP and local addresses'],
  ['R4', 'International hostname characters'], ['R5', 'Campus name impersonation'],
  ['R6', 'Shortened destination'], ['R7', 'Embedded destinations'], ['R8', 'Hostname complexity'],
  ['R9', 'Sign-in wording'], ['R10', 'Unencrypted sign-in'], ['P1', 'Parsing and normalization'],
  ['F1', 'Similar domain spelling'],
] as const;
const SIGN_IN = /(?:^|[^a-z0-9])(?:login|log-in|signin|sign-in|sign_in|signon|sign-on|password|passwd|authenticate|authentication|auth|sso|verify-account)(?:$|[^a-z0-9])/i;
const REDIRECT_KEY = /^(?:next|url|uri|redirect|redirect_?uri|redirect_?url|redirect_?to|return|return_?to|return_?url|continue|destination|dest|target|callback|callback_?url|goto|link)$/i;
const SECRET_KEY = /^(?:password|passwd|pwd|token|access_?token|refresh_?token|id_?token|secret|api[_-]?key|authorization|session(?:id)?|code)$/i;
const CONTROLS = /[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/;
const DEFAULT_ACTION = 'Confirm that this is the destination you intended. A structural check cannot verify website ownership or content.';
const REVIEW_ACTION = 'Confirm the full destination with the sender or your institution’s official service directory before entering information.';
const SUSPICIOUS_ACTION = 'Avoid entering credentials or downloading files through this link. Confirm the official address through a trusted campus source.';
type Context = { candidates: number; limitsReached: boolean; ancestors: Set<string> };

function visible(value: string): string {
  return value.replace(/[\u0000-\u001f\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]/g,
    c => `[U+${c.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}]`);
}
function decode(value: string): string {
  try { return decodeURIComponent(value); } catch { return value; }
}
function hostKey(host: string): string { return host.toLowerCase().replace(/\.+$/, ''); }
function isTrusted(host: string): boolean {
  const normalized = hostKey(host);
  return POLICY.trustedDomains.some(domain => normalized === domain || (POLICY.trustSubdomains && normalized.endsWith(`.${domain}`)));
}
function registrable(host: string): string | null {
  const normalized = hostKey(host);
  if (normalized.endsWith('.example')) return normalized.split('.').slice(-2).join('.');
  return parseDomain(normalized, { allowPrivateDomains: true }).domain;
}
function unicodeHost(host: string): string {
  try { return toUnicode(host); } catch { return host; }
}
function identity(host: string): string {
  const domain = registrable(host);
  return domain ? unicodeHost(domain).split('.')[0]! : '';
}
function scopeV4(host: string): UrlParts['ipScope'] {
  const [a = 0, b = 0, c = 0] = host.split('.').map(Number);
  if (a === 127) return 'loopback';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) return 'private';
  if ((a === 192 && b === 0 && c === 2) || (a === 198 && b === 51 && c === 100) || (a === 203 && b === 0 && c === 113)) return 'documentation';
  if (a === 0 || a >= 224 || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || (a === 198 && (b === 18 || b === 19))) return 'other';
  return 'public';
}
function ipInfo(host: string): { isIp: boolean; scope: UrlParts['ipScope'] } {
  const normalized = hostKey(host);
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(normalized)) return { isIp: true, scope: scopeV4(normalized) };
  if (normalized.startsWith('[') && normalized.endsWith(']')) {
    const address = normalized.slice(1, -1);
    const halves = address.split('::');
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves[1] ? halves[1].split(':') : [];
    const words = halves.length === 2 ? [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right] : left;
    const nums = words.map(word => Number.parseInt(word, 16));
    if (nums.slice(0, 5).every(n => n === 0) && nums[5] === 0xffff) {
      const v4 = [nums[6]! >> 8, nums[6]! & 255, nums[7]! >> 8, nums[7]! & 255].join('.');
      return { isIp: true, scope: scopeV4(v4) };
    }
    if (nums.slice(0, 7).every(n => n === 0) && nums[7] === 1) return { isIp: true, scope: 'loopback' };
    if (nums.every(n => n === 0) || (nums[0]! & 0xffc0) === 0xfe80 || (nums[0]! & 0xff00) === 0xff00) return { isIp: true, scope: 'other' };
    if ((nums[0]! & 0xfe00) === 0xfc00) return { isIp: true, scope: 'private' };
    if (nums[0] === 0x2001 && nums[1] === 0xdb8) return { isIp: true, scope: 'documentation' };
    return { isIp: true, scope: 'public' };
  }
  if (normalized === 'localhost' || normalized.endsWith('.localhost')) return { isIp: false, scope: 'loopback' };
  return { isIp: false, scope: null };
}

/** Small reviewed mapping, deliberately not a claim of complete Unicode confusable coverage. */
function skeleton(value: string): string {
  const mapping: Record<string, string> = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x', 'у': 'y', 'і': 'l', 'ј': 'j', 'ѕ': 's',
    'α': 'a', 'ο': 'o', 'ρ': 'p', 'υ': 'u', 'ν': 'u', 'ι': 'l', 'κ': 'k', 'τ': 't',
    '0': 'o', '1': 'l', 'i': 'l', '3': 'e', '4': 'a', '5': 's', '8': 'b', '9': 'g', 'v': 'u',
  };
  return Array.from(value.toLowerCase().normalize('NFKC')).map(c => mapping[c] ?? c).join('').replace(/rn/g, 'm').replace(/vv/g, 'w');
}
function levenshtein(a: string, b: string): number {
  if (Math.abs(a.length - b.length) > 2) return 3;
  let prior = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const next = [i];
    for (let j = 1; j <= b.length; j++) next[j] = Math.min(next[j - 1]! + 1, prior[j]! + 1, prior[j - 1]! + (a[i - 1] === b[j - 1] ? 0 : 1));
    prior = next;
  }
  return prior[b.length]!;
}

function looseRedact(value: string): string {
  return value.replace(/((?:[a-z][a-z0-9+.-]*:)?[\\/]{2})([^\s/?#\\]*)/gi, (_whole, start: string, authority: string) => {
    const at = authority.lastIndexOf('@');
    if (at < 0) return start + authority;
    const user = authority.slice(0, at);
    const colon = user.indexOf(':');
    return start + (colon >= 0 ? `${user.slice(0, colon)}:[redacted]` : user) + authority.slice(at);
  }).replace(/^([^\s/?#@:]+):([^\s/?#@]+)@/, '$1:[redacted]@');
}

function signInWording(url: URL): string {
  const scalarValues: string[] = [];
  for (const [key, value] of url.searchParams) {
    if (SECRET_KEY.test(key)) continue;
    let decoded = value;
    for (let pass = 0; pass < POLICY.limits.maxExtraDecodes; pass++) {
      const next = decode(decoded); if (next === decoded) break; decoded = next;
    }
    // An embedded URL has its own checks. Do not attribute its login path to the outer host.
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|\.\.?\/|\/)/i.test(decoded) || /%[0-9a-f]{2}/i.test(decoded)) continue;
    scalarValues.push(decoded);
  }
  return decode([url.hostname, url.pathname, ...url.searchParams.keys(), ...scalarValues].join('/'));
}

/** Presentation-only scrubber. Detection always operates on the original parsed object. */
function displayUrl(url: URL, depth = 0): { text: string; query: string; redacted: boolean } {
  const copy = new URL(url.href);
  let redacted = false;
  if (copy.password) { copy.password = 'REDACTED'; redacted = true; }
  const cleanParams = new URLSearchParams();
  let queryChanged = false;
  for (const [key, rawValue] of copy.searchParams) {
    let value = rawValue;
    let valueRedacted = false;
    if (SECRET_KEY.test(key)) { value = '[redacted]'; queryChanged = true; redacted = true; }
    else {
      for (let pass = 0; pass <= POLICY.limits.maxExtraDecodes; pass++) {
        const scrubbed = looseRedact(value);
        if (scrubbed !== value) { value = scrubbed; valueRedacted = true; break; }
        if (/^(?:https?|ftp):\/\//i.test(value) || value.startsWith('//')) {
          try {
            if (depth < 3) {
              const child = displayUrl(new URL(value, copy), depth + 1);
              if (child.redacted) { value = child.text; valueRedacted = true; }
            } else if (/[?@:]/.test(value)) { value = '[nested value omitted]'; valueRedacted = true; }
          } catch { /* Malformed text is handled by the checker, never executed. */ }
          break;
        }
        const decoded = decode(value);
        if (decoded === value) break;
        value = decoded;
      }
      if (valueRedacted) { redacted = true; queryChanged = true; }
      else value = rawValue;
    }
    cleanParams.append(key, value);
  }
  if (queryChanged) copy.search = cleanParams.toString();
  return { text: visible(copy.href), query: visible(copy.search), redacted };
}

function aggregate(findings: Finding[]): Verdict {
  if (findings.some(f => f.severity === 'suspicious')) return 'suspicious';
  if (findings.some(f => f.severity === 'review') || new Set(findings.filter(f => f.severity === 'weak').map(f => f.ruleId)).size >= 2) return 'review';
  return 'safe';
}
function actionFor(verdict: Verdict): string { return verdict === 'suspicious' ? SUSPICIOUS_ACTION : verdict === 'review' ? REVIEW_ACTION : DEFAULT_ACTION; }
function pronounce(host: string): string { return visible(host).replace(/\./g, ' dot ').replace(/-/g, ' hyphen '); }
function emptyChecks(): RuleCheck[] { return RULES.map(([id, name]) => ({ id, name, state: 'not-evaluated', severity: 'info', explanation: 'The URL has not been parsed sufficiently to run this check.' })); }

function analyze(input: string, context: Context, depth: number): Analysis {
  const findings: Finding[] = [];
  const checks = emptyChecks();
  const notes: string[] = [];
  const nodes: DestinationNode[] = [];
  const add = (ruleId: string, severity: Severity, title: string, component: string, evidence: string, explanation: string, action = REVIEW_ACTION) => {
    findings.push({ ruleId, severity, title, component, evidence: visible(evidence), explanation, action });
    const check = checks.find(c => c.id === ruleId)!;
    check.state = 'triggered';
    if ({ info: 0, safe: 0, weak: 1, review: 2, suspicious: 3 }[severity] >= { info: 0, safe: 0, weak: 1, review: 2, suspicious: 3 }[check.severity]) {
      check.severity = severity; check.explanation = explanation;
    }
  };
  const mark = (id: string, explanation: string, state: RuleCheck['state'] = 'not-triggered') => {
    const check = checks.find(c => c.id === id)!;
    if (check.state !== 'triggered') { check.state = state; check.explanation = explanation; }
  };
  const parseNote = (message: string) => { notes.push(message); add('P1', 'review', 'Parsing needs attention', 'input', 'Input interpretation changed or is incomplete', message); };
  const finish = (parts: UrlParts | null, original: string, normalized: string, segments: UrlSegment[], limited = false): Analysis => {
    const verdict = aggregate(findings);
    const weak = findings.find(f => f.severity === 'weak');
    const decisive = findings.find(f => f.severity === verdict) ?? ((verdict === 'review' || verdict === 'safe') ? weak : undefined);
    const summary = verdict === 'safe' && weak ? 'A weak signal was found, but no review threshold was reached. Website safety remains unverified.' : decisive?.explanation ?? 'No configured warning signs were found. This does not establish that the destination is trustworthy.';
    const accessibleSummary = `${verdict[0]!.toUpperCase() + verdict.slice(1)}. ${parts?.hostname ? `Actual host: ${pronounce(parts.hostname)}. ` : 'No web hostname could be established. '}${summary} ${actionFor(verdict)}`;
    return { original, normalized, verdict, decisiveRule: decisive?.ruleId ?? 'NONE', summary, action: actionFor(verdict), accessibleSummary,
      parts, segments, findings, checks, destinations: nodes, normalizationNotes: notes, policyVersion: POLICY.version, limitsReached: limited || context.limitsReached };
  };

  if (new TextEncoder().encode(input).length > POLICY.limits.maxInputBytes) {
    context.limitsReached = true;
    parseNote(`Input exceeds the ${POLICY.limits.maxInputBytes}-byte inspection limit. Nothing beyond this limit was analyzed.`);
    const scheme = input.trimStart().match(/^([a-z][a-z0-9+.-]*):/i)?.[1]?.toLowerCase();
    if (scheme && ['javascript', 'data', 'file', 'vbscript'].includes(scheme)) add('R1', 'suspicious', 'Active or local-data scheme', 'scheme', scheme, `The ${scheme}: scheme can invoke code or local data rather than an ordinary web page.`, SUSPICIOUS_ACTION);
    return finish(null, '[Input omitted: inspection limit exceeded]', '', [], true);
  }
  let text = input.trim();
  if (!text) { parseNote('Paste an absolute URL to inspect. Empty text has no destination.'); return finish(null, '', '', []); }
  if (text !== input) notes.push('Leading and trailing whitespace was removed before parsing.');
  if (CONTROLS.test(input)) parseNote('Control or directional formatting characters were found. Their visible U+ codes are shown because they can change how a URL is read.');
  if (text.includes('\\')) parseNote('Backslashes were interpreted using browser URL rules. Read the normalized host carefully.');
  if (/%(?![0-9a-f]{2})/i.test(text)) parseNote('The input contains a malformed percent escape. Its displayed text may not match the sender’s intended encoding.');
  const schemeMatch = text.match(/^([a-z][a-z0-9+.-]*):/i);
  const looksHostPort = /^(?:[^\s/?#:]+\.[^\s/?#:]+|localhost|\[[^\]]+\]):\d+(?:[/?#]|$)/i.test(text);
  if (text.startsWith('//')) {
    parseNote('No scheme was supplied. HTTPS is a provisional interpretation, not a confirmed original URL.'); text = `https:${text}`;
  } else if (!schemeMatch || looksHostPort) {
    if (/^(?:[^\s/?#:@]+\.[^\s/?#:@]+|localhost|\[[^\]]+\])(?::\d+)?(?:[/?#]|$)/i.test(text) || /^[^\s/?#]+@[^\s/?#]+\.[^\s/?#]+/.test(text)) {
      parseNote('No scheme was supplied. HTTPS is a provisional interpretation, not a confirmed original URL.'); text = `https://${text}`;
    } else {
      parseNote('This text is not an absolute URL. A relative path or plain word needs a known base address, which was not supplied.');
      return finish(null, '[Unresolved input: edit the original text in the input field]', '', []);
    }
  }
  const scheme = text.match(/^([a-z][a-z0-9+.-]*):/i)?.[1]?.toLowerCase() ?? '';
  if (['javascript', 'data', 'file', 'vbscript'].includes(scheme)) {
    add('R1', 'suspicious', 'Active or local-data scheme', 'scheme', `${scheme}:`,
      scheme === 'file' ? 'A file: URL refers to a local or network file rather than an ordinary web page.' : `A ${scheme}: URL can represent executable or embedded content rather than an ordinary web page.`, SUSPICIOUS_ACTION);
  } else if (!['http', 'https'].includes(scheme)) add('R1', 'review', 'Non-web scheme', 'scheme', `${scheme}:`, `The ${scheme}: scheme may invoke another application. This checker cannot establish an ordinary web destination for it.`);
  else mark('R1', 'HTTP or HTTPS web scheme; this alone does not establish safety.');
  if (['http', 'https'].includes(scheme) && !/^https?:\/\/[^/]/i.test(text)) parseNote('The web scheme was written without its normal // authority separator. The browser parser supplied a normalized interpretation.');
  let url: URL;
  try { url = new URL(text); } catch {
    parseNote('The browser URL parser rejected this address. No reliable destination or valid port could be established.');
    return finish(null, '[Unparseable input: edit the original text in the input field]', '', []);
  }
  const host = url.hostname;
  const canonicalHost = hostKey(host);
  const internationalHost = unicodeHost(host);
  const trusted = isTrusted(host);
  const ip = ipInfo(host);
  const domain = ip.isIp ? null : registrable(host);
  const web = ['http:', 'https:'].includes(url.protocol);
  const hostMeaningful = Boolean(host);
  const username = visible(decode(url.username));
  const rawAuthority = text.match(/^[a-z][a-z0-9+.-]*:\/\/([^/?#]*)/i)?.[1] ?? '';
  const rawHostPort = rawAuthority.slice(rawAuthority.lastIndexOf('@') + 1);
  const rawPort = !rawHostPort.includes('\\') ? rawHostPort.match(/:(\d+)$/)?.[1] ?? '' : '';
  const effectivePort = url.port || (url.protocol === 'https:' ? '443' : url.protocol === 'http:' ? '80' : url.protocol === 'ftp:' ? '21' : '');
  const explicitPort = rawPort && Number(rawPort) === Number(effectivePort) ? rawPort : url.port;
  if (rawHostPort.includes('%')) parseNote('Percent-encoded text in the authority was decoded by the browser parser. The normalized hostname is the destination used for checks.');
  if (host.endsWith('.')) parseNote('A trailing hostname dot was retained for display and ignored only for domain comparison. Confirm the intended address.');
  if (ip.isIp && !host.startsWith('[') && rawHostPort.replace(/:\d+$/, '') !== host) parseNote('A numeric IPv4 spelling was normalized to dotted decimal. The normalized IP address is the actual host.');
  if (/:(?:80|443)$/.test(rawHostPort) && !url.port) notes.push('The explicit default port was removed by the browser parser; the effective port is shown separately.');
  if (/[^\x00-\x7f]/.test(internationalHost)) notes.push('The hostname is shown in both Unicode and the browser’s ASCII/Punycode representation.');
  if (url.href !== text && !notes.length) notes.push('The browser parser normalized case, escaping, or the empty path.');

  if (url.username || url.password) {
    const possibleBait = username.toLowerCase();
    const domainShape = /^(?:[a-z0-9-]+\.)+[a-z0-9-]+$/i.test(possibleBait);
    const userDomain = domainShape ? parseDomain(possibleBait) : null;
    const bait = POLICY.trustedDomains.some(t => possibleBait.includes(t)) || (domainShape && (possibleBait.endsWith('.example') || userDomain?.isIcann));
    add('R2', bait ? 'suspicious' : 'review', bait ? 'A domain name appears before @' : 'User information in the URL', 'userinfo', `${username || '(empty username)'}${url.password ? ':[redacted]' : ''}@`,
      bait ? `The text before @ resembles a hostname, but the actual host is ${visible(host)}. User information does not select the destination.` : 'This URL contains user information before @. That field does not establish the destination; any password value is hidden.', bait ? SUSPICIOUS_ACTION : REVIEW_ACTION);
  } else mark('R2', 'No username or password appears in the authority.');

  if (!hostMeaningful) {
    for (const id of ['R3', 'R4', 'R5', 'R6', 'R8', 'R9', 'F1']) mark(id, 'This parsed URL has no hostname to evaluate.', 'not-applicable');
  } else {
    const wording = signInWording(url);
    const signIn = SIGN_IN.test(wording);
    if (ip.isIp || ip.scope === 'loopback') {
      const strong = signIn && (ip.scope === 'public' || ip.scope === 'documentation');
      add('R3', strong ? 'suspicious' : 'review', 'Numeric or local destination', 'hostname', `${host} (${ip.scope})`,
        strong ? `The ${ip.scope} IP address is combined with sign-in wording. This is a strong warning under this policy, not proof of a malicious page.` : `This is a ${ip.scope} address. It may be an internal service, but its address alone does not verify who operates it.`, strong ? SUSPICIOUS_ACTION : REVIEW_ACTION);
    } else mark('R3', 'The hostname is not an IP address or localhost address.');

    const idLabel = identity(host);
    const unicode = /[^\x00-\x7f]/.test(internationalHost) || /(?:^|\.)xn--/i.test(host);
    const visualMatch = !trusted && idLabel ? POLICY.trustedDomains.find(t => identity(t) !== idLabel && skeleton(identity(t)) === skeleton(idLabel)) : undefined;
    if (unicode) {
      add('R4', visualMatch ? 'suspicious' : 'review', visualMatch ? 'International lookalike of a configured domain' : 'International hostname', 'hostname', `${internationalHost} | ${host}`,
        visualMatch ? `The identity label visually resembles ${visualMatch} under the configured confusable mapping. Its actual ASCII hostname is ${visible(host)}.` : 'This hostname uses international characters or Punycode. These are legitimate features; verify the spelling because visual similarities can be difficult to notice.', visualMatch ? SUSPICIOUS_ACTION : REVIEW_ACTION);
    } else mark('R4', 'No international hostname or Punycode was found.');

    if (trusted) mark('R5', 'The hostname matches a configured domain at an exact dot boundary. This does not exempt embedded destinations or transport checks.');
    else {
      const hostLabels = canonicalHost.split('.');
      const baitDomain = POLICY.trustedDomains.find(t => canonicalHost.startsWith(`${t}.`) || canonicalHost.includes(`.${t}.`));
      const namedLabel = POLICY.trustedDomains.find(t => {
        const name = identity(t);
        return hostLabels.some(label => new RegExp(`^(?:${name}-(?:login|signin|secure|verify|account|portal|auth)|(?:login|signin|secure|verify|account|portal|auth)-${name})$`).test(label));
      });
      if (baitDomain || namedLabel || (visualMatch && !unicode)) add('R5', 'suspicious', 'Configured campus identity imitated', 'hostname', `${internationalHost} ≠ ${baitDomain ?? namedLabel ?? visualMatch}`,
        baitDomain ? `${baitDomain} appears inside a longer hostname whose main domain is ${domain ?? host}. Familiar text in a subdomain does not make it that institution’s domain.` : visualMatch ? `${internationalHost} visually resembles ${visualMatch} under the configured character mapping, but it is a different hostname.` : `The hostname combines a configured campus name with an account or sign-in term, outside the configured domain boundary.`, SUSPICIOUS_ACTION);
      else if (idLabel && POLICY.trustedDomains.some(t => identity(t) === idLabel)) add('R5', 'review', 'Familiar name on a different domain', 'hostname', host, 'The main-domain name matches a configured campus name, but its suffix is different. Confirm the complete official domain.');
      else mark('R5', 'No configured strong campus-name impersonation pattern was found.');
    }

    if (POLICY.shorteners.some(s => canonicalHost === s || canonicalHost === `www.${s}`)) add('R6', 'review', 'Final destination hidden by a short link', 'hostname', host, 'This is a locally listed short-link host. Its final destination is unknown because the checker does not follow links.');
    else mark('R6', 'The host is absent from the bundled shortener list. Unlisted shorteners cannot be identified reliably offline.');

    if (!trusted && !ip.isIp && (host.split('.').length >= 5 || host.split('.').some(label => (label.match(/-/g) ?? []).length >= 3))) add('R8', 'weak', 'Complex hostname', 'hostname', host, 'The unfamiliar hostname is deep or contains many hyphens. This is only a weak signal; ordinary services can use the same structure.');
    else mark('R8', trusted ? 'Cosmetic depth and hyphen warnings are skipped for configured campus subdomains.' : 'No configured hostname-complexity threshold was reached.');
    if (signIn && !trusted && !ip.isIp && ip.scope !== 'loopback') add('R9', 'weak', 'Sign-in wording on an unfamiliar host', 'path or hostname', 'A bounded sign-in token appears in the URL', 'The URL contains sign-in wording on a host outside the configured campus list. Wording alone does not show what the page actually asks for.');
    else mark('R9', trusted ? 'This host is within the configured campus boundary; sign-in words alone are not a warning.' : 'No independent unfamiliar-host sign-in signal was found.');

    if (trusted || ip.isIp || !idLabel) mark('F1', 'No fuzzy comparison is needed for configured domains, IP addresses, or hosts without an identity label.', 'not-applicable');
    else {
      const match = POLICY.trustedDomains.map(t => ({ domain: t, label: identity(t), distance: levenshtein(idLabel, identity(t)) }))
        .filter(m => m.distance > 0 && m.distance <= 2 && Math.min(idLabel.length, m.label.length) >= 5 && m.distance / Math.max(idLabel.length, m.label.length) <= 0.34).sort((a, b) => a.distance - b.distance)[0];
      if (match) add('F1', 'review', 'Similar spelling to a configured domain', 'main domain', `${idLabel} ↔ ${match.label}; ${match.distance} edit${match.distance === 1 ? '' : 's'}`,
        `The main-domain label “${visible(idLabel)}” differs from “${match.label}” by ${match.distance} character edit${match.distance === 1 ? '' : 's'}. Similarity alone does not prove impersonation.`);
      else mark('F1', 'No length-qualified distance of one or two edits from a configured identity label was found.');
    }
  }
  const transportWording = signInWording(url);
  if (url.protocol === 'http:' && SIGN_IN.test(transportWording)) add('R10', 'review', 'Sign-in wording over HTTP', 'scheme', 'http: + sign-in wording', 'This URL combines sign-in wording with unencrypted HTTP. If credentials are entered over this connection, they may be exposed. Trust-list membership does not remove this concern.');
  else mark('R10', web ? 'No combination of HTTP and sign-in wording was found.' : 'This is not an HTTP or HTTPS URL.', web ? 'not-triggered' : 'not-applicable');

  if (url.search && web) {
    const entries = Array.from(url.searchParams.entries());
    const rawValues = url.search.slice(1).split('&').filter(Boolean).map(entry => entry.includes('=') ? entry.slice(entry.indexOf('=') + 1) : '');
    const dedupe = new Set<string>();
    for (const [index, [parameter, initial]] of entries.entries()) {
      if (context.candidates >= POLICY.limits.maxCandidates) { context.limitsReached = true; break; }
      context.candidates++;
      let value = initial.trim();
      let steps = /%[0-9a-f]{2}|\+/i.test(rawValues[index] ?? '') ? 1 : 0;
      let extra = 0;
      while (!/^(?:[a-z][a-z0-9+.-]*:|\/\/)/i.test(value) && extra < POLICY.limits.maxExtraDecodes) {
        const next = decode(value); if (next === value) break; value = next.trim(); steps++; extra++;
      }
      const absolute = /^[a-z][a-z0-9+.-]*:/i.test(value);
      const protocolRelative = value.startsWith('//');
      const relative = REDIRECT_KEY.test(parameter) && /^(?:\/(?!\/)|\.\.?\/)/.test(value);
      if (!absolute && !protocolRelative && !relative) {
        if (extra === POLICY.limits.maxExtraDecodes && /%[0-9a-f]{2}/i.test(value)) {
          context.limitsReached = true;
          add('R7', 'review', 'Decoding inspection is incomplete', 'query', visible(parameter), `A parameter remains percent-encoded after ${POLICY.limits.maxExtraDecodes} additional decoding passes. Further destination text may remain hidden.`);
          continue;
        }
        if (REDIRECT_KEY.test(parameter) && value && (/https?%|%2f|[a-z0-9]\.[a-z]/i.test(value))) {
          add('R7', 'review', 'Unresolved destination-like parameter', 'query', visible(parameter), 'A destination parameter contains address-like text that could not be resolved within the supported decoding rules. Its use by the server is unknown.');
        }
        continue;
      }
      if (dedupe.has(value)) continue;
      dedupe.add(value);
      if (depth >= POLICY.limits.maxDepth) { context.limitsReached = true; break; }
      let childInput = value;
      let resolution = '';
      try {
        if (protocolRelative || relative) { childInput = new URL(value, url).href; resolution = ' Interpreted relative to the outer URL; actual server behavior is unverified.'; }
      } catch { /* Child parser records the failure. */ }
      let key = childInput;
      try { key = new URL(childInput).href; } catch { /* Keep bounded text for cycle comparison. */ }
      if (context.ancestors.has(key)) { context.limitsReached = true; continue; }
      context.ancestors.add(key);
      const child = analyze(childInput, context, depth + 1);
      context.ancestors.delete(key);
      const sameSite = Boolean(child.parts?.hostname && (hostKey(child.parts.hostname) === canonicalHost || (domain && domain === child.parts.domain)));
      nodes.push({ parameter: visible(parameter), host: child.parts?.hostname ?? '(unresolved)', verdict: child.verdict, depth: depth + 1, decodeSteps: steps, sameSite,
        explanation: `Destination text found in the ${visible(parameter)} parameter. This is not a verified redirect.${resolution}`, findings: child.findings, children: child.destinations });
      const severity = child.verdict === 'suspicious' ? 'suspicious' : child.verdict === 'review' || !sameSite || protocolRelative ? 'review' : 'info';
      add('R7', severity, severity === 'suspicious' ? 'A hidden destination has a strong warning' : sameSite && severity === 'info' ? 'Same-site destination text' : 'An additional destination needs review', 'query', `${visible(parameter)} → ${child.parts?.hostname ?? '(unresolved host)'}`,
        severity === 'suspicious' ? `The ${visible(parameter)} parameter contains a destination with a suspicious ${child.decisiveRule} finding. The outer host does not remove that warning; redirect behavior is unverified.` : severity === 'info' ? 'The embedded destination remains within the same registrable domain and has no configured warnings. Whether the server redirects there is unverified.' : 'An embedded destination is external, uncertain, or has a warning of its own. The checker exposes this text without following it; redirect behavior is unverified.', severity === 'suspicious' ? SUSPICIOUS_ACTION : REVIEW_ACTION);
    }
    if (context.limitsReached) add('R7', 'review', 'Embedded inspection is incomplete', 'query', 'Inspection limit reached', `The checker stopped at its bounded inspection limit (${POLICY.limits.maxCandidates} parameter values and ${POLICY.limits.maxDepth} nesting levels). Uninspected text may contain further destinations.`);
    mark('R7', 'No supported embedded destination was found in the inspected query values.');
  } else mark('R7', web ? 'No query parameters are present.' : 'Embedded web-query inspection is not applicable to this scheme.', web ? 'not-triggered' : 'not-applicable');
  mark('P1', 'The browser URL parser established a destination without consequential interpretation warnings.');

  const display = displayUrl(url);
  if (display.redacted) notes.push('Password or sensitive query values are redacted from displayed output. They are not stored.');
  const parts: UrlParts = { scheme: url.protocol.slice(0, -1), username, hasPassword: Boolean(url.password), hostname: visible(host), unicodeHostname: visible(internationalHost), domain,
    port: explicitPort, effectivePort, path: visible(url.pathname), query: display.query, fragment: visible(url.hash), trusted, isIp: ip.isIp, ipScope: ip.scope };
  const segments: UrlSegment[] = hostMeaningful ? [
    { text: `${url.protocol}//`, kind: 'scheme' },
    ...(url.username || url.password ? [{ text: `${username}${url.password ? ':[redacted]' : ''}@`, kind: 'userinfo' as const }] : []),
    { text: visible(host), kind: 'host' },
    ...(url.port ? [{ text: `:${url.port}`, kind: 'plain' as const }] : []),
    { text: `${visible(url.pathname)}${display.query}${visible(url.hash)}`, kind: 'path' },
  ] : [{ text: `${url.protocol}`, kind: 'scheme' }, { text: '[non-web content is not executed]', kind: 'plain' }];
  return finish(parts, display.redacted ? display.text : visible(looseRedact(input)), display.text, segments);
}

/** Pure, synchronous analysis. No fetch, navigation, DNS, persistence, or telemetry. */
export function analyzeUrl(input: string): Analysis {
  const context: Context = { candidates: 0, limitsReached: false, ancestors: new Set() };
  try { context.ancestors.add(new URL(input).href); } catch { /* Provisional parsing is handled inside analyze. */ }
  return analyze(input, context, 0);
}
