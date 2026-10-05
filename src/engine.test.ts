import { describe, expect, it } from 'vitest';
import { analyzeUrl } from './engine';
import { POLICY } from './policy';
import { PRESETS } from './presets';

const has = (input: string, id: string, severity?: string) => analyzeUrl(input).findings.some(f => f.ruleId === id && (!severity || f.severity === severity));
const wrap = (inner: string, parameter = 'next', host = 'portal.campus.example') => `https://${host}/continue?${parameter}=${encodeURIComponent(inner)}`;

describe('specified demonstration outcomes', () => {
  it.each(PRESETS)('$label → $expected', preset => {
    expect(analyzeUrl(preset.url).verdict).toBe(preset.expected);
  });
  it('returns the entire ten-rule checklist plus parsing and edit-distance receipts', () => {
    const result = analyzeUrl(PRESETS[0]!.url);
    expect(result.checks.map(c => c.id)).toEqual(['R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'P1', 'F1']);
    expect(result.checks.every(c => c.state !== 'not-evaluated')).toBe(true);
    expect(result.policyVersion).toBe(POLICY.version);
  });
  it('does not run hostname checks on malformed input', () => {
    const result = analyzeUrl('https://[::1');
    expect(result.parts).toBeNull();
    expect(result.checks.find(c => c.id === 'R3')?.state).toBe('not-evaluated');
    expect(result.decisiveRule).toBe('P1');
  });
});

describe('browser parsing and normalization', () => {
  it.each([
    ['https://campus.example@other.example/login', 'other.example', 'suspicious'],
    ['https://campus.example@library.example@other.example/login', 'other.example', 'suspicious'],
    ['https://other.example/path@campus.example', 'other.example', 'safe'],
    ['https://campus.example?email=me@other.example', 'campus.example', 'safe'],
    ['https://campus.example\\@other.example/login', 'campus.example', 'review'],
    ['https://%63ampus.example/notices', 'campus.example', 'review'],
    ['https://2130706433/login', '127.0.0.1', 'review'],
    ['https://0x7f000001/login', '127.0.0.1', 'review'],
    ['https://127.1/login', '127.0.0.1', 'review'],
    ['campus.example:8443/notices', 'campus.example', 'review'],
    ['//campus.example/notices', 'campus.example', 'review'],
    ['https:campus.example/notices', 'campus.example', 'review'],
    ['https://campus.example./notices', 'campus.example.', 'review'],
    ['https://CAMPUS.EXAMPLE:443/notices', 'campus.example', 'safe'],
    ['https://campus.example/a b', 'campus.example', 'safe'],
    ['https://campus.example/%zz', 'campus.example', 'review'],
  ])('%s → actual %s (%s)', (input, host, verdict) => {
    const result = analyzeUrl(input);
    expect(result.parts?.hostname).toBe(host);
    expect(result.verdict).toBe(verdict);
  });
  it.each(['https://other.example:70000/', 'https://other.example:abc/', '/login', 'just some words', '', 'https://[2001:db8::1/login'])('unresolved %s → Review', input => {
    const result = analyzeUrl(input); expect(result.verdict).toBe('review'); expect(result.parts).toBeNull();
  });
  it('exposes browser normalization and effective default port', () => {
    const result = analyzeUrl('https://campus.example:443/');
    expect(result.parts?.port).toBe('443'); expect(result.parts?.effectivePort).toBe('443');
    expect(result.normalizationNotes.join(' ')).toContain('default port');
  });
  it('marks controls visibly without treating their removal as safe', () => {
    const result = analyzeUrl('https://cam\tpus.example/path');
    expect(result.parts?.hostname).toBe('campus.example'); expect(result.verdict).toBe('review');
    expect(result.original).toContain('[U+0009]');
  });
  it('always renders the actual authority host as the host segment', () => {
    const result = analyzeUrl('https://campus.example@library.example@other.example/notices');
    expect(result.segments.filter(s => s.kind === 'host')).toEqual([{ text: 'other.example', kind: 'host' }]);
    expect(result.segments.find(s => s.kind === 'userinfo')?.text).toContain('campus.example');
  });
});

describe('domain boundaries and Unicode', () => {
  it.each([
    ['https://notcampus.example/', false],
    ['https://campus.example.other.example/', false],
    ['https://lab.campus.example/', true],
    ['https://campus.example/', true],
  ])('trust is an exact dot boundary: %s', (input, trusted) => expect(analyzeUrl(input).parts?.trusted).toBe(trusted));
  it('uses the Public Suffix List, including private suffixes', () => {
    expect(analyzeUrl('https://a.department.example.co.uk').parts?.domain).toBe('example.co.uk');
    expect(analyzeUrl('https://alice.github.io').parts?.domain).toBe('alice.github.io');
    expect(analyzeUrl('https://alice.github.io/?next=https://bob.github.io').destinations[0]?.sameSite).toBe(false);
  });
  it.each(['campvs.example', 'carnpus.example', 'campu5.example', 'cаmpus.example'])('detects the configured visual match %s', host => {
    const result = analyzeUrl(`https://${host}/`); expect(result.verdict).toBe('suspicious');
    expect(result.findings.some(f => f.ruleId === 'R4' || f.ruleId === 'R5')).toBe(true);
  });
  it('treats edit distance alone as Review', () => {
    expect(has('https://camqus.example/', 'F1', 'review')).toBe(true);
    expect(analyzeUrl('https://camqus.example/').verdict).toBe('review');
  });
  it('does not flag a short fuzzy collision, a technical label, or a path reference as high risk', () => {
    for (const input of ['https://api2.other.example/docs', 'https://lab.example/', 'https://other.example/docs/campus.example']) expect(analyzeUrl(input).verdict).toBe('safe');
  });
  it('treats IDN by itself as Review', () => expect(analyzeUrl('https://пример.example/docs').verdict).toBe('review'));
  it('treats unfamiliar suffix alone as ordinary structure', () => expect(analyzeUrl('https://ordinary.xyz/docs').verdict).toBe('safe'));
  it('does not suppress userinfo warnings on configured hosts', () => expect(analyzeUrl('https://other.example@campus.example').verdict).toBe('suspicious'));
  it('treats a simple username and password as Review', () => {
    expect(analyzeUrl('https://alice@campus.example').verdict).toBe('review');
    expect(analyzeUrl('https://alice:password@campus.example').verdict).toBe('review');
    expect(analyzeUrl('https://jane.doe@campus.example').verdict).toBe('review');
  });
});

describe('IP scopes and schemes', () => {
  it.each([
    ['http://192.0.2.10/login', 'documentation', 'suspicious'],
    ['https://192.0.2.10/status', 'documentation', 'review'],
    ['http://10.0.0.5:8080/admin/login', 'private', 'review'],
    ['https://172.16.0.5/login', 'private', 'review'],
    ['https://172.31.255.255/login', 'private', 'review'],
    ['https://172.32.0.1/login', 'public', 'suspicious'],
    ['https://127.0.0.1/login', 'loopback', 'review'],
    ['https://[::1]/login', 'loopback', 'review'],
    ['https://[::ffff:192.0.2.1]/login', 'documentation', 'suspicious'],
    ['https://[::ffff:192.168.1.1]/login', 'private', 'review'],
    ['https://[2001:db8::1]/login', 'documentation', 'suspicious'],
    ['https://[fd00::1]/login', 'private', 'review'],
    ['https://[fe80::1]/login', 'other', 'review'],
    ['https://localhost/login', 'loopback', 'review'],
  ])('%s → %s (%s)', (input, scope, verdict) => {
    const result = analyzeUrl(input); expect(result.parts?.ipScope).toBe(scope); expect(result.verdict).toBe(verdict);
  });
  it.each(['javascript:alert(1)', 'data:text/html,<script>alert(1)</script>', 'file:///C:/Users/test.txt', 'vbscript:MsgBox(1)'])('%s has a strong scheme finding', input => expect(has(input, 'R1', 'suspicious')).toBe(true));
  it.each(['mailto:help@campus.example', 'ftp://files.campus.example/readme', 'custom:hello'])('%s is Review', input => expect(analyzeUrl(input).verdict).toBe('review'));
  it('does not penalize ordinary HTTP as phishing', () => expect(analyzeUrl('http://other.example/notices').verdict).toBe('safe'));
  it('does not exempt configured sign-in URLs from transport checks', () => expect(has('http://campus.example/login', 'R10', 'review')).toBe(true));
  it('inspects nonsecret scalar query values for sign-in wording', () => {
    expect(analyzeUrl('https://192.0.2.1/?action=login').verdict).toBe('suspicious');
    expect(has('https://other.example/?action=login', 'R9', 'weak')).toBe(true);
    expect(has('http://campus.example/?action=login', 'R10', 'review')).toBe(true);
  });
  it('does not attribute an embedded target sign-in path to the outer host', () => {
    const result = analyzeUrl('http://192.0.2.1/?next=https%3A%2F%2Fcampus.example%2Flogin');
    expect(result.verdict).toBe('review');
    expect(result.findings.some(f => f.ruleId === 'R10')).toBe(false);
    expect(result.findings.find(f => f.ruleId === 'R3')?.severity).toBe('review');
  });
});

describe('embedded destination inspection', () => {
  it('propagates a hidden suspicious target beneath a configured outer host', () => {
    const result = analyzeUrl(wrap('https://campus.example@other.example/login'));
    expect(result.parts?.trusted).toBe(true); expect(result.verdict).toBe('suspicious'); expect(result.decisiveRule).toBe('R7');
    expect(result.destinations[0]?.host).toBe('other.example'); expect(result.destinations[0]?.findings.some(f => f.ruleId === 'R2')).toBe(true);
  });
  it('does not exempt a listed nested shortener', () => expect(analyzeUrl(wrap('https://short.example/a')).verdict).toBe('review'));
  it('records an external ordinary target as requiring review', () => {
    const result = analyzeUrl(wrap('https://ordinary.example/docs'));
    expect(result.verdict).toBe('review'); expect(result.destinations[0]?.verdict).toBe('safe'); expect(result.destinations[0]?.sameSite).toBe(false);
  });
  it('permits same-site ordinary target without high risk', () => {
    const result = analyzeUrl(wrap('https://lab.campus.example/notices'));
    expect(result.verdict).toBe('safe'); expect(result.destinations[0]?.sameSite).toBe(true); expect(result.findings.find(f => f.ruleId === 'R7')?.severity).toBe('info');
  });
  it('handles two nested target levels', () => {
    const result = analyzeUrl(wrap(wrap('https://campus.example@other.example', 'url', 'other.example')));
    expect(result.verdict).toBe('suspicious'); expect(result.destinations[0]?.children[0]?.host).toBe('other.example');
  });
  it('handles protocol-relative targets without navigating', () => {
    const result = analyzeUrl(wrap('//other.example/login'));
    expect(result.destinations[0]?.host).toBe('other.example'); expect(result.verdict).toBe('review');
  });
  it('handles explicitly relative destination parameters against the outer URL', () => {
    const result = analyzeUrl(wrap('/notices'));
    expect(result.destinations[0]?.host).toBe('portal.campus.example'); expect(result.verdict).toBe('safe');
    expect(result.destinations[0]?.explanation).toContain('relative');
  });
  it('handles URLSearchParams decoding plus two additional percent layers', () => {
    const target = 'https://campus.example@other.example/login';
    const result = analyzeUrl(wrap(encodeURIComponent(encodeURIComponent(target))));
    expect(result.verdict).toBe('suspicious'); expect(result.destinations[0]?.decodeSteps).toBe(3);
  });
  it('reports undecoded targets beyond the decoding budget', () => {
    const target = 'https://campus.example@other.example/login';
    const result = analyzeUrl(wrap(encodeURIComponent(encodeURIComponent(encodeURIComponent(target)))));
    expect(result.verdict).toBe('review'); expect(result.findings.some(f => f.ruleId === 'R7')).toBe(true);
  });
  it('inspects URL-valued parameters with unfamiliar names', () => expect(analyzeUrl(wrap('https://campus.example@other.example', 'payload')).verdict).toBe('suspicious'));
  it('inspects URL-valued secret parameters while redacting their displayed values', () => {
    const result = analyzeUrl(wrap('https://campus.example@other.example/login', 'token'));
    expect(result.verdict).toBe('suspicious'); expect(result.destinations[0]?.host).toBe('other.example');
    expect(result.parts?.query).toContain('redacted');
  });
  it('reports decoding exhaustion under arbitrary parameter names', () => {
    const result = analyzeUrl(wrap(encodeURIComponent(encodeURIComponent(encodeURIComponent('https://campus.example@other.example/login'))), 'x'));
    expect(result.verdict).toBe('review'); expect(result.limitsReached).toBe(true);
  });
  it('counts form-decoding on the relevant parameter only', () => {
    const result = analyzeUrl('https://campus.example/?note=hello%20world&next=https://other.example');
    expect(result.destinations[0]?.decodeSteps).toBe(0);
  });
  it('handles embedded executable schemes without evaluating them', () => expect(analyzeUrl(wrap('javascript:alert(1)')).verdict).toBe('suspicious'));
  it('reports an invalid embedded target without claiming a destination', () => {
    const result = analyzeUrl(wrap('https://[broken'));
    expect(result.verdict).toBe('review'); expect(result.destinations[0]?.host).toBe('(unresolved)');
  });
  it('stops at the depth limit with explicit incomplete inspection', () => {
    const result = analyzeUrl(wrap(wrap(wrap('https://other.example/docs'))));
    expect(result.limitsReached).toBe(true); expect(result.verdict).toBe('review');
    expect(result.findings.some(f => f.title === 'Embedded inspection is incomplete')).toBe(true);
  });
  it('stops at the parameter budget', () => {
    const result = analyzeUrl(`https://campus.example/?${Array.from({ length: 21 }, (_, n) => `a${n}=value`).join('&')}`);
    expect(result.limitsReached).toBe(true); expect(result.verdict).toBe('review');
  });
  it('does not duplicate identical embedded targets', () => {
    const result = analyzeUrl('https://campus.example/?next=https://other.example&url=https://other.example');
    expect(result.destinations).toHaveLength(1);
  });
});

describe('privacy, bounded processing, and verdict consistency', () => {
  it.each([
    'https://alice:VERY_PRIVATE_PASSWORD@campus.example/',
    'https://alice:VERY_PRIVATE_PASSWORD@other.example:999999/',
    wrap('https://alice:VERY_PRIVATE_PASSWORD@other.example/login'),
    wrap(encodeURIComponent('https://alice:VERY_PRIVATE_PASSWORD@other.example/login')),
    'https://campus.example/?token=VERY_PRIVATE_PASSWORD',
  ])('does not return a password or secret in renderable results: %s', input => {
    expect(JSON.stringify(analyzeUrl(input))).not.toContain('VERY_PRIVATE_PASSWORD');
  });
  it('keeps large input bounded and reports incomplete inspection', () => {
    const result = analyzeUrl(`https://campus.example/${'x'.repeat(9000)}`);
    expect(result.verdict).toBe('review'); expect(result.limitsReached).toBe(true); expect(result.parts).toBeNull();
  });
  it('retains an independently detectable active scheme when over budget', () => expect(analyzeUrl(`javascript:${'x'.repeat(9000)}`).verdict).toBe('suspicious'));
  it('uses UTF-8 bytes, not only character count, for the size budget', () => expect(analyzeUrl(`https://campus.example/${'文'.repeat(3000)}`).limitsReached).toBe(true));
  it('requires two independent weak findings for Review', () => {
    expect(analyzeUrl('https://a.b.c.other.example/docs').verdict).toBe('safe');
    expect(analyzeUrl('https://other.example/login').verdict).toBe('safe');
    expect(analyzeUrl('https://a.b.c.other.example/login').verdict).toBe('review');
  });
  it('does not claim no warning signs when one weak finding is present', () => {
    const result = analyzeUrl('https://other.example/login');
    expect(result.verdict).toBe('safe'); expect(result.summary).toContain('weak signal'); expect(result.decisiveRule).toBe('R9');
  });
  it('does not match sign-in words as unbounded substrings', () => expect(has('https://a.b.c.other.example/catalogins', 'R9')).toBe(false));
  it('does not let department wording change risk findings', () => {
    const a = analyzeUrl('https://forms.campus.example/submit?ref=cs-dept');
    const b = analyzeUrl('https://forms.campus.example/submit?ref=library-dept');
    expect(a.verdict).toBe(b.verdict); expect(a.findings).toEqual(b.findings); expect(a.checks).toEqual(b.checks);
  });
  it('returns deterministic results without modifying the supplied string', () => {
    const input = wrap('https://campus.example@other.example');
    expect(analyzeUrl(input)).toEqual(analyzeUrl(input));
  });
});
