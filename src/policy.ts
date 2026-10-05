/** Institution-wide demonstration policy. Production domains require institution approval. */
export const POLICY = Object.freeze({
  version: '2026.10.05.1',
  trustedDomains: Object.freeze([
    'campus.example', 'library.example', 'studentportal.example', 'research.example', 'university.example',
  ]),
  trustSubdomains: true,
  shorteners: Object.freeze(['short.example', 'bit.ly', 'tinyurl.com', 'is.gd', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 'cutt.ly', 'rb.gy']),
  limits: Object.freeze({ maxInputBytes: 8192, maxCandidates: 20, maxExtraDecodes: 2, maxDepth: 2 }),
  verdictPolicy: 'Any suspicious finding → Suspicious. Otherwise any review finding or two different weak rules → Review. Otherwise Safe.',
  demoSuffixNote: 'For reserved .example demo names, the label immediately before .example identifies the main domain. Other names use the bundled Public Suffix List, including private suffixes.',
});
