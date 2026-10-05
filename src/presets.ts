import type { Preset } from './types';

export const PRESETS: Preset[] = [
  { id: 'ordinary', category: 'Ordinary', label: 'Campus notice', description: 'An ordinary HTTPS link to an approved campus subdomain.', url: 'https://portal.campus.example/notices', expected: 'safe' },
  { id: 'unusual', category: 'Unusual but safe', label: 'Long lab link', description: 'A long host, hyphens, and a custom port do not prove danger.', url: 'https://week-3-lab-manual.portal.lab.campus.example:8443/forms/submit?ref=notice-2026', expected: 'safe' },
  { id: 'userinfo', category: 'Deceptive', label: 'The @ disguise', description: 'The familiar campus name is user information, not the destination.', url: 'https://campus.example@other.example/login', expected: 'suspicious' },
  { id: 'nested', category: 'Deceptive', label: 'Hidden destination', description: 'An approved outer host contains an encoded, deceptive target.', url: 'https://portal.campus.example/continue?next=https%3A%2F%2Fcampus.example%40other.example%2Flogin', expected: 'suspicious' },
  { id: 'shortener', category: 'Ambiguous', label: 'Short link', description: 'A synthetic shortener whose final destination is unknown offline.', url: 'https://short.example/abc123', expected: 'review' },
  { id: 'lookalike', category: 'Deceptive', label: 'One swapped letter', description: 'Compare campvs with the configured campus name.', url: 'https://campvs.example/login', expected: 'suspicious' },
  { id: 'subdomain', category: 'Deceptive', label: 'Domain disguise', description: 'The campus name is a subdomain of other.example.', url: 'https://campus.example.other.example/login', expected: 'suspicious' },
  { id: 'ip', category: 'Deceptive', label: 'IP sign-in', description: 'A documentation IP address paired with sign-in wording.', url: 'http://192.0.2.10/login', expected: 'suspicious' },
  { id: 'unicode', category: 'Ambiguous', label: 'International name', description: 'Punycode is valid; it merits inspection without proving impersonation.', url: 'https://xn--e1afmkfd.example/docs', expected: 'review' },
  { id: 'malformed', category: 'Parser edge cases', label: 'Incomplete IPv6', description: 'A missing bracket prevents reliable parsing.', url: 'https://[2001:db8::1/login', expected: 'review' },
  { id: 'bare', category: 'Parser edge cases', label: 'Missing scheme', description: 'A provisional HTTPS interpretation is labeled explicitly.', url: 'campus.example/notices', expected: 'review' },
  { id: 'same-site', category: 'Ordinary', label: 'Same-site return', description: 'An embedded return URL stays within the same configured site.', url: 'https://portal.campus.example/continue?next=https%3A%2F%2Fportal.campus.example%2Fnotices', expected: 'safe' },
  { id: 'library', category: 'Unusual but safe', label: 'Library archive', description: 'A custom port and long path are legitimate URL structures.', url: 'https://library.example:8443/archive/2026/notice.pdf?view=full', expected: 'safe' },
  { id: 'department-cs', category: 'Ordinary', label: 'Computer science', description: 'Department wording does not change the URL policy.', url: 'https://forms.campus.example/submit?ref=cs-dept', expected: 'safe' },
  { id: 'department-library', category: 'Ordinary', label: 'Library department', description: 'The same structural URL receives the same verdict.', url: 'https://forms.campus.example/submit?ref=library-dept', expected: 'safe' }
];
