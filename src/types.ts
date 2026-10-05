export type Verdict = 'safe' | 'review' | 'suspicious';
export type Severity = Verdict | 'weak' | 'info';
export type RuleState = 'triggered' | 'not-triggered' | 'not-applicable' | 'not-evaluated';
export interface Finding {
  ruleId: string;
  title: string;
  severity: Severity;
  component: string;
  evidence: string;
  explanation: string;
  action: string;
}
export interface RuleCheck {
  id: string;
  name: string;
  state: RuleState;
  severity: Severity;
  explanation: string;
}
export interface UrlParts {
  scheme: string;
  username: string;
  hasPassword: boolean;
  hostname: string;
  unicodeHostname: string;
  domain: string | null;
  port: string;
  effectivePort: string;
  path: string;
  query: string;
  fragment: string;
  trusted: boolean;
  isIp: boolean;
  ipScope: 'public' | 'private' | 'loopback' | 'documentation' | 'other' | null;
}
export interface UrlSegment { text: string; kind: 'host' | 'userinfo' | 'plain' | 'scheme' | 'path'; }
export interface DestinationNode {
  parameter: string;
  host: string;
  verdict: Verdict;
  depth: number;
  decodeSteps: number;
  sameSite: boolean;
  explanation: string;
  findings: Finding[];
  children: DestinationNode[];
}
export interface Analysis {
  original: string;
  normalized: string;
  verdict: Verdict;
  decisiveRule: string;
  summary: string;
  action: string;
  accessibleSummary: string;
  parts: UrlParts | null;
  segments: UrlSegment[];
  findings: Finding[];
  checks: RuleCheck[];
  destinations: DestinationNode[];
  normalizationNotes: string[];
  policyVersion: string;
  limitsReached: boolean;
}
export interface Preset { id: string; category: string; label: string; description: string; url: string; expected: Verdict; }
export interface AiStatus { available: boolean; models: string[]; message: string; }
export interface AiExplanation { explanation: string; action: string; model: string; generated: boolean; }
