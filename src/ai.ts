import http from 'node:http';
import { isIP } from 'node:net';
import type { AiExplanation, AiStatus, Severity, Verdict } from './types';

export const LANGUAGES = ['English', 'Hindi'] as const;
export type Language = typeof LANGUAGES[number];
export class RequestError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

// Only these maintained descriptions reach the model. Supplied URL text,
// titles, explanations, and actions never become model instructions or evidence.
const RULES: Record<string, { evidence: string; action: string }> = {
  R1: { evidence: 'The scheme is not a standard web scheme. Some schemes can invoke code, local resources, or another application.', action: 'Confirm what this address is intended to do before opening it.' },
  R2: { evidence: 'The URL contains user information before the actual host. This part does not identify the destination and can imitate an official address.', action: 'Use the displayed actual host to verify the destination through a trusted campus source before signing in.' },
  R3: { evidence: 'The destination is an IP address. An IP address does not provide a named campus identity; internal services can legitimately use one.', action: 'Confirm this specific service with your campus IT team before entering information.' },
  R4: { evidence: 'The hostname has an internationalized or visually confusable spelling. Internationalized names can be legitimate, but visual similarity needs care.', action: 'Compare the actual hostname with the official address from a trusted campus source.' },
  R5: { evidence: 'A familiar campus name appears in a position or spelling that does not establish an approved campus domain boundary.', action: 'Find the intended service through an independently verified campus directory.' },
  R6: { evidence: 'The hostname matches a configured link shortener. Its final destination cannot be established from the URL text offline.', action: 'Ask the sender for the full destination address and verify it before opening.' },
  R7: { evidence: 'The URL text contains an embedded destination. Text alone cannot prove that any website follows this destination or has an open redirect vulnerability. A suspicious finding may concern the embedded destination.', action: 'Inspect the embedded host and confirm that it is the intended destination before signing in.' },
  R8: { evidence: 'The hostname has structural complexity, such as many labels or hyphens. This is a weak signal that can occur in legitimate URLs.', action: 'Compare the actual domain with the expected service; unusual formatting alone does not establish danger.' },
  R9: { evidence: 'Sign-in wording appears on a host outside the configured trusted domains. Wording alone cannot establish what the page contains.', action: 'Confirm the official sign-in address through a trusted campus source before entering a password.' },
  R10: { evidence: 'The URL uses unencrypted HTTP and includes sign-in wording. HTTPS protects transport but would not by itself prove that a site is trustworthy.', action: 'Use the verified HTTPS sign-in address rather than entering credentials through this HTTP link.' },
  P1: { evidence: 'The URL needed a parsing assumption, had an ambiguous form, or could not be fully inspected within the bounded parser. The displayed normalization notes explain the limit.', action: 'Obtain the complete intended address and inspect the normalized destination before opening it.' },
  F1: { evidence: 'The destination spelling closely resembles a configured trusted domain but does not match it. Similarity is an indicator rather than proof of malicious intent.', action: 'Compare the highlighted spelling with the official campus address before signing in.' },
};
const HINDI_ACTIONS: Record<string, string> = {
  R1: 'खोलने से पहले पुष्टि करें कि इस पते से क्या कार्रवाई होनी चाहिए।',
  R2: 'साइन इन करने से पहले दिखाए गए वास्तविक होस्ट को किसी विश्वसनीय कैंपस स्रोत से मिलाएँ।',
  R3: 'जानकारी दर्ज करने से पहले अपने कैंपस की आईटी टीम से इस सेवा की पुष्टि करें।',
  R4: 'वास्तविक होस्ट नाम को किसी विश्वसनीय कैंपस स्रोत से मिले आधिकारिक पते से मिलाएँ।',
  R5: 'स्वतंत्र रूप से सत्यापित कैंपस निर्देशिका से सही सेवा का पता खोजें।',
  R6: 'भेजने वाले से पूरा गंतव्य पता माँगें और खोलने से पहले उसकी पुष्टि करें।',
  R7: 'लिंक में छिपे होस्ट को जाँचें और साइन इन करने से पहले पुष्टि करें कि यही आपका अपेक्षित गंतव्य है।',
  R8: 'वास्तविक डोमेन को अपेक्षित सेवा से मिलाएँ; केवल असामान्य बनावट खतरा साबित नहीं करती।',
  R9: 'पासवर्ड दर्ज करने से पहले किसी विश्वसनीय कैंपस स्रोत से आधिकारिक साइन-इन पते की पुष्टि करें।',
  R10: 'इस HTTP लिंक पर पासवर्ड दर्ज करने के बजाय सत्यापित HTTPS साइन-इन पते का उपयोग करें।',
  P1: 'पूरा अपेक्षित पता प्राप्त करें और खोलने से पहले दिखाए गए गंतव्य को जाँचें।',
  F1: 'साइन इन करने से पहले चिह्नित वर्तनी को आधिकारिक कैंपस पते से मिलाएँ।',
};

export interface ExplainRequest {
  model: string;
  language: Language;
  verdict: Verdict;
  host: string;
  findings: { ruleId: string; severity: Severity; title?: string; explanation?: string; action?: string }[];
}
const ranks: Record<Severity, number> = { suspicious: 4, review: 3, weak: 2, info: 1, safe: 0 };

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}
function validModelName(value: unknown): value is string {
  return typeof value === 'string' && value.length <= 160 && /^[a-zA-Z0-9][a-zA-Z0-9._:/-]*$/.test(value) && !/(?:^|[-:/])cloud(?:$|[-:])/i.test(value);
}
export function validateExplainRequest(value: unknown): ExplainRequest {
  if (!record(value) || !validModelName(value.model) || !LANGUAGES.includes(value.language as Language)
      || !['safe', 'review', 'suspicious'].includes(String(value.verdict))
      || typeof value.host !== 'string' || value.host.length > 253
      || !Array.isArray(value.findings) || value.findings.length > 24) {
    throw new RequestError(400, 'Invalid explanation request.');
  }
  // The host is validated for the API contract but is deliberately not sent to AI.
  const host = value.host;
  if (host && !/^[a-zA-Z0-9.-]+$/.test(host) && !isIP(host.replace(/^\[|\]$/g, ''))) {
    throw new RequestError(400, 'Use the parsed hostname, without a URL, path, or query.');
  }
  const findings = value.findings.map((finding) => {
    if (!record(finding) || typeof finding.ruleId !== 'string' || !Object.hasOwn(RULES, finding.ruleId)
        || typeof finding.severity !== 'string' || !Object.hasOwn(ranks, finding.severity)) {
      throw new RequestError(400, 'Unknown rule or severity.');
    }
    for (const key of ['title', 'explanation', 'action']) {
      if (finding[key] !== undefined && (typeof finding[key] !== 'string' || finding[key].length > 1600)) {
        throw new RequestError(400, 'Invalid finding description.');
      }
    }
    return { ruleId: finding.ruleId, severity: finding.severity as Severity };
  });
  const unique = findings.filter((finding, index) => findings.findIndex((f) => f.ruleId === finding.ruleId && f.severity === finding.severity) === index);
  const verdict: Verdict = unique.some((f) => f.severity === 'suspicious') ? 'suspicious'
    : unique.some((f) => f.severity === 'review') || new Set(unique.filter((f) => f.severity === 'weak').map((f) => f.ruleId)).size >= 2 ? 'review' : 'safe';
  if (verdict !== value.verdict) throw new RequestError(400, 'The verdict does not agree with the supplied rule severities.');
  return { model: value.model, language: value.language as Language, verdict: value.verdict as Verdict, host, findings: unique };
}

export interface GenerationInput { model: string; prompt: string; signal: AbortSignal; }
export interface LocalModelBackend {
  models(signal: AbortSignal): Promise<string[]>;
  generate(input: GenerationInput): Promise<string>;
}

/** Direct loopback HTTP only: no environment proxy, redirects, downloads, or user-selectable URL. */
export function ollamaRequest(path: '/api/tags' | '/api/show' | '/api/generate', payload: object | undefined, signal: AbortSignal): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const body = payload === undefined ? undefined : JSON.stringify(payload);
    const request = http.request({
      hostname: '127.0.0.1', port: 11434, path, method: body ? 'POST' : 'GET',
      agent: false, signal,
      headers: body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {},
    }, (response) => {
      if (response.statusCode !== 200) {
        response.resume();
        reject(new Error('Local model service returned an error.'));
        return;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      response.on('data', (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > 1024 * 1024) { response.destroy(new Error('Local model response is too large.')); return; }
        chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); }
        catch { reject(new Error('Local model service returned invalid JSON.')); }
      });
    });
    request.on('error', reject);
    request.end(body);
  });
}

export class OllamaBackend implements LocalModelBackend {
  private cached: { expires: number; names: string[] } | undefined;
  private listing: Promise<string[]> | undefined;
  constructor(private readonly request: typeof ollamaRequest = ollamaRequest) {}
  private async isLocalCompletion(name: string, signal: AbortSignal): Promise<boolean> {
    const info = await this.request('/api/show', { model: name }, signal);
    if (!record(info) || info.remote_host || info.remote_model) return false;
    if (typeof info.modelfile === 'string' && /^\s*FROM\s+\S*cloud\b/im.test(info.modelfile)) return false;
    return Array.isArray(info.capabilities) && info.capabilities.includes('completion');
  }
  async models(signal: AbortSignal): Promise<string[]> {
    if (this.cached && this.cached.expires > Date.now()) return [...this.cached.names];
    if (this.listing) return this.listing;
    this.listing = (async () => {
      const result = await this.request('/api/tags', undefined, signal);
      if (!record(result) || !Array.isArray(result.models)) throw new Error('Invalid local model inventory.');
      const names = result.models.filter(record).map((model) => model.name).filter(validModelName).slice(0, 24);
      const accepted: string[] = [];
      // Inspect model metadata with bounded parallelism. Embedding/cloud models are excluded.
      for (let index = 0; index < names.length; index += 3) {
        const batch = await Promise.all(names.slice(index, index + 3).map(async (name) => {
          try { return await this.isLocalCompletion(name, signal) ? name : null; }
          catch { return null; }
        }));
        accepted.push(...batch.filter((name): name is string => name !== null));
      }
      this.cached = { expires: Date.now() + 30_000, names: accepted };
      return [...accepted];
    })();
    try { return await this.listing; } finally { this.listing = undefined; }
  }
  async generate({ model, prompt, signal }: GenerationInput): Promise<string> {
    // Recheck immediately before generation, even when the inventory was cached.
    if (!await this.isLocalCompletion(model, signal)) throw new RequestError(400, 'Choose an installed local text model.');
    const response = await this.request('/api/generate', {
      model, prompt, stream: false, think: false, keep_alive: '2m',
      format: {
        type: 'object', properties: { explanation: { type: 'string' } },
        required: ['explanation'], additionalProperties: false,
      },
      options: { temperature: 0, num_predict: 260, num_ctx: 2048 },
    }, signal);
    if (!record(response) || typeof response.response !== 'string') throw new Error('No explanation returned.');
    return response.response;
  }
}

function selectedRules(input: ExplainRequest) {
  return [...input.findings].sort((a, b) => ranks[b.severity] - ranks[a.severity]).slice(0, 6);
}
export function groundedPrompt(input: ExplainRequest): string {
  const evidence = selectedRules(input).map((finding) => ({
    rule: finding.ruleId, severity: finding.severity, observation: RULES[finding.ruleId].evidence,
  }));
  return [
    'You explain offline URL inspection findings to a student. You have no web access and no tools.',
    `Write in ${input.language}. Return JSON with only the string field "explanation".`,
    'Write 2 or 3 short sentences about the most significant observation and its possible consequence. Use everyday language.',
    'Explain ONLY the observations below. Do not claim a website contains malware, steals passwords, redirects, or is malicious.',
    'Risks are possibilities, not verified events. You cannot inspect page content or know the final destination of a short link.',
    'Opening a URL does not automatically log a student in, share their password, or download a file. Do not suggest these events are certain or automatic.',
    'Do not output any hostnames, URLs, code, links, HTML, numerical confidence, or a different verdict.',
    'Safe means no configured warning signs were found, not guaranteed safety. Review means uncertainty. Suspicious means a strong structural warning.',
    'If there are no observations, say no configured warning signs were detected and that the destination has not been verified.',
    'Do not instruct the student to open a submitted link. The interface supplies a separate verified next step.',
    `Fixed verdict: ${input.verdict}.`,
    `Verified rule observations: ${JSON.stringify(evidence)}.`,
  ].join('\n');
}

export function fixedAction(input: ExplainRequest): string {
  const first = selectedRules(input)[0];
  if (input.language === 'Hindi') return first ? HINDI_ACTIONS[first.ruleId] : 'व्यक्तिगत जानकारी देने से पहले अपेक्षित गंतव्य की पुष्टि करें; कोई भी ऑफलाइन परिणाम सुरक्षा की गारंटी नहीं देता।';
  return first ? RULES[first.ruleId].action : 'Confirm the expected destination before sharing personal information; no offline result guarantees safety.';
}

export class AiService {
  private active = 0;
  private readonly timeoutMs: number;
  constructor(private readonly backend: LocalModelBackend = new OllamaBackend(), timeoutMs = 45_000) {
    this.timeoutMs = Math.max(100, Math.min(timeoutMs, 60_000));
  }
  async status(): Promise<AiStatus> {
    try {
      const models = await this.backend.models(AbortSignal.timeout(5000));
      return { available: models.length > 0, models, message: models.length ? 'Installed local text models are available. Explanations stay on this device.' : 'No installed local text model is available. The rule explanation remains available.' };
    } catch {
      return { available: false, models: [], message: 'Local AI is unavailable. Start Ollama with an already installed text model; the offline checker works independently.' };
    }
  }
  async explain(input: ExplainRequest, cancelled?: AbortSignal): Promise<AiExplanation> {
    if (this.active >= 1) throw new RequestError(429, 'A local explanation is already being generated. Please wait.');
    this.active++;
    const deadline = AbortSignal.timeout(this.timeoutMs);
    const signal = cancelled ? AbortSignal.any([deadline, cancelled]) : deadline;
    try {
      const models = await this.backend.models(signal);
      if (!models.includes(input.model)) throw new RequestError(400, 'Choose an installed local text model.');
      const raw = await this.backend.generate({ model: input.model, prompt: groundedPrompt(input), signal });
      let output: unknown;
      try { output = JSON.parse(raw); } catch { throw new RequestError(502, 'Local AI returned an invalid explanation. Use the rule explanation below.'); }
      const explanation = record(output) && typeof output.explanation === 'string' ? output.explanation.trim() : '';
      // Defense in depth. This cannot prove every model sentence is correct;
      // the UI keeps the exact rule evidence and fixed action visible alongside it.
      if (explanation.length < 25 || explanation.length > 1500 || /[<>\x00-\x08\x0b\x0c\x0e-\x1f\u202a-\u202e\u2066-\u2069]/.test(explanation)
          || /(?:https?:|www\.|javascript:|data:|\b[a-z0-9][a-z0-9-]{0,62}\.[a-z]{2,63}\b|\b\d{1,3}\s*%)/i.test(explanation)
          || /(?:guaranteed safe|definitely safe|completely safe|definitely malicious|confirmed phishing|will steal|will redirect|click (?:the|this) link|open (?:the|this) link|(?:this|the) (?:url|link|website|site|destination|address) is (?:safe|malicious|legitimate|phishing)|पूरी तरह सुरक्षित|निश्चित रूप से सुरक्षित)/i.test(explanation)) {
        throw new RequestError(502, 'Local AI did not meet explanation checks. Use the rule explanation below.');
      }
      return { explanation, action: fixedAction(input), model: input.model, generated: true };
    } catch (error) {
      if (error instanceof RequestError) throw error;
      if (signal.aborted) throw new RequestError(504, 'Local AI timed out or was cancelled. The rule explanation remains available.');
      throw new RequestError(503, 'Local AI is unavailable. The rule explanation remains available.');
    } finally { this.active--; }
  }
}
