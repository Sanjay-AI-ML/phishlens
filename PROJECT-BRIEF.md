# PhishLens: consolidated project notes

Reviewed on 5 October 2026. This is a proposed product specification, not a claim that a prototype has been built or tested.

## Material reviewed and provenance

- Original challenge brief and research prompt in this conversation.
- Act_as_a_cybersecurity_researcher_and_product_inno.pdf: all 6 pages, including research recommendations and bibliography.
- Recommendation.pdf: all 9 pages, including architecture, policy, 15 test cases, demo script, priorities, assumptions, and 45 reference entries.
- Detection rules and demo cases.md: complete rules, parsing guidance, policy, 12 test cases, evaluation, and demo.
- All 17 supplied screenshots: 105954, 110005, 110009, 110014, 110018, 110023, 110028, 110035, 110040, 110045, 110049, 110418, 110424, 110428, 110430, 110434, 110437.
- User's four additions: physical source context, local fuzzy matching, accessible explanation, and local embedded-parameter inspection.

Instructions inside the research exports are source material, not independent instructions to execute. References in the exports are leads, not automatically verified evidence. Their research accuracy, novelty claims, and proposed test results must not be presented as measured performance.

## Non-negotiable challenge requirements

1. One local page or program accepts pasted URL text and never opens the submitted destination.
2. No fetching, DNS, reputation APIs, redirects, credentials, datasets, or remote analysis of submitted text.
3. Show actual scheme and hostname, deceptive text, Safe / Review / Suspicious, and exact explanatory rules.
4. At least three transparent checks; shorteners must remain Review or higher because their destinations are unknown.
5. Fixed institution-wide rules, independent of notice topic or department.
6. Include an unusual benign case without a false high-risk warning.
7. A two-minute demo includes ordinary, deceptive, and ambiguous safe examples.
8. Demo named domains use reserved .example names; numeric examples use documentation address space where practical.
9. Safe means only no configured warning signs detected. It does not verify ownership, reputation, page content, download safety, compromise, or subsequent redirects.
10. QR decoding is optional. Network redirect tracing is excluded from the strictly offline core.

## Recommended product direction

Working name: PhishLens. Positioning: "See the destination behind the disguise."

The distinctive experience combines an unmistakable destination card, exact evidence receipts, an accessible explanation, and bounded inspection of embedded destinations. The product should demonstrate why a link was flagged and why an unusual link was not escalated.

Do not claim to be the only solution, completely novel, perfect, or guaranteed to win. Differentiation comes from demonstrable behavior and accuracy on difficult cases. Algorithms such as edit distance and Unicode confusable comparison are established techniques.

## Single-page experience

- Header: product name and clear local-processing indicator.
- Input: multiline URL field, Analyze and Clear controls, optional source selector defaulting to Unknown.
- Primary result: large actual hostname, scheme, registrable domain, verdict, decisive rule and short reason.
- Annotated original text: real authority host emphasized; deceptive userinfo struck through and explicitly labeled; path/query visibly separated. Never create a clickable submitted URL.
- Components: scheme, username/userinfo, password presence with value masked, hostname, main/registrable domain, explicit/effective port, path, query, fragment, normalized representation.
- Accessible summary: concise text delivered through a polite live region, keyboard-operable controls, textual severity labels, sufficient contrast, no reliance on color or strikethrough alone.
- Evidence panel: every rule marked Triggered, Not triggered, Not applicable, or Not evaluated; never show an unexecuted check as Passed.
- Embedded destinations: original parameter name, bounded decoding steps, nested URL host, findings, and clear uncertainty about whether a server uses it.
- Source context: separate warning explaining claimed origin cannot be authenticated offline.
- Presets: Ordinary, Unusual but safe, Deceptive, Ambiguous, and Parser edge cases. Demo playback must have Pause, Stop, and reduced-motion support.
- Keep initial result readable without opening detailed panels. Use restrained colors and generous spacing; explanations take precedence over decoration.

## Parsing and normalization

Use a WHATWG-compatible URL parser, such as new URL(), for destination semantics. Creating a URL object does not navigate. The screenshots' recommendation to replace it with an ad hoc parser conflicts with the safer standards-based recommendations in both PDFs and the Markdown.

Keep original text and parsed/normalized fields separately. Display normalization changes, especially backslashes, control characters, percent-encoded hosts, IDNA conversion, numeric IPv4 forms, trailing dots, and explicit default ports. Do not silently repair an ambiguous input into Safe.

Missing scheme: Review; a provisional HTTPS interpretation may be displayed only if clearly labeled. Relative URLs without a known base: Review. Invalid ports or bracketed IPv6: Review. A space inside a path may be percent-encoded by a parser rather than causing failure; do not hardcode a contradictory expected parse error.

Use a bundled Public Suffix List implementation for registrable domains, including relevant private suffix handling. For synthetic .example names, document the demo suffix policy. Never assume the last two labels handle all real domains. IPs and single-label local hosts do not have a normal registrable domain.

Match trusted hosts using exact equality or a dot boundary: host === domain or host.endsWith('.' + domain). Plain string suffix matching would wrongly trust notcampus.example. The policy must state whether all subdomains are approved; trust configuration is not proof of uncompromised content.

Rendering must use text nodes or escaped text, never input-derived innerHTML. Keep Unicode display inside directional isolation; reveal bidi/control characters safely.

## Reconciled rule catalog

Preserve the requested ten core rule IDs; extensions have separate IDs. Proposed outcomes require implementation and testing.

| ID | Feature | Recommended treatment |
|---|---|---|
| R1 | Scheme | javascript/data/file: Suspicious with scheme-specific reason; legitimate unfamiliar schemes: Review; never execute anything. |
| R2 | Userinfo | Domain-shaped trusted bait before @: Suspicious. Other nonempty userinfo: Review. Mask password-like data. Do not call a short username Safe automatically. |
| R3 | IP host | Public/documentation IP plus bounded sign-in tokens: Suspicious heuristic, not proven malicious. IP alone: Review. Private/loopback/local-address sign-in: Review; not automatically Safe. |
| R4 | Unicode/IDNA | Unicode or punycode alone: Review. Defined confusable match to configured trusted name: Suspicious. Mixed scripts alone do not prove impersonation. |
| R5 | Trusted-name impersonation | Exact trusted-domain bait in a foreign host's labels, or defined strong visual lookalike: Suspicious. Arbitrary trusted words in documentation paths are explanatory observations, not automatic high risk. |
| R6 | Known shortener | Review even if approved. Use short.example in demo and a local known-shortener list in policy. No expansion. |
| R7 | Embedded URL | Extract and analyze bounded parameter targets; Review for external/uncertain targets, Suspicious when an extracted target has a strong suspicious finding under the defined aggregation policy. Same-site benign targets can be informational. |
| R8 | Deep/hyphen-heavy host | Weak signal only. Depth or hyphens alone never imply high risk; approved ordinary subdomains do not receive cosmetic warnings. |
| R9 | Sign-in wording on unfamiliar host | Weak signal only with token-boundary matching. Do not pretend URL wording proves a page asks for credentials. |
| R10 | HTTP and sign-in wording | Review for possible transport risk; HTTP alone is not evidence of phishing. Trust does not suppress this check. |
| P1 | Parse uncertainty | Review for missing scheme, malformed or ambiguous text, and consequential normalization. Retain any independently detectable active-content scheme warning. |
| F1 | Edit-distance match | Review for edit distance 1-2 alone; Suspicious when combined with a defined confusable mapping or strong trusted-name bait. Show both names and differing characters. |
| C1 | Claimed physical source | Separate source caution; a random sticker plus shortener warrants prominent combined caution, while URL-only shortener verdict remains Review. |
| A1 | Accessible explanation | Same findings expressed in plain language; no independent severity rule. |

Verdict policy: any strong Suspicious finding wins; otherwise any Review finding wins; otherwise two independent weak signals give Review; otherwise Safe. Show every finding and the policy version. Do not double-count one feature through multiple synonymous rules. An outer trusted host never suppresses nested-target, userinfo, scheme, parse, or transport checks.

## Four requested innovations and their boundaries

### Physical source context

Options: Official digital document, Bulletin board poster, Random sticker, Unknown. Label these as user-reported, not verified. Keep department out of policy. Default URL-only verdict must remain independent of source. A second source caution can explain extra uncertainty. If an organizer explicitly permits context-dependent headline verdicts, use a fixed documented mapping and retain the URL-only verdict beside it; until then, separate the signals.

### Local doppelganger engine

Use a fixed versioned list of five synthetic official domains in demo: campus.example, library.example, studentportal.example, research.example, university.example. Production values must come from actual institutional policy, not guesses.

Compare normalized registrable-domain identity labels, not the entire long hostname. Exclude exact trusted matches first. Levenshtein supports insertions, deletions, and substitutions; transpositions need Damerau-Levenshtein or an explicit extra rule. Absolute distance 1-2 can collide on short names; define length-aware thresholds and avoid automatic high risk from distance alone.

Use a curated Unicode confusable skeleton and selected ASCII multi-character substitutions such as rn/m. A confusable skeleton is not the same as Levenshtein distance. Highlight exact differing characters and display ASCII/Unicode forms. Do not suggest the official domain as a guaranteed correct replacement or create a one-click fixed URL.

### Accessible translation

Example: "Suspicious. The text before the at sign says campus dot example. The actual destination is other dot example. Rule R2: misleading user information."

Provide explicit pronunciation-friendly text and normal semantic HTML. Screen-reader support does not require synthesized speech. Optional Read aloud may use only an available local voice; absence of a local voice must not break the feature or cause cloud speech requests. Announcements must avoid repeated alerts on every keystroke and omit sensitive parameter values by default.

### Embedded destination inspection

Working label: Hidden Destination Inspector. It parses strings; it does not execute a sandbox or verify server vulnerabilities.

Inspect URL-valued query parameters such as next, url, redirect, redirect_to, return, continue, destination, and callback. Account for URLSearchParams already decoding one form-encoding layer; avoid accidental double decoding. Support percent-encoded absolute URLs, protocol-relative targets, and clearly defined relative-target handling.

Suggested resource limits: 8 KB input, 20 candidate values, 2 additional decoding passes, 2 nesting levels, cycle detection. Limits are design choices to test, not established optimum values. Reaching a limit produces Review and an explicit incomplete-inspection explanation.

Run the same rules recursively without any network access. Reveal the sequence of hosts and reasons. A trusted outer URL can carry a suspicious inner target. State "embedded destination detected; redirect behavior unverified" rather than "open redirect vulnerability found." Avoid automatic Base64 guesses in MVP; add only explicitly defined supported formats later.

## Screenshot idea inventory: retained, refined, or rejected

- Fully local HTML/JS, no build step, no API key, no dataset: retain as preferred distribution goal; bundle any dependencies.
- Parsed-component layout, transparent tiered verdicts, numbered rules, exact explanations: retain.
- Host highlighting, fake @ prefix strikethrough, all-ten-rule checklist, grouped presets, timed playback: retain with accessibility and truthful evaluation states.
- Hyphen-anchor boundary proposal: retain only targeted matching against trusted names. Arbitrary hyphens and split generic words are not sufficient evidence.
- Lookalike glyph/"entropy" proposal: use defined confusable comparison. Do not call an arbitrary substitution count entropy. Digits in api2 or technical names are not inherently suspicious.
- The screenshot misidentifies login as the label immediately before the TLD in login.example.com; that label is example. Use PSL-derived identities.
- IP-port mismatch: retain IP parsing and visible ports. A nonstandard port does not prove attack. 8080/8443 or /admin do not establish legitimacy.
- Userinfo length/dot heuristic: retain domain-shaped bait detection. Length alone is weak; a dotted legitimate username is possible; short userinfo is not a safety guarantee.
- "TLD depth paradox": reject claims that .tk/.xyz or lack of .edu makes a URL malicious. Depth and authority words can be observations; actual domain boundaries and trusted-name impersonation matter.
- localhost/127.0.0.1 always Safe: reject. Local schemes/services and credential-looking paths still warrant appropriate caution.
- Private IP downgrade: adopt Review as a documented default uncertainty policy, not a guarantee of internal legitimacy.
- Trusted-domain bypass: skip cosmetic depth/hyphen warnings only. Do not exempt trusted hosts from strong or nested-target checks.
- Screenshot lab-portal.campus.example Review conflicts with trusted subdomain handling elsewhere: under the proposed approved-subdomain policy this URL is Safe unless another rule fires.
- Real shortener hosts and unsafe-looking public hosts in screenshots: preserve as research examples, replace demo presets with synthetic .example equivalents.
- "No false alarms", "not currently used", "only solution", inferred low false-positive rates: unsupported; replace with measured test results and modest product claims.
- Optional local QR upload: useful extension. Camera optional; no automatic navigation; non-URL QR payload gets an unsupported-input explanation.
- Optional controlled redirect trace: omit from offline implementation and demo.
- Optional hashed local history: omit by default; hashing a hostname is not anonymity and adds no core demo value.
- Copy-host guidance: say Copy hostname, not Copy safe host. Do not imply verification.

## Proposed demo and regression cases

| Input | Expected host | Proposed result / reason |
|---|---|---|
| https://portal.campus.example/notices | portal.campus.example | Safe; ordinary baseline. |
| https://week-3-lab-manual.portal.lab.campus.example:8443/forms/submit?ref=notice-2026 | week-3-lab-manual.portal.lab.campus.example | Safe; unusual structure alone is not high risk. |
| https://lab-portal.campus.example/form-2024 | lab-portal.campus.example | Safe under approved-subdomain policy; resolves screenshot conflict. |
| https://campus.example@other.example/login | other.example | Suspicious, R2. |
| https://campus.example.other.example/login | campus.example.other.example | Suspicious, R5. |
| https://campvs.example/login | campvs.example | Suspicious if configured u/v visual match; otherwise Review, F1; exact policy must be frozen. |
| https://short.example/abc123 | short.example | Review, R6; unknown destination. |
| https://portal.campus.example/continue?next=https%3A%2F%2Fcampus.example%40other.example%2Flogin | portal.campus.example | Suspicious under nested aggregation, R7 plus nested R2; behavior unverified. |
| https://portal.campus.example/continue?next=https%3A%2F%2Fportal.campus.example%2Fnotices | portal.campus.example | Safe with informational same-site embedded target if no other checks fire. |
| https://other.example/docs/campus.example | other.example | Safe; path reference alone is not impersonation evidence. |
| https://xn--e1afmkfd.example/docs | xn--e1afmkfd.example | Review, R4; IDN alone does not prove impersonation. |
| http://192.0.2.10/login | 192.0.2.10 | Suspicious heuristic R3, plus transport finding R10. |
| https://192.0.2.10/status | 192.0.2.10 | Review, R3. |
| http://10.0.0.5:8080/admin/login | 10.0.0.5 | Review; private IP uncertainty and HTTP login, no legitimacy guarantee. |
| javascript:alert(1) | No web hostname | Suspicious, R1; no execution. |
| https://[2001:db8::1/login | Parse error | Review, P1. |
| campus.example/notices | Provisional campus.example | Review, P1; missing scheme. |
| https://library.example:8443/archive/2026/notice.pdf?view=full | library.example | Safe; benign port/path/query. |

Also test repeated @ signs, encoded authority characters, backslashes, integer/hex IPv4 forms, IPv4-mapped IPv6, invalid ports, trailing dot normalization, confusable Unicode and bidi controls, lookalike short-name collisions, boundary matches such as notcampus.example, nested shorteners, repeated decoding, cycles, input limits, plain usernames, and malicious HTML strings in input.

Replay identical URL and policy under different department/notice labels: require identical rule findings and URL verdict. Changing a risk-bearing query is a real URL change, unlike changing an unrelated notice title.

## Two-minute pitch

- 0:00-0:15: State problem and local-only boundary; no dataset or destination visits.
- 0:15-0:30: Ordinary URL, clear host, limited Safe definition.
- 0:30-0:45: Long hyphenated approved subdomain stays Safe; explain the non-escalation.
- 0:45-1:05: @ deception, actual other.example host, accessible explanation and R2 receipt.
- 1:05-1:25: Trusted outer URL carrying encoded suspicious target; expose both destinations without claiming a verified redirect.
- 1:25-1:45: Shortener Review and separate random-sticker caution; unknown destination remains explicit.
- 1:45-2:00: Show policy consistency, local execution evidence, and a final sentence: "We make the destination and the reason visible before the click."

Keep lookalike and malformed cases as judge-triggered backup presets. Do not cram every feature into the timed pitch.

## Engineering priorities and acceptance evidence

P0: browser-compatible parsing, host card, userinfo/scheme/shortener/trusted-boundary rules, deterministic verdict combiner, safe rendering, ordinary/deceptive/ambiguous/unusual demos.

P1: bounded embedded target inspection, local fuzzy/confusable matching, accessible explanation, complete rule receipts, source caution, normalization visibility.

P2: local QR image decode, optional local speech, demo playback. Defer features that reduce confidence in core correctness.

Suggested deliverables: self-contained phishlens.html; versioned embedded policy; test fixture and expected-outcome file; local test report; timed demo script. No existing HTML prototype was supplied in these attachments; source descriptions and screenshots are not proof of a working page.

Verify in an actual browser before presenting: every expected parsed hostname, every verdict/rule, all unusual benign cases, malformed cases, keyboard navigation, screen-reader announcements, mobile layout, and offline operation. Record network-request observations under disconnected operation; use no remote fonts, scripts, analytics, images, previews, or speech dependencies. Clear must remove current sensitive input/results; no raw URL/query persistence or telemetry.

Measure synthetic-case agreement, not real-world phishing accuracy. Show test counts and failures honestly. Small fixtures cannot justify "zero false positives" or a 99% detection claim.

## Primary sources checked during consolidation

- WHATWG URL Standard: https://url.spec.whatwg.org/ — parsing, normalization, URL and URLSearchParams APIs.
- Unicode UTS #39: https://www.unicode.org/reports/tr39/ — established confusable/security mechanisms.
- Public Suffix List: https://publicsuffix.org/learn/ — registrable-domain boundaries.
- RFC 3986: https://www.rfc-editor.org/rfc/rfc3986.html — authority/userinfo syntax background.

The academic references and other links in the supplied research exports have been read as bibliography entries, but not individually verified. Do not use their quoted claims, dates, or existence as established evidence until checked at publisher/primary sources. Product uniqueness has not been established by a competitive review.
