# PhishLens

**Clarity before you click.** A local URL inspector for campus links, with transparent rules, nested destination inspection, QR image decoding, and optional explanations from an installed local AI model.

## Run

Requires Node.js 22.12+ (Node 24 recommended). From this directory:

```powershell
npm ci
npm run build
npm start
```

Open **http://127.0.0.1:4173**. The production server listens only on your computer's loopback interface. After dependencies are installed and the app is built, it runs without internet access. Stop with Ctrl+C. The generated `dist` directory can also be served by a static server for the checker; the optional AI API requires the bundled local server.

For development, run the built server in one terminal and `npm run dev` in another; open http://127.0.0.1:5173. The Vite server forwards AI requests to the local application server.

## What is included

- Browser-standard URL parsing with original/normalized views, actual hostname, registrable domain, scheme, userinfo, masked password presence, port, path, query, and fragment.
- Ten visible rule checks and supplemental parsing/fuzzy-match findings. Verdict precedence is fixed and versioned.
- Destination X-Ray: bounded inspection of URL-valued query parameters, extra encoding layers, nested destinations, protocol-relative and supported relative targets.
- Trusted-domain boundary checks, a bundled Public Suffix List, conservative Unicode/ASCII confusable matching, and edit distance against five synthetic official domains.
- Shortener uncertainty, IP sign-in checks, weak-signal combination, and explicit unusual-but-benign examples.
- Local QR decoding of PNG, JPEG, and WebP uploads. No destination navigation or image upload to a server.
- Plain-language evidence, a screen-reader summary, optional device-local voice, source caution, official-domain information, and next-step guidance.
- A two-minute demo with play/pause/stop and safe `.example` presets. Four QR images are supplied in `demo/`.
- Optional local AI explanations. No quizzes, exercises, or practice prompts.

## Local AI

The checker does not require AI. Its deterministic reason and action are always available. To generate an additional explanation, install Ollama and download a suitable text model **before** going offline. PhishLens does not download models, call cloud models, or follow model-generated links.

On a machine with Ollama running, use **Check local AI**, select an installed model, and request an explanation. English and Hindi are available as requested output languages; fluency depends on the model. A small model may need several seconds to load. If the model is unavailable, times out, or returns unacceptable output, the original rule explanation stays visible.

For a fully disconnected demonstration, disable your network connection after setup. Ollama documents `OLLAMA_NO_CLOUD=1` for local-only operation; restart Ollama after changing its configuration. Ollama's own updater and other applications are outside PhishLens's control. PhishLens communicates only with its same-origin server and, on an explicit AI request, the fixed loopback Ollama service at `127.0.0.1:11434`.

The AI receives bounded rule information, not credentials or raw query strings. It has no tools. It cannot change the rule verdict, trigger navigation, or supply a replacement link. Model text is rendered as plain text. Validation and grounding reduce hallucinations but cannot prove arbitrary generated language correct; human review is appropriate before deploying a particular model to students.

## Policy and limitations

Edit `src/policy.ts` to change the institution-wide policy, then rebuild and rerun tests. The five shipped `.example` domains are **synthetic demonstration configuration**, not any real university's approved services. Keep domain policy centrally managed; individual departments should not change detection logic. An approved domain match is not a content or ownership verification.

- **Safe** means no configured warning signs were found. It never guarantees trustworthiness.
- **Review** means ambiguity or a defined caution requires confirmation.
- **Suspicious** means a configured stronger warning fired; it is not proof of a malicious website.
- Embedded URL inspection does not verify that a server redirects, nor prove an open-redirect vulnerability.
- Shorteners are never expanded. Their final destinations remain unknown.
- Unicode/confusable and edit-distance checks have limited coverage; no blacklist, reputation, page-content, certificate, or malware inspection is performed.
- Source context is self-reported. It adds a separate caution and cannot authenticate a poster or change the URL verdict.
- Local/private IPs and unusual ports are not guarantees of legitimacy.
- Input length, image dimensions, decoding passes, candidate count, and nesting are bounded. An incomplete inspection must be visible.

The application is intended for local single-user use. Do not expose its AI server to the public internet. A campus-wide hosted rollout requires an additional deployment design, model evaluation, policy ownership, and institutional review.

## Privacy

URL analysis happens in browser memory. There is no URL history, analytics, external font, remote image, reputation request, or automatic navigation. Inputs are not stored in browser storage. Clear removes the current input and result. Reloading also clears the application state. The host browser, operating system, clipboard, and manually saved screenshots remain outside that guarantee.

Passwords in URL userinfo are masked in result views. Query strings may themselves contain sensitive data; they are available for inspection on your own screen but are not sent to AI. Avoid displaying real tokens during a public demo.

## Validate

```powershell
npm run typecheck
npm test
npm run build
npm run test:e2e
```

Browser tests default to installed Microsoft Edge in headless mode. To test on another machine, adjust the `channel` in `playwright.config.ts` or install Playwright Chromium and omit the channel. Tests cover real QR input, every demo preset, host reveal, nested destinations, injection-safe rendering, password masking, offline analysis, no external destination requests, empty storage, keyboard access, automated accessibility, and mobile overflow.

`npm run check` runs all gates. `npm audit --omit=dev` checks installed runtime dependency advisories. Synthetic test agreement is not a real-world phishing detection rate. Automated accessibility checks supplement, but do not replace, evaluation with screen-reader users.

## Project structure

| Location | Purpose |
|---|---|
| `src/engine.ts` / `src/policy.ts` | Pure offline URL analysis and policy |
| `src/main.ts` / `src/styles.css` | Accessible application UI |
| `src/qr.ts` | Bounded local raster-image QR decoder |
| `src/presets.ts` | Safe demonstration fixtures |
| `src/server.ts` | Loopback static server and local AI bridge |
| `src/*.test.ts` | Rule and server regression tests |
| `tests/app.spec.ts` | Browser workflows and accessibility checks |
| `demo/` | QR images, URL fixtures, and pitch script |
| `PROJECT-BRIEF.md` | Source review and design history |

## Standards and dependencies

Parsing follows the [WHATWG URL Standard](https://url.spec.whatwg.org/). Registrable-domain extraction uses [tldts](https://github.com/remusao/tldts) with bundled suffix data. QR decoding uses [jsQR](https://github.com/cozmo/jsQR). Unicode comparisons are deliberately limited and informed by [Unicode security mechanisms](https://www.unicode.org/reports/tr39/). Local explanation integration uses [Ollama's structured output API](https://docs.ollama.com/api/generate) and [local-only guidance](https://docs.ollama.com/faq).

Dependency versions are pinned in `package-lock.json`. Rebuild and retest when upgrading libraries or policy data.
